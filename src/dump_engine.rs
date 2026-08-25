//! Library core of the il2cpp dumper.
//!
//! This module extracts the full dump pipeline from `main.rs` into a
//! reusable library API. All user interaction (spinners, prompts, styled
//! output) is abstracted behind the [`DumpSink`] trait so that the same
//! pipeline can drive the CLI binary, an Android JNI bridge, or tests.
//!
//! The CLI entry point in `main.rs` keeps its own interactive helpers and
//! does not go through this module; it remains the reference behaviour.
//! Keep the two implementations in sync when changing pipeline logic.

use std::fs;
use std::time::Instant;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::executor::Il2CppExecutor;
use crate::formats::elf::Elf;
use crate::formats::macho::{extract_fat_slice, parse_fat, MachO, MH_MAGIC_64};
use crate::formats::nso::Nso;
use crate::formats::pe::Pe;
use crate::formats::wasm::Wasm;
use crate::il2cpp::base::{Il2Cpp, VaSegment};
use crate::il2cpp::metadata::{Metadata, MetadataVariant};
use crate::output::decompiler::Il2CppDecompiler;
use crate::output::struct_generator::StructGenerator;

pub const MAGIC_METADATA: u32 = 0xFAB11BAF;
pub const MAGIC_ELF: u32 = 0x464C457F;
pub const MAGIC_PE: u16 = 0x5A4D;
pub const MAGIC_MACHO32: u32 = 0xFEEDFACE;
pub const MAGIC_MACHO64: u32 = 0xFEEDFACF;
pub const MAGIC_MACHOFAT: u32 = 0xBEBAFECA;
pub const MAGIC_NSO: u32 = 0x304F534E;
pub const MAGIC_WASM: u32 = 0x6D736100;

/// Receives progress/status events from the dump pipeline.
///
/// Every method has a default no-op implementation, so a sink only needs
/// to override the callbacks it cares about. `request_input` returning
/// `None` is treated as "decline to answer": the caller falls back to the
/// default value or skips the interaction entirely.
pub trait DumpSink {
    /// Plain informational message (replaces CLI `print_info`/`print_detection`).
    fn log(&mut self, _msg: &str) {}

    /// Transient progress message (replaces CLI spinner messages).
    fn progress(&mut self, _msg: &str) {}

    /// Warning message (replaces CLI `print_warn`).
    fn warn(&mut self, _msg: &str) {}

    /// Success message (replaces CLI `print_success`).
    fn success(&mut self, _msg: &str) {}

    /// Ask the user a question. `default` is the value to use when the user
    /// declines or when no interactive channel exists.
    fn request_input(&mut self, _prompt: &str, _default: Option<&str>) -> Option<String> {
        None
    }
}

/// A silent sink for headless / test use.
pub struct NullSink;

impl DumpSink for NullSink {}

/// Result of a completed dump run, suitable for serializing back to callers.
#[derive(Debug, Clone)]
pub struct DumpSummary {
    pub output_dir: String,
    pub generated_files: Vec<String>,
    pub elapsed_secs: f64,
    pub metadata_version: f64,
    pub metadata_decryption: Option<String>,
    pub unity_version: Option<String>,
    pub format: String,
}

// ---------------------------------------------------------------------------
// Public helpers (shared with the JNI bridge)
// ---------------------------------------------------------------------------

pub fn read_magic_u32(data: &[u8]) -> u32 {
    if data.len() < 4 {
        return 0;
    }
    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
}

pub fn read_magic_u16(data: &[u8]) -> u16 {
    if data.len() < 2 {
        return 0;
    }
    u16::from_le_bytes([data[0], data[1]])
}

pub fn is_valid_metadata_version(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    let ver = i32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    ver > 0 && ver < 200
}

pub fn detect_format(data: &[u8]) -> &'static str {
    let magic32 = read_magic_u32(data);
    let magic16 = read_magic_u16(data);
    match magic32 {
        MAGIC_ELF => "elf",
        MAGIC_MACHO32 | MAGIC_MACHO64 => "macho",
        MAGIC_MACHOFAT => "macho_fat",
        MAGIC_NSO => "nso",
        MAGIC_WASM => "wasm",
        _ if magic16 == MAGIC_PE => "pe",
        _ => "unknown",
    }
}

pub fn format_file_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

pub fn detect_unity_version(data: &[u8]) -> Option<String> {
    let mut best: Option<String> = None;
    let mut i = 0;
    while i + 12 < data.len() {
        if data[i] == b'2'
            && data[i + 1] == b'0'
            && data[i + 2].is_ascii_digit()
            && data[i + 3].is_ascii_digit()
            && data[i + 4] == b'.'
            && data[i + 5].is_ascii_digit()
        {
            let max_len = std::cmp::min(24, data.len() - i);
            let end = data[i..i + max_len]
                .iter()
                .position(|&b| !b.is_ascii_alphanumeric() && b != b'.')
                .unwrap_or(max_len);
            let candidate = &data[i..i + end];
            if candidate.len() >= 8 && candidate.len() <= 20 {
                if let Ok(s) = std::str::from_utf8(candidate) {
                    if s.chars().filter(|c| *c == '.').count() == 2
                        && (s.contains('f') || s.contains('b') || s.contains('a') || s.contains('p'))
                        && s.ends_with(|c: char| c.is_ascii_digit())
                    {
                        if best.as_ref().map_or(true, |prev| s > prev.as_str()) {
                            best = Some(s.to_string());
                        }
                    }
                }
            }
            i += end.max(1);
        } else {
            i += 1;
        }
    }
    best
}

/// Try the built-in metadata decryption schemes in-place.
///
/// Mirrors `main.rs::try_decrypt_metadata`. Returns a human-readable
/// description of the scheme that worked, or `None` if the data is either
/// already plaintext or unrecognized.
pub fn try_decrypt_metadata(data: &mut Vec<u8>) -> Option<String> {
    if data.len() < 16 {
        return None;
    }

    let magic = MAGIC_METADATA.to_le_bytes();

    let k1 = magic[0] ^ data[0];
    if k1 != 0 && (1..4).all(|i| (magic[i] ^ data[i]) == k1) {
        let mut test = data.clone();
        for b in test.iter_mut() {
            *b ^= k1;
        }
        if is_valid_metadata_version(&test) {
            *data = test;
            return Some(format!("Single-byte XOR (key: 0x{k1:02X})"));
        }
    }

    let key4: [u8; 4] = std::array::from_fn(|i| magic[i] ^ data[i]);
    if key4 != [0u8; 4] && !key4.windows(2).all(|w| w[0] == w[1]) {
        let mut test = data.clone();
        for (i, b) in test.iter_mut().enumerate() {
            *b ^= key4[i % 4];
        }
        if is_valid_metadata_version(&test) {
            *data = test;
            return Some(format!(
                "4-byte XOR (key: {:02X}{:02X}{:02X}{:02X})",
                key4[0], key4[1], key4[2], key4[3]
            ));
        }
    }

    let key8: [u8; 8] = std::array::from_fn(|i| {
        if i < 4 {
            magic[i] ^ data[i]
        } else {
            data[i]
        }
    });
    if key8[0..4] != [0u8; 4] {
        let expected_ver_bytes: Vec<u8> = (4..8).map(|i| data[i] ^ key8[i]).collect();
        let test_ver = i32::from_le_bytes([
            expected_ver_bytes[0],
            expected_ver_bytes[1],
            expected_ver_bytes[2],
            expected_ver_bytes[3],
        ]);
        if test_ver > 0 && test_ver < 200 {
            let mut test = data.clone();
            for (i, b) in test.iter_mut().enumerate() {
                *b ^= key8[i % 8];
            }
            if is_valid_metadata_version(&test) {
                *data = test;
                return Some(format!(
                    "8-byte XOR (key: {:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X})",
                    key8[0], key8[1], key8[2], key8[3], key8[4], key8[5], key8[6], key8[7]
                ));
            }
        }
    }

    for key_len in [16usize, 32, 64, 128, 256] {
        if data.len() < key_len * 2 {
            continue;
        }
        let key: Vec<u8> = (0..key_len)
            .map(|i| if i < 4 { magic[i] ^ data[i] } else { data[i] ^ 0 })
            .collect();
        if key[0..4] == [0u8; 4] {
            continue;
        }
        let mut test = data[..8].to_vec();
        for (i, b) in test.iter_mut().enumerate() {
            *b ^= key[i % key_len];
        }
        if &test[0..4] == &magic && is_valid_metadata_version(&test) {
            for (i, b) in data.iter_mut().enumerate() {
                *b ^= key[i % key_len];
            }
            return Some(format!("{key_len}-byte rolling XOR key"));
        }
    }

    {
        let mut test = data.clone();
        for (i, b) in test.iter_mut().enumerate() {
            *b ^= key4[i % 4] ^ (i as u8);
        }
        if &test[0..4] == &magic && is_valid_metadata_version(&test) {
            *data = test;
            return Some(format!(
                "Position-dependent XOR (base key: {:02X}{:02X}{:02X}{:02X})",
                key4[0], key4[1], key4[2], key4[3]
            ));
        }
    }

    {
        let mut test = data.clone();
        for (i, b) in test.iter_mut().enumerate() {
            *b ^= key4[i % 4] ^ ((i & 0xFF) as u8);
        }
        if &test[0..4] == &magic && is_valid_metadata_version(&test) {
            *data = test;
            return Some(format!(
                "Masked position XOR (base key: {:02X}{:02X}{:02X}{:02X})",
                key4[0], key4[1], key4[2], key4[3]
            ));
        }
    }

    {
        let header_size = 256usize.min(data.len());
        let mut test = data.clone();
        for i in 0..header_size {
            test[i] ^= key4[i % 4];
        }
        if &test[0..4] == &magic && is_valid_metadata_version(&test) {
            *data = test;
            return Some(format!(
                "Header-only XOR ({header_size} bytes, key: {:02X}{:02X}{:02X}{:02X})",
                key4[0], key4[1], key4[2], key4[3]
            ));
        }
    }

    // Mfuscator: rotating-key header encryption + section shuffling
    // (reference port of Cpp2IL's Mfuscator plugin; v27-37 only).
    if let Some(rebuilt) = crate::mfuscator::try_fixup_mfuscator(data) {
        *data = rebuilt;
        return Some("Mfuscator (rotating XOR + section rebuild)".into());
    }

    None
}

// ---------------------------------------------------------------------------
// Input helpers (sink-backed replacements for dialoguer prompts)
// ---------------------------------------------------------------------------

fn validate_hex(input: &str, field: &str) -> std::result::Result<(), String> {
    let trimmed = input.trim().trim_start_matches("0x").trim_start_matches("0X");
    if trimmed.is_empty() {
        return Err(format!("Invalid hex for {field}: '{input}'"));
    }
    u64::from_str_radix(trimmed, 16)
        .map(|_| ())
        .map_err(|_| format!("Invalid hex for {field}: '{input}'"))
}

fn parse_hex_input(input: &str) -> u64 {
    let trimmed = input.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(trimmed, 16).unwrap_or(0)
}

/// Ask for a memory-dump base address; `None` means "skip" (address 0).
fn request_dump_address(sink: &mut dyn DumpSink) -> Option<u64> {
    sink.warn("Detected this may be a dump file.");
    let input = sink.request_input("Dump base address (hex), or 0 to skip", Some("0"))?;
    let addr = parse_hex_input(&input);
    if addr != 0 {
        Some(addr)
    } else {
        None
    }
}

/// Ask for CodeRegistration / MetadataRegistration addresses.
///
/// Mirrors the reference native engine: a single request tagged
/// `manual_addresses` whose reply is `"codeReg,metaReg"` (comma-separated
/// hex values). Each field is validated independently.
fn request_manual_addresses(sink: &mut dyn DumpSink) -> Result<(u64, u64)> {
    sink.warn("Auto mode failed, requesting manual addresses...");
    let input = sink
        .request_input("manual_addresses", None)
        .ok_or_else(|| Error::Other("Manual mode cancelled".into()))?;
    let mut parts = input.split(',');
    let cr_input = parts.next().unwrap_or("").trim();
    let mr_input = parts.next().unwrap_or("").trim();
    validate_hex(cr_input, "CodeRegistration").map_err(Error::Other)?;
    validate_hex(mr_input, "MetadataRegistration").map_err(Error::Other)?;
    let cr = parse_hex_input(cr_input);
    let mr = parse_hex_input(mr_input);
    sink.log(&format!("CodeRegistration: 0x{cr:x}"));
    sink.log(&format!("MetadataRegistration: 0x{mr:x}"));
    Ok((cr, mr))
}

fn resolve_codm(config: &Config, metadata: &Metadata) -> bool {
    config.codm || metadata.variant == MetadataVariant::Codm
}

/// Pick the `DumpN` output directory under `output_dir_arg`, mirroring the
/// CLI's incrementing behaviour.
pub fn resolve_output_dir(output_dir_arg: &str) -> String {
    let base_dir = std::path::Path::new(output_dir_arg);
    let mut dump_num = 0u32;
    while base_dir.join(format!("Dump{dump_num}")).exists() {
        dump_num += 1;
    }
    let output_dir = base_dir.join(format!("Dump{dump_num}"));
    fs::create_dir_all(&output_dir).ok();
    output_dir.to_string_lossy().to_string()
}

// ---------------------------------------------------------------------------
// Binary format initializers (sink-backed)
// ---------------------------------------------------------------------------

fn init_elf(
    data: Vec<u8>,
    metadata: &Metadata,
    config: &Config,
    sink: &mut dyn DumpSink,
) -> Result<Il2Cpp> {
    let is_64 = data.len() > 4 && data[4] == 2;
    sink.log(&format!("Detected ELF{} format", if is_64 { "64" } else { "32" }));

    let mut elf = if metadata.variant == MetadataVariant::Codm {
        Elf::new_with_codm_diag(data, !is_64, true)?
    } else {
        Elf::new(data, !is_64)?
    };

    let version = if config.force_il2cpp_version {
        config.force_version
    } else {
        metadata.version
    };

    elf.set_properties(version, metadata.metadata_usages_count as u64);
    sink.log(&format!("IL2CPP Version: {version}"));

    if config.force_dump || elf.check_dump() {
        if let Some(addr) = request_dump_address(sink) {
            elf.stream.image_base = addr;
            elf.is_dumped = true;
            if !config.no_redirected_pointer {
                elf.load()?;
            }
        }
    }

    sink.progress("Searching for registrations...");
    let method_count = metadata
        .method_defs
        .iter()
        .filter(|m| m.method_index >= 0)
        .count();
    let type_count = metadata.type_defs.len();
    let image_count = metadata.image_defs.len();

    let mut helper = elf.get_section_helper(method_count, type_count, image_count);
    let code_reg = helper.find_code_registration();
    let metadata_reg = if metadata.variant == MetadataVariant::Codm {
        helper
            .find_metadata_registration_codm()
            .or_else(|| helper.find_metadata_registration())
    } else {
        helper.find_metadata_registration()
    };

    // Print CR/MR only once — after the strategy that actually succeeds.
    let mut found = false;
    let mut final_cr: Option<u64> = None;
    let mut final_mr: Option<u64> = None;
    let mut how = "";

    if elf.auto_plus_init(code_reg, metadata_reg).unwrap_or(false) {
        found = true;
        final_cr = code_reg;
        final_mr = metadata_reg;
        how = "Section scan";
    }

    if !found {
        if let Ok(Some((cr, mr))) = elf.symbol_search() {
            if elf.init_with_auto_plus(cr, mr).is_ok() {
                found = true;
                final_cr = Some(cr);
                final_mr = Some(mr);
                how = "Symbol table";
            }
        }
    }

    if !found {
        if let Some((cr, mr)) = elf.search_arm32(version) {
            if elf.init_with_auto_plus(cr, mr).is_ok() {
                found = true;
                final_cr = Some(cr);
                final_mr = Some(mr);
                how = "ARM32 search pattern";
            }
        }
    }

    if !found {
        let (cr, mr) = request_manual_addresses(sink)?;
        elf.init_with_auto_plus(cr, mr)?;
    } else {
        if !how.is_empty() {
            sink.log(&format!("Detected {how}"));
        }
        if let Some(cr) = final_cr {
            sink.log(&format!("CodeRegistration: 0x{cr:x}"));
        }
        if let Some(mr) = final_mr {
            sink.log(&format!("MetadataRegistration: 0x{mr:x}"));
        }
    }

    let elf_exports = elf.list_exported_symbols().unwrap_or_default();
    let mut il2cpp = Il2Cpp::from_elf(&elf);
    il2cpp.codm = il2cpp.codm || resolve_codm(config, metadata);
    il2cpp.exported_symbols = elf_exports.iter().map(|(n, _)| n.clone()).collect();
    for (name, addr) in elf_exports {
        if name.starts_with("il2cpp_") || name.starts_with("mono_") {
            let rva = il2cpp.get_rva(addr);
            il2cpp.api_export_rvas.insert(name, rva);
        }
    }
    Ok(il2cpp)
}

fn init_pe(
    data: Vec<u8>,
    metadata: &Metadata,
    config: &Config,
    sink: &mut dyn DumpSink,
) -> Result<Il2Cpp> {
    let mut pe = Pe::new(data)?;
    sink.log(&format!(
        "Detected PE{} format",
        if pe.is_32bit { "32" } else { "64" }
    ));

    let version = if config.force_il2cpp_version {
        config.force_version
    } else {
        metadata.version
    };

    pe.stream.version = version;
    pe.stream.is_32bit = pe.is_32bit;
    sink.log(&format!("IL2CPP Version: {version}"));

    if config.force_dump || pe.check_dump() {
        if let Some(addr) = request_dump_address(sink) {
            pe.stream.image_base = addr;
        }
    }

    sink.progress("Searching for registrations...");
    let method_count = metadata
        .method_defs
        .iter()
        .filter(|m| m.method_index >= 0)
        .count();
    let type_count = metadata.type_defs.len();
    let image_count = metadata.image_defs.len();
    let mu_count = metadata.metadata_usages_count;

    let mut cr_addr = 0u64;
    let mut mr_addr = 0u64;

    if let Ok(Some((cr, mr))) = pe.symbol_search() {
        sink.log("Detected Symbol table");
        sink.log(&format!("CodeRegistration: 0x{cr:x}"));
        sink.log(&format!("MetadataRegistration: 0x{mr:x}"));
        cr_addr = cr;
        mr_addr = mr;
    }

    if cr_addr == 0 || mr_addr == 0 {
        let mut helper = pe.get_section_helper(method_count, type_count, mu_count, image_count, version);
        let code_reg = helper.find_code_registration();
        let metadata_reg = helper.find_metadata_registration();
        if let (Some(cr), Some(mr)) = (code_reg, metadata_reg) {
            sink.log(&format!("CodeRegistration: 0x{cr:x}"));
            sink.log(&format!("MetadataRegistration: 0x{mr:x}"));
            cr_addr = cr;
            mr_addr = mr;
        }
    }

    if cr_addr == 0 || mr_addr == 0 {
        let (cr, mr) = request_manual_addresses(sink)?;
        cr_addr = cr;
        mr_addr = mr;
    }

    let pe_image_base = pe.image_base();
    let va_segments: Vec<VaSegment> = pe
        .sections
        .iter()
        .map(|s| VaSegment {
            vaddr: s.virtual_address as u64 + pe_image_base,
            memsz: s.virtual_size as u64,
            offset: s.pointer_to_raw_data as u64,
        })
        .collect();

    let mut il2cpp = Il2Cpp::new(pe.stream.clone(), version, pe.is_32bit);
    il2cpp.va_segments = va_segments;
    il2cpp.image_base = pe_image_base;
    il2cpp.is_pe = true;
    il2cpp.codm = resolve_codm(config, metadata);
    il2cpp.arch = Some(if pe.is_32bit {
        crate::disassembler::Architecture::X86
    } else {
        crate::disassembler::Architecture::X64
    });
    il2cpp.init_with_auto_plus(cr_addr, mr_addr, &|addr| pe.map_vatr(addr), false)?;
    il2cpp.data_sections = pe.data_search_sections();
    if let Ok(exports) = pe.list_exported_symbols() {
        il2cpp.exported_symbols = exports.iter().map(|(n, _)| n.clone()).collect();
        for (name, rva) in exports {
            if name.starts_with("il2cpp_") || name.starts_with("mono_") {
                il2cpp.api_export_rvas.insert(name, rva);
            }
        }
    }
    Ok(il2cpp)
}

fn init_macho_fat(
    data: Vec<u8>,
    metadata: &Metadata,
    config: &Config,
    sink: &mut dyn DumpSink,
) -> Result<Il2Cpp> {
    let arches = parse_fat(&data)?;
    sink.log(&format!(
        "Detected Fat Mach-O with {} architectures",
        arches.len()
    ));

    // Mirrors the reference so's auto architecture selection
    // (fcn.003e7d6c): prefer the first 64-bit slice, fall back to the
    // first architecture otherwise, and report what was picked.
    let selection = arches
        .iter()
        .position(|arch| arch.magic == MH_MAGIC_64)
        .unwrap_or(0);
    let bits = if arches[selection].magic == MH_MAGIC_64 {
        "64-bit"
    } else {
        "32-bit"
    };
    sink.log(&format!("Auto-selected architecture: {bits}"));

    let slice = extract_fat_slice(&data, &arches[selection])?;
    init_macho(slice, metadata, config, sink)
}

fn init_macho(
    data: Vec<u8>,
    metadata: &Metadata,
    config: &Config,
    sink: &mut dyn DumpSink,
) -> Result<Il2Cpp> {
    let magic = read_magic_u32(&data);
    let is_64 = magic == MAGIC_MACHO64;
    sink.log(&format!(
        "Detected Mach-O {} format",
        if is_64 { "64-bit" } else { "32-bit" }
    ));

    let mut macho = if metadata.variant == MetadataVariant::Codm {
        MachO::new_with_codm_fixups(data, !is_64, true)?
    } else {
        MachO::new(data, !is_64)?
    };

    let version = if config.force_il2cpp_version {
        config.force_version
    } else {
        metadata.version
    };

    macho.stream.version = version;
    macho.stream.is_32bit = macho.is_32bit;
    sink.log(&format!("IL2CPP Version: {version}"));

    sink.progress("Searching for registrations...");
    let method_count = metadata
        .method_defs
        .iter()
        .filter(|m| m.method_index >= 0)
        .count();
    let type_count = metadata.type_defs.len();
    let image_count = metadata.image_defs.len();
    let mu_count = metadata.metadata_usages_count;

    let mut cr_addr = 0u64;
    let mut mr_addr = 0u64;

    if let Some((cr, mr)) = macho.symbol_search() {
        sink.log("Detected Symbol table");
        sink.log(&format!("CodeRegistration: 0x{cr:x}"));
        sink.log(&format!("MetadataRegistration: 0x{mr:x}"));
        cr_addr = cr;
        mr_addr = mr;
    }

    if cr_addr == 0 || mr_addr == 0 {
        if let Some((cr, mr)) = macho.search_mod_init_func(version) {
            sink.log("Detected __mod_init_func section");
            sink.log(&format!("CodeRegistration: 0x{cr:x}"));
            sink.log(&format!("MetadataRegistration: 0x{mr:x}"));
            cr_addr = cr;
            mr_addr = mr;
        }
    }

    if cr_addr == 0 || mr_addr == 0 {
        let mut helper = macho.get_section_helper(method_count, type_count, mu_count, image_count, version);
        let code_reg = helper.find_code_registration();
        let metadata_reg = if metadata.variant == MetadataVariant::Codm {
            helper
                .find_metadata_registration_codm()
                .or_else(|| helper.find_metadata_registration())
        } else {
            helper.find_metadata_registration()
        };
        if let (Some(cr), Some(mr)) = (code_reg, metadata_reg) {
            sink.log(&format!("CodeRegistration: 0x{cr:x}"));
            sink.log(&format!("MetadataRegistration: 0x{mr:x}"));
            cr_addr = cr;
            mr_addr = mr;
        }
    }

    if cr_addr == 0 || mr_addr == 0 {
        let (cr, mr) = request_manual_addresses(sink)?;
        cr_addr = cr;
        mr_addr = mr;
    }

    let va_segments: Vec<VaSegment> = macho
        .segments
        .iter()
        .map(|s| VaSegment {
            vaddr: s.vmaddr,
            memsz: s.vmsize,
            offset: s.fileoff,
        })
        .collect();

    // Try a (cr, mr) pair with il2cpp.init and report whether it parsed
    // cleanly. Auto-detection on Mach-O can land on byte-pattern false
    // positives that look right but blow up when pointer fields are
    // dereferenced — catching that here lets us fall back to manual input
    // instead of dying.
    let try_init = |cr: u64, mr: u64| -> Result<Il2Cpp> {
        let mut il2cpp = Il2Cpp::new(macho.stream.clone(), version, macho.is_32bit);
        il2cpp.va_segments = va_segments.clone();
        il2cpp.codm = resolve_codm(config, metadata);
        il2cpp.init_with_auto_plus(cr, mr, &|addr| macho.map_vatr(addr), false)?;
        Ok(il2cpp)
    };

    let mut il2cpp = match try_init(cr_addr, mr_addr) {
        Ok(i) => i,
        Err(e) => {
            sink.warn(&format!(
                "Auto-detected CodeRegistration / MetadataRegistration failed to parse ({e}). \
                 Likely a byte-pattern false positive. Please enter the correct addresses \
                 (e.g. from IDA / Ghidra cross-references on s_Il2CppCodeRegistration / \
                 s_Il2CppMetadataRegistration)."
            ));
            let (cr2, mr2) = request_manual_addresses(sink)?;
            cr_addr = cr2;
            mr_addr = mr2;
            try_init(cr_addr, mr_addr)?
        }
    };

    il2cpp.data_sections = macho.data_search_sections();

    if macho.is_32bit {
        for ptr in il2cpp.method_pointers.iter_mut() {
            if *ptr > 0 {
                *ptr -= 1;
            }
        }
        for ptr in il2cpp.custom_attribute_generators.iter_mut() {
            if *ptr > 0 {
                *ptr -= 1;
            }
        }
    }

    let macho_exports = macho.list_exported_symbols();
    il2cpp.exported_symbols = macho_exports.iter().map(|(n, _)| n.clone()).collect();
    for (name, addr) in macho_exports {
        if name.starts_with("il2cpp_") || name.starts_with("mono_") {
            let rva = il2cpp.get_rva(addr);
            il2cpp.api_export_rvas.insert(name, rva);
        }
    }

    Ok(il2cpp)
}

fn init_nso(
    data: Vec<u8>,
    metadata: &Metadata,
    config: &Config,
    sink: &mut dyn DumpSink,
) -> Result<Il2Cpp> {
    sink.log("Detected NSO (Nintendo Switch) format");

    let mut nso = Nso::new(data)?;

    let version = if config.force_il2cpp_version {
        config.force_version
    } else {
        metadata.version
    };

    nso.stream.version = version;
    nso.stream.is_32bit = nso.is_32bit;
    sink.log(&format!("IL2CPP Version: {version}"));

    sink.progress("Searching for registrations...");
    let method_count = metadata
        .method_defs
        .iter()
        .filter(|m| m.method_index >= 0)
        .count();
    let type_count = metadata.type_defs.len();
    let image_count = metadata.image_defs.len();
    let mu_count = metadata.metadata_usages_count;

    let mut helper = nso.get_section_helper(method_count, type_count, mu_count, image_count, version);
    let code_reg = helper.find_code_registration();
    let metadata_reg = helper.find_metadata_registration();

    let (cr_addr, mr_addr) = if let (Some(cr), Some(mr)) = (code_reg, metadata_reg) {
        sink.log(&format!("CodeRegistration: 0x{cr:x}"));
        sink.log(&format!("MetadataRegistration: 0x{mr:x}"));
        (cr, mr)
    } else {
        request_manual_addresses(sink)?
    };

    let stream_len = nso.stream.data().len() as u64;
    let mut il2cpp = Il2Cpp::new(nso.stream.clone(), version, nso.is_32bit);
    il2cpp.va_segments = vec![VaSegment {
        vaddr: 0,
        memsz: stream_len,
        offset: 0,
    }];
    il2cpp.codm = resolve_codm(config, metadata);
    il2cpp.init_with_auto_plus(cr_addr, mr_addr, &|addr| nso.map_vatr(addr), false)?;
    il2cpp.data_sections = nso.data_search_sections();

    if let Ok(nso_exports) = nso.list_exported_symbols() {
        il2cpp.exported_symbols = nso_exports.iter().map(|(n, _)| n.clone()).collect();
        for (name, addr) in nso_exports {
            if name.starts_with("il2cpp_") || name.starts_with("mono_") {
                let rva = il2cpp.get_rva(addr);
                il2cpp.api_export_rvas.insert(name, rva);
            }
        }
    }

    Ok(il2cpp)
}

fn init_wasm(
    data: Vec<u8>,
    metadata: &Metadata,
    config: &Config,
    sink: &mut dyn DumpSink,
) -> Result<Il2Cpp> {
    sink.log("Detected WebAssembly (WASM) format");

    let mut wasm = Wasm::new(data)?;

    let version = if config.force_il2cpp_version {
        config.force_version
    } else {
        metadata.version
    };

    wasm.stream.version = version;
    wasm.stream.is_32bit = wasm.is_32bit;
    sink.log(&format!("IL2CPP Version: {version}"));

    sink.progress("Searching for registrations...");
    let method_count = metadata
        .method_defs
        .iter()
        .filter(|m| m.method_index >= 0)
        .count();
    let type_count = metadata.type_defs.len();
    let image_count = metadata.image_defs.len();
    let mu_count = metadata.metadata_usages_count;

    let mut helper = wasm.get_section_helper(method_count, type_count, mu_count, image_count, version);
    let code_reg = helper.find_code_registration();
    let metadata_reg = helper.find_metadata_registration();

    let (cr_addr, mr_addr) = if let (Some(cr), Some(mr)) = (code_reg, metadata_reg) {
        sink.log(&format!("CodeRegistration: 0x{cr:x}"));
        sink.log(&format!("MetadataRegistration: 0x{mr:x}"));
        (cr, mr)
    } else {
        request_manual_addresses(sink)?
    };

    let stream_len = wasm.stream.data().len() as u64;
    let mut il2cpp = Il2Cpp::new(wasm.stream.clone(), version, wasm.is_32bit);
    il2cpp.va_segments = vec![VaSegment {
        vaddr: 0,
        memsz: stream_len,
        offset: 0,
    }];
    il2cpp.codm = resolve_codm(config, metadata);
    il2cpp.init_with_auto_plus(cr_addr, mr_addr, &|addr| wasm.map_vatr(addr), true)?;
    il2cpp.data_sections = wasm.data_search_sections();
    Ok(il2cpp)
}

// ---------------------------------------------------------------------------
// Main pipeline
// ---------------------------------------------------------------------------

/// Run the full dump pipeline, reporting progress through `sink`.
///
/// This mirrors `main.rs::run()` with all interactive/CLI output replaced by
/// `DumpSink` callbacks and file-system inputs taken directly as arguments.
pub fn dump_with_sink(
    binary_path: &str,
    metadata_path: &str,
    output_dir_arg: &str,
    config: &Config,
    sink: &mut dyn DumpSink,
) -> Result<DumpSummary> {
    let start_time = Instant::now();

    let output_dir = resolve_output_dir(output_dir_arg);
    sink.log(&format!("Output directory: {output_dir}"));

    sink.progress("Loading IL2CPP binary...");
    let il2cpp_bytes = fs::read(binary_path)?;
    let binary_size = il2cpp_bytes.len() as u64;
    sink.success(&format!(
        "Binary loaded: {binary_path} ({})",
        format_file_size(binary_size)
    ));

    let unity_version_str = detect_unity_version(&il2cpp_bytes);
    if let Some(ref uv) = unity_version_str {
        sink.log(&format!("Unity Version: {uv}"));
    }

    sink.progress("Loading metadata...");
    let mut metadata_bytes = fs::read(metadata_path)?;
    let metadata_size = metadata_bytes.len() as u64;
    sink.success(&format!(
        "Metadata loaded: {metadata_path} ({})",
        format_file_size(metadata_size)
    ));

    let mut metadata_decryption: Option<String> = None;
    let metadata_magic = read_magic_u32(&metadata_bytes);
    if metadata_magic != MAGIC_METADATA {
        match try_decrypt_metadata(&mut metadata_bytes) {
            Some(scheme) => {
                sink.log(&format!("Decrypted metadata: {scheme}"));
                metadata_decryption = Some(scheme);
            }
            None => {
                let b0 = (metadata_magic & 0xFF) as u8;
                let b1 = ((metadata_magic >> 8) & 0xFF) as u8;
                let b2 = ((metadata_magic >> 16) & 0xFF) as u8;
                let b3 = ((metadata_magic >> 24) & 0xFF) as u8;
                return Err(Error::InvalidMetadata(format!(
                    "Wrong magic 0x{metadata_magic:08X} (bytes {b0:02X} {b1:02X} {b2:02X} {b3:02X}). \
                     Expected AF 1B B1 FA. File is likely encrypted, obfuscated, truncated, or not \
                     global-metadata.dat. Encryption scheme not recognized by built-in decryptors. \
                     Protected games often need a runtime memory dump of decrypted metadata."
                )));
            }
        }
    }

    sink.progress("Parsing metadata structures...");
    let mut metadata = Metadata::new_with_options(
        metadata_bytes,
        unity_version_str.as_deref(),
        config.codm,
    )?;
    let metadata_version = metadata.version;
    sink.log(&format!("Metadata Version: {metadata_version}"));
    sink.log(&format!("Type Definitions: {}", metadata.type_defs.len()));
    sink.log(&format!("Method Definitions: {}", metadata.method_defs.len()));

    let format = detect_format(&il2cpp_bytes);

    let mut il2cpp = match format {
        "elf" => init_elf(il2cpp_bytes, &metadata, config, sink)?,
        "pe" => init_pe(il2cpp_bytes, &metadata, config, sink)?,
        "macho" => init_macho(il2cpp_bytes, &metadata, config, sink)?,
        "macho_fat" => init_macho_fat(il2cpp_bytes, &metadata, config, sink)?,
        "nso" => init_nso(il2cpp_bytes, &metadata, config, sink)?,
        "wasm" => init_wasm(il2cpp_bytes, &metadata, config, sink)?,
        _ => {
            let magic = read_magic_u32(&il2cpp_bytes);
            return Err(Error::Other(format!(
                "Unsupported binary format (magic: 0x{magic:08X})"
            )));
        }
    };

    if il2cpp.version >= 27.0 && il2cpp.is_dumped {
        if let Some(type_def) = metadata.type_defs.first() {
            let byval_idx = type_def.byval_type_index as usize;
            if byval_idx < il2cpp.types.len() {
                let il2cpp_type = &il2cpp.types[byval_idx];
                let type_handle = il2cpp_type.type_handle();
                il2cpp.image_base =
                    type_handle.wrapping_sub(metadata.header.type_definitions_offset as u64);
            }
        }
    }

    sink.progress("Generating dump.cs...");
    let mut executor = Il2CppExecutor::new(&metadata, &mut il2cpp)?;

    Il2CppDecompiler::decompile(
        &mut executor,
        &mut metadata,
        &mut il2cpp,
        config,
        &output_dir,
        |msg| sink.progress(msg),
    )?;
    sink.success("dump.cs generated");

    let mut generated_files: Vec<String> = vec!["dump.cs".into()];

    let static_catalog = if config.dump_static_field_metadata {
        sink.progress("Analyzing thread-static / FieldRVA metadata...");
        let catalog = crate::output::static_field_exporter::StaticFieldCatalog::collect(
            &mut executor,
            &mut metadata,
            &mut il2cpp,
            config,
        )?;
        crate::output::static_field_exporter::StaticFieldExporter::write_document(
            &catalog, &il2cpp, &output_dir,
        )?;
        sink.success(&format!(
            "static_metadata.json generated ({} thread-static, {} FieldRVA)",
            catalog.summary.thread_static_count,
            catalog.summary.field_rva_count,
        ));
        generated_files.push("static_metadata.json".into());
        Some(catalog)
    } else {
        None
    };

    if config.generate_struct {
        sink.progress("Generating structs...");
        StructGenerator::write_all(
            &mut executor,
            &mut metadata,
            &mut il2cpp,
            config,
            &output_dir,
            static_catalog.as_ref(),
        )?;
        crate::output::embedded_scripts::write_scripts(std::path::Path::new(&output_dir))?;
        sink.success("script.json, il2cpp.h, il2cpp-functions.h, stringliteral.json generated");
        generated_files.extend([
            "script.json".into(),
            "il2cpp.h".into(),
            "il2cpp-functions.h".into(),
            "stringliteral.json".into(),
        ]);
    }

    if config.generate_dummy_dll {
        sink.progress("Generating dummy DLLs...");
        crate::output::dummy_assembly_generator::generate_dummy_dlls(
            &mut executor,
            &mut metadata,
            &mut il2cpp,
            config,
            &output_dir,
        )?;
        sink.success("Dummy DLL files generated");
        generated_files.push("DummyDll/*.dll".into());
    }

    if config.generate_generics_dump {
        sink.progress("Generating generics dump...");
        let generics_path = std::path::Path::new(&output_dir).join("generics_dump.txt");
        if let Err(e) = crate::output::generics::dump_generics(
            &generics_path.to_string_lossy(),
            &mut metadata,
            &mut il2cpp,
            &mut executor,
            config,
        ) {
            sink.warn(&format!("Failed to generate generics_dump.txt: {e}"));
        } else {
            sink.success("generics_dump.txt generated");
            generated_files.push("generics_dump.txt".into());
        }
    }

    let elapsed = start_time.elapsed();

    Ok(DumpSummary {
        output_dir,
        generated_files,
        elapsed_secs: elapsed.as_secs_f64(),
        metadata_version,
        metadata_decryption,
        unity_version: unity_version_str,
        format: format.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sink that returns a canned reply for `request_input` and records
    /// every prompt/log/warn line it receives.
    struct StubSink {
        reply: Option<String>,
        prompts: Vec<String>,
        warns: Vec<String>,
        logs: Vec<String>,
    }

    impl DumpSink for StubSink {
        fn request_input(&mut self, prompt: &str, _default: Option<&str>) -> Option<String> {
            self.prompts.push(prompt.to_string());
            self.reply.clone()
        }
        fn warn(&mut self, msg: &str) {
            self.warns.push(msg.to_string());
        }
        fn log(&mut self, msg: &str) {
            self.logs.push(msg.to_string());
        }
    }

    fn stub(reply: Option<&str>) -> StubSink {
        StubSink {
            reply: reply.map(String::from),
            prompts: vec![],
            warns: vec![],
            logs: vec![],
        }
    }

    #[test]
    fn validate_hex_reports_field_specific_errors() {
        assert_eq!(
            validate_hex("zz", "CodeRegistration"),
            Err("Invalid hex for CodeRegistration: 'zz'".to_string())
        );
        assert_eq!(
            validate_hex("", "MetadataRegistration"),
            Err("Invalid hex for MetadataRegistration: ''".to_string())
        );
        assert!(validate_hex("0xABCDEF", "CodeRegistration").is_ok());
    }

    #[test]
    fn manual_addresses_parses_comma_separated_single_request() {
        let mut sink = stub(Some("ABCDEF,123456"));
        let (cr, mr) = request_manual_addresses(&mut sink).unwrap();
        assert_eq!(cr, 0xABCDEF);
        assert_eq!(mr, 0x123456);
        assert_eq!(sink.prompts, vec!["manual_addresses".to_string()]);
        assert_eq!(
            sink.warns,
            vec!["Auto mode failed, requesting manual addresses...".to_string()]
        );
    }

    #[test]
    fn manual_addresses_tolerates_spaces_and_prefix() {
        let mut sink = stub(Some("0xABC, 0x123"));
        let (cr, mr) = request_manual_addresses(&mut sink).unwrap();
        assert_eq!(cr, 0xABC);
        assert_eq!(mr, 0x123);
    }

    #[test]
    fn manual_addresses_rejects_bad_field() {
        let mut sink = stub(Some("ABC,zzz"));
        let err = request_manual_addresses(&mut sink).unwrap_err();
        assert!(
            err.to_string().contains("Invalid hex for MetadataRegistration: 'zzz'"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn manual_addresses_cancelled_without_channel() {
        let mut sink = stub(None);
        let err = request_manual_addresses(&mut sink).unwrap_err();
        assert_eq!(err.to_string(), "Manual mode cancelled");
    }
}
