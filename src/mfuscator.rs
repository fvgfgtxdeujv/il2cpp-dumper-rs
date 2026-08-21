//! Mfuscator metadata deobfuscation.
//!
//! Reference-implementation port of Cpp2IL's `Cpp2IL.Plugin.Mfuscator`
//! (MIT licensed). Mfuscator encrypts the metadata header with a rotating
//! XOR key, shuffles the section layout in the file, and re-encrypts a few
//! sections with a per-section rotating key. This module recovers the
//! original XOR key from the header, reconstructs the true section layout
//! via depth-first search, decrypts the encrypted sections and rebuilds a
//! standard global-metadata.dat.
//!
//! Like the Cpp2IL plugin, only metadata versions 27-37 are supported
//! (8 bytes per section header field; v38+ uses 12 and is not supported).

use std::collections::{HashMap, HashSet};

/// Largest header we will consider when searching for its end.
const MAX_HEADER_SIZE: usize = 480;

// Section indexes used by Mfuscator's fixed layout (v27-37).
const SL_IDX: usize = 0; // string literals
const SLD_IDX: usize = 1; // string literal data
const STRINGS_IDX: usize = 2; // strings
const PROPERTIES_IDX: usize = 4;
const METHODS_IDX: usize = 5;
const FIELDS_IDX: usize = 11;
const ASSEMBLIES_IDX: usize = 21;

const EXPECTED_SECTION_COUNT: usize = 31;

/// A single step in a reconstructed section layout.
#[derive(Debug, Clone, Copy)]
struct ReconstructedSection {
    offset_in_header: usize,
    length: usize,
    delta: i64,
}

impl ReconstructedSection {
    fn actual_offset(&self) -> usize {
        (self.offset_in_header as i64 + self.delta).max(0) as usize
    }

    fn actual_end(&self) -> usize {
        self.actual_offset().saturating_add(self.length)
    }
}

/// Rotating XOR used for the header: `xorKey ± (offset + i)`.
fn cyclic_xor_header(data: &[u8], xor_key: u8, is_plus: bool, offset: usize) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| {
            let key_byte = if is_plus {
                (xor_key as usize + offset + i) & 0xFF
            } else {
                (xor_key as i64 - (offset as i64 + i as i64)).rem_euclid(256) as usize
            };
            b ^ key_byte as u8
        })
        .collect()
}

/// Rotating XOR used for sections: `xorKey ± (offset ± i)`.
fn cyclic_xor(data: &[u8], xor_key: u8, is_plus: bool, offset: usize) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| {
            let key_byte = if is_plus {
                (xor_key as usize + offset + i) & 0xFF
            } else {
                // C#: (i - offset - xorKey) & 0xFF
                (i as i64 - offset as i64 - xor_key as i64).rem_euclid(256) as usize
            };
            b ^ key_byte as u8
        })
        .collect()
}

/// Derives the header XOR key from the encrypted bytes.
///
/// The first two header words (sanity, version) have zero in their top byte;
/// with a rotating key the encrypted values at `[off+3]` and `[off+7]`
/// differ by exactly 4 (one field length), which reveals both the direction
/// and the key.
fn derive_xor_key(encrypted_header: &[u8]) -> Option<(u8, bool)> {
    let mut value_offset = 0usize;
    while value_offset + 4 + 3 < encrypted_header.len() {
        let known_zero_byte = encrypted_header[value_offset + 3];
        let known_zero_byte_two = encrypted_header[value_offset + 4 + 3];

        let looks_plus = ((known_zero_byte as i32 + 4) & 0xFF) as u8 == known_zero_byte_two;
        let looks_minus = ((known_zero_byte as i32 - 4) & 0xFF) as u8 == known_zero_byte_two;

        if !looks_minus && !looks_plus {
            value_offset += 4;
            continue;
        }

        let is_plus = looks_plus;
        let key = if is_plus {
            ((known_zero_byte as i32 - value_offset as i32 - 3) & 0xFF) as u8
        } else {
            ((known_zero_byte as i32 + value_offset as i32 + 3) & 0xFF) as u8
        };
        return Some((key, is_plus));
    }
    None
}

/// Decrypts the header and locates its true end by scanning for the first
/// non-zero high byte (the start of the string-literal data section).
fn decrypt_header(
    encrypted_header: &[u8],
    xor_key: u8,
    is_plus: bool,
) -> Option<(Vec<u8>, u8, bool)> {
    let mut header_size = 0usize;
    while header_size < MAX_HEADER_SIZE {
        if header_size + 4 > encrypted_header.len() {
            return None;
        }
        let encrypted_word = &encrypted_header[header_size..header_size + 4];
        let decrypted_word = cyclic_xor_header(encrypted_word, xor_key, is_plus, header_size);
        header_size += 4;

        // Top byte of every header field is zero (offsets/lengths < 32MB).
        if decrypted_word[0] == 0 {
            continue;
        }

        // We reached the string-literal data. Its first bytes are sequential
        // under the same rotating key, which lets us confirm the boundary.
        let sl_plus = ((encrypted_word[0] as i32 + 1) & 0xFF) as u8 == encrypted_word[1];
        let sl_minus = ((encrypted_word[0] as i32 - 1) & 0xFF) as u8 == encrypted_word[1];
        if !sl_plus && !sl_minus {
            continue;
        }

        let addend: i32 = if sl_plus { 1 } else { -1 };
        let mut looks_valid = true;
        for i in 0..3 {
            if (((encrypted_word[i] as i32 + addend) & 0xFF) as u8) != encrypted_word[i + 1] {
                looks_valid = false;
                break;
            }
        }
        if !looks_valid {
            continue;
        }

        header_size -= 4; // last word was actually the start of string-literal data
        let decrypted_header = cyclic_xor_header(&encrypted_header[..header_size], xor_key, is_plus, 0);
        let sl_key = encrypted_word[0];
        let next_word = encrypted_header.get(header_size + 4..header_size + 8)?;
        let sl_is_plus = next_word[0] == encrypted_word[0].wrapping_add(4);
        return Some((decrypted_header, sl_key, sl_is_plus));
    }
    None
}

/// Depth-first search that reconstructs the true section layout.
///
/// The header words (offset/size pairs, in section order) are the pool. We
/// walk the file from just past the header, and at each step pick an offset
/// from the pool whose value differs from the current position by the
/// Mfuscator shift range (0x10-0x40) and a length from the remaining pool
/// such that the sections chain up to the end of the metadata.
fn find_paths(
    header_words: &[u32],
    data_start: usize,
    file_end: usize,
    expected_count: usize,
) -> Vec<Vec<ReconstructedSection>> {
    const MIN_DELTA: i64 = 0x10;
    const MAX_DELTA: i64 = 0x40;
    const MAX_RESULTS: usize = 65536;
    // fieldAndParameterDefaultValueData is 8-byte aligned (index 8)
    const MAX_ALIGN_PAD: usize = 7;

    fn offset_in_range(candidate: u32, actual_pos: usize) -> bool {
        let delta = (actual_pos as i64 - candidate as i64).abs();
        delta >= MIN_DELTA && delta <= MAX_DELTA
    }

    fn apply_alignment(actual_pos: usize, section_index: usize) -> usize {
        if section_index != 8 {
            return actual_pos;
        }
        let remainder = actual_pos % 8;
        if remainder == 0 {
            actual_pos
        } else {
            actual_pos + (8 - remainder)
        }
    }

    fn dfs(
        mut actual_pos: usize,
        pool: &mut Vec<u32>,
        sections: &mut Vec<ReconstructedSection>,
        results: &mut Vec<Vec<ReconstructedSection>>,
        data_start: usize,
        file_end: usize,
        expected_count: usize,
        max_align_pad: usize,
    ) {
        if results.len() >= MAX_RESULTS {
            return;
        }
        let section_index = sections.len();
        actual_pos = apply_alignment(actual_pos, section_index);

        let shortfall = file_end as i64 - actual_pos as i64;
        if shortfall <= 0 {
            if sections.len() == expected_count {
                results.push(sections.clone());
            }
            return;
        }

        // Candidate offsets: header words near the current position.
        let mut candidate_offsets: Vec<u32> = pool
            .iter()
            .copied()
            .filter(|&o| offset_in_range(o, actual_pos))
            .collect();
        if candidate_offsets.is_empty() {
            return;
        }
        candidate_offsets.sort_unstable();

        let mut any_length_found = false;
        for i in 0..candidate_offsets.len() {
            let candidate_offset = candidate_offsets[i];
            // Remove one occurrence of this offset.
            let idx = pool.iter().position(|&v| v == candidate_offset).unwrap();
            pool.remove(idx);
            let delta = actual_pos as i64 - candidate_offset as i64;

            // Lengths are the remaining pool values, tried ascending.
            pool.sort_unstable();
            let mut j = 0;
            while j < pool.len() {
                let length = pool[j] as usize;
                let new_pos = actual_pos + length;
                if new_pos > file_end + max_align_pad {
                    break; // sorted ascending: the rest are too long
                }
                if section_index < 26 && length == 0 {
                    j += 1;
                    continue;
                }

                pool.remove(j);
                sections.push(ReconstructedSection {
                    offset_in_header: candidate_offset as usize,
                    length,
                    delta,
                });
                dfs(
                    new_pos,
                    pool,
                    sections,
                    results,
                    data_start,
                    file_end,
                    expected_count,
                    max_align_pad,
                );
                sections.pop();
                pool.insert(j, length as u32);
                j += 1;
                any_length_found = true;
            }

            pool.insert(idx.min(pool.len()), candidate_offset);
            let _ = data_start;
        }
        let _ = any_length_found;
    }

    let mut pool: Vec<u32> = header_words.to_vec();
    pool.sort_unstable();
    let mut results = Vec::new();
    let mut sections = Vec::new();
    dfs(
        data_start,
        &mut pool,
        &mut sections,
        &mut results,
        data_start,
        file_end,
        expected_count,
        MAX_ALIGN_PAD,
    );
    results
}

/// Decrypts the sections that Mfuscator encrypted.
///
/// Returns a map of section index -> decrypted bytes for the encrypted
/// sections (the others are copied verbatim by the caller).
fn decrypt_encrypted_sections(
    encrypted: &[u8],
    sections: &[(usize, usize)],
    sl_key: u8,
    sl_is_plus: bool,
) -> Option<HashMap<usize, Vec<u8>>> {
    let sl_start = sections.get(SL_IDX)?.0;
    let sl_size = sections.get(SL_IDX)?.1.saturating_sub(sl_start);

    for using_offset in [true, false] {
        let mut decrypted: HashMap<usize, Vec<u8>> = HashMap::new();

        let sl_component = if using_offset { sl_start } else { sl_size };
        let addend = if sl_is_plus {
            (sl_key as i64 - sl_component as i64).rem_euclid(256) as u8
        } else {
            (sl_key as i64 + sl_component as i64).rem_euclid(256) as u8
        };

        // String literals start with two zero bytes; decrypt and verify.
        let dec_literals = cyclic_xor(&encrypted[sl_start..sl_start + sl_size], addend, sl_is_plus, sl_component);
        if dec_literals.first() == Some(&0) && dec_literals.get(1) == Some(&0) {
            decrypted.insert(SL_IDX, dec_literals);
        }
        if !decrypted.contains_key(&SL_IDX) {
            continue;
        }

        // String literal data.
        let sld_start = sections.get(SLD_IDX)?.0;
        let sld_size = sections.get(SLD_IDX)?.1.saturating_sub(sld_start);
        if sld_start + sld_size > encrypted.len() || sld_start + 2 > encrypted.len() {
            continue;
        }
        let sld_component = if using_offset { sld_start } else { sld_size };
        let first = encrypted[sld_start];
        let second = encrypted[sld_start + 1];
        let mut sld_is_plus = ((first as i32 + 1) & 0xFF) as u8 == second;
        let sld_is_minus = ((first as i32 - 1) & 0xFF) as u8 == second;
        if !sld_is_plus && !sld_is_minus {
            continue;
        }

        let mut addend2 = addend;
        if sld_is_plus {
            // Check for underflow that produced a wrong initial key.
            let dec_first = cyclic_xor(&encrypted[sld_start..sld_start + 4], addend2, true, sld_component);
            if dec_first.first() != Some(&0) {
                sld_is_plus = false;
                addend2 = (0u16.wrapping_sub(sl_key as u16).wrapping_sub(sl_component as u16) & 0xFF) as u8;
            }
        }
        let dec_literal_data = cyclic_xor(
            &encrypted[sld_start..sld_start + sld_size],
            addend2,
            sld_is_plus,
            sld_component,
        );
        decrypted.insert(SLD_IDX, dec_literal_data);

        // Strings: find two null terminators in the first 32 bytes.
        let strings_start = sections.get(STRINGS_IDX)?.0;
        let strings_size = sections.get(STRINGS_IDX)?.1.saturating_sub(strings_start);
        if strings_start + strings_size > encrypted.len() {
            continue;
        }
        let strings_component = if using_offset { strings_start } else { strings_size };
        let mut strings_is_plus = false;
        let mut found_zeroes = 0usize;
        for test_plus in [true, false] {
            found_zeroes = 0;
            strings_is_plus = test_plus;
            let scan_end = strings_size.min(32);
            for i in 0..scan_end {
                let assumed_key = if test_plus {
                    ((i + strings_component) as i64 + addend as i64).rem_euclid(256) as usize
                } else {
                    (i as i64 - strings_component as i64 - addend as i64).rem_euclid(256) as usize
                };
                if encrypted[strings_start + i] ^ assumed_key as u8 == 0 {
                    found_zeroes += 1;
                    if found_zeroes == 2 {
                        break;
                    }
                }
            }
            if found_zeroes == 2 {
                break;
            }
        }
        if found_zeroes != 2 {
            continue;
        }
        let dec_strings = cyclic_xor(
            &encrypted[strings_start..strings_start + strings_size],
            addend,
            strings_is_plus,
            strings_component,
        );
        decrypted.insert(STRINGS_IDX, dec_strings);

        // Remaining encrypted sections: direction by "third byte is zero".
        for &sec_idx in &[PROPERTIES_IDX, METHODS_IDX, FIELDS_IDX, ASSEMBLIES_IDX] {
            let Some(&(s, e)) = sections.get(sec_idx) else {
                continue;
            };
            let size = e.saturating_sub(s);
            if s + size > encrypted.len() || size < 4 {
                continue;
            }
            let component = if using_offset { s } else { size };
            let mut ok = false;
            for test_plus in [true, false] {
                let dec = cyclic_xor(&encrypted[s..s + size], addend, test_plus, component);
                if dec.get(3) == Some(&0) {
                    decrypted.insert(sec_idx, dec);
                    ok = true;
                    break;
                }
            }
            if !ok {
                continue;
            }
        }

        return Some(decrypted);
    }
    None
}

/// Rebuilds a standard global-metadata.dat from the encrypted file and the
/// reconstructed section layout.
fn rebuild_metadata(
    encrypted: &[u8],
    sections: &[(usize, usize)],
    sl_key: u8,
    sl_is_plus: bool,
    offset_delta: i64,
    version: u32,
) -> Option<Vec<u8>> {
    let decrypted_sections = decrypt_encrypted_sections(encrypted, sections, sl_key, sl_is_plus)?;

    let mut out = vec![0u8; encrypted.len()];
    out[0..4].copy_from_slice(&0xFAB11BAFu32.to_le_bytes());
    out[4..8].copy_from_slice(&(version as i32).to_le_bytes());

    let mut header_pos = 8usize;
    for (i, &(start, end)) in sections.iter().enumerate() {
        if header_pos + 8 > out.len() {
            return None;
        }
        let new_off = start as i64 + offset_delta;
        if new_off < 0 || new_off as usize + (end - start) > out.len() {
            return None;
        }
        out[header_pos..header_pos + 4].copy_from_slice(&(new_off as i32).to_le_bytes());
        out[header_pos + 4..header_pos + 8].copy_from_slice(&((end - start) as i32).to_le_bytes());
        header_pos += 8;

        let dst = new_off as usize;
        let data: &[u8] = match decrypted_sections.get(&i) {
            Some(sec) => sec.as_slice(),
            None => &encrypted[start..end],
        };
        if data.len() != end - start {
            return None;
        }
        out[dst..dst + (end - start)].copy_from_slice(data);
    }

    Some(out)
}

/// Entry point: attempts to deobfuscate a Mfuscator-mangled metadata file.
/// Returns the rebuilt standard metadata, or `None` if the file does not
/// look like a (supported) Mfuscator output.
pub fn try_fixup_mfuscator(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 16 {
        return None;
    }

    let (xor_key, is_plus) = derive_xor_key(data)?;
    let (header, sl_key, sl_is_plus) = decrypt_header(data, xor_key, is_plus)?;
    if header.len() < 8 {
        return None;
    }
    let version = u32::from_le_bytes(header[4..8].try_into().ok()?);
    // Only 8-bytes-per-field headers are supported (v27-37).
    if version < 27 || version >= 38 {
        return None;
    }

    let original_header_size = 8 + EXPECTED_SECTION_COUNT * 8;
    let data_start = header.len();
    let header_words: Vec<u32> = header
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();

    // The end of the file contains garbage; try shorter lengths first.
    let mut metadata_len = data.len();
    let mut visited_layouts: HashSet<Vec<(usize, usize)>> = HashSet::new();
    while metadata_len >= data_start {
        let paths = find_paths(&header_words, data_start, metadata_len, EXPECTED_SECTION_COUNT);
        if !paths.is_empty() {
            for path in &paths {
                let ranges: Vec<(usize, usize)> = path
                    .iter()
                    .map(|s| (s.actual_offset(), s.actual_end()))
                    .collect();
                if ranges.iter().any(|&(s, e)| e > data.len() || s >= e) {
                    continue;
                }
                if !visited_layouts.insert(ranges.clone()) {
                    continue;
                }
                if let Some(reb) = rebuild_metadata(
                    data,
                    &ranges,
                    sl_key,
                    sl_is_plus,
                    original_header_size as i64 - header.len() as i64,
                    version,
                ) {
                    return Some(reb);
                }
            }
        }
        if metadata_len < 4 {
            break;
        }
        metadata_len -= 4;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cyclic_xor_roundtrip() {
        let data = [0x00u8, 0x01, 0x02, 0x03, 0x04];
        let key = 0x55u8;
        let enc = cyclic_xor_header(&data, key, true, 0);
        let dec = cyclic_xor_header(&enc, key, true, 0);
        assert_eq!(dec, data);

        let enc = cyclic_xor(&data, key, false, 8);
        let dec = cyclic_xor(&enc, key, false, 8);
        assert_eq!(dec, data);
    }

    #[test]
    fn derive_key_known_pattern() {
        // Simulated encrypted header: sanity+version (high bytes zero) with a
        // plus-rotating key, so byte[3] and byte[7] differ by 4.
        let key = 0x2Au8;
        let mut enc = vec![0u8; 16];
        enc[0] = 0xAF ^ key;
        enc[1] = 0x1B ^ key.wrapping_add(1);
        enc[2] = 0xB1 ^ key.wrapping_add(2);
        enc[3] = 0x00 ^ key.wrapping_add(3);
        enc[4] = 0x1B ^ key.wrapping_add(4);
        enc[5] = 0x00 ^ key.wrapping_add(5);
        enc[6] = 0x00 ^ key.wrapping_add(6);
        enc[7] = 0x00 ^ key.wrapping_add(7);
        let (derived, is_plus) = derive_xor_key(&enc).expect("key should be derivable");
        assert!(is_plus);
        assert_eq!(derived, key);
    }
}
