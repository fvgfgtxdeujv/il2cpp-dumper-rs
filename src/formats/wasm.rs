use crate::io::BinaryStream;
use crate::search::{SectionHelper, SearchSection};
use crate::error::{Error, Result};

pub const WASM_MAGIC: u32 = 0x6D736100;
pub const WASM_VERSION: u32 = 1;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmSectionId {
    Custom = 0,
    Type = 1,
    Import = 2,
    Function = 3,
    Table = 4,
    Memory = 5,
    Global = 6,
    Export = 7,
    Start = 8,
    Element = 9,
    Code = 10,
    Data = 11,
    DataCount = 12,
    Unknown = 255,
}

impl From<u8> for WasmSectionId {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Custom,
            1 => Self::Type,
            2 => Self::Import,
            3 => Self::Function,
            4 => Self::Table,
            5 => Self::Memory,
            6 => Self::Global,
            7 => Self::Export,
            8 => Self::Start,
            9 => Self::Element,
            10 => Self::Code,
            11 => Self::Data,
            12 => Self::DataCount,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
struct WasmSection {
    _id: WasmSectionId,
    size: usize,
    offset: u64,
}

#[derive(Debug, Clone, Default)]
struct WasmDataSegment {
    offset: i64,
    size: usize,
    data_offset: u64,
}

pub struct Wasm {
    pub stream: BinaryStream,
    pub is_32bit: bool,
    code_section: Option<WasmSection>,
    data_segments: Vec<WasmDataSegment>,
}

impl Wasm {
    pub fn new(data: Vec<u8>) -> Result<Self> {
        let mut wasm = Self {
            stream: BinaryStream::new(data),
            is_32bit: true,
            code_section: None,
            data_segments: Vec::new(),
        };
        wasm.stream.is_32bit = true;
        wasm.load()?;
        Ok(wasm)
    }

    fn load(&mut self) -> Result<()> {
        self.stream.set_position(0);
        let magic = self.stream.read_u32()?;
        if magic != WASM_MAGIC {
            return Err(Error::InvalidFormat("Invalid WebAssembly magic".into()));
        }
        let version = self.stream.read_u32()?;
        if version != WASM_VERSION {
            return Err(Error::InvalidFormat(format!("Unsupported WASM version: {}", version)));
        }

        let data_len = self.stream.len();
        while self.stream.position() < data_len {
            let section_id_byte = self.stream.read_u8()?;
            let section_id = WasmSectionId::from(section_id_byte);
            let section_size = self.read_leb128_unsigned()?;
            let section_offset = self.stream.position();

            match section_id {
                WasmSectionId::Code => {
                    self.code_section = Some(WasmSection {
                        _id: section_id,
                        size: section_size,
                        offset: section_offset,
                    });
                }
                WasmSectionId::Data => {
                    self.parse_data_section(section_offset, section_size)?;
                }
                WasmSectionId::Custom => {
                    let name_len = self.read_leb128_unsigned()?;
                    let _name = self.stream.read_bytes(name_len)?;
                }
                _ => {}
            }

            self.stream.set_position(section_offset + section_size as u64);
        }

        Ok(())
    }

    fn parse_data_section(&mut self, offset: u64, _size: usize) -> Result<()> {
        self.stream.set_position(offset);
        let num_segments = self.read_leb128_unsigned()?;

        for _ in 0..num_segments {
            let flags = self.read_leb128_unsigned()?;
            let mut segment = WasmDataSegment::default();

            match flags {
                0 => {
                    let opcode = self.stream.read_u8()?;
                    if opcode == 0x41 {
                        segment.offset = self.read_leb128_signed()?;
                    }
                    let _end = self.stream.read_u8()?;
                }
                1 => {
                    segment.offset = 0;
                }
                2 => {
                    let _memory_index = self.read_leb128_unsigned()?;
                    let opcode = self.stream.read_u8()?;
                    if opcode == 0x41 {
                        segment.offset = self.read_leb128_signed()?;
                    }
                    let _end = self.stream.read_u8()?;
                }
                _ => {}
            }

            segment.size = self.read_leb128_unsigned()?;
            segment.data_offset = self.stream.position();
            self.stream.set_position(self.stream.position() + segment.size as u64);
            self.data_segments.push(segment);
        }

        Ok(())
    }

    fn read_leb128_unsigned(&mut self) -> Result<usize> {
        let mut result = 0usize;
        let mut shift = 0;
        loop {
            let byte = self.stream.read_u8()?;
            result |= ((byte & 0x7F) as usize) << shift;
            if (byte & 0x80) == 0 {
                break;
            }
            shift += 7;
        }
        Ok(result)
    }

    fn read_leb128_signed(&mut self) -> Result<i64> {
        let mut result = 0i64;
        let mut shift = 0;
        let mut byte;
        loop {
            byte = self.stream.read_u8()?;
            result |= ((byte & 0x7F) as i64) << shift;
            shift += 7;
            if (byte & 0x80) == 0 {
                break;
            }
        }
        if shift < 64 && (byte & 0x40) != 0 {
            result |= !0i64 << shift;
        }
        Ok(result)
    }

    pub fn map_vatr(&self, addr: u64) -> Result<u64> {
        let addr_i = addr as i64;
        for segment in &self.data_segments {
            if addr_i >= segment.offset && addr_i < segment.offset + segment.size as i64 {
                return Ok(segment.data_offset + (addr_i - segment.offset) as u64);
            }
        }
        Ok(addr)
    }

    pub fn map_rtva(&self, offset: u64) -> u64 {
        for segment in &self.data_segments {
            if offset >= segment.data_offset && offset < segment.data_offset + segment.size as u64 {
                return (segment.offset + (offset as i64 - segment.data_offset as i64)) as u64;
            }
        }
        offset
    }

    pub fn data_search_sections(&self) -> Vec<SearchSection> {
        self.data_segments
            .iter()
            .map(|segment| {
                SearchSection::new(
                    segment.data_offset,
                    segment.data_offset + segment.size as u64,
                    segment.offset as u64,
                    segment.offset as u64 + segment.size as u64,
                )
            })
            .collect()
    }

    pub fn get_section_helper(&self, method_count: usize, type_definitions_count: usize, metadata_usages_count: usize, image_count: usize, version: f64) -> SectionHelper<'_> {
        let mut exec_list = Vec::new();
        let data_list = self.data_search_sections();
        let mut all = Vec::new();

        if let Some(code) = &self.code_section {
            let s = SearchSection::new(code.offset, code.offset + code.size as u64, code.offset, code.offset + code.size as u64);
            all.push(s.clone());
            exec_list.push(s);
        }

        for segment in &self.data_segments {
            let s = SearchSection::new(
                segment.data_offset,
                segment.data_offset + segment.size as u64,
                segment.offset as u64,
                segment.offset as u64 + segment.size as u64,
            );
            all.push(s.clone());
        }

        let bss = data_list.clone();

        SectionHelper::new(
            self.stream.data(),
            self.is_32bit,
            version,
            false,
            all,
            data_list,
            exec_list,
            bss,
            method_count,
            type_definitions_count,
            metadata_usages_count,
            image_count,
        )
    }

    pub fn check_dump(&self) -> bool {
        false
    }

    pub fn get_rva(&self, pointer: u64) -> u64 {
        pointer
    }
}
