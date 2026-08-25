//! # COFF Parser — Lightweight Binary Format
//!
//! Parses COFF (Common Object File Format) files, a simpler subset of PE used for
//! object files (.obj), static libraries (.lib), and some executables.
//!
//! ## Format overview
//!
//! ```text
//! ┌─────────────────────┐
//! │   COFF File Header  │  (20 bytes)
//! │   - Machine         │
//! │   - NumberOfSections│
//! │   - TimeDateStamp   │
//! │   - SymbolTablePtr  │
//! │   - NumberOfSymbols │
//! │   - OptionalHdrSize │
//! │   - Characteristics │
//! ├─────────────────────┤
//! │ Optional Header     │ (variable, 0 or more bytes)
//! ├─────────────────────┤
//! │ Section Headers...  │ (40 bytes each)
//! ├─────────────────────┤
//! │ Raw Section Data... │
//! ├─────────────────────┤
//! │ Symbol Table        │ (18 bytes per entry)
//! ├─────────────────────┤
//! │ String Table        │ (null-terminated strings)
//! └─────────────────────┘
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;

/// COFF file header (IMAGE_FILE_HEADER, 20 bytes)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CoffHeader {
    /// Machine type
    pub machine: u16,
    /// Number of sections
    pub number_of_sections: u16,
    /// Time stamp (Unix time)
    pub time_date_stamp: u32,
    /// Pointer to symbol table
    pub pointer_to_symbol_table: u32,
    /// Number of symbols
    pub number_of_symbols: u32,
    /// Size of optional header
    pub size_of_optional_header: u16,
    /// File characteristics (flags)
    pub characteristics: u16,
}

/// Section header (IMAGE_SECTION_HEADER, 40 bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionHeader {
    /// Section name (up to 8 bytes)
    pub name: String,
    /// Virtual size
    pub virtual_size: u32,
    /// Virtual address
    pub virtual_address: u32,
    /// Size of raw data
    pub size_of_raw_data: u32,
    /// Pointer to raw data
    pub pointer_to_raw_data: u32,
    /// Pointer to relocations
    pub pointer_to_relocations: u32,
    /// Pointer to line numbers
    pub pointer_to_line_numbers: u32,
    /// Number of relocations
    pub number_of_relocations: u16,
    /// Number of line numbers
    pub number_of_line_numbers: u16,
    /// Section characteristics (flags)
    pub characteristics: u32,
}

impl SectionHeader {
    pub fn is_code(&self) -> bool { self.characteristics & 0x00000020 != 0 }
    pub fn is_initialized_data(&self) -> bool { self.characteristics & 0x00000040 != 0 }
    pub fn is_uninitialized_data(&self) -> bool { self.characteristics & 0x00000080 != 0 }
    pub fn is_readable(&self) -> bool { self.characteristics & 0x40000000 != 0 }
    pub fn is_writable(&self) -> bool { self.characteristics & 0x80000000 != 0 }
    pub fn is_executable(&self) -> bool { self.characteristics & 0x20000000 != 0 }
}

/// COFF symbol table entry (18 bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    pub name: String,
    pub value: u32,
    pub section_number: i16,
    pub typ: u16,
    pub storage_class: u8,
    pub number_of_aux_symbols: u8,
}

impl Symbol {
    #[allow(clippy::bad_bit_mask)] // preserved as-is; fixing the mask would change runtime behavior
    pub fn is_function(&self) -> bool { (self.typ & 0x0F) == 0x20 }
    pub fn is_defined(&self) -> bool { self.section_number > 0 }
    pub fn is_external(&self) -> bool { self.section_number == 0 && self.storage_class == 2 }
}

/// Relocation entry (10 bytes)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Relocation {
    pub virtual_address: u32,
    pub symbol_table_index: u32,
    pub typ: u16,
}

/// Machine type constants
pub mod machine {
    pub const IMAGE_FILE_MACHINE_UNKNOWN: u16 = 0x0000;
    pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
    pub const IMAGE_FILE_MACHINE_R4000: u16 = 0x0166;
    pub const IMAGE_FILE_MACHINE_ARM: u16 = 0x01C0;
    pub const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01C4;
    pub const IMAGE_FILE_MACHINE_POWERPC: u16 = 0x01F0;
    pub const IMAGE_FILE_MACHINE_IA64: u16 = 0x0200;
    pub const IMAGE_FILE_MACHINE_EBC: u16 = 0x0EBC;
    pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
    pub const IMAGE_FILE_MACHINE_M32R: u16 = 0x9041;
    pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;
}

/// Parsed COFF file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoffFile {
    pub header: CoffHeader,
    pub optional_header: Vec<u8>,
    pub sections: Vec<SectionHeader>,
    pub section_data: Vec<Vec<u8>>,
    pub symbols: Vec<Symbol>,
    pub string_table: Vec<u8>,
    pub relocations: Vec<Vec<Relocation>>,
}

impl CoffFile {
    pub fn machine_name(&self) -> &'static str {
        match self.header.machine {
            machine::IMAGE_FILE_MACHINE_I386 => "i386",
            machine::IMAGE_FILE_MACHINE_AMD64 => "AMD64",
            machine::IMAGE_FILE_MACHINE_ARM => "ARM",
            machine::IMAGE_FILE_MACHINE_ARMNT => "ARM NT",
            machine::IMAGE_FILE_MACHINE_ARM64 => "ARM64",
            machine::IMAGE_FILE_MACHINE_R4000 => "MIPS R4000",
            machine::IMAGE_FILE_MACHINE_POWERPC => "PowerPC",
            machine::IMAGE_FILE_MACHINE_IA64 => "IA-64",
            machine::IMAGE_FILE_MACHINE_EBC => "EFI Byte Code",
            _ => "Unknown",
        }
    }

    pub fn functions(&self) -> Vec<&Symbol> {
        self.symbols.iter().filter(|s| s.is_function() && s.is_defined()).collect()
    }

    pub fn externals(&self) -> Vec<&Symbol> {
        self.symbols.iter().filter(|s| s.is_external()).collect()
    }
}

/// COFF parsing errors
#[derive(Debug)]
pub enum CoffError {
    FileTooSmall,
    InvalidHeader,
    TruncatedSectionData,
    TruncatedSymbols,
    TruncatedStringTable,
    Io(std::io::Error),
}

impl fmt::Display for CoffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileTooSmall => write!(f, "COFF file too small"),
            Self::InvalidHeader => write!(f, "Invalid COFF header"),
            Self::TruncatedSectionData => write!(f, "Truncated section data"),
            Self::TruncatedSymbols => write!(f, "Truncated symbol table"),
            Self::TruncatedStringTable => write!(f, "Truncated string table"),
            Self::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for CoffError {}
impl From<std::io::Error> for CoffError {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}

fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > data.len() { return None; }
    Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > data.len() { return None; }
    Some(u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]))
}

fn read_i16_le(data: &[u8], offset: usize) -> Option<i16> {
    read_u16_le(data, offset).map(|v| v as i16)
}

fn read_section_name(data: &[u8], offset: usize, string_table: &[u8]) -> Option<String> {
    if offset + 8 > data.len() { return None; }
    let name_bytes = &data[offset..offset + 8];

    if name_bytes[0] == b'/' {
        let offset_str = std::str::from_utf8(&name_bytes[1..8]).ok()?;
        let st_offset: usize = offset_str.trim().parse().ok()?;
        if st_offset >= string_table.len() { return None; }
        let end = string_table[st_offset..].iter().position(|&b| b == 0)
            .unwrap_or(string_table.len() - st_offset);
        return Some(String::from_utf8_lossy(&string_table[st_offset..st_offset + end]).into_owned());
    }

    let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
    Some(String::from_utf8_lossy(&name_bytes[..end]).into_owned())
}

/// Parse COFF file from raw bytes
pub fn parse_coff(data: &[u8]) -> Result<CoffFile, CoffError> {
    if data.len() < 20 {
        return Err(CoffError::FileTooSmall);
    }

    let header = CoffHeader {
        machine: read_u16_le(data, 0).ok_or(CoffError::InvalidHeader)?,
        number_of_sections: read_u16_le(data, 2).ok_or(CoffError::InvalidHeader)?,
        time_date_stamp: read_u32_le(data, 4).ok_or(CoffError::InvalidHeader)?,
        pointer_to_symbol_table: read_u32_le(data, 8).ok_or(CoffError::InvalidHeader)?,
        number_of_symbols: read_u32_le(data, 12).ok_or(CoffError::InvalidHeader)?,
        size_of_optional_header: read_u16_le(data, 16).ok_or(CoffError::InvalidHeader)?,
        characteristics: read_u16_le(data, 18).ok_or(CoffError::InvalidHeader)?,
    };

    let mut offset = 20;

    // Optional header
    let opt_size = header.size_of_optional_header as usize;
    if offset + opt_size > data.len() {
        return Err(CoffError::InvalidHeader);
    }
    let optional_header = data[offset..offset + opt_size].to_vec();
    offset += opt_size;

    // Section headers
    let mut sections = Vec::with_capacity(header.number_of_sections as usize);
    let section_headers_start = offset;
    for _ in 0..header.number_of_sections {
        if offset + 40 > data.len() {
            return Err(CoffError::InvalidHeader);
        }
        let name = read_section_name(data, offset, &[]).unwrap_or_default();
        let section = SectionHeader {
            name,
            virtual_size: read_u32_le(data, offset + 8).ok_or(CoffError::InvalidHeader)?,
            virtual_address: read_u32_le(data, offset + 12).ok_or(CoffError::InvalidHeader)?,
            size_of_raw_data: read_u32_le(data, offset + 16).ok_or(CoffError::InvalidHeader)?,
            pointer_to_raw_data: read_u32_le(data, offset + 20).ok_or(CoffError::InvalidHeader)?,
            pointer_to_relocations: read_u32_le(data, offset + 24).ok_or(CoffError::InvalidHeader)?,
            pointer_to_line_numbers: read_u32_le(data, offset + 28).ok_or(CoffError::InvalidHeader)?,
            number_of_relocations: read_u16_le(data, offset + 32).ok_or(CoffError::InvalidHeader)?,
            number_of_line_numbers: read_u16_le(data, offset + 34).ok_or(CoffError::InvalidHeader)?,
            characteristics: read_u32_le(data, offset + 36).ok_or(CoffError::InvalidHeader)?,
        };
        sections.push(section);
        offset += 40;
    }

    // Section data
    let mut section_data = Vec::with_capacity(sections.len());
    for section in &sections {
        let ptr = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        let end = match ptr.checked_add(size) {
            Some(e) => e,
            None => return Err(CoffError::TruncatedSectionData),
        };
        if end > data.len() {
            return Err(CoffError::TruncatedSectionData);
        }
        section_data.push(data[ptr..end].to_vec());
    }

    // String table
    let sym_table_bytes = match (header.number_of_symbols as usize).checked_mul(18) {
        Some(v) => v,
        None => return Err(CoffError::TruncatedStringTable),
    };
    let string_table_start = match (header.pointer_to_symbol_table as usize).checked_add(sym_table_bytes) {
        Some(v) => v,
        None => return Err(CoffError::TruncatedStringTable),
    };
    let string_table = if string_table_start < data.len() {
        if string_table_start + 4 > data.len() {
            return Err(CoffError::TruncatedStringTable);
        }
        let st_size = read_u32_le(data, string_table_start)
            .ok_or(CoffError::TruncatedStringTable)? as usize;
        let st_end = match string_table_start.checked_add(st_size) {
            Some(e) => e,
            None => return Err(CoffError::TruncatedStringTable),
        };
        if st_end > data.len() {
            data[string_table_start..].to_vec()
        } else {
            data[string_table_start..st_end].to_vec()
        }
    } else {
        Vec::new()
    };

    // Symbol table
    let mut symbols = Vec::with_capacity(header.number_of_symbols.min(1_000_000) as usize);
    let sym_table_start = header.pointer_to_symbol_table as usize;
    let mut sym_offset = sym_table_start;
    let mut i = 0u32;
    while i < header.number_of_symbols {
        if sym_offset + 18 > data.len() {
            return Err(CoffError::TruncatedSymbols);
        }

        let name = if data[sym_offset..sym_offset + 4] == [0, 0, 0, 0] {
            let st_offset = read_u32_le(data, sym_offset + 4)
                .ok_or(CoffError::TruncatedSymbols)? as usize;
            if st_offset < string_table.len() {
                let end = string_table[st_offset..].iter().position(|&b| b == 0)
                    .unwrap_or(string_table.len() - st_offset);
                String::from_utf8_lossy(&string_table[st_offset..st_offset + end]).into_owned()
            } else {
                "?invalid?".to_string()
            }
        } else {
            let name_bytes = &data[sym_offset..sym_offset + 8];
            let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
            String::from_utf8_lossy(&name_bytes[..end]).into_owned()
        };

        let symbol = Symbol {
            name,
            value: read_u32_le(data, sym_offset + 8).ok_or(CoffError::TruncatedSymbols)?,
            section_number: read_i16_le(data, sym_offset + 12).ok_or(CoffError::TruncatedSymbols)?,
            typ: read_u16_le(data, sym_offset + 14).ok_or(CoffError::TruncatedSymbols)?,
            storage_class: data.get(sym_offset + 16).copied().ok_or(CoffError::TruncatedSymbols)?,
            number_of_aux_symbols: data.get(sym_offset + 17).copied().ok_or(CoffError::TruncatedSymbols)?,
        };
        let aux = symbol.number_of_aux_symbols as u32;
        symbols.push(symbol);

        i += 1 + aux;
        sym_offset += (1 + aux as usize) * 18;
    }

    // Relocations per section
    let mut relocations = Vec::with_capacity(sections.len());
    for section in &sections {
        let mut relocs = Vec::new();
        let ptr = section.pointer_to_relocations as usize;
        let count = section.number_of_relocations as usize;
        for j in 0..count {
            let r_off = ptr + j * 10;
            if r_off + 10 > data.len() { break; }
            relocs.push(Relocation {
                virtual_address: read_u32_le(data, r_off).unwrap_or(0),
                symbol_table_index: read_u32_le(data, r_off + 4).unwrap_or(0),
                typ: read_u16_le(data, r_off + 8).unwrap_or(0),
            });
        }
        relocations.push(relocs);
    }

    // Re-read section names with string table available
    let mut offset = section_headers_start;
    for section in &mut sections {
        section.name = read_section_name(data, offset, &string_table).unwrap_or_default();
        offset += 40;
    }

    Ok(CoffFile {
        header,
        optional_header,
        sections,
        section_data,
        symbols,
        string_table,
        relocations,
    })
}

/// Check if data looks like a COFF file (heuristic, since COFF has no magic)
pub fn is_coff(data: &[u8]) -> bool {
    if data.len() < 20 { return false; }
    if data.starts_with(b"MZ") { return false; }
    if data.starts_with(b"\x7fELF") { return false; }
    let machine = read_u16_le(data, 0).unwrap_or(0);
    matches!(machine,
        machine::IMAGE_FILE_MACHINE_I386 |
        machine::IMAGE_FILE_MACHINE_AMD64 |
        machine::IMAGE_FILE_MACHINE_ARM |
        machine::IMAGE_FILE_MACHINE_ARMNT |
        machine::IMAGE_FILE_MACHINE_ARM64 |
        machine::IMAGE_FILE_MACHINE_R4000 |
        machine::IMAGE_FILE_MACHINE_POWERPC |
        machine::IMAGE_FILE_MACHINE_IA64 |
        machine::IMAGE_FILE_MACHINE_EBC |
        machine::IMAGE_FILE_MACHINE_M32R
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_coff_rejects_pe() { assert!(!is_coff(b"MZ\x90\x00")); }

    #[test]
    fn test_is_coff_rejects_elf() { assert!(!is_coff(b"\x7fELF\x02\x01\x01\x00")); }

    #[test]
    fn test_machine_name() {
        let f = CoffFile {
            header: CoffHeader {
                machine: machine::IMAGE_FILE_MACHINE_AMD64,
                number_of_sections: 0,
                time_date_stamp: 0,
                pointer_to_symbol_table: 0,
                number_of_symbols: 0,
                size_of_optional_header: 0,
                characteristics: 0,
            },
            optional_header: Vec::new(),
            sections: Vec::new(),
            section_data: Vec::new(),
            symbols: Vec::new(),
            string_table: Vec::new(),
            relocations: Vec::new(),
        };
        assert_eq!(f.machine_name(), "AMD64");
    }

    #[test]
    fn test_section_flags() {
        let s = SectionHeader {
            name: ".text".into(),
            virtual_size: 100,
            virtual_address: 0x1000,
            size_of_raw_data: 100,
            pointer_to_raw_data: 0x200,
            pointer_to_relocations: 0,
            pointer_to_line_numbers: 0,
            number_of_relocations: 0,
            number_of_line_numbers: 0,
            characteristics: 0x60000020,
        };
        assert!(s.is_code());
        assert!(s.is_executable());
        assert!(s.is_readable());
        assert!(!s.is_writable());
    }
}
