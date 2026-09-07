#![allow(unused_assignments)]
//! # elf-parser
//!
//! Security-oriented ELF32/ELF64 parser for malware analysis.
//! Zero-copy, no unsafe, validates all offsets before access.
//! Reports structural anomalies relevant to Linux/IoT malware detection.

mod anomalies;
mod error;
mod header;
mod program;
mod sections;
mod symbols;

pub use error::{ElfError, ElfParseResult, ElfWarning, ElfWarningKind};
pub use header::{ElfClass, ElfEndian, ElfIdent, ElfMachine, ElfType};
pub use program::{ProgramFlags, ProgramHeader, ProgramType};
pub use sections::{SectionFlags, SectionHeader};
pub use symbols::{SymbolBinding, SymbolEntry, SymbolType as SymType};
// ElfAnomaly re-export removed — anomalies module uses ElfWarning directly

/// Parsed ELF file with all extracted metadata and warnings.
#[derive(Debug)]
pub struct ElfFile<'a> {
    /// Raw file data (zero-copy reference).
    pub data: &'a [u8],
    /// ELF identification bytes.
    pub ident: ElfIdent,
    /// ELF type (EXEC, DYN, REL, etc.)
    pub elf_type: ElfType,
    /// Target machine architecture.
    pub machine: ElfMachine,
    /// Entry point virtual address.
    pub entry_point: u64,
    /// Program headers.
    pub program_headers: Vec<ProgramHeader>,
    /// Section headers.
    pub section_headers: Vec<SectionHeader<'a>>,
    /// Symbol table entries (if present).
    pub symbols: Vec<SymbolEntry<'a>>,
    /// Dynamic symbol table entries (if present).
    pub dyn_symbols: Vec<SymbolEntry<'a>>,
    /// Detected anomalies / warnings.
    pub warnings: Vec<ElfWarning>,
}

impl<'a> ElfFile<'a> {
    /// Parse an ELF file from raw bytes.
    /// Returns parsed structure + warnings (never fails on malformed input).
    pub fn parse(data: &'a [u8]) -> ElfParseResult<Self> {
        let mut warnings = Vec::new();

        // Validate minimum size
        if data.len() < 16 {
            return Err(ElfError::TooSmall(data.len()));
        }

        // Parse ELF identification
        let ident = header::parse_ident(data, &mut warnings)?;

        // Dispatch based on class (32/64) and endianness
        match (ident.class, ident.endian) {
            (ElfClass::Elf64, ElfEndian::Little) => {
                Self::parse_elf64::<false>(data, ident, warnings)
            }
            (ElfClass::Elf64, ElfEndian::Big) => Self::parse_elf64::<true>(data, ident, warnings),
            (ElfClass::Elf32, ElfEndian::Little) => {
                Self::parse_elf32::<false>(data, ident, warnings)
            }
            (ElfClass::Elf32, ElfEndian::Big) => Self::parse_elf32::<true>(data, ident, warnings),
        }
    }

    /// Get section data by name.
    pub fn section_by_name(&self, name: &str) -> Option<&SectionHeader<'a>> {
        self.section_headers.iter().find(|s| s.name == name)
    }

    /// Get all executable sections.
    pub fn executable_sections(&self) -> Vec<&SectionHeader<'a>> {
        self.section_headers
            .iter()
            .filter(|s| s.flags.contains(SectionFlags::EXECINSTR))
            .collect()
    }

    /// Get all writable+executable sections (RWX anomaly).
    pub fn rwx_sections(&self) -> Vec<&SectionHeader<'a>> {
        self.section_headers
            .iter()
            .filter(|s| {
                s.flags.contains(SectionFlags::WRITE) && s.flags.contains(SectionFlags::EXECINSTR)
            })
            .collect()
    }

    /// Check if the ELF is statically linked (no INTERP segment).
    pub fn is_statically_linked(&self) -> bool {
        !self
            .program_headers
            .iter()
            .any(|p| p.p_type == ProgramType::Interp)
    }

    /// Check if the ELF is stripped (no symbol table).
    pub fn is_stripped(&self) -> bool {
        self.symbols.is_empty() && !self.section_headers.iter().any(|s| s.name == ".symtab")
    }

    /// Get imported function names from dynamic symbols.
    pub fn imported_functions(&self) -> Vec<&str> {
        self.dyn_symbols
            .iter()
            .filter(|s| s.binding == SymbolBinding::Global && s.shndx == 0)
            .filter_map(|s| s.name)
            .collect()
    }
}

// ─── Internal parsing helpers ────────────────────────────────────────

impl<'a> ElfFile<'a> {
    fn parse_elf64<const BE: bool>(
        data: &'a [u8],
        ident: ElfIdent,
        mut warnings: Vec<ElfWarning>,
    ) -> ElfParseResult<Self> {
        use header::*;

        if data.len() < 64 {
            return Err(ElfError::TooSmall(data.len()));
        }

        let e_type = read_u16::<BE>(data, 16).unwrap_or(0);
        let e_machine = read_u16::<BE>(data, 18).unwrap_or(0);
        let e_entry = read_u64::<BE>(data, 24).unwrap_or(0);
        let e_phoff = read_u64::<BE>(data, 32).unwrap_or(0);
        let e_shoff = read_u64::<BE>(data, 40).unwrap_or(0);
        let e_phentsize = read_u16::<BE>(data, 54).unwrap_or(0);
        let e_phnum = read_u16::<BE>(data, 56).unwrap_or(0);
        let e_shentsize = read_u16::<BE>(data, 58).unwrap_or(0);
        let e_shnum = read_u16::<BE>(data, 60).unwrap_or(0);
        let e_shstrndx = read_u16::<BE>(data, 62).unwrap_or(0);

        let elf_type = ElfType::from_raw(e_type);
        let machine = ElfMachine::from_raw(e_machine);

        // Parse program headers
        let program_headers = program::parse_program_headers_64::<BE>(
            data,
            e_phoff,
            e_phentsize,
            e_phnum,
            &mut warnings,
        );

        // Parse section headers
        let section_headers = sections::parse_section_headers_64::<BE>(
            data,
            e_shoff,
            e_shentsize,
            e_shnum,
            e_shstrndx,
            &mut warnings,
        );

        // Parse symbol tables
        let (symbols, dyn_symbols) =
            symbols::parse_all_symbols_64::<BE>(data, &section_headers, &mut warnings);

        // Run anomaly detection
        anomalies::detect_anomalies_elf64(
            data,
            &program_headers,
            &section_headers,
            &ident,
            &mut warnings,
        );

        Ok(Self {
            data,
            ident,
            elf_type,
            machine,
            entry_point: e_entry,
            program_headers,
            section_headers,
            symbols,
            dyn_symbols,
            warnings,
        })
    }

    fn parse_elf32<const BE: bool>(
        data: &'a [u8],
        ident: ElfIdent,
        mut warnings: Vec<ElfWarning>,
    ) -> ElfParseResult<Self> {
        use header::*;

        if data.len() < 52 {
            return Err(ElfError::TooSmall(data.len()));
        }

        let e_type = read_u16::<BE>(data, 16).unwrap_or(0);
        let e_machine = read_u16::<BE>(data, 18).unwrap_or(0);
        let e_entry = read_u32::<BE>(data, 24).unwrap_or(0) as u64;
        let e_phoff = read_u32::<BE>(data, 28).unwrap_or(0) as u64;
        let e_shoff = read_u32::<BE>(data, 32).unwrap_or(0) as u64;
        let e_phentsize = read_u16::<BE>(data, 42).unwrap_or(0);
        let e_phnum = read_u16::<BE>(data, 44).unwrap_or(0);
        let e_shentsize = read_u16::<BE>(data, 46).unwrap_or(0);
        let e_shnum = read_u16::<BE>(data, 48).unwrap_or(0);
        let e_shstrndx = read_u16::<BE>(data, 50).unwrap_or(0);

        let elf_type = ElfType::from_raw(e_type);
        let machine = ElfMachine::from_raw(e_machine);

        let program_headers = program::parse_program_headers_32::<BE>(
            data,
            e_phoff,
            e_phentsize,
            e_phnum,
            &mut warnings,
        );

        let section_headers = sections::parse_section_headers_32::<BE>(
            data,
            e_shoff,
            e_shentsize,
            e_shnum,
            e_shstrndx,
            &mut warnings,
        );

        let (symbols, dyn_symbols) =
            symbols::parse_all_symbols_32::<BE>(data, &section_headers, &mut warnings);

        anomalies::detect_anomalies_elf32(
            data,
            &program_headers,
            &section_headers,
            &ident,
            &mut warnings,
        );

        Ok(Self {
            data,
            ident,
            elf_type,
            machine,
            entry_point: e_entry,
            program_headers,
            section_headers,
            symbols,
            dyn_symbols,
            warnings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_too_small() {
        let result = ElfFile::parse(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_magic() {
        let data = vec![0u8; 64];
        let result = ElfFile::parse(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_elf64_minimal() {
        // Minimal valid ELF64 LE header
        let mut data = vec![0u8; 128];
        // Magic
        data[0] = 0x7f;
        data[1] = b'E';
        data[2] = b'L';
        data[3] = b'F';
        // Class: 64-bit
        data[4] = 2;
        // Endian: little
        data[5] = 1;
        // Version
        data[6] = 1;
        // Type: EXEC
        data[16] = 2;
        data[17] = 0;
        // Machine: x86-64
        data[18] = 0x3E;
        data[19] = 0;

        let result = ElfFile::parse(&data);
        assert!(result.is_ok());
        let elf = result.unwrap();
        assert_eq!(elf.ident.class, ElfClass::Elf64);
        assert_eq!(elf.ident.endian, ElfEndian::Little);
        assert_eq!(elf.machine, ElfMachine::X86_64);
    }
}
