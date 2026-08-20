//! ELF section header parsing.

use crate::error::{ElfWarning, ElfWarningKind};
use crate::header::{read_u32, read_u64};
use bitflags::bitflags;

bitflags! {
    /// Section header flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SectionFlags: u64 {
        const WRITE     = 0x1;
        const ALLOC     = 0x2;
        const EXECINSTR = 0x4;
        const MERGE     = 0x10;
        const STRINGS   = 0x20;
        const INFO_LINK = 0x40;
        const TLS       = 0x400;
    }
}

/// Parsed ELF section header with zero-copy data reference.
#[derive(Debug, Clone)]
pub struct SectionHeader<'a> {
    /// Section name (resolved from shstrtab).
    pub name: String,
    /// Raw section type value.
    pub sh_type: u32,
    /// Section flags.
    pub flags: SectionFlags,
    /// Virtual address in memory.
    pub addr: u64,
    /// Offset in file.
    pub offset: u64,
    /// Size in bytes.
    pub size: u64,
    /// Alignment requirement.
    pub addralign: u64,
    /// Zero-copy slice of section data from the file.
    pub data: &'a [u8],
}

impl<'a> SectionHeader<'a> {
    /// Check if this is a writable+executable section.
    pub fn is_rwx(&self) -> bool {
        self.flags.contains(SectionFlags::WRITE) && self.flags.contains(SectionFlags::EXECINSTR)
    }

    /// Check if this section contains executable code.
    pub fn is_executable(&self) -> bool {
        self.flags.contains(SectionFlags::EXECINSTR)
    }

    /// Check if this section is allocated in memory.
    pub fn is_allocated(&self) -> bool {
        self.flags.contains(SectionFlags::ALLOC)
    }
}

/// Resolve section name from the string table.
fn resolve_name(data: &[u8], strtab_offset: usize, strtab_size: usize, name_offset: usize) -> String {
    if strtab_offset == 0 || strtab_size == 0 {
        return format!("<unnamed@{}>", name_offset);
    }
    let start = strtab_offset + name_offset;
    if start >= data.len() {
        return format!("<oob@{}>", name_offset);
    }
    let end = data[start..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| start + p)
        .unwrap_or(data.len().min(start + 256));
    String::from_utf8_lossy(&data[start..end]).to_string()
}

/// Parse ELF64 section headers.
pub fn parse_section_headers_64<'a, const BE: bool>(
    data: &'a [u8],
    sh_offset: u64,
    sh_entsize: u16,
    sh_num: u16,
    sh_strndx: u16,
    warnings: &mut Vec<ElfWarning>,
) -> Vec<SectionHeader<'a>> {
    if sh_num == 0 || sh_offset == 0 {
        return Vec::new();
    }

    let entry_size = if sh_entsize == 0 { 64usize } else { sh_entsize as usize };
    let total_size = entry_size * sh_num as usize;

    if sh_offset as usize + total_size > data.len() {
        warnings.push(ElfWarning {
            kind: ElfWarningKind::SuspiciousSection,
            message: format!(
                "Section headers extend beyond file: offset=0x{:X} size=0x{:X} file=0x{:X}",
                sh_offset, total_size, data.len()
            ),
        });
        return Vec::new();
    }

    // Resolve string table location
    let (strtab_off, strtab_sz) = if (sh_strndx as usize) < sh_num as usize {
        let st_idx = sh_strndx as usize * entry_size;
        let st_base = sh_offset as usize + st_idx;
        if st_base + entry_size <= data.len() {
            let off = read_u64::<BE>(data, st_base + 24) as usize;
            let sz = read_u64::<BE>(data, st_base + 32) as usize;
            (off, sz)
        } else {
            (0, 0)
        }
    } else {
        (0, 0)
    };

    let mut sections = Vec::with_capacity(sh_num as usize);

    for i in 0..sh_num as usize {
        let base = sh_offset as usize + i * entry_size;
        if base + entry_size > data.len() {
            break;
        }

        let sh_name = read_u32::<BE>(data, base) as usize;
        let sh_type = read_u32::<BE>(data, base + 4);
        let sh_flags_raw = read_u64::<BE>(data, base + 8);
        let sh_addr = read_u64::<BE>(data, base + 16);
        let sh_offset_val = read_u64::<BE>(data, base + 24);
        let sh_size = read_u64::<BE>(data, base + 32);
        let sh_addralign = read_u64::<BE>(data, base + 48);

        let flags = SectionFlags::from_bits_truncate(sh_flags_raw);

        // Extract section data safely
        let sec_data = if sh_offset_val as usize + sh_size as usize <= data.len() {
            &data[sh_offset_val as usize..sh_offset_val as usize + sh_size as usize]
        } else {
            &[]
        };

        let name = resolve_name(data, strtab_off, strtab_sz, sh_name);

        // Warn on RWX sections
        if flags.contains(SectionFlags::WRITE) && flags.contains(SectionFlags::EXECINSTR) {
            warnings.push(ElfWarning {
                kind: ElfWarningKind::RwxSection,
                message: format!("Section '{}' has W+X permissions", name),
            });
        }

        // Warn on suspicious section names
        let suspicious_names = [".upx", ".packed", ".encrypt", ".hidden", ".backdoor"];
        for sn in &suspicious_names {
            if name.contains(sn) {
                warnings.push(ElfWarning {
                    kind: ElfWarningKind::SuspiciousSection,
                    message: format!("Suspicious section name: '{}'", name),
                });
                break;
            }
        }

        sections.push(SectionHeader {
            name,
            sh_type,
            flags,
            addr: sh_addr,
            offset: sh_offset_val,
            size: sh_size,
            addralign: sh_addralign,
            data: sec_data,
        });
    }

    sections
}

/// Parse ELF32 section headers.
pub fn parse_section_headers_32<'a, const BE: bool>(
    data: &'a [u8],
    sh_offset: u64,
    sh_entsize: u16,
    sh_num: u16,
    sh_strndx: u16,
    warnings: &mut Vec<ElfWarning>,
) -> Vec<SectionHeader<'a>> {
    if sh_num == 0 || sh_offset == 0 {
        return Vec::new();
    }

    let entry_size = if sh_entsize == 0 { 40usize } else { sh_entsize as usize };
    let total_size = entry_size * sh_num as usize;

    if sh_offset as usize + total_size > data.len() {
        warnings.push(ElfWarning {
            kind: ElfWarningKind::SuspiciousSection,
            message: format!(
                "Section headers extend beyond file: offset=0x{:X} size=0x{:X} file=0x{:X}",
                sh_offset, total_size, data.len()
            ),
        });
        return Vec::new();
    }

    // Resolve string table
    let (strtab_off, strtab_sz) = if (sh_strndx as usize) < sh_num as usize {
        let st_idx = sh_strndx as usize * entry_size;
        let st_base = sh_offset as usize + st_idx;
        if st_base + entry_size <= data.len() {
            let off = read_u32::<BE>(data, st_base + 16) as usize;
            let sz = read_u32::<BE>(data, st_base + 20) as usize;
            (off, sz)
        } else {
            (0, 0)
        }
    } else {
        (0, 0)
    };

    let mut sections = Vec::with_capacity(sh_num as usize);

    for i in 0..sh_num as usize {
        let base = sh_offset as usize + i * entry_size;
        if base + entry_size > data.len() {
            break;
        }

        let sh_name = read_u32::<BE>(data, base) as usize;
        let sh_type = read_u32::<BE>(data, base + 4);
        let sh_flags_raw = read_u32::<BE>(data, base + 8) as u64;
        let sh_addr = read_u32::<BE>(data, base + 12) as u64;
        let sh_offset_val = read_u32::<BE>(data, base + 16) as u64;
        let sh_size = read_u32::<BE>(data, base + 20) as u64;
        let sh_addralign = read_u32::<BE>(data, base + 32) as u64;

        let flags = SectionFlags::from_bits_truncate(sh_flags_raw);

        let sec_data = if sh_offset_val as usize + sh_size as usize <= data.len() {
            &data[sh_offset_val as usize..sh_offset_val as usize + sh_size as usize]
        } else {
            &[]
        };

        let name = resolve_name(data, strtab_off, strtab_sz, sh_name);

        if flags.contains(SectionFlags::WRITE) && flags.contains(SectionFlags::EXECINSTR) {
            warnings.push(ElfWarning {
                kind: ElfWarningKind::RwxSection,
                message: format!("Section '{}' has W+X permissions", name),
            });
        }

        sections.push(SectionHeader {
            name,
            sh_type,
            flags,
            addr: sh_addr,
            offset: sh_offset_val,
            size: sh_size,
            addralign: sh_addralign,
            data: sec_data,
        });
    }

    sections
}
