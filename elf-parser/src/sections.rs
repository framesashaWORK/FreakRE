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
    /// Link to associated section (e.g. string table for symbol tables).
    pub sh_link: u32,
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
fn resolve_name(
    data: &[u8],
    strtab_offset: usize,
    strtab_size: usize,
    name_offset: usize,
) -> String {
    if strtab_offset == 0 || strtab_size == 0 {
        return format!("<unnamed@{}>", name_offset);
    }
    let start = match strtab_offset.checked_add(name_offset) {
        Some(s) => s,
        None => return format!("<unnamed@{}>", name_offset),
    };
    if strtab_offset >= data.len() || start >= data.len() {
        return format!("<oob@{}>", name_offset);
    }
    let strtab_end = data.len().min(strtab_offset.saturating_add(strtab_size));
    // A malformed sh_name can point past the string table (sh_name > sh_size),
    // which would make `start > strtab_end` and panic on the reversed slice.
    // Clamp before slicing; a name outside the table resolves to empty.
    let start = start.min(strtab_end);
    if start >= strtab_end {
        return String::new();
    }
    let end = data[start..strtab_end]
        .iter()
        .position(|&b| b == 0)
        .map(|p| start + p)
        .unwrap_or(strtab_end);
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

    const EXPECTED_ENTSIZE: usize = 64;
    let entry_size = if sh_entsize == 0 {
        warnings.push(ElfWarning {
            kind: ElfWarningKind::SuspiciousSection,
            message: format!(
                "e_shentsize is 0, assuming default {} bytes",
                EXPECTED_ENTSIZE
            ),
        });
        EXPECTED_ENTSIZE
    } else if (sh_entsize as usize) != EXPECTED_ENTSIZE {
        warnings.push(ElfWarning {
            kind: ElfWarningKind::SuspiciousSection,
            message: format!(
                "Unusual e_shentsize={} (expected {} for ELF64): entries may be misread or overlap",
                sh_entsize, EXPECTED_ENTSIZE
            ),
        });
        sh_entsize as usize
    } else {
        EXPECTED_ENTSIZE
    };
    let total_size = match entry_size.checked_mul(sh_num as usize) {
        Some(s) => s,
        None => {
            warnings.push(ElfWarning {
                kind: ElfWarningKind::SuspiciousSection,
                message: "Section header table size overflow".into(),
            });
            return Vec::new();
        }
    };

    if (sh_offset as usize)
        .checked_add(total_size)
        .is_none_or(|end| end > data.len())
    {
        warnings.push(ElfWarning {
            kind: ElfWarningKind::SuspiciousSection,
            message: format!(
                "Section headers extend beyond file: offset=0x{:X} size=0x{:X} file=0x{:X}",
                sh_offset,
                total_size,
                data.len()
            ),
        });
        return Vec::new();
    }

    // FIXED: Validate e_shstrndx against sh_num to prevent out-of-bounds access.
    // Malformed ELF files may set e_shstrndx >= e_shnum, which would cause
    // incorrect string table resolution or panic.
    let (strtab_off, strtab_sz) = if (sh_strndx as usize) < sh_num as usize {
        let st_idx = sh_strndx as usize * entry_size;
        let st_base = sh_offset as usize + st_idx;
        if st_base + entry_size <= data.len() {
            let off = read_u64::<BE>(data, st_base + 24).unwrap_or(0) as usize;
            let sz = read_u64::<BE>(data, st_base + 32).unwrap_or(0) as usize;
            (off, sz)
        } else {
            warnings.push(ElfWarning {
                kind: ElfWarningKind::SuspiciousSection,
                message: format!(
                    "String table section header at index {} extends beyond file",
                    sh_strndx
                ),
            });
            (0, 0)
        }
    } else {
        if sh_strndx != 0 && sh_strndx != 0xFFFF {
            warnings.push(ElfWarning {
                kind: ElfWarningKind::SuspiciousSection,
                message: format!(
                    "e_shstrndx={} is out of bounds (sh_num={})",
                    sh_strndx, sh_num
                ),
            });
        }
        (0, 0)
    };

    let mut sections = Vec::with_capacity(sh_num as usize);

    for i in 0..sh_num as usize {
        let Some(base) = i
            .checked_mul(entry_size)
            .and_then(|o| (sh_offset as usize).checked_add(o))
        else {
            break;
        };
        let Some(end) = base.checked_add(entry_size) else {
            break;
        };
        if end > data.len() {
            break;
        }

        let sh_name = read_u32::<BE>(data, base).unwrap_or(0) as usize;
        let sh_type = read_u32::<BE>(data, base + 4).unwrap_or(0);
        let sh_flags_raw = read_u64::<BE>(data, base + 8).unwrap_or(0);
        let sh_addr = read_u64::<BE>(data, base + 16).unwrap_or(0);
        let sh_offset_val = read_u64::<BE>(data, base + 24).unwrap_or(0);
        let sh_size = read_u64::<BE>(data, base + 32).unwrap_or(0);
        let sh_link = read_u32::<BE>(data, base + 40).unwrap_or(0);
        let sh_addralign = read_u64::<BE>(data, base + 48).unwrap_or(0);

        let flags = SectionFlags::from_bits_truncate(sh_flags_raw);

        // Extract section data safely
        let sec_data = if sh_offset_val
            .checked_add(sh_size)
            .is_some_and(|end| end as usize <= data.len())
        {
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
            sh_link,
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

    const EXPECTED_ENTSIZE: usize = 40;
    let entry_size = if sh_entsize == 0 {
        warnings.push(ElfWarning {
            kind: ElfWarningKind::SuspiciousSection,
            message: format!(
                "e_shentsize is 0, assuming default {} bytes",
                EXPECTED_ENTSIZE
            ),
        });
        EXPECTED_ENTSIZE
    } else if (sh_entsize as usize) != EXPECTED_ENTSIZE {
        warnings.push(ElfWarning {
            kind: ElfWarningKind::SuspiciousSection,
            message: format!(
                "Unusual e_shentsize={} (expected {} for ELF32): entries may be misread or overlap",
                sh_entsize, EXPECTED_ENTSIZE
            ),
        });
        sh_entsize as usize
    } else {
        EXPECTED_ENTSIZE
    };
    let total_size = match entry_size.checked_mul(sh_num as usize) {
        Some(s) => s,
        None => {
            warnings.push(ElfWarning {
                kind: ElfWarningKind::SuspiciousSection,
                message: "Section header table size overflow".into(),
            });
            return Vec::new();
        }
    };

    if (sh_offset as usize)
        .checked_add(total_size)
        .is_none_or(|end| end > data.len())
    {
        warnings.push(ElfWarning {
            kind: ElfWarningKind::SuspiciousSection,
            message: format!(
                "Section headers extend beyond file: offset=0x{:X} size=0x{:X} file=0x{:X}",
                sh_offset,
                total_size,
                data.len()
            ),
        });
        return Vec::new();
    }

    // FIXED: Validate e_shstrndx against sh_num to prevent out-of-bounds access.
    let (strtab_off, strtab_sz) = if (sh_strndx as usize) < sh_num as usize {
        let st_idx = sh_strndx as usize * entry_size;
        let st_base = sh_offset as usize + st_idx;
        if st_base + entry_size <= data.len() {
            let off = read_u32::<BE>(data, st_base + 16).unwrap_or(0) as usize;
            let sz = read_u32::<BE>(data, st_base + 20).unwrap_or(0) as usize;
            (off, sz)
        } else {
            warnings.push(ElfWarning {
                kind: ElfWarningKind::SuspiciousSection,
                message: format!(
                    "String table section header at index {} extends beyond file",
                    sh_strndx
                ),
            });
            (0, 0)
        }
    } else {
        if sh_strndx != 0 && sh_strndx != 0xFFFF {
            warnings.push(ElfWarning {
                kind: ElfWarningKind::SuspiciousSection,
                message: format!(
                    "e_shstrndx={} is out of bounds (sh_num={})",
                    sh_strndx, sh_num
                ),
            });
        }
        (0, 0)
    };

    let mut sections = Vec::with_capacity(sh_num as usize);

    for i in 0..sh_num as usize {
        let Some(base) = i
            .checked_mul(entry_size)
            .and_then(|o| (sh_offset as usize).checked_add(o))
        else {
            break;
        };
        let Some(end) = base.checked_add(entry_size) else {
            break;
        };
        if end > data.len() {
            break;
        }

        let sh_name = read_u32::<BE>(data, base).unwrap_or(0) as usize;
        let sh_type = read_u32::<BE>(data, base + 4).unwrap_or(0);
        let sh_flags_raw = read_u32::<BE>(data, base + 8).unwrap_or(0) as u64;
        let sh_addr = read_u32::<BE>(data, base + 12).unwrap_or(0) as u64;
        let sh_offset_val = read_u32::<BE>(data, base + 16).unwrap_or(0) as u64;
        let sh_size = read_u32::<BE>(data, base + 20).unwrap_or(0) as u64;
        let sh_link = read_u32::<BE>(data, base + 24).unwrap_or(0);
        let sh_addralign = read_u32::<BE>(data, base + 32).unwrap_or(0) as u64;

        let flags = SectionFlags::from_bits_truncate(sh_flags_raw);

        let sec_data = if sh_offset_val
            .checked_add(sh_size)
            .is_some_and(|end| end as usize <= data.len())
        {
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
            sh_link,
            addralign: sh_addralign,
            data: sec_data,
        });
    }

    sections
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_name_sh_name_beyond_strtab() {
        // String table at 128 with size 6; a large sh_name points past the
        // table but still inside `data` — must not panic on a reversed slice.
        let mut data = vec![0u8; 256];
        data[128..134].copy_from_slice(b".text\0");
        assert_eq!(resolve_name(&data, 128, 6, 0), ".text");
        assert_eq!(resolve_name(&data, 128, 6, 2), "ext");
        // sh_name == strtab_size: start lands exactly on the table end.
        assert_eq!(resolve_name(&data, 128, 6, 5), "");
        // sh_name > strtab_size: start would be past strtab_end.
        assert_eq!(resolve_name(&data, 128, 6, 100), "");
    }

    #[test]
    fn test_section_headers_malformed_sh_name_no_panic() {
        // Minimal ELF64 section header table where section 1's sh_name
        // exceeds the shstrtab size (sh_name > sh_size).
        let mut data = vec![0u8; 512];
        let s0 = 64usize;
        data[s0 + 24..s0 + 32].copy_from_slice(&300u64.to_le_bytes()); // strtab offset
        data[s0 + 32..s0 + 40].copy_from_slice(&6u64.to_le_bytes()); // strtab size
        let s1 = s0 + 64;
        data[s1..s1 + 4].copy_from_slice(&200u32.to_le_bytes()); // sh_name = 200 > 6
        data[300..306].copy_from_slice(b".text\0");

        let mut warnings = Vec::new();
        let sections = parse_section_headers_64::<false>(&data, 64, 64, 2, 0, &mut warnings);
        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].name, ".text");
        assert!(sections[1].name.is_empty());
    }
}
