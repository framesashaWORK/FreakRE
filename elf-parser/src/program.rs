//! ELF program header (segment) parsing.

use crate::error::{ElfWarning, ElfWarningKind};
use crate::header::{read_u32, read_u64};
use bitflags::bitflags;

/// Program header type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramType {
    Null,
    Load,
    Dynamic,
    Interp,
    Note,
    Shlib,
    Phdr,
    Tls,
    GnuEhFrame,
    GnuStack,
    GnuRelro,
    Unknown(u32),
}

impl ProgramType {
    pub fn from_raw(val: u32) -> Self {
        match val {
            0 => Self::Null,
            1 => Self::Load,
            2 => Self::Dynamic,
            3 => Self::Interp,
            4 => Self::Note,
            5 => Self::Shlib,
            6 => Self::Phdr,
            7 => Self::Tls,
            0x6474e550 => Self::GnuEhFrame,
            0x6474e551 => Self::GnuStack,
            0x6474e552 => Self::GnuRelro,
            v => Self::Unknown(v),
        }
    }
}

bitflags! {
    /// Program header flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ProgramFlags: u32 {
        const EXECUTE = 0x1;
        const WRITE   = 0x2;
        const READ    = 0x4;
    }
}

/// Parsed ELF program header.
#[derive(Debug, Clone)]
pub struct ProgramHeader {
    pub p_type: ProgramType,
    pub flags: ProgramFlags,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

impl ProgramHeader {
    pub fn is_executable(&self) -> bool {
        self.flags.contains(ProgramFlags::EXECUTE)
    }

    pub fn is_writable(&self) -> bool {
        self.flags.contains(ProgramFlags::WRITE)
    }

    pub fn is_rwx(&self) -> bool {
        self.flags.contains(ProgramFlags::READ)
            && self.flags.contains(ProgramFlags::WRITE)
            && self.flags.contains(ProgramFlags::EXECUTE)
    }
}

/// Parse ELF64 program headers.
pub fn parse_program_headers_64<const BE: bool>(
    data: &[u8],
    ph_offset: u64,
    ph_entsize: u16,
    ph_num: u16,
    warnings: &mut Vec<ElfWarning>,
) -> Vec<ProgramHeader> {
    if ph_num == 0 || ph_offset == 0 {
        return Vec::new();
    }

    let entry_size = if ph_entsize == 0 { 56usize } else { ph_entsize as usize };
    let total = match entry_size.checked_mul(ph_num as usize) {
        Some(t) => t,
        None => {
            warnings.push(ElfWarning {
                kind: ElfWarningKind::OverlappingRegions,
                message: "Program header table size overflow".into(),
            });
            return Vec::new();
        }
    };

    if (ph_offset as usize).checked_add(total).is_none_or(|end| end > data.len()) {
        warnings.push(ElfWarning {
            kind: ElfWarningKind::OverlappingRegions,
            message: format!(
                "Program headers extend beyond file: offset=0x{:X} size=0x{:X}",
                ph_offset, total
            ),
        });
        return Vec::new();
    }

    let mut headers = Vec::with_capacity(ph_num as usize);

    for i in 0..ph_num as usize {
        let Some(base) = i.checked_mul(entry_size)
            .and_then(|o| (ph_offset as usize).checked_add(o))
        else {
            break;
        };
        let Some(end) = base.checked_add(entry_size) else {
            break;
        };
        if end > data.len() {
            break;
        }

        let p_type_raw = read_u32::<BE>(data, base).unwrap_or(0);
        let p_flags_raw = read_u32::<BE>(data, base + 4).unwrap_or(0);
        let p_offset = read_u64::<BE>(data, base + 8).unwrap_or(0);
        let p_vaddr = read_u64::<BE>(data, base + 16).unwrap_or(0);
        let p_paddr = read_u64::<BE>(data, base + 24).unwrap_or(0);
        let p_filesz = read_u64::<BE>(data, base + 32).unwrap_or(0);
        let p_memsz = read_u64::<BE>(data, base + 40).unwrap_or(0);
        let p_align = read_u64::<BE>(data, base + 48).unwrap_or(0);

        let p_type = ProgramType::from_raw(p_type_raw);
        let flags = ProgramFlags::from_bits_truncate(p_flags_raw);

        // Check for executable stack
        if p_type == ProgramType::GnuStack && flags.contains(ProgramFlags::EXECUTE) {
            warnings.push(ElfWarning {
                kind: ElfWarningKind::ExecutableStack,
                message: "GNU_STACK segment has execute permission".into(),
            });
        }

        // Check for RWX segments
        if p_type == ProgramType::Load && flags.bits() == 0x7 {
            warnings.push(ElfWarning {
                kind: ElfWarningKind::RwxSection,
                message: format!("LOAD segment at 0x{:X} has RWX permissions", p_vaddr),
            });
        }

        // memsz >> filesz can indicate runtime unpacking
        if p_type == ProgramType::Load && p_memsz > p_filesz.saturating_mul(4) && p_filesz > 0 {
            warnings.push(ElfWarning {
                kind: ElfWarningKind::ExecutableWithoutFile,
                message: format!(
                    "Segment memsz (0x{:X}) >> filesz (0x{:X}), possible runtime unpacking",
                    p_memsz, p_filesz
                ),
            });
        }

        headers.push(ProgramHeader {
            p_type,
            flags,
            offset: p_offset,
            vaddr: p_vaddr,
            paddr: p_paddr,
            filesz: p_filesz,
            memsz: p_memsz,
            align: p_align,
        });
    }

    headers
}

/// Parse ELF32 program headers.
pub fn parse_program_headers_32<const BE: bool>(
    data: &[u8],
    ph_offset: u64,
    ph_entsize: u16,
    ph_num: u16,
    warnings: &mut Vec<ElfWarning>,
) -> Vec<ProgramHeader> {
    if ph_num == 0 || ph_offset == 0 {
        return Vec::new();
    }

    let entry_size = if ph_entsize == 0 { 32usize } else { ph_entsize as usize };
    let total = match entry_size.checked_mul(ph_num as usize) {
        Some(t) => t,
        None => {
            warnings.push(ElfWarning {
                kind: ElfWarningKind::OverlappingRegions,
                message: "Program header table size overflow".into(),
            });
            return Vec::new();
        }
    };

    if (ph_offset as usize).checked_add(total).is_none_or(|end| end > data.len()) {
        warnings.push(ElfWarning {
            kind: ElfWarningKind::OverlappingRegions,
            message: format!(
                "Program headers extend beyond file: offset=0x{:X} size=0x{:X}",
                ph_offset, total
            ),
        });
        return Vec::new();
    }

    let mut headers = Vec::with_capacity(ph_num as usize);

    for i in 0..ph_num as usize {
        let Some(base) = i.checked_mul(entry_size)
            .and_then(|o| (ph_offset as usize).checked_add(o))
        else {
            break;
        };
        let Some(end) = base.checked_add(entry_size) else {
            break;
        };
        if end > data.len() {
            break;
        }

        let p_type_raw = read_u32::<BE>(data, base).unwrap_or(0);
        let p_offset = read_u32::<BE>(data, base + 4).unwrap_or(0) as u64;
        let p_vaddr = read_u32::<BE>(data, base + 8).unwrap_or(0) as u64;
        let p_paddr = read_u32::<BE>(data, base + 12).unwrap_or(0) as u64;
        let p_filesz = read_u32::<BE>(data, base + 16).unwrap_or(0) as u64;
        let p_memsz = read_u32::<BE>(data, base + 20).unwrap_or(0) as u64;
        let p_flags_raw = read_u32::<BE>(data, base + 24).unwrap_or(0);
        let p_align = read_u32::<BE>(data, base + 28).unwrap_or(0) as u64;

        let p_type = ProgramType::from_raw(p_type_raw);
        let flags = ProgramFlags::from_bits_truncate(p_flags_raw);

        if p_type == ProgramType::GnuStack && flags.contains(ProgramFlags::EXECUTE) {
            warnings.push(ElfWarning {
                kind: ElfWarningKind::ExecutableStack,
                message: "GNU_STACK segment has execute permission".into(),
            });
        }

        if p_type == ProgramType::Load && flags.bits() == 0x7 {
            warnings.push(ElfWarning {
                kind: ElfWarningKind::RwxSection,
                message: format!("LOAD segment at 0x{:X} has RWX permissions", p_vaddr),
            });
        }

        headers.push(ProgramHeader {
            p_type,
            flags,
            offset: p_offset,
            vaddr: p_vaddr,
            paddr: p_paddr,
            filesz: p_filesz,
            memsz: p_memsz,
            align: p_align,
        });
    }

    headers
}
