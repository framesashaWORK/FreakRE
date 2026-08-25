//! ELF header parsing: identification, type, machine, class, endianness.

use crate::error::{ElfError, ElfWarning};

/// ELF identification (first 16 bytes).
#[derive(Debug, Clone)]
pub struct ElfIdent {
    pub class: ElfClass,
    pub endian: ElfEndian,
    pub version: u8,
    pub os_abi: u8,
}

/// ELF class (32/64 bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfClass {
    Elf32,
    Elf64,
}

/// Byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfEndian {
    Little,
    Big,
}

/// ELF file type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfType {
    None,
    Rel,
    Exec,
    Dyn,
    Core,
    Unknown(u16),
}

impl ElfType {
    pub fn from_raw(val: u16) -> Self {
        match val {
            0 => Self::None,
            1 => Self::Rel,
            2 => Self::Exec,
            3 => Self::Dyn,
            4 => Self::Core,
            v => Self::Unknown(v),
        }
    }
}

/// Target machine architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfMachine {
    X86,
    X86_64,
    Arm,
    AArch64,
    Mips,
    PowerPC,
    RiscV,
    Unknown(u16),
}

impl ElfMachine {
    pub fn from_raw(val: u16) -> Self {
        match val {
            3 => Self::X86,
            62 => Self::X86_64,
            40 => Self::Arm,
            183 => Self::AArch64,
            8 => Self::Mips,
            20 => Self::PowerPC,
            243 => Self::RiscV,
            v => Self::Unknown(v),
        }
    }
}

/// Parse the 16-byte ELF identification header.
pub fn parse_ident(data: &[u8], _warnings: &mut Vec<ElfWarning>) -> Result<ElfIdent, ElfError> {
    if data.len() < 16 {
        return Err(ElfError::TooSmall(data.len()));
    }

    // Check magic: \x7fELF
    if data[0] != 0x7f || data[1] != b'E' || data[2] != b'L' || data[3] != b'F' {
        return Err(ElfError::InvalidMagic([data[0], data[1], data[2], data[3]]));
    }

    let class = match data[4] {
        1 => ElfClass::Elf32,
        2 => ElfClass::Elf64,
        _ => return Err(ElfError::UnsupportedFormat),
    };

    let endian = match data[5] {
        1 => ElfEndian::Little,
        2 => ElfEndian::Big,
        _ => return Err(ElfError::UnsupportedFormat),
    };

    Ok(ElfIdent {
        class,
        endian,
        version: data[6],
        os_abi: data[7],
    })
}

// ─── Safe integer reading helpers ────────────────────────────────────

/// Read a u16 from `data` at `offset`.
/// Returns `None` if the read would go out of bounds (instead of silently returning 0).
#[inline]
#[must_use]
pub fn read_u16<const BE: bool>(data: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > data.len() {
        return None;
    }
    let bytes: [u8; 2] = [data[offset], data[offset + 1]];
    Some(if BE {
        u16::from_be_bytes(bytes)
    } else {
        u16::from_le_bytes(bytes)
    })
}

/// Read a u32 from `data` at `offset`.
/// Returns `None` if the read would go out of bounds.
#[inline]
#[must_use]
pub fn read_u32<const BE: bool>(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > data.len() {
        return None;
    }
    let bytes: [u8; 4] = [
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ];
    Some(if BE {
        u32::from_be_bytes(bytes)
    } else {
        u32::from_le_bytes(bytes)
    })
}

/// Read a u64 from `data` at `offset`.
/// Returns `None` if the read would go out of bounds.
#[inline]
#[must_use]
pub fn read_u64<const BE: bool>(data: &[u8], offset: usize) -> Option<u64> {
    if offset + 8 > data.len() {
        return None;
    }
    let bytes: [u8; 8] = [
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ];
    Some(if BE {
        u64::from_be_bytes(bytes)
    } else {
        u64::from_le_bytes(bytes)
    })
}
