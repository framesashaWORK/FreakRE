#![allow(dead_code, unused_assignments)]
//! Zero-copy PE32/PE32+ parser for malware analysis.

use std::fmt;
use std::ops::Range;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum PeError {
    #[error("file too small for DOS header ({0} bytes)")]
    TooSmallForDos(usize),
    #[error("invalid DOS magic: expected 0x5A4D, got 0x{0:04X}")]
    BadDosMagic(u16),
    #[error("e_lfanew points beyond file end (offset {0}, file size {1})")]
    LfanewOutOfBounds(u32, usize),
    #[error("file too small for PE signature at offset {0}")]
    TooSmallForPeSig(u32),
    #[error("invalid PE signature: expected 0x00004550, got 0x{0:08X}")]
    BadPeSig(u32),
    #[error("file too small for COFF header at offset {0}")]
    TooSmallForCoff(u32),
    #[error("file too small for optional header at offset {0}")]
    TooSmallForOpt(u32),
    #[error("unknown optional header magic: 0x{0:04X}")]
    UnknownOptMagic(u16),
    #[error("file too small for section headers (need {needed}, have {have})")]
    TooSmallForSections { needed: usize, have: usize },
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DOS_MAGIC: u16 = 0x5A4D;
const PE_SIG: u32 = 0x0000_4550;
const OPT_MAGIC_PE32: u16 = 0x010B;
const OPT_MAGIC_PE32PLUS: u16 = 0x020B;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;

const MAX_RELOC_BLOCKS: usize = 65_536;
const MAX_RELOC_ENTRIES: usize = 1_000_000;
const MAX_METADATA_STREAMS: usize = 64;
const MAX_METADATA_VERSION_LEN: usize = 1024;
const COR20_MIN_DIRECTORY_SIZE: u32 = 0x48;

// ─── Data Directory indices ─────────────────────────────────────────
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
pub const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: usize = 7;
pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR: usize = 8;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

// ─── DllCharacteristics flags ───────────────────────────────────────
const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;
const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
const IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: u16 = 0x0080;
const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
const IMAGE_DLLCHARACTERISTICS_NO_ISOLATION: u16 = 0x0200;
const IMAGE_DLLCHARACTERISTICS_NO_SEH: u16 = 0x0400;
const IMAGE_DLLCHARACTERISTICS_NO_BIND: u16 = 0x0800;
const IMAGE_DLLCHARACTERISTICS_APPCONTAINER: u16 = 0x1000;
const IMAGE_DLLCHARACTERISTICS_WDM_DRIVER: u16 = 0x2000;
const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;
const IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE: u16 = 0x8000;

// ---------------------------------------------------------------------------
// Little-endian helpers
// ---------------------------------------------------------------------------

#[inline]
fn read_u16(data: &[u8], offset: usize) -> u16 {
    // Safety: callers must ensure bounds. This is a hot-path helper.
    // All call sites in parse() are guarded by explicit bounds checks.
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

#[inline]
fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

#[inline]
fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

/// Bounds-checked variants for use in methods that may receive untrusted offsets.
#[inline]
fn try_read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    data.get(offset..end)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

#[inline]
fn try_read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    data.get(offset..end)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

#[inline]
fn try_read_u64(data: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    data.get(offset..end)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

// ---------------------------------------------------------------------------
// Machine type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineType {
    I386,
    Amd64,
    Arm,
    Arm64,
    Unknown(u16),
}

impl MachineType {
    pub fn from_raw(val: u16) -> Self {
        match val {
            0x014C => MachineType::I386,
            0x8664 => MachineType::Amd64,
            0x01C0 => MachineType::Arm,
            0xAA64 => MachineType::Arm64,
            other => MachineType::Unknown(other),
        }
    }

    pub fn is_64bit(self) -> bool {
        matches!(self, MachineType::Amd64 | MachineType::Arm64)
    }

    pub fn to_raw(self) -> u16 {
        match self {
            MachineType::I386 => 0x014C,
            MachineType::Amd64 => 0x8664,
            MachineType::Arm => 0x01C0,
            MachineType::Arm64 => 0xAA64,
            MachineType::Unknown(v) => v,
        }
    }
}

impl fmt::Display for MachineType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MachineType::I386 => write!(f, "x86"),
            MachineType::Amd64 => write!(f, "x64"),
            MachineType::Arm => write!(f, "ARM"),
            MachineType::Arm64 => write!(f, "ARM64"),
            MachineType::Unknown(v) => write!(f, "Unknown(0x{v:04X})"),
        }
    }
}

// ---------------------------------------------------------------------------
// Data directory
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

impl DataDirectory {
    pub fn is_empty(self) -> bool {
        self.virtual_address == 0 || self.size == 0
    }
}

// ---------------------------------------------------------------------------
// Warning types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WarningKind {
    RwxSection,
    AnomalousELfanew,
    ZeroSections,
    DebugSymbolsInRelease,
    OverlappingSections,
    ExecutableWithoutCodeFlag,
    EmptyRawWithVirtualSize,
    MalformedDirectoryRange,
    Other,
}

#[derive(Debug, Clone)]
pub struct PeWarning {
    pub kind: WarningKind,
    pub message: String,
}

fn directory_file_range(
    data: &[u8],
    sections: &[SectionHeader],
    index: usize,
    directory: DataDirectory,
) -> Result<Range<usize>, &'static str> {
    let size = directory.size as usize;
    if index == IMAGE_DIRECTORY_ENTRY_SECURITY {
        let start = directory.virtual_address as usize;
        let end = start
            .checked_add(size)
            .ok_or("file offset plus size overflows")?;
        return (end <= data.len())
            .then_some(start..end)
            .ok_or("range extends beyond the file");
    }

    directory
        .virtual_address
        .checked_add(directory.size)
        .ok_or("RVA plus size overflows")?;

    for section in sections {
        let mapped_size = section.virtual_size.max(section.raw_data_size);
        let Some(virtual_end) = section.virtual_address.checked_add(mapped_size) else {
            continue;
        };
        if directory.virtual_address < section.virtual_address
            || directory.virtual_address >= virtual_end
        {
            continue;
        }

        let in_section = directory.virtual_address - section.virtual_address;
        let available = section
            .raw_data_size
            .checked_sub(in_section)
            .ok_or("range starts outside file-backed section data")?;
        if directory.size > available {
            return Err("range extends beyond file-backed section data");
        }
        let start = (section.raw_data_offset as usize)
            .checked_add(in_section as usize)
            .ok_or("file offset overflows")?;
        let end = start
            .checked_add(size)
            .ok_or("file offset plus size overflows")?;
        return (end <= data.len())
            .then_some(start..end)
            .ok_or("range extends beyond the file");
    }

    Err("RVA is not mapped to file-backed section data")
}

// ---------------------------------------------------------------------------
// Section header
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_data_size: u32,
    pub raw_data_offset: u32,
    pub characteristics: u32,
}

impl SectionHeader {
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, PeError> {
        let needed = match offset.checked_add(40) {
            Some(n) => n,
            None => {
                return Err(PeError::TooSmallForSections {
                    needed: usize::MAX,
                    have: data.len(),
                })
            }
        };
        if needed > data.len() {
            return Err(PeError::TooSmallForSections {
                needed,
                have: data.len(),
            });
        }
        let mut name = [0u8; 8];
        name.copy_from_slice(&data[offset..offset + 8]);
        Ok(Self {
            name,
            virtual_size: read_u32(data, offset + 8),
            virtual_address: read_u32(data, offset + 12),
            raw_data_size: read_u32(data, offset + 16),
            raw_data_offset: read_u32(data, offset + 20),
            characteristics: read_u32(data, offset + 36),
        })
    }

    pub fn name_string(&self) -> String {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        String::from_utf8_lossy(&self.name[..end]).into_owned()
    }

    pub fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }

    pub fn is_writable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_WRITE != 0
    }

    pub fn is_readable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_READ != 0
    }

    pub fn is_code(&self) -> bool {
        self.characteristics & IMAGE_SCN_CNT_CODE != 0
    }

    pub fn is_rwx(&self) -> bool {
        self.is_readable() && self.is_writable() && self.is_executable()
    }

    pub fn is_unpacked_placeholder(&self) -> bool {
        self.raw_data_size == 0 && self.virtual_size > 0
    }

    /// Get the raw data slice for this section from the full file buffer.
    pub fn raw_data<'a>(&self, file_data: &'a [u8]) -> &'a [u8] {
        let start = self.raw_data_offset as usize;
        let end = start.saturating_add(self.raw_data_size as usize);
        if end <= file_data.len() {
            &file_data[start..end]
        } else if start < file_data.len() {
            &file_data[start..]
        } else {
            &[]
        }
    }
}

// ---------------------------------------------------------------------------
// NT Headers (simplified view for scanner compatibility)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FileHeader {
    pub machine: MachineType,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
}

#[derive(Debug, Clone)]
pub struct NtHeaders {
    pub file_header: FileHeader,
}

// ---------------------------------------------------------------------------
// Base relocations
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocType {
    Absolute = 0,
    High = 1,
    Low = 2,
    HighLow = 3,
    HighAdj = 4,
    MipsJmpAddr = 5,
    Section = 6,
    Rel32 = 7,
    RiscvLow12S = 8,
    MipsJmpAddr16 = 9,
    Dir64 = 10,
}

impl RelocType {
    pub fn from_raw(val: u16) -> Option<Self> {
        match val {
            0 => Some(RelocType::Absolute),
            1 => Some(RelocType::High),
            2 => Some(RelocType::Low),
            3 => Some(RelocType::HighLow),
            4 => Some(RelocType::HighAdj),
            5 => Some(RelocType::MipsJmpAddr),
            6 => Some(RelocType::Section),
            7 => Some(RelocType::Rel32),
            8 => Some(RelocType::RiscvLow12S),
            9 => Some(RelocType::MipsJmpAddr16),
            10 => Some(RelocType::Dir64),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaseRelocation {
    pub rva: u32,
    pub typ: u16,
}

/// x64 exception/unwind function range from the PE Exception Directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeFunction {
    pub begin_rva: u32,
    pub end_rva: u32,
    pub unwind_info_rva: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnwindOp {
    PushNonVol {
        register: u8,
        code_offset: u8,
    },
    AllocLarge {
        size: u32,
        code_offset: u8,
    },
    AllocSmall {
        size: u32,
        code_offset: u8,
    },
    SetFpReg {
        code_offset: u8,
    },
    SaveNonVol {
        register: u8,
        stack_offset: u32,
        code_offset: u8,
    },
    SaveNonVolFar {
        register: u8,
        stack_offset: u32,
        code_offset: u8,
    },
    SaveXmm128 {
        register: u8,
        stack_offset: u32,
        code_offset: u8,
    },
    SaveXmm128Far {
        register: u8,
        stack_offset: u32,
        code_offset: u8,
    },
    PushMachFrame {
        error_code: bool,
        code_offset: u8,
    },
    Unknown {
        op: u8,
        info: u8,
        code_offset: u8,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwindInfo {
    pub version: u8,
    pub flags: u8,
    pub prologue_size: u8,
    pub code_count: u8,
    pub frame_register: u8,
    pub frame_offset: u8,
    pub codes: Vec<UnwindOp>,
    pub chained: Option<RuntimeFunction>,
}

// ---------------------------------------------------------------------------
// .NET CLI metadata
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Cor20Header {
    pub cb: u32,
    pub major_runtime_version: u16,
    pub minor_runtime_version: u16,
    pub metadata_rva: u32,
    pub metadata_size: u32,
    pub flags: u32,
    pub entry_point_token: u32,
}

#[derive(Debug, Clone)]
pub struct DotNetInfo {
    pub is_dotnet: bool,
    pub runtime_version: String,
    pub metadata_version: String,
    pub streams: Vec<(String, u32, u32)>,
    pub table_rows: Vec<(u32, u32)>,
}

// ---------------------------------------------------------------------------
// Main PE file structure
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct PeFile<'a> {
    pub data: &'a [u8],
    pub nt_headers: NtHeaders,
    pub is_64bit: bool,
    pub entry_point: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub sections: Vec<SectionHeader>,
    pub data_directories: Vec<DataDirectory>,
    pub dll_characteristics: u16,
    pub warnings: Vec<PeWarning>,
}

impl<'a> PeFile<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, PeError> {
        // --- DOS Header ---
        if data.len() < 64 {
            return Err(PeError::TooSmallForDos(data.len()));
        }
        let dos_magic = read_u16(data, 0);
        if dos_magic != DOS_MAGIC {
            return Err(PeError::BadDosMagic(dos_magic));
        }
        let lfanew = read_u32(data, 60);
        let lfanew_usize = lfanew as usize;
        if lfanew_usize >= data.len() {
            return Err(PeError::LfanewOutOfBounds(lfanew, data.len()));
        }

        // --- PE Signature ---
        if lfanew_usize
            .checked_add(4)
            .is_none_or(|end| end > data.len())
        {
            return Err(PeError::TooSmallForPeSig(lfanew));
        }
        let pe_sig = read_u32(data, lfanew_usize);
        if pe_sig != PE_SIG {
            return Err(PeError::BadPeSig(pe_sig));
        }

        // --- COFF Header ---
        let coff_off = lfanew_usize
            .checked_add(4)
            .ok_or(PeError::TooSmallForCoff(lfanew))?;
        if coff_off.checked_add(20).is_none_or(|end| end > data.len()) {
            return Err(PeError::TooSmallForCoff(lfanew));
        }
        let machine_raw = read_u16(data, coff_off);
        let machine = MachineType::from_raw(machine_raw);
        let number_of_sections = read_u16(data, coff_off + 2);
        let timestamp = read_u32(data, coff_off + 4);

        // --- Optional Header ---
        let opt_off = coff_off
            .checked_add(20)
            .ok_or(PeError::TooSmallForOpt(lfanew))?;
        if opt_off.checked_add(2).is_none_or(|end| end > data.len()) {
            return Err(PeError::TooSmallForOpt(lfanew));
        }
        let opt_magic = read_u16(data, opt_off);
        let is_64bit = match opt_magic {
            OPT_MAGIC_PE32 => false,
            OPT_MAGIC_PE32PLUS => true,
            other => return Err(PeError::UnknownOptMagic(other)),
        };

        let (
            entry_point,
            image_base,
            section_alignment,
            file_alignment,
            num_ddr,
            dll_characteristics,
        ) = if is_64bit {
            if opt_off + 112 > data.len() {
                return Err(PeError::TooSmallForOpt(lfanew));
            }
            (
                read_u32(data, opt_off + 16),
                read_u64(data, opt_off + 24),
                read_u32(data, opt_off + 32),
                read_u32(data, opt_off + 36),
                read_u32(data, opt_off + 108),
                read_u16(data, opt_off + 70),
            )
        } else {
            if opt_off + 96 > data.len() {
                return Err(PeError::TooSmallForOpt(lfanew));
            }
            (
                read_u32(data, opt_off + 16),
                read_u32(data, opt_off + 28) as u64,
                read_u32(data, opt_off + 32),
                read_u32(data, opt_off + 36),
                read_u32(data, opt_off + 92),
                read_u16(data, opt_off + 46),
            )
        };

        // Section headers follow SizeOfOptionalHeader, not the number of
        // directories. The latter is attacker-controlled and may be larger
        // than the optional header actually present in the file. Keep the
        // legacy zero-sized synthetic fixtures compatible by falling back to
        // the minimum header size in that case.
        let declared_opt_size = read_u16(data, coff_off + 16) as usize;
        let minimum_opt_size = if is_64bit { 112usize } else { 96usize };
        let opt_size = declared_opt_size.max(minimum_opt_size);
        if opt_size < minimum_opt_size
            || opt_off
                .checked_add(opt_size)
                .is_none_or(|end| end > data.len())
        {
            return Err(PeError::TooSmallForOpt(lfanew));
        }

        // --- Data Directories ---
        let ddr_off = if is_64bit {
            opt_off + 112
        } else {
            opt_off + 96
        };
        // PE spec: max 16 standard data directories, but some tools set
        // higher values. Cap at 128 to prevent overflow / excessive allocation
        // from malformed PE files. num_ddr is u32 from file — must be bounded.
        let clamped_num_ddr = (num_ddr as usize).min(128);
        let mut data_directories = Vec::with_capacity(clamped_num_ddr);
        for i in 0..clamped_num_ddr {
            let off = match ddr_off.checked_add(i * 8) {
                Some(o) => o,
                None => break,
            };
            if off + 8 > data.len() {
                break;
            }
            data_directories.push(DataDirectory {
                virtual_address: read_u32(data, off),
                size: read_u32(data, off + 4),
            });
        }

        // --- Section Headers ---
        // PE spec: max 96 sections. Malware may set a large number_of_sections
        // to trigger integer overflow or excessive allocation. Clamp it.
        let clamped_num_sections = (number_of_sections as usize).min(96);
        // A few old/synthetic images leave SizeOfOptionalHeader as zero. In
        // that malformed-but-common case retain the historical directory
        // based fallback, while valid headers always use the declared size.
        let section_table_off = if declared_opt_size >= minimum_opt_size {
            opt_off.checked_add(declared_opt_size)
        } else {
            ddr_off.checked_add(clamped_num_ddr.saturating_mul(8))
        }
        .ok_or(PeError::TooSmallForSections {
            needed: usize::MAX,
            have: data.len(),
        })?;
        let sections_end = match section_table_off.checked_add(clamped_num_sections * 40) {
            Some(e) => e,
            None => {
                return Err(PeError::TooSmallForSections {
                    needed: usize::MAX,
                    have: data.len(),
                })
            }
        };
        if sections_end > data.len() {
            return Err(PeError::TooSmallForSections {
                needed: sections_end,
                have: data.len(),
            });
        }

        let mut sections = Vec::with_capacity(clamped_num_sections);
        for i in 0..clamped_num_sections {
            let sec_off = match section_table_off.checked_add(i * 40) {
                Some(o) => o,
                None => {
                    return Err(PeError::TooSmallForSections {
                        needed: usize::MAX,
                        have: data.len(),
                    })
                }
            };
            sections.push(SectionHeader::parse(data, sec_off)?);
        }

        // --- Warnings ---
        let mut warnings = Vec::new();

        if clamped_num_sections == 0 {
            warnings.push(PeWarning {
                kind: WarningKind::ZeroSections,
                message: "PE has zero sections".into(),
            });
        }

        if number_of_sections as usize > 96 {
            warnings.push(PeWarning {
                kind: WarningKind::Other,
                message: format!(
                    "Anomalous number of sections: {} (clamped to 96)",
                    number_of_sections
                ),
            });
        }

        if lfanew > 0x1000 {
            warnings.push(PeWarning {
                kind: WarningKind::AnomalousELfanew,
                message: format!("Anomalous e_lfanew value: 0x{:X}", lfanew),
            });
        }

        for sec in &sections {
            if sec.is_rwx() {
                warnings.push(PeWarning {
                    kind: WarningKind::RwxSection,
                    message: format!("RWX section: {}", sec.name_string()),
                });
            }
            if sec.is_unpacked_placeholder() {
                warnings.push(PeWarning {
                    kind: WarningKind::EmptyRawWithVirtualSize,
                    message: format!(
                        "Section '{}' has empty raw data but virtual_size={}",
                        sec.name_string(),
                        sec.virtual_size
                    ),
                });
            }
            if sec.is_executable() && !sec.is_code() {
                warnings.push(PeWarning {
                    kind: WarningKind::ExecutableWithoutCodeFlag,
                    message: format!(
                        "Section '{}' is executable but lacks CODE flag",
                        sec.name_string()
                    ),
                });
            }
        }

        for (index, directory) in data_directories.iter().copied().enumerate() {
            if directory.is_empty() {
                continue;
            }
            if let Err(reason) = directory_file_range(data, &sections, index, directory) {
                warnings.push(PeWarning {
                    kind: WarningKind::MalformedDirectoryRange,
                    message: format!(
                        "Data directory {index} has malformed range (address=0x{:X}, size=0x{:X}): {reason}",
                        directory.virtual_address, directory.size
                    ),
                });
            }
        }

        // Overlapping sections check
        for i in 0..sections.len() {
            for j in (i + 1)..sections.len() {
                let a = &sections[i];
                let b = &sections[j];
                let a_start = a.raw_data_offset;
                let a_end = a_start.saturating_add(a.raw_data_size);
                let b_start = b.raw_data_offset;
                let b_end = b_start.saturating_add(b.raw_data_size);
                if a.raw_data_size > 0 && b.raw_data_size > 0 && a_start < b_end && b_start < a_end
                {
                    warnings.push(PeWarning {
                        kind: WarningKind::OverlappingSections,
                        message: format!(
                            "Overlapping sections: {} <-> {}",
                            a.name_string(),
                            b.name_string()
                        ),
                    });
                }
            }
        }

        Ok(Self {
            data,
            nt_headers: NtHeaders {
                file_header: FileHeader {
                    machine,
                    number_of_sections,
                    time_date_stamp: timestamp,
                },
            },
            is_64bit,
            entry_point,
            image_base,
            section_alignment,
            file_alignment,
            sections,
            data_directories,
            dll_characteristics,
            warnings,
        })
    }

    /// Resolve an RVA to a file offset.
    /// FIXED: A malformed section (e.g. `virtual_address + size` overflowing)
    /// is skipped instead of aborting translation for the whole image, and the
    /// mapped range is constrained to the file-backed part (`raw_data_size`)
    /// so RVAs in the virtual tail cannot resolve onto unrelated file bytes.
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        for sec in &self.sections {
            let mapped_size = sec.virtual_size.max(sec.raw_data_size);
            let virt_end = match sec.virtual_address.checked_add(mapped_size) {
                Some(end) => end,
                None => continue,
            };
            if rva >= sec.virtual_address && rva < virt_end {
                let offset_in_section = rva - sec.virtual_address;
                if offset_in_section >= sec.raw_data_size {
                    continue;
                }
                let file_offset =
                    match (sec.raw_data_offset as usize).checked_add(offset_in_section as usize) {
                        Some(off) => off,
                        None => continue,
                    };
                if file_offset < self.data.len() {
                    return Some(file_offset);
                }
            }
        }
        None
    }

    fn raw_backed_bytes_from_rva(&self, rva: u32) -> Option<usize> {
        let sec = self.sections.iter().find(|sec| {
            let size = sec.virtual_size.max(sec.raw_data_size);
            sec.virtual_address
                .checked_add(size)
                .is_some_and(|end| rva >= sec.virtual_address && rva < end)
        })?;
        let in_section = rva.checked_sub(sec.virtual_address)?;
        if in_section >= sec.raw_data_size {
            return None;
        }
        let file_offset = (sec.raw_data_offset as usize).checked_add(in_section as usize)?;
        if file_offset >= self.data.len() {
            return None;
        }
        Some(((sec.raw_data_size - in_section) as usize).min(self.data.len() - file_offset))
    }

    /// Return a data directory only when its complete declared range is
    /// present in the file-backed image. The Security Directory is handled as
    /// a file offset as required by the PE format; all other entries use RVAs.
    pub fn directory_bytes(&self, index: usize) -> Option<&'a [u8]> {
        let directory = *self.data_directories.get(index)?;
        if directory.is_empty() {
            return None;
        }
        let range = directory_file_range(self.data, &self.sections, index, directory).ok()?;
        self.data.get(range)
    }

    /// Get the .text section data.
    pub fn text_section_data(&self) -> Option<&'a [u8]> {
        self.sections
            .iter()
            .find(|s| s.is_code() || s.name_string() == ".text")
            .map(|s| s.raw_data(self.data))
    }

    // ─── Import Table Helpers ─────────────────────────────────────────

    /// Get the Import Directory RVA and size from the data directories.
    /// Returns `None` if the Import Directory entry is absent or empty.
    pub fn import_directory(&self) -> Option<(u32, u32)> {
        let dd = self.data_directories.get(IMAGE_DIRECTORY_ENTRY_IMPORT)?;
        if dd.is_empty() {
            return None;
        }
        Some((dd.virtual_address, dd.size))
    }

    /// Get the IAT (Import Address Table) RVA and size.
    pub fn iat_directory(&self) -> Option<(u32, u32)> {
        let dd = self.data_directories.get(IMAGE_DIRECTORY_ENTRY_IAT)?;
        if dd.is_empty() {
            return None;
        }
        Some((dd.virtual_address, dd.size))
    }

    /// Get the Resource Directory RVA and size.
    pub fn resource_directory(&self) -> Option<(u32, u32)> {
        let dd = self.data_directories.get(IMAGE_DIRECTORY_ENTRY_RESOURCE)?;
        if dd.is_empty() {
            return None;
        }
        Some((dd.virtual_address, dd.size))
    }

    /// Get the TLS Directory RVA and size.
    pub fn tls_directory(&self) -> Option<(u32, u32)> {
        let dd = self.data_directories.get(IMAGE_DIRECTORY_ENTRY_TLS)?;
        if dd.is_empty() {
            return None;
        }
        Some((dd.virtual_address, dd.size))
    }

    /// Get the Delay Import Directory RVA and size.
    pub fn delay_import_directory(&self) -> Option<(u32, u32)> {
        let dd = self
            .data_directories
            .get(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)?;
        if dd.is_empty() {
            return None;
        }
        Some((dd.virtual_address, dd.size))
    }

    /// Get the Bound Import Directory RVA and size.
    pub fn bound_import_directory(&self) -> Option<(u32, u32)> {
        let dd = self
            .data_directories
            .get(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT)?;
        if dd.is_empty() {
            return None;
        }
        Some((dd.virtual_address, dd.size))
    }

    /// Get the COM Descriptor (CLR/.NET) Directory RVA and size.
    pub fn com_descriptor_directory(&self) -> Option<(u32, u32)> {
        let dd = self
            .data_directories
            .get(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)?;
        if dd.is_empty() {
            return None;
        }
        Some((dd.virtual_address, dd.size))
    }

    /// Get the Debug Directory RVA and size.
    pub fn debug_directory(&self) -> Option<(u32, u32)> {
        let dd = self.data_directories.get(IMAGE_DIRECTORY_ENTRY_DEBUG)?;
        if dd.is_empty() {
            return None;
        }
        Some((dd.virtual_address, dd.size))
    }

    /// Read bounded x64 `RUNTIME_FUNCTION` entries from the exception
    /// directory. Malformed or truncated entries are ignored safely.
    pub fn runtime_functions(&self) -> Vec<RuntimeFunction> {
        if !matches!(self.nt_headers.file_header.machine, MachineType::Amd64) {
            return Vec::new();
        }
        let bytes = match self.directory_bytes(IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
            Some(bytes) => bytes,
            None => return Vec::new(),
        };
        let mut result = Vec::new();
        let mut pos = 0usize;
        while pos.checked_add(12).is_some_and(|p| p <= bytes.len()) {
            let begin_rva = match try_read_u32(bytes, pos) {
                Some(v) => v,
                None => break,
            };
            let end_rva = match try_read_u32(bytes, pos + 4) {
                Some(v) => v,
                None => break,
            };
            let unwind_info_rva = match try_read_u32(bytes, pos + 8) {
                Some(v) => v,
                None => break,
            };
            if begin_rva < end_rva
                && unwind_info_rva & 3 == 0
                && self.rva_to_offset(unwind_info_rva).is_some()
                && result.last().is_none_or(|prev: &RuntimeFunction| {
                    prev.begin_rva <= begin_rva && prev.end_rva <= begin_rva
                })
            {
                result.push(RuntimeFunction {
                    begin_rva,
                    end_rva,
                    unwind_info_rva,
                });
            }
            pos += 12;
        }
        result
    }

    /// Return the unwind-defined end RVA for the function containing `rva`.
    pub fn runtime_function_end(&self, rva: u32) -> Option<u32> {
        self.runtime_functions()
            .into_iter()
            .find(|f| rva >= f.begin_rva && rva < f.end_rva)
            .map(|f| f.end_rva)
    }

    pub fn unwind_info(&self, function: &RuntimeFunction) -> Option<UnwindInfo> {
        if function.unwind_info_rva & 3 != 0 {
            return None;
        }
        let off = self.rva_to_offset(function.unwind_info_rva)?;
        let available = self.raw_backed_bytes_from_rva(function.unwind_info_rva)?;
        let b0 = *self.data.get(off)?;
        let b1 = *self.data.get(off + 1)?;
        let b2 = *self.data.get(off + 2)?;
        let b3 = *self.data.get(off + 3)?;
        let version = b0 & 7;
        let flags = b0 >> 3;
        if version != 1 || (flags & 4 != 0 && flags & 3 != 0) {
            return None;
        }
        let code_count = b2;
        let codes_len = 4usize.checked_add(code_count as usize * 2)?;
        let chain_len = if flags & 4 != 0 {
            12
        } else if flags & 3 != 0 {
            4
        } else {
            0
        };
        if codes_len.checked_add(chain_len)? > available {
            return None;
        }
        let mut codes = Vec::new();
        let mut i = 0usize;
        while i < code_count as usize {
            let p = off + 4 + i * 2;
            let code_offset = self.data[p];
            let opinfo = self.data[p + 1];
            let op = opinfo & 0x0F;
            let info = opinfo >> 4;
            let read_u16 = |at: usize| -> Option<u16> {
                Some(u16::from_le_bytes([
                    *self.data.get(at)?,
                    *self.data.get(at + 1)?,
                ]))
            };
            let remaining = code_count as usize - i;
            let item = match op {
                0 => UnwindOp::PushNonVol {
                    register: info,
                    code_offset,
                },
                1 if info == 0 && remaining >= 2 => {
                    let size = read_u16(p + 2)? as u32 * 8;
                    i += 1;
                    UnwindOp::AllocLarge { size, code_offset }
                }
                1 if info == 1 && remaining >= 3 => {
                    let lo = read_u16(p + 2)? as u32;
                    let hi = read_u16(p + 4)? as u32;
                    i += 1;
                    i += 1;
                    UnwindOp::AllocLarge {
                        size: lo | (hi << 16),
                        code_offset,
                    }
                }
                2 => UnwindOp::AllocSmall {
                    size: (info as u32 + 1) * 8,
                    code_offset,
                },
                3 => UnwindOp::SetFpReg { code_offset },
                4 if remaining >= 2 => {
                    let stack_offset = read_u16(p + 2)? as u32 * 8;
                    i += 1;
                    UnwindOp::SaveNonVol {
                        register: info,
                        stack_offset,
                        code_offset,
                    }
                }
                5 if remaining >= 3 => {
                    let lo = read_u16(p + 2)? as u32;
                    let hi = read_u16(p + 4)? as u32;
                    i += 2;
                    UnwindOp::SaveNonVolFar {
                        register: info,
                        stack_offset: lo | (hi << 16),
                        code_offset,
                    }
                }
                8 if remaining >= 2 => {
                    let stack_offset = read_u16(p + 2)? as u32 * 16;
                    i += 1;
                    UnwindOp::SaveXmm128 {
                        register: info,
                        stack_offset,
                        code_offset,
                    }
                }
                9 if remaining >= 3 => {
                    let lo = read_u16(p + 2)? as u32;
                    let hi = read_u16(p + 4)? as u32;
                    i += 2;
                    UnwindOp::SaveXmm128Far {
                        register: info,
                        stack_offset: lo | (hi << 16),
                        code_offset,
                    }
                }
                10 => UnwindOp::PushMachFrame {
                    error_code: info != 0,
                    code_offset,
                },
                _ if matches!(op, 1 | 4 | 5 | 8 | 9) => return None,
                _ => UnwindOp::Unknown {
                    op,
                    info,
                    code_offset,
                },
            };
            codes.push(item);
            i += 1;
        }
        let aligned_codes = (code_count as usize + 1) & !1;
        let chained = if flags & 4 != 0 {
            let p = off.checked_add(4 + aligned_codes * 2)?;
            let begin_rva = try_read_u32(self.data, p)?;
            let end_rva = try_read_u32(self.data, p + 4)?;
            let unwind_info_rva = try_read_u32(self.data, p + 8)?;
            (begin_rva < end_rva).then_some(RuntimeFunction {
                begin_rva,
                end_rva,
                unwind_info_rva,
            })
        } else {
            None
        };
        Some(UnwindInfo {
            version,
            flags,
            prologue_size: b1,
            code_count,
            frame_register: b3 & 0x0F,
            frame_offset: b3 >> 4,
            codes,
            chained,
        })
    }

    /// Get the Security Directory RVA and size.
    pub fn security_directory(&self) -> Option<(u32, u32)> {
        let dd = self.data_directories.get(IMAGE_DIRECTORY_ENTRY_SECURITY)?;
        if dd.is_empty() {
            return None;
        }
        Some((dd.virtual_address, dd.size))
    }

    /// Get the Base Relocations Directory RVA and size.
    pub fn base_reloc_directory(&self) -> Option<(u32, u32)> {
        let dd = self.data_directories.get(IMAGE_DIRECTORY_ENTRY_BASERELOC)?;
        if dd.is_empty() {
            return None;
        }
        Some((dd.virtual_address, dd.size))
    }

    /// Parse all base relocations from the .reloc section.
    pub fn base_relocations(&self) -> Result<Vec<BaseRelocation>, PeError> {
        let mut result = Vec::new();
        let (dir_rva, dir_size) = match self.base_reloc_directory() {
            Some(d) => d,
            None => return Ok(result),
        };
        let start = match self.rva_to_offset(dir_rva) {
            Some(o) => o,
            None => return Ok(result),
        };
        let end = start.saturating_add(dir_size as usize).min(self.data.len());
        let mut pos = start;
        let mut blocks = 0usize;
        let mut entries_seen = 0usize;

        while pos < end {
            if blocks >= MAX_RELOC_BLOCKS || entries_seen >= MAX_RELOC_ENTRIES {
                break;
            }
            let hdr_end = match pos.checked_add(8) {
                Some(h) => h,
                None => break,
            };
            if hdr_end > end {
                break;
            }
            let page_rva = match try_read_u32(self.data, pos) {
                Some(v) => v,
                None => break,
            };
            let size_of_block = match try_read_u32(self.data, pos + 4) {
                Some(v) => v,
                None => break,
            };
            if size_of_block < 8 {
                break;
            }
            let block_size = size_of_block as usize;
            let entry_count = (block_size - 8) / 2;
            let block_end = match pos.checked_add(block_size) {
                Some(b) => b.min(end),
                None => break,
            };

            let mut entry_pos = match pos.checked_add(8) {
                Some(p) => p,
                None => break,
            };
            for _ in 0..entry_count {
                let next = match entry_pos.checked_add(2) {
                    Some(n) => n,
                    None => break,
                };
                if next > block_end {
                    break;
                }
                let word = match try_read_u16(self.data, entry_pos) {
                    Some(w) => w,
                    None => break,
                };
                entry_pos = next;

                let typ = word >> 12;
                if typ == 0 {
                    continue;
                }
                let offs = (word & 0x0FFF) as u32;
                let rva = match page_rva.checked_add(offs) {
                    Some(r) => r,
                    None => continue,
                };
                result.push(BaseRelocation { rva, typ });
                entries_seen += 1;
                if entries_seen >= MAX_RELOC_ENTRIES {
                    break;
                }
            }

            pos = match pos.checked_add(block_size) {
                Some(p) => p,
                None => break,
            };
            blocks += 1;
        }

        Ok(result)
    }

    pub fn relocation_count(&self) -> usize {
        self.base_relocations().map(|r| r.len()).unwrap_or(0)
    }

    pub fn has_valid_relocs(&self) -> bool {
        let relocs = match self.base_relocations() {
            Ok(r) => r,
            Err(_) => return false,
        };
        if relocs.is_empty() {
            return false;
        }
        let expected: u16 = match self.nt_headers.file_header.machine {
            MachineType::Amd64 | MachineType::Arm64 => RelocType::Dir64 as u16,
            MachineType::I386 | MachineType::Arm => RelocType::HighLow as u16,
            _ => return false,
        };
        relocs.iter().all(|r| r.typ == expected)
    }

    /// Read a null-terminated ASCII string at the given file offset.
    /// Returns `None` if the offset is out of bounds.
    /// FIXED: uses checked arithmetic — an overflowing `max_len` saturates
    /// instead of wrapping around and slicing out of bounds.
    pub fn read_cstring_at(&self, offset: usize, max_len: usize) -> Option<String> {
        if offset >= self.data.len() {
            return None;
        }
        let end = offset.saturating_add(max_len).min(self.data.len());
        let slice = &self.data[offset..end];
        let len = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        Some(String::from_utf8_lossy(&slice[..len]).into_owned())
    }

    /// Read a null-terminated string at the given RVA.
    pub fn read_cstring_at_rva(&self, rva: u32, max_len: usize) -> Option<String> {
        let offset = self.rva_to_offset(rva)?;
        self.read_cstring_at(offset, max_len)
    }

    /// Whether this PE uses 64-bit thunk entries (8 bytes) or 32-bit (4 bytes).
    pub fn thunk_entry_size(&self) -> usize {
        if self.is_64bit {
            8
        } else {
            4
        }
    }

    /// The ordinal flag for thunk entries.
    pub fn ordinal_flag(&self) -> u64 {
        if self.is_64bit {
            0x8000_0000_0000_0000
        } else {
            0x8000_0000
        }
    }

    // ─── DllCharacteristics Analysis ───────────────────────────────

    /// Return human-readable list of DllCharacteristics flags.
    pub fn dll_characteristics_flags(&self) -> Vec<String> {
        let dc = self.dll_characteristics;
        let mut flags = Vec::new();
        if dc & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA != 0 {
            flags.push("HIGH_ENTROPY_VA".into());
        }
        if dc & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0 {
            flags.push("DYNAMIC_BASE/ASLR".into());
        }
        if dc & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY != 0 {
            flags.push("FORCE_INTEGRITY".into());
        }
        if dc & IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0 {
            flags.push("NX_COMPAT/DEP".into());
        }
        if dc & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION != 0 {
            flags.push("NO_ISOLATION".into());
        }
        if dc & IMAGE_DLLCHARACTERISTICS_NO_SEH != 0 {
            flags.push("NO_SEH".into());
        }
        if dc & IMAGE_DLLCHARACTERISTICS_NO_BIND != 0 {
            flags.push("NO_BIND".into());
        }
        if dc & IMAGE_DLLCHARACTERISTICS_APPCONTAINER != 0 {
            flags.push("APPCONTAINER".into());
        }
        if dc & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER != 0 {
            flags.push("WDM_DRIVER".into());
        }
        if dc & IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0 {
            flags.push("GUARD_CF/CFG".into());
        }
        if dc & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE != 0 {
            flags.push("TERMINAL_SERVER_AWARE".into());
        }
        flags
    }

    // ─── .NET CLR Detection ───────────────────────────────────────

    /// Whether this PE is a .NET assembly (has COM Descriptor/CLR header).
    pub fn is_dotnet(&self) -> bool {
        self.com_descriptor_directory().is_some()
    }

    /// Parse the IMAGE_COR20_HEADER (CLR runtime header).
    pub fn cor20_header(&self) -> Option<Cor20Header> {
        let (rva, _size) = self.com_descriptor_directory()?;
        let off = self.rva_to_offset(rva)?;
        let cb = try_read_u32(self.data, off)?;
        let major_runtime_version = try_read_u16(self.data, off + 4)?;
        let minor_runtime_version = try_read_u16(self.data, off + 6)?;
        let metadata_rva = try_read_u32(self.data, off + 8)?;
        let metadata_size = try_read_u32(self.data, off + 12)?;
        let flags = try_read_u32(self.data, off + 16)?;
        let entry_point_token = try_read_u32(self.data, off + 20)?;
        Some(Cor20Header {
            cb,
            major_runtime_version,
            minor_runtime_version,
            metadata_rva,
            metadata_size,
            flags,
            entry_point_token,
        })
    }

    /// Collect .NET runtime and CLI metadata information.
    pub fn dotnet_info(&self) -> Option<DotNetInfo> {
        let (_, dir_size) = self.com_descriptor_directory()?;
        let cor = self.cor20_header();
        let mut info = DotNetInfo {
            is_dotnet: dir_size >= COR20_MIN_DIRECTORY_SIZE,
            runtime_version: cor
                .as_ref()
                .map(|c| format!("{}.{}", c.major_runtime_version, c.minor_runtime_version))
                .unwrap_or_default(),
            metadata_version: String::new(),
            streams: Vec::new(),
            table_rows: Vec::new(),
        };
        if let Some(c) = cor.as_ref() {
            if let Some(root_off) = self.rva_to_offset(c.metadata_rva) {
                parse_metadata_root(self.data, root_off, &mut info);
            }
        }
        Some(info)
    }

    // ─── Overlay Detection ─────────────────────────────────────────

    /// Calculate the size of overlay data (data appended after the last section).
    /// Returns 0 if no overlay is present.
    /// FIXED: Uses checked arithmetic to prevent integer overflow when
    /// raw_data_offset + raw_data_size exceeds usize::MAX.
    pub fn overlay_size(&self) -> usize {
        if self.sections.is_empty() {
            return 0;
        }
        let last_section_end = self
            .sections
            .iter()
            .filter_map(|s| (s.raw_data_offset as usize).checked_add(s.raw_data_size as usize))
            .max()
            .unwrap_or(0);
        let threshold = match last_section_end.checked_add(0x200) {
            Some(t) => t,
            None => return 0,
        };
        if self.data.len() > threshold {
            self.data.len() - last_section_end
        } else {
            0
        }
    }

    /// Return overlay data slice (data after last section), if present.
    /// FIXED: Uses checked arithmetic to prevent integer overflow.
    pub fn overlay_data(&self) -> Option<&[u8]> {
        if self.sections.is_empty() {
            return None;
        }
        let last_section_end = self
            .sections
            .iter()
            .filter_map(|s| (s.raw_data_offset as usize).checked_add(s.raw_data_size as usize))
            .max()
            .unwrap_or(0);
        let threshold = last_section_end.checked_add(0x200)?;
        if self.data.len() > threshold {
            Some(&self.data[last_section_end..])
        } else {
            None
        }
    }

    // ─── TLS Callbacks ────────────────────────────────────────────

    /// Parse TLS callbacks from IMAGE_TLS_DIRECTORY.
    /// TLS callbacks execute before the entry point — common anti-debug technique.
    pub fn tls_callbacks(&self) -> Vec<u64> {
        let (rva, _size) = match self.tls_directory() {
            Some(d) => d,
            None => return Vec::new(),
        };

        let offset = match self.rva_to_offset(rva) {
            Some(o) => o,
            None => return Vec::new(),
        };

        // IMAGE_TLS_DIRECTORY32: 24 bytes
        //   AddressOfCallBacks at offset 12 (4 bytes, VA to array of VAs)
        // IMAGE_TLS_DIRECTORY64: 40 bytes
        //   AddressOfCallBacks at offset 24 (8 bytes, VA to array of VAs)
        let callback_array_va = if self.is_64bit {
            if offset + 40 > self.data.len() {
                return Vec::new();
            }
            read_u64(self.data, offset + 24)
        } else {
            if offset + 24 > self.data.len() {
                return Vec::new();
            }
            read_u32(self.data, offset + 12) as u64
        };

        if callback_array_va == 0 {
            return Vec::new();
        }

        let callback_array_rva = callback_array_va.wrapping_sub(self.image_base) as u32;
        let callback_array_offset = match self.rva_to_offset(callback_array_rva) {
            Some(o) => o,
            None => return Vec::new(),
        };

        let entry_size = if self.is_64bit { 8 } else { 4 };
        let mut callbacks = Vec::new();
        let mut pos = callback_array_offset;

        // Read up to 64 callbacks (safety limit)
        for _ in 0..64 {
            if pos + entry_size > self.data.len() {
                break;
            }
            let cb = if self.is_64bit {
                read_u64(self.data, pos)
            } else {
                read_u32(self.data, pos) as u64
            };
            if cb == 0 {
                break;
            } // NULL terminator
            callbacks.push(cb);
            pos += entry_size;
        }

        callbacks
    }

    // ─── Rich Header Fingerprint ──────────────────────────────────

    /// Parse Rich header (between DOS stub and PE signature).
    /// Returns list of compiler tool version strings.
    pub fn rich_header(&self) -> Vec<String> {
        if self.data.len() < 128 {
            return Vec::new();
        }

        // Find "Rich" marker at end of Rich header (just before e_lfanew)
        let lfanew = read_u32(self.data, 60) as usize;
        if lfanew >= self.data.len() || lfanew < 16 {
            return Vec::new();
        }

        // Search backward from e_lfanew for "Rich" signature.
        // Guard against e_lfanew=0xFFFFFFFF causing near-infinite loop.
        let search_end = lfanew.min(self.data.len()).saturating_sub(4);
        let search_start = 0x80.min(search_end);
        let mut rich_offset = None;
        for i in (search_start..=search_end).rev().step_by(4) {
            if i + 4 <= self.data.len() && &self.data[i..i + 4] == b"Rich" {
                rich_offset = Some(i);
                break;
            }
        }

        let rich_offset = match rich_offset {
            Some(o) => o,
            None => return Vec::new(),
        };

        // XOR key is at rich_offset + 4
        if rich_offset + 8 > self.data.len() {
            return Vec::new();
        }
        let xor_key = read_u32(self.data, rich_offset + 4);

        // Search backward for "DanS" (0x536E6144 XOR xor_key)
        let dans_marker = 0x536E6144 ^ xor_key;
        let mut dans_offset = None;
        let dans_search_start = 0x80.min(rich_offset);
        for i in (dans_search_start..rich_offset).rev().step_by(4) {
            if i + 4 <= self.data.len() && read_u32(self.data, i) == dans_marker {
                dans_offset = Some(i);
                break;
            }
        }

        let dans_offset = match dans_offset {
            Some(o) => o,
            None => return Vec::new(),
        };

        // Parse entries (each is 8 bytes: comp_id XOR key, count XOR key)
        let mut results = Vec::new();
        let mut pos = dans_offset + 16; // Skip DanS + 3 dwords padding
        while pos + 8 <= rich_offset {
            let comp_id = read_u32(self.data, pos) ^ xor_key;
            let count = read_u32(self.data, pos + 4) ^ xor_key;

            let build_id = comp_id & 0xFFFF;
            let prod_id = (comp_id >> 16) & 0xFFFF;

            let tool_name = match prod_id {
                1 => "Import0",
                2 => "Linker",
                3 => "Export0",
                4 => "Cv",
                6 => "C++",
                8 => "C",
                9 => "Asm",
                10 => "Resource",
                11 => "Import",
                12 => "Linker",
                13 => "Cvtomf",
                14 => "C#",
                15 => "VBasic",
                _ => "Unknown",
            };

            results.push(format!("{} v{} (count={})", tool_name, build_id, count));
            pos += 8;
        }

        results
    }

    // ─── Resources ────────────────────────────────────────────────

    /// Count resources and detect suspicious ones (high entropy, RT_RCDATA).
    /// Returns (total_resources, suspicious_resources).
    pub fn resource_info(&self) -> (usize, usize) {
        let (rva, size) = match self.resource_directory() {
            Some(d) => d,
            None => return (0, 0),
        };

        let _offset = match self.rva_to_offset(rva) {
            Some(o) => o,
            None => return (0, 0),
        };

        // Simple resource count from directory size
        // Each resource entry is ~16 bytes (IMAGE_RESOURCE_DIRECTORY_ENTRY)
        let approx_count = (size as usize / 16).min(1000);

        // Heuristic: suspicious if resource section has very high entropy
        let suspicious =
            if let Some(sec) = self.sections.iter().find(|s| s.name_string() == ".rsrc") {
                let raw = sec.raw_data(self.data);
                if !raw.is_empty() {
                    let ent = crate::calculate_section_entropy(raw);
                    if ent > 7.5 {
                        approx_count
                    } else {
                        0
                    }
                } else {
                    0
                }
            } else {
                0
            };

        (approx_count, suspicious)
    }

    // ─── Delay Imports ────────────────────────────────────────────

    /// Parse delay import descriptors and return list of DLL names.
    pub fn delay_imports(&self) -> Vec<String> {
        let (rva, _size) = match self.delay_import_directory() {
            Some(d) => d,
            None => return Vec::new(),
        };

        let offset = match self.rva_to_offset(rva) {
            Some(o) => o,
            None => return Vec::new(),
        };

        let mut dlls = Vec::new();
        let mut pos = offset;

        // Each ImgDelayDescriptor is 32 bytes (PE32) or 32 bytes (PE32+)
        // struct ImgDelayDescriptor {
        //   DWORD grAttrs;       // 0
        //   DWORD rvaDLLName;    // 4
        //   DWORD rvaHmod;       // 8
        //   DWORD rvaIAT;        // 12
        //   DWORD rvaINT;        // 16
        //   DWORD rvaBoundIAT;   // 20
        //   DWORD rvaUnloadIAT;  // 24
        //   DWORD dwTimeStamp;   // 28
        // };
        for _ in 0..128 {
            // Safety limit
            if pos + 32 > self.data.len() {
                break;
            }
            let attrs = read_u32(self.data, pos);
            let name_field = read_u32(self.data, pos + 4);
            let hmod_field = read_u32(self.data, pos + 8);

            // End of table: all-zero descriptor
            if name_field == 0 && hmod_field == 0 {
                break;
            }

            // grAttrs bit 0 (dlattrRva): fields are RVAs when set,
            // legacy VAs (pre-VC8) otherwise.
            let dll_name = if attrs & 1 == 0 {
                let va = name_field as u64;
                if va == 0 {
                    None
                } else {
                    let rva = va.wrapping_sub(self.image_base);
                    if rva != 0 && rva <= u32::MAX as u64 {
                        self.read_cstring_at_rva(rva as u32, 256)
                    } else {
                        None
                    }
                }
            } else if name_field != 0 {
                self.read_cstring_at_rva(name_field, 256)
            } else {
                None
            };

            if let Some(dll_name) = dll_name {
                dlls.push(dll_name);
            }
            pos += 32;
        }

        dlls
    }

    // ─── Export Table ────────────────────────────────────────────────

    /// Get the Export Directory RVA and size from the data directories.
    pub fn export_directory(&self) -> Option<(u32, u32)> {
        let dd = self.data_directories.get(IMAGE_DIRECTORY_ENTRY_EXPORT)?;
        if dd.is_empty() {
            return None;
        }
        Some((dd.virtual_address, dd.size))
    }

    /// Parse the export table and return (dll_name, exported_functions).
    /// Each export is (ordinal, name_or_ordinal, rva).
    pub fn exports(&self) -> (Option<String>, Vec<(u16, String, u32)>) {
        let directory = match self.directory_bytes(IMAGE_DIRECTORY_ENTRY_EXPORT) {
            Some(bytes) => bytes,
            None => return (None, Vec::new()),
        };
        if directory.len() < 40 {
            return (None, Vec::new());
        }

        // IMAGE_EXPORT_DIRECTORY layout:
        //  0: Characteristics (u32, usually 0)
        //  4: TimeDateStamp (u32)
        //  8: MajorVersion (u16)
        // 10: MinorVersion (u16)
        // 12: Name (u32, RVA to DLL name)
        // 16: Base (u32, ordinal base)
        // 20: NumberOfFunctions (u32)
        // 24: NumberOfNames (u32)
        // 28: AddressOfFunctions (u32, RVA)
        // 32: AddressOfNames (u32, RVA)
        // 36: AddressOfNameOrdinals (u32, RVA)
        let name_rva = read_u32(directory, 12);
        let base = read_u32(directory, 16);
        let num_functions = read_u32(directory, 20).min(8192);
        let num_names = read_u32(directory, 24).min(8192);
        let addr_functions = read_u32(directory, 28);
        let addr_names = read_u32(directory, 32);
        let addr_ordinals = read_u32(directory, 36);

        let dll_name = if name_rva != 0 {
            self.read_cstring_at_rva(name_rva, 256)
        } else {
            None
        };

        // Convert AddressOfFunctions RVA to file offset. The name/ordinal
        // tables may legitimately be absent (ordinal-only export tables have
        // NumberOfNames == 0 and null RVAs), so their absence must not
        // invalidate the whole function table.
        let func_off = self.rva_to_offset(addr_functions);
        let name_off = if addr_names != 0 {
            self.rva_to_offset(addr_names)
        } else {
            None
        };
        let ord_off = if addr_ordinals != 0 {
            self.rva_to_offset(addr_ordinals)
        } else {
            None
        };

        let mut exports = Vec::new();

        if let Some(fo) = func_off {
            // Build ordinal→name map from named exports
            let mut ordinal_to_name: std::collections::HashMap<u16, String> =
                std::collections::HashMap::new();
            if let (Some(no), Some(oo)) = (name_off, ord_off) {
                for i in 0..num_names {
                    let name_ptr_off = match no.checked_add(i as usize * 4) {
                        Some(o) => o,
                        None => break,
                    };
                    let ord_ptr_off = match oo.checked_add(i as usize * 2) {
                        Some(o) => o,
                        None => break,
                    };
                    let Some(name_ptr_rva) = try_read_u32(self.data, name_ptr_off) else {
                        break;
                    };
                    let Some(ordinal_idx) = try_read_u16(self.data, ord_ptr_off) else {
                        break;
                    };
                    // The ordinal table indexes the address table. Ignore corrupt
                    // indexes instead of wrapping them into a different export.
                    if ordinal_idx as u32 >= num_functions {
                        continue;
                    }
                    if let Some(name) = self.read_cstring_at_rva(name_ptr_rva, 256) {
                        ordinal_to_name.insert(ordinal_idx, name);
                    }
                }
            }

            // Enumerate all exported functions
            for i in 0..num_functions {
                let func_ptr_off = match fo.checked_add(i as usize * 4) {
                    Some(o) => o,
                    None => break,
                };
                let Some(func_rva) = try_read_u32(self.data, func_ptr_off) else {
                    break;
                };
                if func_rva == 0 {
                    continue;
                } // unused ordinal slot
                let Some(ordinal_value) = base.checked_add(i) else {
                    continue;
                };
                let Some(ordinal) = u16::try_from(ordinal_value).ok() else {
                    continue;
                };
                let name = ordinal_to_name
                    .get(&(i as u16))
                    .cloned()
                    .unwrap_or_else(|| format!("ord_{}", ordinal));
                exports.push((ordinal, name, func_rva));
            }
        }

        (dll_name, exports)
    }

    /// Return just the export names (convenience).
    pub fn export_names(&self) -> Vec<String> {
        self.exports()
            .1
            .into_iter()
            .map(|(_, name, _)| name)
            .collect()
    }
}

/// Helper: calculate entropy of a byte slice (for PE-internal use).
fn calculate_section_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let total = data.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn parse_metadata_root(data: &[u8], root_off: usize, info: &mut DotNetInfo) {
    match data.get(root_off..root_off + 4) {
        Some(sig) if sig == b"BSJB" => {}
        _ => return,
    }
    let ver_len = match try_read_u32(data, root_off + 12) {
        Some(v) if (v as usize) <= MAX_METADATA_VERSION_LEN => v as usize,
        _ => return,
    };
    let ver_padded = (ver_len + 3) & !3;
    let ver_start = match root_off.checked_add(16) {
        Some(o) => o,
        None => return,
    };
    let ver_end = match ver_start.checked_add(ver_padded) {
        Some(e) => e,
        None => return,
    };
    let ver_bytes = match data.get(ver_start..ver_end) {
        Some(b) => b,
        None => return,
    };
    let core = &ver_bytes[..ver_len.min(ver_bytes.len())];
    let end = core.iter().position(|&b| b == 0).unwrap_or(core.len());
    info.metadata_version = String::from_utf8_lossy(&core[..end]).into_owned();

    let mut pos = ver_start + ver_padded;
    if try_read_u16(data, pos).is_none() || try_read_u16(data, pos + 2).is_none() {
        return;
    }
    let nstreams = try_read_u16(data, pos + 2).unwrap_or(0) as usize;
    pos += 4;

    for _ in 0..nstreams.min(MAX_METADATA_STREAMS) {
        let st_off = match try_read_u32(data, pos) {
            Some(v) => v,
            None => return,
        };
        let st_size = match try_read_u32(data, pos + 4) {
            Some(v) => v,
            None => return,
        };
        let name_start = match pos.checked_add(8) {
            Some(p) => p,
            None => return,
        };
        let mut nul = None;
        for i in 0..256usize {
            match data.get(name_start + i) {
                Some(0) => {
                    nul = Some(name_start + i);
                    break;
                }
                Some(_) => {}
                None => break,
            }
        }
        let nul = match nul {
            Some(n) => n,
            None => return,
        };
        let name = String::from_utf8_lossy(&data[name_start..nul]).into_owned();
        info.streams.push((name, st_off, st_size));
        let padded_len = (nul - name_start + 1 + 3) & !3;
        pos = match name_start.checked_add(padded_len) {
            Some(p) => p,
            None => return,
        };
    }

    let tables_stream = info
        .streams
        .iter()
        .find(|(n, _, _)| n == "#~" || n == "#-")
        .map(|(_, o, _)| *o);
    if let Some(t_off) = tables_stream {
        parse_metadata_tables(data, root_off, t_off, info);
    }
}

fn parse_metadata_tables(data: &[u8], root_off: usize, stream_off: u32, info: &mut DotNetInfo) {
    let base = match root_off.checked_add(stream_off as usize) {
        Some(b) => b,
        None => return,
    };
    let valid_hdr = match base.checked_add(8) {
        Some(o) => o,
        None => return,
    };
    let valid = match try_read_u64(data, valid_hdr) {
        Some(v) => v,
        None => return,
    };
    let mut row_off = match base.checked_add(24) {
        Some(o) => o,
        None => return,
    };
    for bit in 0..64u32 {
        if (valid >> bit) & 1 == 0 {
            continue;
        }
        let rows = match try_read_u32(data, row_off) {
            Some(v) => v,
            None => break,
        };
        info.table_rows.push((bit, rows));
        row_off = match row_off.checked_add(4) {
            Some(o) => o,
            None => break,
        };
    }
}

pub fn table_name(num: u32) -> &'static str {
    match num {
        0x00 => "Module",
        0x01 => "TypeRef",
        0x02 => "TypeDef",
        0x03 => "FieldPtr",
        0x04 => "Field",
        0x05 => "MethodPtr",
        0x06 => "MethodDef",
        0x07 => "ParamPtr",
        0x08 => "Param",
        0x09 => "InterfaceImpl",
        0x0A => "MemberRef",
        0x0B => "Constant",
        0x0C => "CustomAttribute",
        0x0D => "FieldMarshal",
        0x0E => "DeclSecurity",
        0x0F => "ClassLayout",
        0x10 => "FieldLayout",
        0x11 => "StandAloneSig",
        0x12 => "EventMap",
        0x13 => "EventPtr",
        0x14 => "Event",
        0x15 => "PropertyMap",
        0x16 => "PropertyPtr",
        0x17 => "Property",
        0x18 => "MethodSemantics",
        0x19 => "MethodImpl",
        0x1A => "ModuleRef",
        0x1B => "TypeSpec",
        0x1C => "ImplMap",
        0x1D => "FieldRVA",
        0x1E => "EncLog",
        0x1F => "ENCMap",
        0x20 => "Assembly",
        0x21 => "AssemblyProcessor",
        0x22 => "AssemblyOS",
        0x23 => "AssemblyRef",
        0x24 => "AssemblyRefProcessor",
        0x25 => "AssemblyRefOS",
        0x26 => "File",
        0x27 => "ExportedType",
        0x28 => "ManifestResource",
        0x29 => "NestedClass",
        0x2A => "GenericParam",
        0x2B => "MethodSpec",
        0x2C => "GenericParamConstraint",
        0x30 => "Document",
        0x31 => "MethodDebugInformation",
        0x32 => "LocalScope",
        0x33 => "LocalVariable",
        0x34 => "LocalConstant",
        0x35 => "ImportScope",
        0x36 => "StateMachineMethod",
        0x37 => "CustomDebugInformation",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_too_small() {
        assert!(matches!(
            PeFile::parse(&[0u8; 10]),
            Err(PeError::TooSmallForDos(_))
        ));
    }

    #[test]
    fn test_bad_dos_magic() {
        let data = [0u8; 64];
        assert!(matches!(PeFile::parse(&data), Err(PeError::BadDosMagic(_))));
    }

    #[test]
    fn test_machine_type_display() {
        assert_eq!(MachineType::I386.to_string(), "x86");
        assert_eq!(MachineType::Amd64.to_string(), "x64");
    }

    #[test]
    fn test_section_flags() {
        let sec = SectionHeader {
            name: *b".test\x00\x00\x00",
            virtual_size: 0x1000,
            virtual_address: 0x1000,
            raw_data_size: 0x200,
            raw_data_offset: 0x400,
            characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE,
        };
        assert!(sec.is_rwx());
        assert_eq!(sec.name_string(), ".test");
    }

    #[test]
    fn test_valid_pe32_parse() {
        // Build a minimal valid PE32
        let mut data = vec![0u8; 1024];
        // DOS header
        data[0] = 0x4D;
        data[1] = 0x5A; // MZ
        data[60] = 0x80; // e_lfanew = 128
                         // PE signature at 0x80
        data[0x80] = 0x50;
        data[0x81] = 0x45;
        data[0x82] = 0;
        data[0x83] = 0;
        // COFF header at 0x84: machine=0x14C (i386), 1 section
        data[0x84] = 0x4C;
        data[0x85] = 0x01;
        data[0x86] = 1;
        data[0x87] = 0; // 1 section
                        // Optional header at 0x98
        data[0x98] = 0x0B;
        data[0x99] = 0x01; // PE32 magic
                           // Entry point at 0x98 + 16 = 0xA8
        data[0xA8] = 0x00;
        data[0xA9] = 0x10; // RVA 0x1000
                           // Number of data directories at 0x98 + 92 = 0xF4
        data[0xF4] = 0; // 0 data directories
                        // Section table at 0xF8 (after opt header of 96 bytes)
        let sec_off = 0xF8;
        // Name: .text
        data[sec_off..sec_off + 5].copy_from_slice(b".text");
        // VirtualSize at +8
        data[sec_off + 8] = 0x00;
        data[sec_off + 9] = 0x10; // 0x1000
                                  // VirtualAddress at +12
        data[sec_off + 12] = 0x00;
        data[sec_off + 13] = 0x10; // 0x1000
                                   // RawDataSize at +16
        data[sec_off + 16] = 0x00;
        data[sec_off + 17] = 0x02; // 0x200
                                   // RawDataOffset at +20
        data[sec_off + 20] = 0x00;
        data[sec_off + 21] = 0x02; // 0x200
                                   // Characteristics at +36
        data[sec_off + 36] = 0x20;
        data[sec_off + 39] = 0x60; // CODE | EXECUTE | READ

        let pe = PeFile::parse(&data).unwrap();
        assert_eq!(pe.sections.len(), 1);
        assert_eq!(pe.sections[0].name_string(), ".text");
        assert!(pe.sections[0].is_executable());
        assert!(!pe.is_64bit);
    }

    #[test]
    fn test_rwx_section_warning() {
        let mut data = vec![0u8; 1024];
        data[0] = 0x4D;
        data[1] = 0x5A;
        data[60] = 0x80;
        data[0x80] = 0x50;
        data[0x81] = 0x45;
        data[0x82] = 0;
        data[0x83] = 0;
        data[0x84] = 0x4C;
        data[0x85] = 0x01;
        data[0x86] = 1;
        data[0x87] = 0;
        data[0x98] = 0x0B;
        data[0x99] = 0x01;
        data[0xF4] = 0;
        let sec_off = 0xF8;
        data[sec_off..sec_off + 4].copy_from_slice(b".bad");
        data[sec_off + 16] = 0x00;
        data[sec_off + 17] = 0x01;
        data[sec_off + 20] = 0x00;
        data[sec_off + 21] = 0x02;
        // RWX characteristics: READ | WRITE | EXECUTE
        data[sec_off + 36] = 0x20;
        data[sec_off + 37] = 0x00;
        data[sec_off + 38] = 0x00;
        data[sec_off + 39] = 0xE0;

        let pe = PeFile::parse(&data).unwrap();
        assert!(pe
            .warnings
            .iter()
            .any(|w| w.kind == WarningKind::RwxSection));
    }

    #[test]
    fn test_zero_sections_warning() {
        let mut data = vec![0u8; 512];
        data[0] = 0x4D;
        data[1] = 0x5A;
        data[60] = 0x80;
        data[0x80] = 0x50;
        data[0x81] = 0x45;
        data[0x82] = 0;
        data[0x83] = 0;
        data[0x84] = 0x4C;
        data[0x85] = 0x01;
        data[0x86] = 0;
        data[0x87] = 0; // 0 sections
        data[0x98] = 0x0B;
        data[0x99] = 0x01;
        data[0xF4] = 0;

        let pe = PeFile::parse(&data).unwrap();
        assert!(pe
            .warnings
            .iter()
            .any(|w| w.kind == WarningKind::ZeroSections));
    }

    #[test]
    fn test_rva_to_offset() {
        let mut data = vec![0u8; 1024];
        data[0] = 0x4D;
        data[1] = 0x5A;
        data[60] = 0x80;
        data[0x80] = 0x50;
        data[0x81] = 0x45;
        data[0x82] = 0;
        data[0x83] = 0;
        data[0x84] = 0x4C;
        data[0x85] = 0x01;
        data[0x86] = 1;
        data[0x87] = 0;
        data[0x98] = 0x0B;
        data[0x99] = 0x01;
        data[0xF4] = 0;
        let sec_off = 0xF8;
        data[sec_off..sec_off + 5].copy_from_slice(b".text");
        data[sec_off + 8] = 0x00;
        data[sec_off + 9] = 0x10;
        data[sec_off + 12] = 0x00;
        data[sec_off + 13] = 0x10; // VA = 0x1000
        data[sec_off + 16] = 0x00;
        data[sec_off + 17] = 0x02;
        data[sec_off + 20] = 0x00;
        data[sec_off + 21] = 0x02; // Raw offset = 0x200
        data[sec_off + 36] = 0x20;
        data[sec_off + 39] = 0x60;

        let pe = PeFile::parse(&data).unwrap();
        // RVA 0x1000 should map to file offset 0x200
        assert_eq!(pe.rva_to_offset(0x1000), Some(0x200));
        // RVA 0x1010 should map to file offset 0x210
        assert_eq!(pe.rva_to_offset(0x1010), Some(0x210));
        // RVA outside sections
        assert_eq!(pe.rva_to_offset(0x5000), None);
    }

    #[test]
    fn test_rva_to_offset_skips_overflowing_section() {
        let mut data = vec![0u8; 1024];
        data[0] = 0x4D;
        data[1] = 0x5A;
        data[60] = 0x80;
        data[0x80..0x84].copy_from_slice(&PE_SIG.to_le_bytes());
        data[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes());
        data[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
        data[0x98..0x9A].copy_from_slice(&OPT_MAGIC_PE32.to_le_bytes());
        data[0xF4..0xF8].copy_from_slice(&0u32.to_le_bytes());

        // Section 0: virtual_address + size overflows u32 — malformed.
        let bad = 0xF8usize;
        data[bad..bad + 4].copy_from_slice(b".bad");
        data[bad + 12..bad + 16].copy_from_slice(&0xFFFFFFF8u32.to_le_bytes());
        data[bad + 16..bad + 20].copy_from_slice(&0x20u32.to_le_bytes());

        // Section 1: valid .text
        let good = 0xF8 + 40;
        data[good..good + 5].copy_from_slice(b".text");
        data[good + 8..good + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        data[good + 12..good + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        data[good + 16..good + 20].copy_from_slice(&0x200u32.to_le_bytes());
        data[good + 20..good + 24].copy_from_slice(&0x200u32.to_le_bytes());
        data[good + 36..good + 40].copy_from_slice(&0x60000020u32.to_le_bytes());

        let pe = PeFile::parse(&data).unwrap();
        // The malformed section must be skipped, not abort RVA translation.
        assert_eq!(pe.rva_to_offset(0x1010), Some(0x210));
    }

    #[test]
    fn test_rva_to_offset_virtual_tail_not_mapped() {
        let mut data = vec![0u8; 1024];
        data[0] = 0x4D;
        data[1] = 0x5A;
        data[60] = 0x80;
        data[0x80..0x84].copy_from_slice(&PE_SIG.to_le_bytes());
        data[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes());
        data[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        data[0x98..0x9A].copy_from_slice(&OPT_MAGIC_PE32.to_le_bytes());
        data[0xF4..0xF8].copy_from_slice(&0u32.to_le_bytes());
        let sec_off = 0xF8;
        data[sec_off..sec_off + 5].copy_from_slice(b".text");
        // VirtualSize 0x1000 but only 0x200 bytes file-backed.
        data[sec_off + 8..sec_off + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        data[sec_off + 12..sec_off + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        data[sec_off + 16..sec_off + 20].copy_from_slice(&0x200u32.to_le_bytes());
        data[sec_off + 20..sec_off + 24].copy_from_slice(&0x200u32.to_le_bytes());
        data[sec_off + 36..sec_off + 40].copy_from_slice(&0x60000020u32.to_le_bytes());

        let pe = PeFile::parse(&data).unwrap();
        // File-backed part resolves normally...
        assert_eq!(pe.rva_to_offset(0x1080), Some(0x280));
        // ...but RVAs in the virtual tail must not map onto unrelated bytes.
        assert_eq!(pe.rva_to_offset(0x1300), None);
    }

    #[test]
    fn test_read_cstring_at_huge_max_len() {
        let mut data = build_pe32_with_dirs(16);
        data[0x600..0x606].copy_from_slice(b"hello\0");
        let pe = PeFile::parse(&data).unwrap();
        // offset + max_len must not overflow; result is bounded by file size.
        assert_eq!(
            pe.read_cstring_at(0x600, usize::MAX),
            Some("hello".to_string())
        );
        assert_eq!(pe.read_cstring_at(0x600, 4), Some("hell".to_string()));
        assert_eq!(pe.read_cstring_at(0x4000, 16), None);
    }

    #[test]
    fn test_section_header_parse_offset_overflow() {
        let data = [0u8; 64];
        let res = SectionHeader::parse(&data, usize::MAX - 10);
        assert!(matches!(res, Err(PeError::TooSmallForSections { .. })));
    }

    #[test]
    fn test_lfanew_out_of_bounds() {
        let mut data = vec![0u8; 64];
        data[0] = 0x4D;
        data[1] = 0x5A;
        data[60] = 0xFF;
        data[61] = 0xFF; // e_lfanew = 0xFFFF, way beyond file
        let err = PeFile::parse(&data).unwrap_err();
        assert!(matches!(err, PeError::LfanewOutOfBounds(..)));
    }

    #[test]
    fn test_bad_pe_signature() {
        let mut data = vec![0u8; 256];
        data[0] = 0x4D;
        data[1] = 0x5A;
        data[60] = 0x80;
        data[0x80] = 0x00;
        data[0x81] = 0x00;
        data[0x82] = 0x00;
        data[0x83] = 0x00; // Bad PE sig
        let err = PeFile::parse(&data).unwrap_err();
        assert!(matches!(err, PeError::BadPeSig(_)));
    }

    #[test]
    fn test_delay_imports_legacy_and_rva() {
        let mut data = vec![0u8; 2048];
        data[0] = 0x4D;
        data[1] = 0x5A;
        data[60] = 0x80;
        data[0x80] = 0x50;
        data[0x81] = 0x45;
        data[0x82] = 0;
        data[0x83] = 0;
        data[0x84] = 0x4C;
        data[0x85] = 0x01;
        data[0x86] = 1;
        data[0x87] = 0;
        data[0x98] = 0x0B;
        data[0x99] = 0x01;
        // Image base 0x400000 (PE32 optional header +28)
        let ib: u32 = 0x400000;
        data[0xB4..0xB8].copy_from_slice(&ib.to_le_bytes());
        // 16 data directories
        data[0xF4..0xF8].copy_from_slice(&16u32.to_le_bytes());
        let sec_off = 0xF8 + 16 * 8;
        data[sec_off..sec_off + 6].copy_from_slice(b".rdata");
        data[sec_off + 8..sec_off + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        data[sec_off + 12..sec_off + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        data[sec_off + 16..sec_off + 20].copy_from_slice(&0x600u32.to_le_bytes());
        data[sec_off + 20..sec_off + 24].copy_from_slice(&0x600u32.to_le_bytes());
        data[sec_off + 36..sec_off + 40].copy_from_slice(&0x40000040u32.to_le_bytes());

        let dd_delay_off = 0xF8 + 13 * 8;
        data[dd_delay_off..dd_delay_off + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        data[dd_delay_off + 4..dd_delay_off + 8].copy_from_slice(&0x40u32.to_le_bytes());

        // Delay descriptors at RVA 0x1000 (file offset 0x600)
        let desc = 0x600usize;
        // Legacy descriptor: grAttrs = 0, fields hold VAs
        data[desc..desc + 4].copy_from_slice(&0u32.to_le_bytes());
        data[desc + 4..desc + 8].copy_from_slice(&(ib + 0x1100).to_le_bytes());
        data[desc + 8..desc + 12].copy_from_slice(&(ib + 0x1200).to_le_bytes());
        // RVA-mode descriptor: grAttrs bit0 set, fields are RVAs
        data[desc + 32..desc + 36].copy_from_slice(&1u32.to_le_bytes());
        data[desc + 36..desc + 40].copy_from_slice(&0x1140u32.to_le_bytes());
        data[desc + 40..desc + 44].copy_from_slice(&0x1240u32.to_le_bytes());

        let mut put_str = |off: usize, s: &[u8]| {
            data[off..off + s.len()].copy_from_slice(s);
        };
        put_str(0x700, b"LEGACY.DLL\0");
        put_str(0x740, b"MODERN.DLL\0");

        let pe = PeFile::parse(&data).unwrap();
        let dlls = pe.delay_imports();
        assert_eq!(
            dlls,
            vec!["LEGACY.DLL".to_string(), "MODERN.DLL".to_string()]
        );
    }

    #[test]
    fn test_directory_bytes_rejects_out_of_file_and_overflow_ranges() {
        let mut data = build_pe32_with_dirs(16);
        let sec_off = 0xF8 + 16 * 8;
        data[sec_off..sec_off + 5].copy_from_slice(b".data");
        data[sec_off + 8..sec_off + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        data[sec_off + 12..sec_off + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        data[sec_off + 16..sec_off + 20].copy_from_slice(&0x200u32.to_le_bytes());
        data[sec_off + 20..sec_off + 24].copy_from_slice(&0x600u32.to_le_bytes());

        let export_dd = 0xF8 + IMAGE_DIRECTORY_ENTRY_EXPORT * 8;
        data[export_dd..export_dd + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        data[export_dd + 4..export_dd + 8].copy_from_slice(&0x20u32.to_le_bytes());
        let import_dd = 0xF8 + IMAGE_DIRECTORY_ENTRY_IMPORT * 8;
        data[import_dd..import_dd + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        data[import_dd + 4..import_dd + 8].copy_from_slice(&0x300u32.to_le_bytes());
        let resource_dd = 0xF8 + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8;
        data[resource_dd..resource_dd + 4].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        data[resource_dd + 4..resource_dd + 8].copy_from_slice(&0x40u32.to_le_bytes());

        let pe = PeFile::parse(&data).unwrap();
        assert_eq!(
            pe.directory_bytes(IMAGE_DIRECTORY_ENTRY_EXPORT)
                .unwrap()
                .len(),
            0x20
        );
        assert!(pe.directory_bytes(IMAGE_DIRECTORY_ENTRY_IMPORT).is_none());
        assert!(pe.directory_bytes(IMAGE_DIRECTORY_ENTRY_RESOURCE).is_none());
        assert!(
            pe.warnings
                .iter()
                .filter(|w| w.kind == WarningKind::MalformedDirectoryRange)
                .count()
                >= 2
        );
    }

    #[test]
    fn test_exports_reject_malformed_directory_payload_safely() {
        let mut data = build_pe32_with_dirs(16);
        let sec_off = 0xF8 + 16 * 8;
        data[sec_off..sec_off + 6].copy_from_slice(b".edata");
        data[sec_off + 8..sec_off + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        data[sec_off + 12..sec_off + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        data[sec_off + 16..sec_off + 20].copy_from_slice(&0x200u32.to_le_bytes());
        data[sec_off + 20..sec_off + 24].copy_from_slice(&0x600u32.to_le_bytes());
        let dd = 0xF8 + IMAGE_DIRECTORY_ENTRY_EXPORT * 8;
        data[dd..dd + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        data[dd + 4..dd + 8].copy_from_slice(&40u32.to_le_bytes());
        let export = 0x600;
        data[export + 20..export + 24].copy_from_slice(&u32::MAX.to_le_bytes());
        data[export + 24..export + 28].copy_from_slice(&u32::MAX.to_le_bytes());
        data[export + 28..export + 40].copy_from_slice(&[0xFF; 12]);

        let pe = PeFile::parse(&data).unwrap();
        assert_eq!(pe.exports(), (None, Vec::new()));
    }

    #[test]
    fn test_runtime_functions_reject_malformed_entries_safely() {
        let mut data = build_pe32_with_dirs(16);
        data[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        let sec_off = 0xF8 + 16 * 8;
        data[sec_off..sec_off + 6].copy_from_slice(b".pdata");
        data[sec_off + 8..sec_off + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        data[sec_off + 12..sec_off + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        data[sec_off + 16..sec_off + 20].copy_from_slice(&0x200u32.to_le_bytes());
        data[sec_off + 20..sec_off + 24].copy_from_slice(&0x600u32.to_le_bytes());
        let dd = 0xF8 + IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8;
        data[dd..dd + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        data[dd + 4..dd + 8].copy_from_slice(&12u32.to_le_bytes());
        data[0x600..0x604].copy_from_slice(&0x20u32.to_le_bytes());
        data[0x604..0x608].copy_from_slice(&0x10u32.to_le_bytes());
        data[0x608..0x60C].copy_from_slice(&0x1001u32.to_le_bytes());

        let pe = PeFile::parse(&data).unwrap();
        assert!(pe.runtime_functions().is_empty());
    }

    fn build_pe32_with_dirs(num_dirs: u16) -> Vec<u8> {
        let mut data = vec![0u8; 2048];
        data[0] = 0x4D;
        data[1] = 0x5A;
        data[60] = 0x80;
        data[0x80..0x84].copy_from_slice(&PE_SIG.to_le_bytes());
        data[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes());
        data[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        data[0x98..0x9A].copy_from_slice(&OPT_MAGIC_PE32.to_le_bytes());
        data[0xF4..0xF8].copy_from_slice(&(num_dirs as u32).to_le_bytes());
        data
    }

    fn build_reloc_test_pe(entries: &[u16]) -> Vec<u8> {
        let mut data = build_pe32_with_dirs(16);
        let sec_off = 0xF8 + 16 * 8;
        data[sec_off..sec_off + 6].copy_from_slice(b".reloc");
        data[sec_off + 8..sec_off + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        data[sec_off + 12..sec_off + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        data[sec_off + 16..sec_off + 20].copy_from_slice(&0x200u32.to_le_bytes());
        data[sec_off + 20..sec_off + 24].copy_from_slice(&0x600u32.to_le_bytes());
        data[sec_off + 36..sec_off + 40].copy_from_slice(&0x42000040u32.to_le_bytes());

        let block_size = (8 + entries.len() * 2) as u32;
        let dd_reloc = 0xF8 + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8;
        data[dd_reloc..dd_reloc + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        data[dd_reloc + 4..dd_reloc + 8].copy_from_slice(&block_size.to_le_bytes());

        let block = 0x600usize;
        data[block..block + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        data[block + 4..block + 8].copy_from_slice(&block_size.to_le_bytes());
        for (i, e) in entries.iter().enumerate() {
            let off = block + 8 + i * 2;
            data[off..off + 2].copy_from_slice(&e.to_le_bytes());
        }
        data
    }

    #[test]
    fn test_base_relocations_parse() {
        let entries = [0x3123u16, 0xA456, 0x0000];
        let data = build_reloc_test_pe(&entries);
        let pe = PeFile::parse(&data).unwrap();
        let relocs = pe.base_relocations().unwrap();
        assert_eq!(relocs.len(), 2);
        assert_eq!(
            relocs[0],
            BaseRelocation {
                rva: 0x1123,
                typ: 3
            }
        );
        assert_eq!(
            relocs[1],
            BaseRelocation {
                rva: 0x1456,
                typ: 10
            }
        );
        assert_eq!(pe.relocation_count(), 2);
        assert_eq!(RelocType::from_raw(3), Some(RelocType::HighLow));
        assert_eq!(RelocType::from_raw(10), Some(RelocType::Dir64));
        assert_eq!(RelocType::from_raw(11), None);
    }

    #[test]
    fn test_has_valid_relocs() {
        let good = build_reloc_test_pe(&[0x3004, 0x3010]);
        let pe_good = PeFile::parse(&good).unwrap();
        assert!(pe_good.has_valid_relocs());

        let mixed = build_reloc_test_pe(&[0x3004, 0xA010]);
        let pe_mixed = PeFile::parse(&mixed).unwrap();
        assert!(!pe_mixed.has_valid_relocs());

        let empty = build_pe32_with_dirs(16);
        let pe_empty = PeFile::parse(&empty).unwrap();
        assert!(!pe_empty.has_valid_relocs());
        assert_eq!(pe_empty.relocation_count(), 0);
    }

    #[test]
    fn test_unwind_info_parser_rejects_unaligned_and_truncated() {
        let mut data = build_pe32_with_dirs(16);
        data.resize(4096, 0);
        // The synthetic layout is PE32-sized, but the exception directory
        // parser is selected by the machine type. This is sufficient for the
        // metadata fixture and keeps the test focused on UNWIND_INFO bounds.
        data[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        data[0x98..0x9A].copy_from_slice(&OPT_MAGIC_PE32PLUS.to_le_bytes());
        data[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
        data[0x104..0x108].copy_from_slice(&16u32.to_le_bytes());
        let sec_off = 0x98 + 240;
        data[sec_off..sec_off + 6].copy_from_slice(b".pdata");
        data[sec_off + 8..sec_off + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        data[sec_off + 12..sec_off + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        data[sec_off + 16..sec_off + 20].copy_from_slice(&0x200u32.to_le_bytes());
        data[sec_off + 20..sec_off + 24].copy_from_slice(&0x600u32.to_le_bytes());
        data[sec_off + 36..sec_off + 40].copy_from_slice(&0x40000040u32.to_le_bytes());
        let dd = 0x108 + IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8;
        data[dd..dd + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        data[dd + 4..dd + 8].copy_from_slice(&12u32.to_le_bytes());
        data[0x600..0x604].copy_from_slice(&0x1100u32.to_le_bytes());
        data[0x604..0x608].copy_from_slice(&0x1120u32.to_le_bytes());
        data[0x608..0x60C].copy_from_slice(&0x1100u32.to_le_bytes());
        // Version 1, one UWOP_ALLOC_SMALL code, no chain.
        data[0x700] = 1;
        data[0x701] = 5;
        data[0x702] = 1;
        data[0x703] = 0;
        data[0x704] = 0x20;
        data[0x705] = 0x22;
        let pe = PeFile::parse(&data).unwrap();
        let runtime = pe.runtime_functions();
        assert_eq!(
            runtime.len(),
            1,
            "sections={:?}, dirs={:?}",
            pe.sections,
            pe.data_directories
        );
        let rf = runtime[0];
        let info = pe
            .unwind_info(&rf)
            .unwrap_or_else(|| panic!("rf={rf:?}, byte={:?}", &pe.data[0x700..0x706]));
        assert_eq!(info.prologue_size, 5);
        assert_eq!(info.code_count, 1);
        assert_eq!(
            info.codes,
            vec![UnwindOp::AllocSmall {
                size: 24,
                code_offset: 0x20
            }]
        );
        assert!(pe
            .unwind_info(&RuntimeFunction {
                unwind_info_rva: 0x1001,
                ..rf
            })
            .is_none());
        assert!(pe
            .unwind_info(&RuntimeFunction {
                unwind_info_rva: 0x1300,
                ..rf
            })
            .is_none());
    }

    #[test]
    fn test_dotnet_info() {
        let mut data = build_pe32_with_dirs(16);
        let sec_off = 0xF8 + 16 * 8;
        data[sec_off..sec_off + 5].copy_from_slice(b".text");
        data[sec_off + 8..sec_off + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        data[sec_off + 12..sec_off + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        data[sec_off + 16..sec_off + 20].copy_from_slice(&0x400u32.to_le_bytes());
        data[sec_off + 20..sec_off + 24].copy_from_slice(&0x400u32.to_le_bytes());
        data[sec_off + 36..sec_off + 40].copy_from_slice(&0x60000020u32.to_le_bytes());

        let dd_com = 0xF8 + IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR * 8;
        data[dd_com..dd_com + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        data[dd_com + 4..dd_com + 8].copy_from_slice(&0x48u32.to_le_bytes());

        let cor = 0x400usize;
        data[cor..cor + 4].copy_from_slice(&0x48u32.to_le_bytes());
        data[cor + 4..cor + 6].copy_from_slice(&2u16.to_le_bytes());
        data[cor + 6..cor + 8].copy_from_slice(&5u16.to_le_bytes());
        data[cor + 8..cor + 12].copy_from_slice(&0x1100u32.to_le_bytes());
        data[cor + 12..cor + 16].copy_from_slice(&0x200u32.to_le_bytes());
        data[cor + 16..cor + 20].copy_from_slice(&1u32.to_le_bytes());
        data[cor + 20..cor + 24].copy_from_slice(&0x06000001u32.to_le_bytes());

        let meta = 0x500usize;
        data[meta..meta + 4].copy_from_slice(b"BSJB");
        data[meta + 4..meta + 6].copy_from_slice(&1u16.to_le_bytes());
        data[meta + 6..meta + 8].copy_from_slice(&1u16.to_le_bytes());
        data[meta + 8..meta + 12].copy_from_slice(&0u32.to_le_bytes());
        data[meta + 12..meta + 16].copy_from_slice(&12u32.to_le_bytes());
        data[meta + 16..meta + 28].copy_from_slice(b"v4.0.30319\0\0");
        data[meta + 28..meta + 30].copy_from_slice(&0u16.to_le_bytes());
        data[meta + 30..meta + 32].copy_from_slice(&1u16.to_le_bytes());
        let sh = meta + 32;
        data[sh..sh + 4].copy_from_slice(&0x80u32.to_le_bytes());
        data[sh + 4..sh + 8].copy_from_slice(&0x40u32.to_le_bytes());
        data[sh + 8..sh + 12].copy_from_slice(b"#~\0\0");

        let tilde = meta + 0x80;
        data[tilde..tilde + 4].copy_from_slice(&0u32.to_le_bytes());
        data[tilde + 4] = 2;
        data[tilde + 7] = 1;
        data[tilde + 8..tilde + 16].copy_from_slice(&0x42u64.to_le_bytes());
        data[tilde + 16..tilde + 24].copy_from_slice(&0u64.to_le_bytes());
        data[tilde + 24..tilde + 28].copy_from_slice(&13u32.to_le_bytes());
        data[tilde + 28..tilde + 32].copy_from_slice(&42u32.to_le_bytes());

        let pe = PeFile::parse(&data).unwrap();
        let info = pe.dotnet_info().unwrap();
        assert!(info.is_dotnet);
        assert_eq!(info.runtime_version, "2.5");
        assert_eq!(info.metadata_version, "v4.0.30319");
        assert_eq!(info.streams.len(), 1);
        assert_eq!(info.streams[0], ("#~".to_string(), 0x80, 0x40));
        assert_eq!(info.table_rows, vec![(1u32, 13u32), (6, 42)]);

        let cor_h = pe.cor20_header().unwrap();
        assert_eq!(cor_h.cb, 0x48);
        assert_eq!(cor_h.entry_point_token, 0x06000001);
        assert_eq!(table_name(1), "TypeRef");
        assert_eq!(table_name(6), "MethodDef");
        assert_eq!(table_name(0x20), "Assembly");
        assert_eq!(table_name(0x23), "AssemblyRef");
        assert_eq!(table_name(0xFF), "Unknown");

        let plain = build_pe32_with_dirs(15);
        let pe_plain = PeFile::parse(&plain).unwrap();
        assert!(pe_plain.dotnet_info().is_none());
    }
}
