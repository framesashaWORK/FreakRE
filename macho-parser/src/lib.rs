#![allow(dead_code, unused_assignments)]
//! Zero-copy Mach-O parser for macOS malware analysis.
//!
//! Supports both 32-bit (MH_MAGIC = 0xFEEDFACE) and 64-bit (MH_MAGIC_64 = 0xFEEDFACF)
//! formats, as well as Fat/Universal binaries (FAT_MAGIC = 0xCAFEBABE).
//!
//! Use [`parse_any`] for automatic detection of thin vs Fat/Universal binaries:
//! it returns [`MachoObject::Thin`] with a parsed [`MachoFile`], or
//! [`MachoObject::Fat`] with the architecture table from [`parse_fat_header`].

use std::fmt;
use thiserror::Error;

// ─── Magic Constants ──────────────────────────────────────────────────

const MH_MAGIC: u32 = 0xFEEDFACE;
const MH_MAGIC_64: u32 = 0xFEEDFACF;
const MH_CIGAM: u32 = 0xCEFAEDFE;
const MH_CIGAM_64: u32 = 0xCFFAEDFE;
const FAT_MAGIC: u32 = 0xCAFEBABE;
const FAT_CIGAM: u32 = 0xBEBAFECA;
const FAT_MAGIC_64: u32 = 0xCAFEBABF;
const FAT_CIGAM_64: u32 = 0xBFBABAFE;

// ─── Mach-O File Types ────────────────────────────────────────────────

const MH_OBJECT: u32 = 0x1;
const MH_EXECUTE: u32 = 0x2;
const MH_FVMLIB: u32 = 0x3;
const MH_CORE: u32 = 0x4;
const MH_PRELOAD: u32 = 0x5;
const MH_DYLIB: u32 = 0x6;
const MH_DYLINKER: u32 = 0x7;
const MH_BUNDLE: u32 = 0x8;
const MH_DYLIB_STUB: u32 = 0x9;
const MH_DSYM: u32 = 0xA;
const MH_KEXT_BUNDLE: u32 = 0xB;

// ─── CPU Types ────────────────────────────────────────────────────────

const CPU_TYPE_X86: u32 = 7;
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const CPU_TYPE_ARM: u32 = 12;
const CPU_TYPE_ARM64: u32 = 0x0100_000C;
const CPU_TYPE_POWERPC: u32 = 18;
const CPU_TYPE_POWERPC64: u32 = 0x0100_0012;

// ─── Load Commands ───────────────────────────────────────────────────

const LC_SEGMENT: u32 = 0x1;
const LC_SYMTAB: u32 = 0x2;
const LC_DYSYMTAB: u32 = 0xB;
const LC_LOAD_DYLIB: u32 = 0xC;
const LC_ID_DYLIB: u32 = 0xD;
const LC_LOAD_DYLINKER: u32 = 0xE;
const LC_ID_DYLINKER: u32 = 0xF;
const LC_UUID: u32 = 0x1B;
const LC_CODE_SIGNATURE: u32 = 0x1D;
const LC_SEGMENT_64: u32 = 0x19;
const LC_MAIN: u32 = 0x8000_0028;
const LC_ENCRYPTION_INFO: u32 = 0x21;
const LC_ENCRYPTION_INFO_64: u32 = 0x2C;
const LC_RPATH: u32 = 0x8000_001C;
const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
const LC_REEXPORT_DYLIB: u32 = 0x8000_001F;
const LC_FUNCTION_STARTS: u32 = 0x26;
const LC_DYLD_INFO: u32 = 0x22;
const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
const LC_SOURCE_VERSION: u32 = 0x2A;

// ─── Section Flags ───────────────────────────────────────────────────

const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;

// ─── VM Protection ───────────────────────────────────────────────────

const VM_PROT_READ: u32 = 0x01;
const VM_PROT_WRITE: u32 = 0x02;
const VM_PROT_EXECUTE: u32 = 0x04;

// ─── Limits ──────────────────────────────────────────────────────────

/// Cap on emitted overlapping-segment warnings: the pair scan is O(n²) and
/// hostile inputs with thousands of segments would otherwise allocate
/// unboundedly.
const MAX_OVERLAP_WARNINGS: usize = 32;

// ─── Errors ──────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum MachoError {
    #[error("file too small for Mach-O header ({0} bytes)")]
    TooSmall(usize),
    #[error("invalid Mach-O magic: 0x{0:08X}")]
    BadMagic(u32),
    #[error("unsupported CPU type: 0x{0:08X}")]
    UnsupportedCpu(u32),
    #[error("load command {0} extends beyond file (offset {1}, size {2}, file {3})")]
    LoadCommandOutOfBounds(usize, usize, usize, usize),
    #[error("load command string at offset {0} not null-terminated within {1} bytes")]
    UnterminatedString(usize, usize),
    #[error("fat binary has {0} architectures (max 64)")]
    TooManyArchitectures(u32),
}

// ─── Warning Types ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WarningKind {
    RwxSection,
    NoCodeSignature,
    EncryptedBinary,
    StaticallyLinked,
    StrippedBinary,
    PieDisabled,
    RestrictOption,
    LazyBinding,
    OverlappingSegments,
    EntitlementsAnomaly,
    UnusualLoadCommand,
    Other,
}

#[derive(Debug, Clone)]
pub struct MachoWarning {
    pub kind: WarningKind,
    pub message: String,
}

// ─── CPU Type ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuType {
    X86,
    X86_64,
    Arm,
    Arm64,
    PowerPc,
    PowerPc64,
    Unknown(u32),
}

impl CpuType {
    pub fn from_raw(val: u32) -> Self {
        match val {
            CPU_TYPE_X86 => CpuType::X86,
            CPU_TYPE_X86_64 => CpuType::X86_64,
            CPU_TYPE_ARM => CpuType::Arm,
            CPU_TYPE_ARM64 => CpuType::Arm64,
            CPU_TYPE_POWERPC => CpuType::PowerPc,
            CPU_TYPE_POWERPC64 => CpuType::PowerPc64,
            other => CpuType::Unknown(other),
        }
    }

    pub fn is_64bit(self) -> bool {
        matches!(self, CpuType::X86_64 | CpuType::Arm64 | CpuType::PowerPc64)
    }
}

impl fmt::Display for CpuType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CpuType::X86 => write!(f, "x86"),
            CpuType::X86_64 => write!(f, "x86_64"),
            CpuType::Arm => write!(f, "ARM"),
            CpuType::Arm64 => write!(f, "ARM64"),
            CpuType::PowerPc => write!(f, "PowerPC"),
            CpuType::PowerPc64 => write!(f, "PowerPC64"),
            CpuType::Unknown(v) => write!(f, "Unknown(0x{:08X})", v),
        }
    }
}

// ─── File Type ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Object,
    Execute,
    FvmLib,
    Core,
    Preload,
    Dylib,
    Dylinker,
    Bundle,
    DylibStub,
    Dsym,
    KextBundle,
    Unknown(u32),
}

impl FileType {
    pub fn from_raw(val: u32) -> Self {
        match val {
            MH_OBJECT => FileType::Object,
            MH_EXECUTE => FileType::Execute,
            MH_FVMLIB => FileType::FvmLib,
            MH_CORE => FileType::Core,
            MH_PRELOAD => FileType::Preload,
            MH_DYLIB => FileType::Dylib,
            MH_DYLINKER => FileType::Dylinker,
            MH_BUNDLE => FileType::Bundle,
            MH_DYLIB_STUB => FileType::DylibStub,
            MH_DSYM => FileType::Dsym,
            MH_KEXT_BUNDLE => FileType::KextBundle,
            other => FileType::Unknown(other),
        }
    }
}

impl fmt::Display for FileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileType::Object => write!(f, "Object"),
            FileType::Execute => write!(f, "Executable"),
            FileType::FvmLib => write!(f, "FVM Library"),
            FileType::Core => write!(f, "Core Dump"),
            FileType::Preload => write!(f, "Preload"),
            FileType::Dylib => write!(f, "Dynamic Library"),
            FileType::Dylinker => write!(f, "Dynamic Linker"),
            FileType::Bundle => write!(f, "Bundle"),
            FileType::DylibStub => write!(f, "Dylib Stub"),
            FileType::Dsym => write!(f, "Debug Symbols"),
            FileType::KextBundle => write!(f, "Kernel Extension"),
            FileType::Unknown(v) => write!(f, "Unknown(0x{:X})", v),
        }
    }
}

// ─── Header Flags ────────────────────────────────────────────────────

const MH_NOUNDEFS: u32 = 0x1;
const MH_DYLDLINK: u32 = 0x4;
const MH_PIE: u32 = 0x200_000;
const MH_RESTRICT: u32 = 0x80_000;
const MH_NO_HEAP_EXECUTION: u32 = 0x0100_0000;

// ─── Load Command Types ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum LoadCommand {
    Segment(Segment),
    Segment64(Segment),
    LoadDylib(DylibRef),
    LazyLoadDylib(DylibRef),
    ReexportDylib(DylibRef),
    IdDylib(DylibRef),
    LoadDylinker(String),
    IdDylinker(String),
    Uuid([u8; 16]),
    Main {
        entry_off: u64,
        stack_size: u64,
    },
    Symtab {
        symoff: u32,
        nsyms: u32,
        stroff: u32,
        strsize: u32,
    },
    EncryptionInfo {
        cryptoff: u32,
        cryptsize: u32,
        cryptid: u32,
    },
    CodeSignature {
        dataoff: u32,
        datasize: u32,
    },
    Rpath(String),
    SourceVersion(u64),
    FunctionStarts {
        dataoff: u32,
        datasize: u32,
    },
    DyldInfo {
        rebase_off: u32,
        rebase_size: u32,
        bind_off: u32,
        bind_size: u32,
        weak_bind_off: u32,
        weak_bind_size: u32,
        lazy_bind_off: u32,
        lazy_bind_size: u32,
        export_off: u32,
        export_size: u32,
    },
    Unknown {
        cmd: u32,
        cmdsize: u32,
    },
}

// ─── Segment ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Segment {
    pub name: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: u32,
    pub initprot: u32,
    pub sections: Vec<Section>,
    pub is_64bit: bool,
}

impl Segment {
    pub fn is_rwx(&self) -> bool {
        let prot = self.initprot;
        (prot & VM_PROT_READ != 0) && (prot & VM_PROT_WRITE != 0) && (prot & VM_PROT_EXECUTE != 0)
    }

    pub fn is_executable(&self) -> bool {
        self.initprot & VM_PROT_EXECUTE != 0
    }

    pub fn is_writable(&self) -> bool {
        self.initprot & VM_PROT_WRITE != 0
    }
}

// ─── Section ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub segment_name: String,
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub flags: u32,
}

impl Section {
    pub fn is_code(&self) -> bool {
        self.flags & S_ATTR_PURE_INSTRUCTIONS != 0
    }

    pub fn has_instructions(&self) -> bool {
        self.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0
    }

    /// Get the raw data slice for this section from the full file buffer.
    pub fn raw_data<'a>(&self, file_data: &'a [u8]) -> &'a [u8] {
        let start = self.offset as usize;
        let end = match start.checked_add(self.size as usize) {
            Some(e) => e,
            None => return &[],
        };
        if end <= file_data.len() {
            &file_data[start..end]
        } else if start < file_data.len() {
            &file_data[start..]
        } else {
            &[]
        }
    }
}

// ─── Dylib Reference ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DylibRef {
    pub name: String,
    pub timestamp: u32,
    pub current_version: u32,
    pub compatibility_version: u32,
}

// ─── Main Mach-O File ────────────────────────────────────────────────

#[derive(Debug)]
pub struct MachoFile<'a> {
    pub data: &'a [u8],
    pub cpu_type: CpuType,
    pub cpu_subtype: u32,
    pub file_type: FileType,
    pub flags: u32,
    pub is_64bit: bool,
    pub is_swapped: bool,
    pub load_commands: Vec<LoadCommand>,
    pub warnings: Vec<MachoWarning>,
}

impl<'a> MachoFile<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, MachoError> {
        if data.len() < 28 {
            return Err(MachoError::TooSmall(data.len()));
        }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        let (is_64bit, is_swapped) = match magic {
            MH_MAGIC => (false, false),
            MH_MAGIC_64 => (true, false),
            MH_CIGAM => (false, true),
            MH_CIGAM_64 => (true, true),
            other => return Err(MachoError::BadMagic(other)),
        };

        let header_size = if is_64bit { 32 } else { 28 };
        if data.len() < header_size {
            return Err(MachoError::TooSmall(data.len()));
        }

        // Parse header fields with byte order handling
        let read_u32 = |off: usize| -> u32 {
            let bytes = [data[off], data[off + 1], data[off + 2], data[off + 3]];
            if is_swapped {
                u32::from_be_bytes(bytes)
            } else {
                u32::from_le_bytes(bytes)
            }
        };

        let cpu_type_raw = read_u32(4);
        let cpu_subtype = read_u32(8);
        let file_type_raw = read_u32(12);
        let ncmds = read_u32(16);
        let sizeofcmds = read_u32(20) as usize;
        let flags = read_u32(24);

        // Validate sizeofcmds fits within the remaining data
        if header_size + sizeofcmds > data.len() {
            return Err(MachoError::LoadCommandOutOfBounds(
                header_size,
                sizeofcmds,
                data.len(),
                data.len(),
            ));
        }

        let cpu_type = CpuType::from_raw(cpu_type_raw);
        let file_type = FileType::from_raw(file_type_raw);

        // Parse load commands
        let mut load_commands = Vec::with_capacity(ncmds.min(10_000) as usize);
        let mut warnings = Vec::new();
        let mut offset = header_size;

        for i in 0..ncmds as usize {
            if offset + 8 > data.len() {
                break;
            }

            let cmd = read_u32_at(data, offset, is_swapped);
            let cmdsize = read_u32_at(data, offset + 4, is_swapped) as usize;

            if cmdsize < 8 || offset + cmdsize > data.len() {
                warnings.push(MachoWarning {
                    kind: WarningKind::Other,
                    message: format!(
                        "Load command #{} at offset 0x{:X} has invalid size {}, skipping",
                        i, offset, cmdsize
                    ),
                });
                offset += 8;
                continue;
            }

            let lc = parse_load_command(data, offset, cmd, cmdsize, is_64bit, is_swapped);
            load_commands.push(lc);
            offset += cmdsize;
        }

        // ─── Generate warnings ──────────────────────────────────

        // PIE check
        if file_type == FileType::Execute && flags & MH_PIE == 0 {
            warnings.push(MachoWarning {
                kind: WarningKind::PieDisabled,
                message: "PIE (Address Space Layout Randomization) is disabled".into(),
            });
        }

        // RESTRICT flag
        if flags & MH_RESTRICT != 0 {
            warnings.push(MachoWarning {
                kind: WarningKind::RestrictOption,
                message: "MH_RESTRICT flag set — restricts dlopen() to trusted code".into(),
            });
        }

        // Check for code signature
        let has_code_sig = load_commands
            .iter()
            .any(|lc| matches!(lc, LoadCommand::CodeSignature { .. }));
        if file_type == FileType::Execute && !has_code_sig {
            warnings.push(MachoWarning {
                kind: WarningKind::NoCodeSignature,
                message: "No code signature found in executable".into(),
            });
        }

        // Check for encryption
        for lc in &load_commands {
            if let LoadCommand::EncryptionInfo { cryptid, .. } = lc {
                if *cryptid != 0 {
                    warnings.push(MachoWarning {
                        kind: WarningKind::EncryptedBinary,
                        message: format!("Binary is encrypted (cryptid={})", cryptid),
                    });
                }
            }
        }

        // Check for RWX segments
        for lc in &load_commands {
            match lc {
                LoadCommand::Segment(seg) | LoadCommand::Segment64(seg) if seg.is_rwx() => {
                    warnings.push(MachoWarning {
                        kind: WarningKind::RwxSection,
                        message: format!("RWX segment: {} (addr=0x{:X})", seg.name, seg.vmaddr),
                    });
                }
                _ => {}
            }
        }

        // Check for overlapping segments
        let segments: Vec<&Segment> = load_commands
            .iter()
            .filter_map(|lc| match lc {
                LoadCommand::Segment(s) | LoadCommand::Segment64(s) => Some(s),
                _ => None,
            })
            .collect();

        let mut overlap_warnings = 0usize;
        'overlap_scan: for i in 0..segments.len() {
            for j in (i + 1)..segments.len() {
                let a = segments[i];
                let b = segments[j];
                if a.filesize > 0
                    && b.filesize > 0
                    && a.fileoff < b.fileoff.saturating_add(b.filesize)
                    && b.fileoff < a.fileoff.saturating_add(a.filesize)
                {
                    if overlap_warnings >= MAX_OVERLAP_WARNINGS {
                        break 'overlap_scan;
                    }
                    overlap_warnings += 1;
                    warnings.push(MachoWarning {
                        kind: WarningKind::OverlappingSegments,
                        message: format!("Overlapping segments: {} <-> {}", a.name, b.name),
                    });
                }
            }
        }

        // Check if statically linked (no dylibs)
        let has_dylibs = load_commands
            .iter()
            .any(|lc| matches!(lc, LoadCommand::LoadDylib(_)));
        if file_type == FileType::Execute && !has_dylibs {
            warnings.push(MachoWarning {
                kind: WarningKind::StaticallyLinked,
                message: "Executable appears to be statically linked".into(),
            });
        }

        Ok(Self {
            data,
            cpu_type,
            cpu_subtype,
            file_type,
            flags,
            is_64bit,
            is_swapped,
            load_commands,
            warnings,
        })
    }

    /// Get all imported dylib names.
    pub fn imported_dylibs(&self) -> Vec<&str> {
        self.load_commands
            .iter()
            .filter_map(|lc| match lc {
                LoadCommand::LoadDylib(d) | LoadCommand::LazyLoadDylib(d) => Some(d.name.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Get all segments.
    pub fn segments(&self) -> Vec<&Segment> {
        self.load_commands
            .iter()
            .filter_map(|lc| match lc {
                LoadCommand::Segment(s) | LoadCommand::Segment64(s) => Some(s),
                _ => None,
            })
            .collect()
    }

    /// Get all sections across all segments.
    pub fn all_sections(&self) -> Vec<&Section> {
        self.segments()
            .iter()
            .flat_map(|seg| seg.sections.iter())
            .collect()
    }

    /// Get the __TEXT segment (if present).
    pub fn text_segment(&self) -> Option<&Segment> {
        self.segments().into_iter().find(|s| s.name == "__TEXT")
    }

    /// Get the __DATA segment (if present).
    pub fn data_segment(&self) -> Option<&Segment> {
        self.segments()
            .into_iter()
            .find(|s| s.name == "__DATA" || s.name == "__DATA_CONST")
    }

    /// Check if PIE (Position Independent Executable) is enabled.
    pub fn is_pie(&self) -> bool {
        self.flags & MH_PIE != 0
    }

    /// Check if the binary has the RESTRICT flag.
    pub fn is_restricted(&self) -> bool {
        self.flags & MH_RESTRICT != 0
    }

    /// Check if there are RWX segments.
    pub fn has_rwx_segments(&self) -> bool {
        self.segments().iter().any(|s| s.is_rwx())
    }

    /// Get the entry point offset (from LC_MAIN or LC_UNIXTHREAD).
    pub fn entry_point(&self) -> Option<u64> {
        for lc in &self.load_commands {
            if let LoadCommand::Main { entry_off, .. } = lc {
                return Some(*entry_off);
            }
        }
        None
    }

    /// Check if the binary is encrypted (FairPlay DRM).
    pub fn is_encrypted(&self) -> bool {
        self.load_commands
            .iter()
            .any(|lc| matches!(lc, LoadCommand::EncryptionInfo { cryptid, .. } if *cryptid != 0))
    }

    /// Check if the binary has a code signature.
    pub fn has_code_signature(&self) -> bool {
        self.load_commands
            .iter()
            .any(|lc| matches!(lc, LoadCommand::CodeSignature { .. }))
    }
}

// ─── Load Command Parsing ────────────────────────────────────────────

fn parse_load_command(
    data: &[u8],
    offset: usize,
    cmd: u32,
    cmdsize: usize,
    is_64bit: bool,
    is_swapped: bool,
) -> LoadCommand {
    let read_u32 = |off: usize| -> u32 {
        let bytes = [data[off], data[off + 1], data[off + 2], data[off + 3]];
        if is_swapped {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        }
    };
    let read_u64 = |off: usize| -> u64 {
        let bytes = [
            data[off],
            data[off + 1],
            data[off + 2],
            data[off + 3],
            data[off + 4],
            data[off + 5],
            data[off + 6],
            data[off + 7],
        ];
        if is_swapped {
            u64::from_be_bytes(bytes)
        } else {
            u64::from_le_bytes(bytes)
        }
    };

    match cmd {
        LC_SEGMENT | LC_SEGMENT_64 => {
            parse_segment(data, offset, cmd, cmdsize, is_64bit, is_swapped)
        }
        LC_LOAD_DYLIB | LC_LAZY_LOAD_DYLIB | LC_REEXPORT_DYLIB | LC_ID_DYLIB => {
            if offset + 20 <= data.len() {
                let name_offset = read_u32(offset + 8) as usize;
                let timestamp = read_u32(offset + 12);
                let current_version = read_u32(offset + 16);
                // LC_REEXPORT_DYLIB uses cmdsize 24, others use 20
                let compatibility_version = if offset + 24 <= data.len() {
                    read_u32(offset + 20)
                } else {
                    0
                };
                let name = match offset.checked_add(name_offset) {
                    Some(abs) => read_cstring(data, abs, cmdsize.saturating_sub(name_offset)),
                    None => String::new(),
                };
                let dylib = DylibRef {
                    name,
                    timestamp,
                    current_version,
                    compatibility_version,
                };
                match cmd {
                    LC_LOAD_DYLIB => LoadCommand::LoadDylib(dylib),
                    LC_LAZY_LOAD_DYLIB => LoadCommand::LazyLoadDylib(dylib),
                    LC_REEXPORT_DYLIB => LoadCommand::ReexportDylib(dylib),
                    LC_ID_DYLIB => LoadCommand::IdDylib(dylib),
                    _ => unreachable!(),
                }
            } else {
                LoadCommand::Unknown {
                    cmd,
                    cmdsize: cmdsize as u32,
                }
            }
        }
        LC_LOAD_DYLINKER => {
            if offset + 12 <= data.len() {
                let name_offset = read_u32(offset + 8) as usize;
                let name = match offset.checked_add(name_offset) {
                    Some(abs) => read_cstring(data, abs, cmdsize.saturating_sub(name_offset)),
                    None => String::new(),
                };
                LoadCommand::LoadDylinker(name)
            } else {
                LoadCommand::Unknown {
                    cmd,
                    cmdsize: cmdsize as u32,
                }
            }
        }
        LC_ID_DYLINKER => {
            if offset + 12 <= data.len() {
                let name_offset = read_u32(offset + 8) as usize;
                let name = match offset.checked_add(name_offset) {
                    Some(abs) => read_cstring(data, abs, cmdsize.saturating_sub(name_offset)),
                    None => String::new(),
                };
                LoadCommand::IdDylinker(name)
            } else {
                LoadCommand::Unknown {
                    cmd,
                    cmdsize: cmdsize as u32,
                }
            }
        }
        LC_UUID => {
            if offset + 24 <= data.len() {
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(&data[offset + 8..offset + 24]);
                LoadCommand::Uuid(uuid)
            } else {
                LoadCommand::Unknown {
                    cmd,
                    cmdsize: cmdsize as u32,
                }
            }
        }
        LC_MAIN => {
            if offset + 24 <= data.len() {
                LoadCommand::Main {
                    entry_off: read_u64(offset + 8),
                    stack_size: read_u64(offset + 16),
                }
            } else {
                LoadCommand::Unknown {
                    cmd,
                    cmdsize: cmdsize as u32,
                }
            }
        }
        LC_SYMTAB => {
            if offset + 24 <= data.len() {
                LoadCommand::Symtab {
                    symoff: read_u32(offset + 8),
                    nsyms: read_u32(offset + 12),
                    stroff: read_u32(offset + 16),
                    strsize: read_u32(offset + 20),
                }
            } else {
                LoadCommand::Unknown {
                    cmd,
                    cmdsize: cmdsize as u32,
                }
            }
        }
        LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64 => {
            if offset + 20 <= data.len() {
                LoadCommand::EncryptionInfo {
                    cryptoff: read_u32(offset + 8),
                    cryptsize: read_u32(offset + 12),
                    cryptid: read_u32(offset + 16),
                }
            } else {
                LoadCommand::Unknown {
                    cmd,
                    cmdsize: cmdsize as u32,
                }
            }
        }
        LC_CODE_SIGNATURE => {
            if offset + 16 <= data.len() {
                LoadCommand::CodeSignature {
                    dataoff: read_u32(offset + 8),
                    datasize: read_u32(offset + 12),
                }
            } else {
                LoadCommand::Unknown {
                    cmd,
                    cmdsize: cmdsize as u32,
                }
            }
        }
        LC_RPATH => {
            if offset + 12 <= data.len() {
                let name_offset = read_u32(offset + 8) as usize;
                let name = match offset.checked_add(name_offset) {
                    Some(abs) => read_cstring(data, abs, cmdsize.saturating_sub(name_offset)),
                    None => String::new(),
                };
                LoadCommand::Rpath(name)
            } else {
                LoadCommand::Unknown {
                    cmd,
                    cmdsize: cmdsize as u32,
                }
            }
        }
        LC_SOURCE_VERSION => {
            if offset + 16 <= data.len() {
                LoadCommand::SourceVersion(read_u64(offset + 8))
            } else {
                LoadCommand::Unknown {
                    cmd,
                    cmdsize: cmdsize as u32,
                }
            }
        }
        LC_FUNCTION_STARTS => {
            if offset + 16 <= data.len() {
                LoadCommand::FunctionStarts {
                    dataoff: read_u32(offset + 8),
                    datasize: read_u32(offset + 12),
                }
            } else {
                LoadCommand::Unknown {
                    cmd,
                    cmdsize: cmdsize as u32,
                }
            }
        }
        LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
            if offset + 48 <= data.len() {
                LoadCommand::DyldInfo {
                    rebase_off: read_u32(offset + 8),
                    rebase_size: read_u32(offset + 12),
                    bind_off: read_u32(offset + 16),
                    bind_size: read_u32(offset + 20),
                    weak_bind_off: read_u32(offset + 24),
                    weak_bind_size: read_u32(offset + 28),
                    lazy_bind_off: read_u32(offset + 32),
                    lazy_bind_size: read_u32(offset + 36),
                    export_off: read_u32(offset + 40),
                    export_size: read_u32(offset + 44),
                }
            } else {
                LoadCommand::Unknown {
                    cmd,
                    cmdsize: cmdsize as u32,
                }
            }
        }
        _ => LoadCommand::Unknown {
            cmd,
            cmdsize: cmdsize as u32,
        },
    }
}

fn parse_segment(
    data: &[u8],
    offset: usize,
    cmd: u32,
    cmdsize: usize,
    _is_64bit: bool,
    is_swapped: bool,
) -> LoadCommand {
    let read_u32 = |off: usize| -> u32 {
        let bytes = [data[off], data[off + 1], data[off + 2], data[off + 3]];
        if is_swapped {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        }
    };
    let read_u64 = |off: usize| -> u64 {
        let bytes = [
            data[off],
            data[off + 1],
            data[off + 2],
            data[off + 3],
            data[off + 4],
            data[off + 5],
            data[off + 6],
            data[off + 7],
        ];
        if is_swapped {
            u64::from_be_bytes(bytes)
        } else {
            u64::from_le_bytes(bytes)
        }
    };

    let seg64 = cmd == LC_SEGMENT_64;

    // Segment name is 16 bytes at offset+8
    let name_start = offset.saturating_add(8);
    let name_end = name_start.saturating_add(16).min(data.len());
    let name_bytes = if name_start < data.len() {
        &data[name_start..name_end]
    } else {
        return LoadCommand::Unknown {
            cmd,
            cmdsize: cmdsize as u32,
        };
    };
    let name = read_fixed_cstring(name_bytes);

    if seg64 {
        // 64-bit segment_command: 72 bytes header
        if offset + 72 > data.len() {
            return LoadCommand::Unknown {
                cmd,
                cmdsize: cmdsize as u32,
            };
        }
        let vmaddr = read_u64(offset + 24);
        let vmsize = read_u64(offset + 32);
        let fileoff = read_u64(offset + 40);
        let filesize = read_u64(offset + 48);
        let maxprot = read_u32(offset + 56);
        let initprot = read_u32(offset + 60);
        let nsects = read_u32(offset + 64) as usize;

        let mut sections = Vec::with_capacity(nsects.min(256));
        // Each section_64 is 80 bytes, starting at offset + 72
        let sect_base = offset + 72;
        for i in 0..nsects.min(256) {
            let sect_off = match sect_base.checked_add(i * 80) {
                Some(v) => v,
                None => break,
            };
            if sect_off + 80 > data.len() {
                break;
            }
            let sect_name = read_fixed_cstring(&data[sect_off..sect_off + 16]);
            let seg_name = read_fixed_cstring(&data[sect_off + 16..sect_off + 32]);
            let addr = read_u64(sect_off + 32);
            let size = read_u64(sect_off + 40);
            let sect_file_off = read_u32(sect_off + 48);
            let flags = read_u32(sect_off + 64);

            sections.push(Section {
                name: sect_name,
                segment_name: seg_name,
                addr,
                size,
                offset: sect_file_off,
                flags,
            });
        }

        LoadCommand::Segment64(Segment {
            name,
            vmaddr,
            vmsize,
            fileoff,
            filesize,
            maxprot,
            initprot,
            sections,
            is_64bit: true,
        })
    } else {
        // 32-bit segment_command: 56 bytes header
        if offset + 56 > data.len() {
            return LoadCommand::Unknown {
                cmd,
                cmdsize: cmdsize as u32,
            };
        }
        let vmaddr = read_u32(offset + 24) as u64;
        let vmsize = read_u32(offset + 28) as u64;
        let fileoff = read_u32(offset + 32) as u64;
        let filesize = read_u32(offset + 36) as u64;
        let maxprot = read_u32(offset + 40);
        let initprot = read_u32(offset + 44);
        let nsects = read_u32(offset + 48) as usize;

        let mut sections = Vec::with_capacity(nsects.min(256));
        // Each section is 68 bytes, starting at offset + 56
        let sect_base = offset + 56;
        for i in 0..nsects.min(256) {
            let sect_off = match sect_base.checked_add(i * 68) {
                Some(v) => v,
                None => break,
            };
            if sect_off + 68 > data.len() {
                break;
            }
            let sect_name = read_fixed_cstring(&data[sect_off..sect_off + 16]);
            let seg_name = read_fixed_cstring(&data[sect_off + 16..sect_off + 32]);
            let addr = read_u32(sect_off + 32) as u64;
            let size = read_u32(sect_off + 36) as u64;
            let sect_file_off = read_u32(sect_off + 40);
            let flags = read_u32(sect_off + 56);

            sections.push(Section {
                name: sect_name,
                segment_name: seg_name,
                addr,
                size,
                offset: sect_file_off,
                flags,
            });
        }

        LoadCommand::Segment(Segment {
            name,
            vmaddr,
            vmsize,
            fileoff,
            filesize,
            maxprot,
            initprot,
            sections,
            is_64bit: false,
        })
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────

fn read_u32_at(data: &[u8], offset: usize, is_swapped: bool) -> u32 {
    let bytes = [
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ];
    if is_swapped {
        u32::from_be_bytes(bytes)
    } else {
        u32::from_le_bytes(bytes)
    }
}

fn read_u64_at(data: &[u8], offset: usize, is_swapped: bool) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&data[offset..offset + 8]);
    if is_swapped {
        u64::from_be_bytes(bytes)
    } else {
        u64::from_le_bytes(bytes)
    }
}

fn read_cstring(data: &[u8], offset: usize, max_len: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }
    let end = (offset + max_len).min(data.len());
    let slice = &data[offset..end];
    let len = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..len]).into_owned()
}

fn read_fixed_cstring(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

// ─── Fat Binary Support ──────────────────────────────────────────────

/// Architecture entry in a Fat/Universal binary.
#[derive(Debug, Clone)]
pub struct FatArch {
    pub cpu_type: CpuType,
    pub cpu_subtype: u32,
    pub offset: u64,
    pub size: u64,
    pub align: u32,
}

/// Parse a Fat/Universal binary and return its architecture entries.
pub fn parse_fat_header(data: &[u8]) -> Result<Vec<FatArch>, MachoError> {
    if data.len() < 8 {
        return Err(MachoError::TooSmall(data.len()));
    }

    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let is_fat64 = match magic {
        FAT_MAGIC | FAT_CIGAM => false,
        FAT_MAGIC_64 | FAT_CIGAM_64 => true,
        other => return Err(MachoError::BadMagic(other)),
    };

    // FIXED: FAT_CIGAM / FAT_CIGAM_64 mark byte-swapped (little-endian)
    // header fields, mirroring the thin MH_CIGAM handling in MachoFile::parse.
    // `is_swapped` here means "fields are big-endian", as in read_u32_at.
    let is_swapped = matches!(magic, FAT_MAGIC | FAT_MAGIC_64);

    let nfat_arch = read_u32_at(data, 4, is_swapped);
    if nfat_arch > 64 {
        return Err(MachoError::TooManyArchitectures(nfat_arch));
    }

    let mut archs = Vec::with_capacity(nfat_arch as usize);

    if is_fat64 {
        // fat_arch_64: 32 bytes each
        for i in 0..nfat_arch as usize {
            let base = 8 + i * 32;
            if base + 32 > data.len() {
                break;
            }
            archs.push(FatArch {
                cpu_type: CpuType::from_raw(read_u32_at(data, base, is_swapped)),
                cpu_subtype: read_u32_at(data, base + 4, is_swapped),
                offset: read_u64_at(data, base + 8, is_swapped),
                size: read_u64_at(data, base + 16, is_swapped),
                align: read_u32_at(data, base + 24, is_swapped),
            });
        }
    } else {
        // fat_arch: 20 bytes each
        for i in 0..nfat_arch as usize {
            let base = 8 + i * 20;
            if base + 20 > data.len() {
                break;
            }
            archs.push(FatArch {
                cpu_type: CpuType::from_raw(read_u32_at(data, base, is_swapped)),
                cpu_subtype: read_u32_at(data, base + 4, is_swapped),
                offset: read_u32_at(data, base + 8, is_swapped) as u64,
                size: read_u32_at(data, base + 12, is_swapped) as u64,
                align: read_u32_at(data, base + 16, is_swapped),
            });
        }
    }

    Ok(archs)
}

/// A parsed Mach-O container: either a thin single-architecture binary
/// or a Fat/Universal binary with its architecture table.
#[derive(Debug)]
pub enum MachoObject<'a> {
    Thin(MachoFile<'a>),
    Fat(Vec<FatArch>),
}

/// Parse any Mach-O container, automatically detecting Fat/Universal binaries.
///
/// Checks the file magic against the FAT magics and dispatches to
/// [`parse_fat_header`] when it is a universal binary; otherwise parses a
/// thin binary via [`MachoFile::parse`]. This is the recommended single entry
/// point so callers do not need manual dispatch on the magic value.
pub fn parse_any(data: &[u8]) -> Result<MachoObject<'_>, MachoError> {
    if data.len() >= 4 {
        let magic_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if matches!(
            magic_be,
            FAT_MAGIC | FAT_CIGAM | FAT_MAGIC_64 | FAT_CIGAM_64
        ) {
            return parse_fat_header(data).map(MachoObject::Fat);
        }
    }
    MachoFile::parse(data).map(MachoObject::Thin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_too_small() {
        assert!(matches!(
            MachoFile::parse(&[0u8; 4]),
            Err(MachoError::TooSmall(_))
        ));
    }

    #[test]
    fn test_bad_magic() {
        let data = vec![0u8; 64];
        assert!(matches!(
            MachoFile::parse(&data),
            Err(MachoError::BadMagic(_))
        ));
    }

    #[test]
    fn test_valid_64bit_header() {
        let mut data = vec![0u8; 128];
        // MH_MAGIC_64 = 0xFEEDFACF (little-endian: CF FA ED FE)
        data[0] = 0xCF;
        data[1] = 0xFA;
        data[2] = 0xED;
        data[3] = 0xFE;
        // CPU_TYPE_X86_64 = 0x01000007 (LE: 07 00 00 01)
        data[4] = 0x07;
        data[5] = 0x00;
        data[6] = 0x00;
        data[7] = 0x01;
        // file_type = MH_EXECUTE = 2
        data[12] = 0x02;
        // ncmds = 0
        data[16] = 0;
        // flags = MH_PIE
        data[24] = 0x00;
        data[25] = 0x00;
        data[26] = 0x20;
        data[27] = 0x00;

        let macho = MachoFile::parse(&data).unwrap();
        assert_eq!(macho.cpu_type, CpuType::X86_64);
        assert_eq!(macho.file_type, FileType::Execute);
        assert!(macho.is_64bit);
        assert!(!macho.is_swapped);
        assert!(macho.is_pie());
    }

    #[test]
    fn test_cpu_type_display() {
        assert_eq!(CpuType::X86_64.to_string(), "x86_64");
        assert_eq!(CpuType::Arm64.to_string(), "ARM64");
    }

    #[test]
    fn test_fat_header() {
        let mut data = vec![0u8; 64];
        // FAT_MAGIC = 0xCAFEBABE (big-endian)
        data[0] = 0xCA;
        data[1] = 0xFE;
        data[2] = 0xBA;
        data[3] = 0xBE;
        // nfat_arch = 1 (big-endian)
        data[4] = 0;
        data[5] = 0;
        data[6] = 0;
        data[7] = 1;
        // fat_arch entry: cpu_type = CPU_TYPE_X86_64
        data[8] = 0x01;
        data[9] = 0x00;
        data[10] = 0x00;
        data[11] = 0x07;
        // cpu_subtype = 3
        data[12] = 0;
        data[13] = 0;
        data[14] = 0;
        data[15] = 3;
        // offset = 0x1000
        data[16] = 0;
        data[17] = 0;
        data[18] = 0x10;
        data[19] = 0x00;
        // size = 0x2000
        data[20] = 0;
        data[21] = 0;
        data[22] = 0x20;
        data[23] = 0x00;
        // align = 12 (2^12 = 4096)
        data[24] = 0;
        data[25] = 0;
        data[26] = 0;
        data[27] = 12;

        let archs = parse_fat_header(&data).unwrap();
        assert_eq!(archs.len(), 1);
        assert_eq!(archs[0].cpu_type, CpuType::X86_64);
        assert_eq!(archs[0].offset, 0x1000);
        assert_eq!(archs[0].size, 0x2000);
    }

    #[test]
    fn test_rwx_segment_warning() {
        let mut data = vec![0u8; 256];
        // MH_MAGIC_64
        data[0] = 0xCF;
        data[1] = 0xFA;
        data[2] = 0xED;
        data[3] = 0xFE;
        // CPU_TYPE_ARM64
        data[4] = 0x0C;
        data[5] = 0x00;
        data[6] = 0x00;
        data[7] = 0x01;
        // MH_EXECUTE
        data[12] = 0x02;
        // ncmds = 1
        data[16] = 1;
        // sizeofcmds = 72 (one segment_64 with 0 sections)
        data[20] = 72;
        // flags = MH_PIE
        data[24] = 0x00;
        data[25] = 0x00;
        data[26] = 0x20;
        data[27] = 0x00;

        // LC_SEGMENT_64 at offset 32
        let lc_off = 32;
        // cmd = LC_SEGMENT_64 = 0x19
        data[lc_off] = 0x19;
        // cmdsize = 72
        data[lc_off + 4] = 72;
        // segname: __RWX
        data[lc_off + 8..lc_off + 11].copy_from_slice(b"RWX");
        // initprot at offset lc_off + 60: READ|WRITE|EXECUTE = 7
        data[lc_off + 60] = 7;
        // maxprot at offset lc_off + 56: 7
        data[lc_off + 56] = 7;
        // nsects = 0 at lc_off + 64
        data[lc_off + 64] = 0;

        let macho = MachoFile::parse(&data).unwrap();
        assert!(macho
            .warnings
            .iter()
            .any(|w| w.kind == WarningKind::RwxSection));
    }

    #[test]
    fn test_fat_cigam_header_little_endian_fields() {
        let mut data = vec![0u8; 64];
        // FAT_CIGAM on disk: fields are little-endian
        data[0] = 0xBE;
        data[1] = 0xBA;
        data[2] = 0xFE;
        data[3] = 0xCA;
        // nfat_arch = 1 (little-endian)
        data[4] = 1;
        // fat_arch entry, all little-endian:
        data[8] = 0x07;
        data[9] = 0x00;
        data[10] = 0x00;
        data[11] = 0x01; // CPU_TYPE_X86_64
        data[12] = 3; // cpu_subtype = 3
        data[16] = 0x00;
        data[17] = 0x10; // offset = 0x1000
        data[20] = 0x00;
        data[21] = 0x20; // size = 0x2000
        data[24] = 12; // align = 12

        let archs = parse_fat_header(&data).unwrap();
        assert_eq!(archs.len(), 1);
        assert_eq!(archs[0].cpu_type, CpuType::X86_64);
        assert_eq!(archs[0].cpu_subtype, 3);
        assert_eq!(archs[0].offset, 0x1000);
        assert_eq!(archs[0].size, 0x2000);
        assert_eq!(archs[0].align, 12);
    }

    #[test]
    fn test_fat_cigam_64_header_little_endian_fields() {
        let mut data = vec![0u8; 64];
        // FAT_CIGAM_64 on disk: fields are little-endian
        data[0] = 0xBF;
        data[1] = 0xBA;
        data[2] = 0xBA;
        data[3] = 0xFE;
        // nfat_arch = 1 (little-endian)
        data[4] = 1;
        // fat_arch_64 entry (32 bytes), all little-endian:
        data[8] = 0x0C;
        data[9] = 0x00;
        data[10] = 0x00;
        data[11] = 0x01; // CPU_TYPE_ARM64
        data[16] = 0x00;
        data[17] = 0x10; // offset = 0x1000
        data[24] = 0x00;
        data[25] = 0x20; // size = 0x2000
        data[32] = 12; // align = 12

        let archs = parse_fat_header(&data).unwrap();
        assert_eq!(archs.len(), 1);
        assert_eq!(archs[0].cpu_type, CpuType::Arm64);
        assert_eq!(archs[0].offset, 0x1000);
        assert_eq!(archs[0].size, 0x2000);
        assert_eq!(archs[0].align, 12);
    }

    #[test]
    fn test_overlapping_segment_warnings_capped() {
        const N: usize = 9; // 36 overlapping pairs > MAX_OVERLAP_WARNINGS
        let mut data = vec![0u8; 4096];
        // MH_MAGIC_64, CPU_TYPE_X86_64, MH_EXECUTE
        data[0] = 0xCF;
        data[1] = 0xFA;
        data[2] = 0xED;
        data[3] = 0xFE;
        data[4] = 0x07;
        data[5] = 0x00;
        data[6] = 0x00;
        data[7] = 0x01;
        data[12] = 0x02;
        data[16..20].copy_from_slice(&(N as u32).to_le_bytes()); // ncmds
        data[24..28].copy_from_slice(&MH_PIE.to_le_bytes()); // flags

        for i in 0..N {
            let lc = 32 + i * 72;
            data[lc..lc + 4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
            data[lc + 4..lc + 8].copy_from_slice(&72u32.to_le_bytes()); // cmdsize
            let name = format!("__SEG{}", i);
            data[lc + 8..lc + 8 + name.len()].copy_from_slice(name.as_bytes());
            // All segments share fileoff=0 with filesize=0x100 → all overlap.
            data[lc + 48..lc + 56].copy_from_slice(&0x100u64.to_le_bytes());
            data[lc + 56..lc + 60].copy_from_slice(&5u32.to_le_bytes()); // maxprot R+X
            data[lc + 60..lc + 64].copy_from_slice(&5u32.to_le_bytes()); // initprot R+X
            data[lc + 64..lc + 68].copy_from_slice(&0u32.to_le_bytes()); // nsects
        }

        let macho = MachoFile::parse(&data).unwrap();
        let overlaps = macho
            .warnings
            .iter()
            .filter(|w| w.kind == WarningKind::OverlappingSegments)
            .count();
        assert!(overlaps > 0);
        assert!(overlaps <= MAX_OVERLAP_WARNINGS);
    }
}
