#![allow(dead_code, unused_assignments)]
//! Zero-copy PE32/PE32+ parser for malware analysis.

use std::fmt;
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
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

#[inline]
fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

#[inline]
fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ])
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
        self.virtual_address == 0 && self.size == 0
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
    Other,
}

#[derive(Debug, Clone)]
pub struct PeWarning {
    pub kind: WarningKind,
    pub message: String,
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
        if offset + 40 > data.len() {
            return Err(PeError::TooSmallForSections {
                needed: offset + 40,
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
        if lfanew_usize + 4 > data.len() {
            return Err(PeError::TooSmallForPeSig(lfanew));
        }
        let pe_sig = read_u32(data, lfanew_usize);
        if pe_sig != PE_SIG {
            return Err(PeError::BadPeSig(pe_sig));
        }

        // --- COFF Header ---
        let coff_off = lfanew_usize + 4;
        if coff_off + 20 > data.len() {
            return Err(PeError::TooSmallForCoff(lfanew));
        }
        let machine_raw = read_u16(data, coff_off);
        let machine = MachineType::from_raw(machine_raw);
        let number_of_sections = read_u16(data, coff_off + 2);
        let timestamp = read_u32(data, coff_off + 4);

        // --- Optional Header ---
        let opt_off = coff_off + 20;
        if opt_off + 2 > data.len() {
            return Err(PeError::TooSmallForOpt(lfanew));
        }
        let opt_magic = read_u16(data, opt_off);
        let is_64bit = match opt_magic {
            OPT_MAGIC_PE32 => false,
            OPT_MAGIC_PE32PLUS => true,
            other => return Err(PeError::UnknownOptMagic(other)),
        };

        let (entry_point, image_base, section_alignment, file_alignment, num_ddr, dll_characteristics) = if is_64bit {
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

        // --- Data Directories ---
        let ddr_off = if is_64bit { opt_off + 112 } else { opt_off + 96 };
        // PE spec: max 16 standard data directories, but some tools set
        // higher values. Cap at 128 to prevent overflow / excessive allocation
        // from malformed PE files. num_ddr is u32 from file — must be bounded.
        let clamped_num_ddr = (num_ddr as usize).min(128);
        let mut data_directories = Vec::with_capacity(clamped_num_ddr);
        for i in 0..clamped_num_ddr {
            let off = ddr_off + i * 8;
            if off + 8 > data.len() { break; }
            data_directories.push(DataDirectory {
                virtual_address: read_u32(data, off),
                size: read_u32(data, off + 4),
            });
        }

        // --- Section Headers ---
        // PE spec: max 96 sections. Malware may set a large number_of_sections
        // to trigger integer overflow or excessive allocation. Clamp it.
        let clamped_num_sections = (number_of_sections as usize).min(96);
        let section_table_off = ddr_off + clamped_num_ddr * 8;
        let sections_end = section_table_off + clamped_num_sections * 40;
        if sections_end > data.len() {
            return Err(PeError::TooSmallForSections {
                needed: sections_end,
                have: data.len(),
            });
        }

        let mut sections = Vec::with_capacity(clamped_num_sections);
        for i in 0..clamped_num_sections {
            sections.push(SectionHeader::parse(data, section_table_off + i * 40)?);
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
                    message: format!("Section '{}' has empty raw data but virtual_size={}", sec.name_string(), sec.virtual_size),
                });
            }
            if sec.is_executable() && !sec.is_code() {
                warnings.push(PeWarning {
                    kind: WarningKind::ExecutableWithoutCodeFlag,
                    message: format!("Section '{}' is executable but lacks CODE flag", sec.name_string()),
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
                if a.raw_data_size > 0 && b.raw_data_size > 0 && a_start < b_end && b_start < a_end {
                    warnings.push(PeWarning {
                        kind: WarningKind::OverlappingSections,
                        message: format!("Overlapping sections: {} <-> {}", a.name_string(), b.name_string()),
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
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        for sec in &self.sections {
            if rva >= sec.virtual_address
                && rva < sec.virtual_address + sec.virtual_size.max(sec.raw_data_size)
            {
                let offset_in_section = rva - sec.virtual_address;
                let file_offset = sec.raw_data_offset + offset_in_section;
                if (file_offset as usize) < self.data.len() {
                    return Some(file_offset as usize);
                }
            }
        }
        None
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
        if dd.is_empty() { return None; }
        Some((dd.virtual_address, dd.size))
    }

    /// Get the IAT (Import Address Table) RVA and size.
    pub fn iat_directory(&self) -> Option<(u32, u32)> {
        let dd = self.data_directories.get(IMAGE_DIRECTORY_ENTRY_IAT)?;
        if dd.is_empty() { return None; }
        Some((dd.virtual_address, dd.size))
    }

    /// Get the Resource Directory RVA and size.
    pub fn resource_directory(&self) -> Option<(u32, u32)> {
        let dd = self.data_directories.get(IMAGE_DIRECTORY_ENTRY_RESOURCE)?;
        if dd.is_empty() { return None; }
        Some((dd.virtual_address, dd.size))
    }

    /// Get the TLS Directory RVA and size.
    pub fn tls_directory(&self) -> Option<(u32, u32)> {
        let dd = self.data_directories.get(IMAGE_DIRECTORY_ENTRY_TLS)?;
        if dd.is_empty() { return None; }
        Some((dd.virtual_address, dd.size))
    }

    /// Get the Delay Import Directory RVA and size.
    pub fn delay_import_directory(&self) -> Option<(u32, u32)> {
        let dd = self.data_directories.get(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)?;
        if dd.is_empty() { return None; }
        Some((dd.virtual_address, dd.size))
    }

    /// Get the Bound Import Directory RVA and size.
    pub fn bound_import_directory(&self) -> Option<(u32, u32)> {
        let dd = self.data_directories.get(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT)?;
        if dd.is_empty() { return None; }
        Some((dd.virtual_address, dd.size))
    }

    /// Get the COM Descriptor (CLR/.NET) Directory RVA and size.
    pub fn com_descriptor_directory(&self) -> Option<(u32, u32)> {
        let dd = self.data_directories.get(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)?;
        if dd.is_empty() { return None; }
        Some((dd.virtual_address, dd.size))
    }

    /// Get the Debug Directory RVA and size.
    pub fn debug_directory(&self) -> Option<(u32, u32)> {
        let dd = self.data_directories.get(IMAGE_DIRECTORY_ENTRY_DEBUG)?;
        if dd.is_empty() { return None; }
        Some((dd.virtual_address, dd.size))
    }

    /// Get the Security Directory RVA and size.
    pub fn security_directory(&self) -> Option<(u32, u32)> {
        let dd = self.data_directories.get(IMAGE_DIRECTORY_ENTRY_SECURITY)?;
        if dd.is_empty() { return None; }
        Some((dd.virtual_address, dd.size))
    }

    /// Get the Base Relocations Directory RVA and size.
    pub fn base_reloc_directory(&self) -> Option<(u32, u32)> {
        let dd = self.data_directories.get(IMAGE_DIRECTORY_ENTRY_BASERELOC)?;
        if dd.is_empty() { return None; }
        Some((dd.virtual_address, dd.size))
    }

    /// Read a null-terminated ASCII string at the given file offset.
    /// Returns `None` if the offset is out of bounds.
    pub fn read_cstring_at(&self, offset: usize, max_len: usize) -> Option<String> {
        if offset >= self.data.len() { return None; }
        let end = (offset + max_len).min(self.data.len());
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
        if self.is_64bit { 8 } else { 4 }
    }

    /// The ordinal flag for thunk entries.
    pub fn ordinal_flag(&self) -> u64 {
        if self.is_64bit { 0x8000_0000_0000_0000 } else { 0x8000_0000 }
    }

    // ─── DllCharacteristics Analysis ───────────────────────────────

    /// Return human-readable list of DllCharacteristics flags.
    pub fn dll_characteristics_flags(&self) -> Vec<String> {
        let dc = self.dll_characteristics;
        let mut flags = Vec::new();
        if dc & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA != 0 { flags.push("HIGH_ENTROPY_VA".into()); }
        if dc & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0 { flags.push("DYNAMIC_BASE/ASLR".into()); }
        if dc & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY != 0 { flags.push("FORCE_INTEGRITY".into()); }
        if dc & IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0 { flags.push("NX_COMPAT/DEP".into()); }
        if dc & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION != 0 { flags.push("NO_ISOLATION".into()); }
        if dc & IMAGE_DLLCHARACTERISTICS_NO_SEH != 0 { flags.push("NO_SEH".into()); }
        if dc & IMAGE_DLLCHARACTERISTICS_NO_BIND != 0 { flags.push("NO_BIND".into()); }
        if dc & IMAGE_DLLCHARACTERISTICS_APPCONTAINER != 0 { flags.push("APPCONTAINER".into()); }
        if dc & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER != 0 { flags.push("WDM_DRIVER".into()); }
        if dc & IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0 { flags.push("GUARD_CF/CFG".into()); }
        if dc & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE != 0 { flags.push("TERMINAL_SERVER_AWARE".into()); }
        flags
    }

    // ─── .NET CLR Detection ───────────────────────────────────────

    /// Whether this PE is a .NET assembly (has COM Descriptor/CLR header).
    pub fn is_dotnet(&self) -> bool {
        self.com_descriptor_directory().is_some()
    }

    // ─── Overlay Detection ─────────────────────────────────────────

    /// Calculate the size of overlay data (data appended after the last section).
    /// Returns 0 if no overlay is present.
    pub fn overlay_size(&self) -> usize {
        if self.sections.is_empty() { return 0; }
        let last_section_end = self.sections.iter()
            .map(|s| s.raw_data_offset as usize + s.raw_data_size as usize)
            .max()
            .unwrap_or(0);
        if self.data.len() > last_section_end + 0x200 {
            // Only report overlay if > 512 bytes (to avoid noise from alignment)
            self.data.len() - last_section_end
        } else {
            0
        }
    }

    /// Return overlay data slice (data after last section), if present.
    pub fn overlay_data(&self) -> Option<&[u8]> {
        if self.sections.is_empty() { return None; }
        let last_section_end = self.sections.iter()
            .map(|s| s.raw_data_offset as usize + s.raw_data_size as usize)
            .max()
            .unwrap_or(0);
        if self.data.len() > last_section_end + 0x200 {
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
            if offset + 40 > self.data.len() { return Vec::new(); }
            read_u64(self.data, offset + 24)
        } else {
            if offset + 24 > self.data.len() { return Vec::new(); }
            read_u32(self.data, offset + 12) as u64
        };

        if callback_array_va == 0 { return Vec::new(); }

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
            if pos + entry_size > self.data.len() { break; }
            let cb = if self.is_64bit {
                read_u64(self.data, pos)
            } else {
                read_u32(self.data, pos) as u64
            };
            if cb == 0 { break; } // NULL terminator
            callbacks.push(cb);
            pos += entry_size;
        }

        callbacks
    }

    // ─── Rich Header Fingerprint ──────────────────────────────────

    /// Parse Rich header (between DOS stub and PE signature).
    /// Returns list of compiler tool version strings.
    pub fn rich_header(&self) -> Vec<String> {
        if self.data.len() < 128 { return Vec::new(); }

        // Find "Rich" marker at end of Rich header (just before e_lfanew)
        let lfanew = read_u32(self.data, 60) as usize;
        if lfanew >= self.data.len() || lfanew < 16 { return Vec::new(); }

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
        if rich_offset + 8 > self.data.len() { return Vec::new(); }
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
        let approx_count = (size as usize / 16).max(0).min(1000);

        // Heuristic: suspicious if resource section has very high entropy
        let suspicious = if let Some(sec) = self.sections.iter().find(|s| s.name_string() == ".rsrc") {
            let raw = sec.raw_data(self.data);
            if !raw.is_empty() {
                let ent = crate::calculate_section_entropy(raw);
                if ent > 7.5 { approx_count } else { 0 }
            } else { 0 }
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
        for _ in 0..128 { // Safety limit
            if pos + 32 > self.data.len() { break; }
            let attrs = read_u32(self.data, pos);
            if attrs == 0 { break; } // End marker

            let dll_name_rva = read_u32(self.data, pos + 4);
            if dll_name_rva != 0 {
                if let Some(dll_name) = self.read_cstring_at_rva(dll_name_rva, 256) {
                    dlls.push(dll_name);
                }
            }
            pos += 32;
        }

        dlls
    }
}

/// Helper: calculate entropy of a byte slice (for PE-internal use).
fn calculate_section_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u32; 256];
    for &b in data { counts[b as usize] += 1; }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_too_small() {
        assert!(matches!(PeFile::parse(&[0u8; 10]), Err(PeError::TooSmallForDos(_))));
    }

    #[test]
    fn test_bad_dos_magic() {
        let mut data = [0u8; 64];
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
        data[0] = 0x4D; data[1] = 0x5A; // MZ
        data[60] = 0x80; // e_lfanew = 128
        // PE signature at 0x80
        data[0x80] = 0x50; data[0x81] = 0x45; data[0x82] = 0; data[0x83] = 0;
        // COFF header at 0x84: machine=0x14C (i386), 1 section
        data[0x84] = 0x4C; data[0x85] = 0x01;
        data[0x86] = 1; data[0x87] = 0; // 1 section
        // Optional header at 0x98
        data[0x98] = 0x0B; data[0x99] = 0x01; // PE32 magic
        // Entry point at 0x98 + 16 = 0xA8
        data[0xA8] = 0x00; data[0xA9] = 0x10; // RVA 0x1000
        // Number of data directories at 0x98 + 92 = 0xF4
        data[0xF4] = 0; // 0 data directories
        // Section table at 0xF8 (after opt header of 96 bytes)
        let sec_off = 0xF8;
        // Name: .text
        data[sec_off..sec_off + 5].copy_from_slice(b".text");
        // VirtualSize at +8
        data[sec_off + 8] = 0x00; data[sec_off + 9] = 0x10; // 0x1000
        // VirtualAddress at +12
        data[sec_off + 12] = 0x00; data[sec_off + 13] = 0x10; // 0x1000
        // RawDataSize at +16
        data[sec_off + 16] = 0x00; data[sec_off + 17] = 0x02; // 0x200
        // RawDataOffset at +20
        data[sec_off + 20] = 0x00; data[sec_off + 21] = 0x02; // 0x200
        // Characteristics at +36
        data[sec_off + 36] = 0x20; data[sec_off + 39] = 0x60; // CODE | EXECUTE | READ

        let pe = PeFile::parse(&data).unwrap();
        assert_eq!(pe.sections.len(), 1);
        assert_eq!(pe.sections[0].name_string(), ".text");
        assert!(pe.sections[0].is_executable());
        assert!(!pe.is_64bit);
    }

    #[test]
    fn test_rwx_section_warning() {
        let mut data = vec![0u8; 1024];
        data[0] = 0x4D; data[1] = 0x5A;
        data[60] = 0x80;
        data[0x80] = 0x50; data[0x81] = 0x45; data[0x82] = 0; data[0x83] = 0;
        data[0x84] = 0x4C; data[0x85] = 0x01;
        data[0x86] = 1; data[0x87] = 0;
        data[0x98] = 0x0B; data[0x99] = 0x01;
        data[0xF4] = 0;
        let sec_off = 0xF8;
        data[sec_off..sec_off + 4].copy_from_slice(b".bad");
        data[sec_off + 16] = 0x00; data[sec_off + 17] = 0x01;
        data[sec_off + 20] = 0x00; data[sec_off + 21] = 0x02;
        // RWX characteristics: READ | WRITE | EXECUTE
        data[sec_off + 36] = 0x20; data[sec_off + 37] = 0x00;
        data[sec_off + 38] = 0x00; data[sec_off + 39] = 0xE0;

        let pe = PeFile::parse(&data).unwrap();
        assert!(pe.warnings.iter().any(|w| w.kind == WarningKind::RwxSection));
    }

    #[test]
    fn test_zero_sections_warning() {
        let mut data = vec![0u8; 512];
        data[0] = 0x4D; data[1] = 0x5A;
        data[60] = 0x80;
        data[0x80] = 0x50; data[0x81] = 0x45; data[0x82] = 0; data[0x83] = 0;
        data[0x84] = 0x4C; data[0x85] = 0x01;
        data[0x86] = 0; data[0x87] = 0; // 0 sections
        data[0x98] = 0x0B; data[0x99] = 0x01;
        data[0xF4] = 0;

        let pe = PeFile::parse(&data).unwrap();
        assert!(pe.warnings.iter().any(|w| w.kind == WarningKind::ZeroSections));
    }

    #[test]
    fn test_rva_to_offset() {
        let mut data = vec![0u8; 1024];
        data[0] = 0x4D; data[1] = 0x5A;
        data[60] = 0x80;
        data[0x80] = 0x50; data[0x81] = 0x45; data[0x82] = 0; data[0x83] = 0;
        data[0x84] = 0x4C; data[0x85] = 0x01;
        data[0x86] = 1; data[0x87] = 0;
        data[0x98] = 0x0B; data[0x99] = 0x01;
        data[0xF4] = 0;
        let sec_off = 0xF8;
        data[sec_off..sec_off + 5].copy_from_slice(b".text");
        data[sec_off + 8] = 0x00; data[sec_off + 9] = 0x10;
        data[sec_off + 12] = 0x00; data[sec_off + 13] = 0x10; // VA = 0x1000
        data[sec_off + 16] = 0x00; data[sec_off + 17] = 0x02;
        data[sec_off + 20] = 0x00; data[sec_off + 21] = 0x02; // Raw offset = 0x200
        data[sec_off + 36] = 0x20; data[sec_off + 39] = 0x60;

        let pe = PeFile::parse(&data).unwrap();
        // RVA 0x1000 should map to file offset 0x200
        assert_eq!(pe.rva_to_offset(0x1000), Some(0x200));
        // RVA 0x1010 should map to file offset 0x210
        assert_eq!(pe.rva_to_offset(0x1010), Some(0x210));
        // RVA outside sections
        assert_eq!(pe.rva_to_offset(0x5000), None);
    }

    #[test]
    fn test_lfanew_out_of_bounds() {
        let mut data = vec![0u8; 64];
        data[0] = 0x4D; data[1] = 0x5A;
        data[60] = 0xFF; data[61] = 0xFF; // e_lfanew = 0xFFFF, way beyond file
        let err = PeFile::parse(&data).unwrap_err();
        assert!(matches!(err, PeError::LfanewOutOfBounds(..)));
    }

    #[test]
    fn test_bad_pe_signature() {
        let mut data = vec![0u8; 256];
        data[0] = 0x4D; data[1] = 0x5A;
        data[60] = 0x80;
        data[0x80] = 0x00; data[0x81] = 0x00; data[0x82] = 0x00; data[0x83] = 0x00; // Bad PE sig
        let err = PeFile::parse(&data).unwrap_err();
        assert!(matches!(err, PeError::BadPeSig(_)));
    }
}


