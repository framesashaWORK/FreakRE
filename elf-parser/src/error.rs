//! Error and warning types for ELF parsing.

use std::fmt;

/// Fatal error that prevents further parsing.
#[derive(Debug, Clone)]
pub enum ElfError {
    /// File too small to contain valid ELF header.
    TooSmall(usize),
    /// Invalid ELF magic bytes.
    InvalidMagic([u8; 4]),
    /// Unsupported ELF class/endian combination.
    UnsupportedFormat,
    /// Section header string table index out of bounds.
    InvalidShstrndx(u16, usize),
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooSmall(size) => write!(f, "File too small for ELF header: {} bytes", size),
            Self::InvalidMagic(m) => {
                write!(f, "Invalid ELF magic: {:02X} {:02X} {:02X} {:02X}", m[0], m[1], m[2], m[3])
            }
            Self::UnsupportedFormat => write!(f, "Unsupported ELF class/endian combination"),
            Self::InvalidShstrndx(idx, count) => {
                write!(f, "shstrndx {} out of bounds ({} sections)", idx, count)
            }
        }
    }
}

impl std::error::Error for ElfError {}

/// Non-fatal warning detected during parsing.
#[derive(Debug, Clone)]
pub struct ElfWarning {
    pub kind: ElfWarningKind,
    pub message: String,
}

impl fmt::Display for ElfWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:?}] {}", self.kind, self.message)
    }
}

/// Categories of ELF warnings relevant to malware analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfWarningKind {
    /// Section with Write+Execute permissions.
    RwxSection,
    /// Executable segment not backed by a file section (runtime-generated code).
    ExecutableWithoutFile,
    /// Statically linked binary (common in IoT malware).
    StaticallyLinked,
    /// Binary is stripped (no symbol table).
    StrippedBinary,
    /// Suspicious section name or characteristics.
    SuspiciousSection,
    /// Entry point outside any executable section.
    EntryPointOutOfBounds,
    /// Overlapping segments or sections.
    OverlappingRegions,
    /// Unusual machine type for the context.
    UnusualArchitecture,
    /// GNU_STACK with execute permission.
    ExecutableStack,
    /// Missing NX/RELRO protections.
    MissingProtection,
    /// Interpreter path anomaly.
    SuspiciousInterpreter,
    /// Anomaly in dynamic section.
    DynamicAnomaly,
}

/// Result type: either a parsed ELF or a fatal error.
pub type ElfParseResult<T> = Result<T, ElfError>;
