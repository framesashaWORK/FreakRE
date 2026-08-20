//! Error types for disassembly operations.

use crate::Arch;
use thiserror::Error;

/// Errors that can occur during disassembly.
#[derive(Debug, Error)]
pub enum DisasmError {
    #[error("Unsupported architecture: {0}")]
    UnsupportedArch(Arch),

    #[error("Invalid mode {1:?} for architecture {0}")]
    InvalidMode(Arch, crate::Mode),

    #[error("Failed to initialize disassembler: {0}")]
    InitFailed(String),

    #[error("Disassembly failed at offset 0x{0:X}: {1}")]
    DisasmFailed(usize, String),

    #[error("Invalid instruction at offset 0x{0:X}")]
    InvalidInstruction(usize),

    #[error("Capstone library not available")]
    LibraryNotAvailable,

    #[error("Internal error: {0}")]
    Internal(String),
}
