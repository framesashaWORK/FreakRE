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

impl From<crate::engine::EngineError> for DisasmError {
    fn from(e: crate::engine::EngineError) -> Self {
        use crate::engine::EngineError as E;
        match e {
            E::Unavailable => DisasmError::LibraryNotAvailable,
            E::Init(msg) => DisasmError::InitFailed(msg),
            E::Unsupported(arch, _) => DisasmError::UnsupportedArch(arch),
            E::Disasm(msg) => DisasmError::DisasmFailed(0, msg),
            E::Internal(msg) => DisasmError::Internal(msg),
        }
    }
}
