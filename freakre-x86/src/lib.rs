//! freakre-x86: Own x86/x64 disassembler.
//! Table-driven, zero-copy, no panics on malformed input.
//! Supports: legacy prefixes, REX, ModR/M, SIB, displacement, immediate.

pub mod types;
pub mod lde;
pub mod decoder;
pub mod formatter;

pub use types::*;
pub use lde::decode_len;
pub use formatter::format_instruction;

/// Decode a single x86/x64 instruction.
/// `is_64bit`: true for x86_64, false for x86 (32-bit).
pub fn decode(code: &[u8], is_64bit: bool) -> Result<Instruction, DecodeError> {
    let mode = if is_64bit { Mode::X64 } else { Mode::X86 };
    decoder::decode(code, 0, mode)
}
