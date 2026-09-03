//! freakre-x86: Own x86/x64 disassembler.
//! Table-driven, zero-copy, no panics on malformed input.
//! Supports: legacy prefixes, REX, ModR/M, SIB, displacement, immediate.

pub mod types;
pub mod lde;
pub mod decoder;
pub mod simd;
pub mod formatter;

pub use types::*;
pub use lde::decode_len;
pub use formatter::format_instruction;
pub use formatter::format_instruction_att;

/// Decode a single x86/x64 instruction.
/// `is_64bit`: true for x86_64, false for x86 (32-bit).
pub fn decode(code: &[u8], is_64bit: bool) -> Result<Instruction, DecodeError> {
    let mode = if is_64bit { Mode::X64 } else { Mode::X86 };
    decoder::decode(code, 0, mode)
}

/// Decode a single instruction in an explicit [`Mode`] (incl. 16-bit).
pub fn decode_mode(code: &[u8], address: u64, mode: Mode) -> Result<Instruction, DecodeError> {
    decoder::decode(code, address, mode)
}

/// Linear-sweep disassembly of a code buffer.
/// On an undecodable byte, emits an `Unknown` pseudo-instruction of length 1
/// and continues from the next byte (best-effort, may drift on real data).
pub fn disassemble(code: &[u8], address: u64, is_64bit: bool) -> Vec<Instruction> {
    let mode = if is_64bit { Mode::X64 } else { Mode::X86 };
    disassemble_mode(code, address, mode)
}

/// Linear-sweep disassembly in an explicit [`Mode`] (incl. 16-bit).
pub fn disassemble_mode(code: &[u8], address: u64, mode: Mode) -> Vec<Instruction> {
    disassemble_limit(code, address, mode, 0)
}

/// Linear-sweep disassembly capped at `max` instructions.
/// `max == 0` means "no limit". The cap bounds allocation on hostile input.
pub fn disassemble_limit(code: &[u8], address: u64, mode: Mode, max: usize) -> Vec<Instruction> {
    let mut out = Vec::new();
    if max > 0 {
        out.reserve(max.min(code.len()));
    }
    let mut off = 0usize;
    while off < code.len() && (max == 0 || out.len() < max) {
        match decoder::decode(&code[off..], address + off as u64, mode) {
            Ok(insn) => {
                let len = insn.length.max(1);
                out.push(insn);
                off += len;
            }
            Err(_) => {
                let mut raw = [0u8; 15];
                raw[0] = code[off];
                out.push(Instruction {
                    address: address + off as u64,
                    mnemonic: Mnemonic::Unknown,
                    operands: vec![Operand::Imm(code[off] as i64)],
                    prefixes: Prefixes::default(),
                    rex: None,
                    length: 1,
                    bytes: raw,
                });
                off += 1;
            }
        }
    }
    out
}

/// Lazy linear-sweep iterator: yields `(offset, decode_result)` without
/// allocating the whole vector up front. Undecodable bytes yield `Err`
/// (unlike [`disassemble`], no `Unknown` synthesis — the caller decides).
pub fn decode_iter(
    code: &[u8],
    address: u64,
    mode: Mode,
) -> impl Iterator<Item = (usize, Result<Instruction, DecodeError>)> + '_ {
    let mut off = 0usize;
    std::iter::from_fn(move || {
        if off >= code.len() {
            return None;
        }
        let cur = off;
        match decoder::decode(&code[cur..], address + cur as u64, mode) {
            Ok(insn) => {
                off += insn.length.max(1);
                Some((cur, Ok(insn)))
            }
            Err(e) => {
                // Step one byte so iteration always makes progress.
                off += 1;
                Some((cur, Err(e)))
            }
        }
    })
}
