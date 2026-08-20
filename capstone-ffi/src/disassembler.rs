//! # Disassembler — Multi-architecture disassembly engine
//!
//! Provides a unified interface for disassembling machine code across
//! multiple CPU architectures. Uses Capstone when available, falls back
//! to a built-in Length Disassembler Engine (LDE) for x86/x64.
//!
//! ## Architecture Support
//!
//! | Architecture | Capstone | Built-in LDE |
//! |-------------|----------|--------------|
//! | x86         | ✅       | ✅           |
//! | x86-64      | ✅       | ✅           |
//! | ARM         | ✅       | ❌           |
//! | AArch64     | ✅       | ❌           |
//! | MIPS        | ✅       | ❌           |
//! | PowerPC     | ✅       | ❌           |
//! | SPARC       | ✅       | ❌           |
//! | RISC-V      | ✅       | ❌           |

use crate::arch::{Arch, Endian, Mode};
use crate::error::DisasmError;
use crate::instruction::{Instruction, InstructionKind};

/// Multi-architecture disassembler.
pub struct Disassembler {
    arch: Arch,
    mode: Mode,
    endian: Endian,
    #[cfg(capstone_available)]
    cs_handle: Option<capstone_bindings::CapstoneHandle>,
    _private: (),
}

impl Disassembler {
    /// Create a new disassembler for the specified architecture and mode.
    pub fn new(arch: Arch, mode: Mode) -> Result<Self, DisasmError> {
        Self::with_endian(arch, mode, arch.default_endian())
    }

    /// Create a new disassembler with explicit endianness.
    pub fn with_endian(arch: Arch, mode: Mode, endian: Endian) -> Result<Self, DisasmError> {
        Self::validate_mode(arch, mode)?;

        #[cfg(capstone_available)]
        {
            match capstone_bindings::CapstoneHandle::new(arch, mode, endian) {
                Ok(handle) => {
                    return Ok(Self {
                        arch,
                        mode,
                        endian,
                        cs_handle: Some(handle),
                        _private: (),
                    });
                }
                Err(_) => {
                    // Capstone init failed — fall through to built-in LDE if available
                }
            }
        }

        // Fallback: built-in LDE (x86/x64 only)
        match arch {
            Arch::X86 => Ok(Self {
                arch,
                mode,
                endian,
                #[cfg(capstone_available)]
                cs_handle: None,
                _private: (),
            }),
            _ => Err(DisasmError::LibraryNotAvailable),
        }
    }

    /// Validate that the mode is compatible with the architecture.
    fn validate_mode(arch: Arch, mode: Mode) -> Result<(), DisasmError> {
        match (arch, mode) {
            (Arch::X86, Mode::Mode16 | Mode::Mode32 | Mode::Mode64) => Ok(()),
            (Arch::ARM, Mode::Arm | Mode::Thumb | Mode::Mode32) => Ok(()),
            (Arch::ARM64, Mode::Mode64) => Ok(()),
            (Arch::MIPS, Mode::Mode32 | Mode::Mode64 | Mode::MicroMips) => Ok(()),
            (Arch::PPC, Mode::Mode32 | Mode::Mode64) => Ok(()),
            (Arch::SPARC, Mode::Mode32 | Mode::Mode64) => Ok(()),
            (Arch::RISCV, Mode::Mode32 | Mode::Mode64) => Ok(()),
            _ => Err(DisasmError::InvalidMode(arch, mode)),
        }
    }

    /// Returns the architecture this disassembler was created for.
    pub fn arch(&self) -> Arch {
        self.arch
    }

    /// Returns the mode of this disassembler.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Whether this disassembler is backed by Capstone.
    pub fn is_capstone(&self) -> bool {
        #[cfg(capstone_available)]
        {
            self.cs_handle.is_some()
        }
        #[cfg(not(capstone_available))]
        {
            false
        }
    }

    /// Disassemble a buffer of machine code.
    ///
    /// `base_address` is the virtual address of the first byte in `code`,
    /// used to resolve relative branch targets.
    ///
    /// Returns all successfully decoded instructions. Decoding stops at
    /// the first invalid instruction.
    pub fn disassemble(&self, code: &[u8], base_address: u64) -> Vec<Instruction> {
        #[cfg(capstone_available)]
        {
            if let Some(ref handle) = self.cs_handle {
                return handle.disassemble(code, base_address);
            }
        }

        // Fallback: built-in LDE (x86/x64 only)
        if self.arch == Arch::X86 {
            return builtin_lde_disassemble(code, base_address, self.mode == Mode::Mode64);
        }

        Vec::new()
    }

    /// Disassemble a single instruction at the given offset.
    /// Returns None if the instruction cannot be decoded.
    pub fn disassemble_one(&self, code: &[u8], base_address: u64) -> Option<Instruction> {
        let result = self.disassemble(code, base_address);
        result.into_iter().next()
    }

    /// Disassemble with a maximum count of instructions.
    pub fn disassemble_n(&self, code: &[u8], base_address: u64, max_count: usize) -> Vec<Instruction> {
        let all = self.disassemble(code, base_address);
        all.into_iter().take(max_count).collect()
    }
}

// ─── Built-in LDE for x86/x64 ────────────────────────────────────────

/// Built-in disassembly using Length Disassembler Engine for x86/x64.
/// This is a fallback when Capstone is not available.
fn builtin_lde_disassemble(code: &[u8], base_address: u64, is_64bit: bool) -> Vec<Instruction> {
    let mut instructions = Vec::new();
    let mut offset = 0usize;

    while offset < code.len() {
        let remaining = &code[offset..];
        let (len, kind) = lde_classify(remaining, is_64bit);

        if len == 0 || offset + len > code.len() {
            break;
        }

        let inst_bytes = code[offset..offset + len].to_vec();
        let mnemonic = mnemonic_from_kind(&kind);
        let operands = operands_from_bytes(&inst_bytes, &kind, is_64bit);

        instructions.push(Instruction {
            address: base_address + offset as u64,
            size: len,
            bytes: inst_bytes,
            mnemonic,
            operands,
            operand_list: Vec::new(), // LDE doesn't parse operands fully
            kind,
        });

        offset += len;
    }

    instructions
}

/// Convert InstructionKind to a rough mnemonic for built-in LDE.
fn mnemonic_from_kind(kind: &InstructionKind) -> String {
    match kind {
        InstructionKind::Return => "ret".into(),
        InstructionKind::Call => "call".into(),
        InstructionKind::ConditionalBranch => "jcc".into(),
        InstructionKind::UnconditionalJump => "jmp".into(),
        InstructionKind::Nop => "nop".into(),
        InstructionKind::Normal => "inst".into(),
        InstructionKind::Unknown => "db".into(),
    }
}

/// Rough operand string from raw bytes for built-in LDE.
fn operands_from_bytes(bytes: &[u8], kind: &InstructionKind, _is_64bit: bool) -> String {
    match kind {
        InstructionKind::ConditionalBranch | InstructionKind::UnconditionalJump => {
            // Check for rel32 FIRST (longer encoding), then fall back to rel8
            if bytes.len() >= 5 && (bytes[0] == 0x0F || bytes[0] == 0xE9) {
                // 0F 8x (Jcc rel32) or E9 (JMP rel32)
                let start = if bytes[0] == 0x0F { 2 } else { 1 };
                if bytes.len() >= start + 4 {
                    let rel = i32::from_le_bytes([
                        bytes[start], bytes[start + 1], bytes[start + 2], bytes[start + 3]
                    ]) as i64;
                    return format!("rel32({:+})", rel);
                }
            }
            if bytes.len() >= 2 {
                let rel = bytes[1] as i8 as i64;
                format!("rel8({:+})", rel)
            } else {
                String::new()
            }
        }
        InstructionKind::Call => {
            if bytes.len() >= 5 && bytes[0] == 0xE8 {
                let rel = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as i64;
                format!("rel32({:+})", rel)
            } else {
                String::new()
            }
        }
        _ => String::new(),
    }
}

// ─── LDE: Length Disassembler Engine (x86/x64) ───────────────────────
// Reused from cfg-builder with full instruction classification.

fn lde_classify(code: &[u8], is_64bit: bool) -> (usize, InstructionKind) {
    if code.is_empty() {
        return (1, InstructionKind::Unknown);
    }

    let mut pos = 0;

    // Skip legacy prefixes (up to 4)
    while pos < code.len() && pos < 4 {
        match code[pos] {
            0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 | 0x66 | 0x67 => {
                pos += 1;
            }
            _ => break,
        }
    }

    // REX prefix in 64-bit mode
    if is_64bit && pos < code.len() && (code[pos] & 0xF0) == 0x40 {
        pos += 1;
    }

    if pos >= code.len() {
        return (pos.max(1), InstructionKind::Unknown);
    }

    let opcode = code[pos];
    pos += 1;

    // Two-byte opcode escape
    if opcode == 0x0F && pos < code.len() {
        let second = code[pos];
        pos += 1;

        // 0F 80-8F: Jcc rel32
        if second >= 0x80 && second <= 0x8F {
            return (pos + 4, InstructionKind::ConditionalBranch);
        }

        // 0F 90-9F: SETcc (ModR/M)
        if second >= 0x90 && second <= 0x9F {
            let len = if pos < code.len() { modrm_length(code[pos]) } else { 0 };
            return (pos + len, InstructionKind::Normal);
        }

        // 0F 40-4F: CMOVcc (ModR/M)
        if second >= 0x40 && second <= 0x4F {
            let len = if pos < code.len() { modrm_length(code[pos]) } else { 0 };
            return (pos + len, InstructionKind::Normal);
        }

        // MOVZX/MOVSX
        if second == 0xB6 || second == 0xB7 || second == 0xBE || second == 0xBF {
            let len = if pos < code.len() { modrm_length(code[pos]) } else { 0 };
            return (pos + len, InstructionKind::Normal);
        }

        // BSF/BSR
        if second == 0xBC || second == 0xBD {
            let len = if pos < code.len() { modrm_length(code[pos]) } else { 0 };
            return (pos + len, InstructionKind::Normal);
        }

        // IMUL r, r/m
        if second == 0xAF {
            let len = if pos < code.len() { modrm_length(code[pos]) } else { 0 };
            return (pos + len, InstructionKind::Normal);
        }

        // No-operand instructions
        if second == 0x31 || second == 0xA2 || second == 0x05 || second == 0x34 {
            return (pos, InstructionKind::Normal);
        }

        // Default: ModR/M
        let len = if pos < code.len() { modrm_length(code[pos]) } else { 0 };
        return (pos + len, InstructionKind::Normal);
    }

    match opcode {
        0xC3 | 0xCB => (pos, InstructionKind::Return),
        0xC2 | 0xCA => (pos + 2, InstructionKind::Return),
        0xE8 => (pos + 4, InstructionKind::Call),
        0xE9 => (pos + 4, InstructionKind::UnconditionalJump),
        0xEB => (pos + 1, InstructionKind::UnconditionalJump),
        0x70..=0x7F => (pos + 1, InstructionKind::ConditionalBranch),
        0xE0..=0xE3 => (pos + 1, InstructionKind::ConditionalBranch),
        0xFF => {
            if pos < code.len() {
                let modrm = code[pos];
                let reg = (modrm >> 3) & 0x07;
                let len = modrm_length(modrm);
                match reg {
                    2 | 3 => (pos + len, InstructionKind::Call),
                    4 | 5 => (pos + len, InstructionKind::UnconditionalJump),
                    _ => (pos + len, InstructionKind::Normal),
                }
            } else {
                (pos, InstructionKind::Unknown)
            }
        }
        0x90 => (pos, InstructionKind::Nop),
        0xCC => (pos, InstructionKind::Nop),
        _ => {
            let extra = operand_size_heuristic(opcode, code.get(pos).copied());
            (pos + extra, InstructionKind::Normal)
        }
    }
}

fn modrm_length(modrm: u8) -> usize {
    let mod_bits = (modrm >> 6) & 0x03;
    let rm = modrm & 0x07;
    let mut len = 1;

    if mod_bits != 3 && rm == 4 {
        len += 1; // SIB
    }

    match mod_bits {
        0 if rm == 5 => len += 4,
        1 => len += 1,
        2 => len += 4,
        _ => {}
    }

    len
}

fn operand_size_heuristic(opcode: u8, next_byte: Option<u8>) -> usize {
    match opcode {
        0x50..=0x5F => 0,
        0xB8..=0xBF => 4,
        0x04 | 0x0C | 0x14 | 0x1C | 0x24 | 0x2C | 0x34 | 0x3C => 1,
        0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D => 4,
        0x80 | 0x82 => next_byte.map(|m| 1 + modrm_length(m) + 1).unwrap_or(2),
        0x81 => next_byte.map(|m| 1 + modrm_length(m) + 4).unwrap_or(5),
        0x83 => next_byte.map(|m| 1 + modrm_length(m) + 1).unwrap_or(2),
        0x88..=0x8B => next_byte.map(|m| modrm_length(m)).unwrap_or(1),
        0x8D => next_byte.map(|m| modrm_length(m)).unwrap_or(1),
        0x84 | 0x85 => next_byte.map(|m| modrm_length(m)).unwrap_or(1),
        0x91..=0x97 => 0,
        0x98 | 0x99 | 0x9B | 0x9C | 0x9D | 0x9E | 0x9F => 0,
        0x6A => 1,
        0x68 => 4,
        0x6B => next_byte.map(|m| modrm_length(m) + 1).unwrap_or(2),
        0x69 => next_byte.map(|m| modrm_length(m) + 4).unwrap_or(5),
        _ => next_byte.map(|m| modrm_length(m)).unwrap_or(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x86_disasm_ret() {
        let disasm = Disassembler::new(Arch::X86, Mode::Mode64).unwrap();
        let code = [0xC3]; // ret
        let insts = disasm.disassemble(&code, 0x1000);
        assert!(!insts.is_empty());
        assert_eq!(insts[0].kind, InstructionKind::Return);
        assert_eq!(insts[0].address, 0x1000);
    }

    #[test]
    fn test_x86_disasm_call() {
        let disasm = Disassembler::new(Arch::X86, Mode::Mode64).unwrap();
        let code = [0xE8, 0x00, 0x01, 0x00, 0x00]; // call +0x100
        let insts = disasm.disassemble(&code, 0x2000);
        assert!(!insts.is_empty());
        assert_eq!(insts[0].kind, InstructionKind::Call);
        assert_eq!(insts[0].size, 5);
    }

    #[test]
    fn test_x86_disasm_sequence() {
        let disasm = Disassembler::new(Arch::X86, Mode::Mode64).unwrap();
        // push rbp; mov rbp, rsp; ret  (roughly)
        let code = [0x55, 0x48, 0x89, 0xE5, 0xC3];
        let insts = disasm.disassemble(&code, 0x0);
        assert!(insts.len() >= 3);
        assert_eq!(insts.last().unwrap().kind, InstructionKind::Return);
    }

    #[test]
    fn test_empty_code() {
        let disasm = Disassembler::new(Arch::X86, Mode::Mode64).unwrap();
        let insts = disasm.disassemble(&[], 0x0);
        assert!(insts.is_empty());
    }

    #[test]
    fn test_disassemble_one() {
        let disasm = Disassembler::new(Arch::X86, Mode::Mode64).unwrap();
        let code = [0x90, 0x90, 0xC3]; // nop; nop; ret
        let one = disasm.disassemble_one(&code, 0x0);
        assert!(one.is_some());
        assert_eq!(one.unwrap().kind, InstructionKind::Nop);
    }
}
