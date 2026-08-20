//! Instruction and operand types for disassembly results.

use serde::{Deserialize, Serialize};

/// A single disassembled instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    /// Address of this instruction in the original binary.
    pub address: u64,
    /// Length in bytes.
    pub size: usize,
    /// Raw bytes.
    pub bytes: Vec<u8>,
    /// Mnemonic (e.g., "mov", "add", "jmp").
    pub mnemonic: String,
    /// Operands as a string (e.g., "eax, ebx").
    pub operands: String,
    /// Parsed operands (if available).
    pub operand_list: Vec<Operand>,
    /// Instruction classification for CFG purposes.
    pub kind: InstructionKind,
}

/// High-level instruction classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstructionKind {
    /// Normal instruction (no control flow change).
    Normal,
    /// Conditional branch.
    ConditionalBranch,
    /// Unconditional jump.
    UnconditionalJump,
    /// Function call.
    Call,
    /// Return.
    Return,
    /// NOP or padding.
    Nop,
    /// Unknown / failed to decode.
    Unknown,
}

/// A single operand in an instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operand {
    /// Register operand.
    Reg(RegId),
    /// Immediate value.
    Imm(i64),
    /// Memory reference: base + index*scale + disp.
    Mem {
        base: Option<RegId>,
        index: Option<RegId>,
        scale: i32,
        disp: i64,
    },
    /// Floating-point immediate.
    Fp(f64),
    /// Unknown operand type.
    Unknown,
}

/// Register identifier (architecture-specific).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegId(pub u32);

impl RegId {
    /// Invalid / no register.
    pub const INVALID: RegId = RegId(0);

    pub fn is_valid(&self) -> bool {
        self.0 != 0
    }
}

impl std::fmt::Display for RegId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "r{}", self.0)
    }
}

impl std::fmt::Display for InstructionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Normal => write!(f, "normal"),
            Self::ConditionalBranch => write!(f, "cond_branch"),
            Self::UnconditionalJump => write!(f, "uncond_jump"),
            Self::Call => write!(f, "call"),
            Self::Return => write!(f, "return"),
            Self::Nop => write!(f, "nop"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}
