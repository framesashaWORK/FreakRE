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
    /// Coarse group tags (`"jump"`, `"call"`, `"ret"`, ...) when the
    /// backend runs with detail enabled. Empty on the LDE fallback.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Resolved direct branch/call target (absolute VA) when it can be
    /// determined statically. `None` for non-branches, indirect branches,
    /// and the LDE fallback.
    #[serde(default)]
    pub branch_target: Option<u64>,
}

impl Instruction {
    /// True for any control-flow transfer (call/jump/branch/ret).
    pub fn is_control_flow(&self) -> bool {
        !matches!(
            self.kind,
            InstructionKind::Normal | InstructionKind::Nop | InstructionKind::Unknown
        )
    }

    /// True for conditional + unconditional jumps/branches.
    pub fn is_branch(&self) -> bool {
        matches!(
            self.kind,
            InstructionKind::ConditionalBranch | InstructionKind::UnconditionalJump
        )
    }
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

/// Stable register name table shared by the LDE fallback and the
/// Capstone `op_str` parser, so both paths produce identical `RegId`s.
///
/// Families share one id (AL/AX/EAX/RAX == 1) — enough for CFG/xrefs,
/// and `Display` prints the canonical full-width name (`rax`, not `r1`).
pub fn reg_name_to_id(name: &str) -> Option<RegId> {
    let id = match name.to_ascii_lowercase().as_str() {
        "al" | "ax" | "eax" | "rax" => 1,
        "cl" | "cx" | "ecx" | "rcx" => 2,
        "dl" | "dx" | "edx" | "rdx" => 3,
        "bl" | "bx" | "ebx" | "rbx" => 4,
        "spl" | "sp" | "esp" | "rsp" | "ah" => 5,
        "bpl" | "bp" | "ebp" | "rbp" | "ch" => 6,
        "sil" | "si" | "esi" | "rsi" | "dh" => 7,
        "dil" | "di" | "edi" | "rdi" | "bh" => 8,
        "r8" | "r8d" | "r8w" | "r8b" => 9,
        "r9" | "r9d" | "r9w" | "r9b" => 10,
        "r10" | "r10d" | "r10w" | "r10b" => 11,
        "r11" | "r11d" | "r11w" | "r11b" => 12,
        "r12" | "r12d" | "r12w" | "r12b" => 13,
        "r13" | "r13d" | "r13w" | "r13b" => 14,
        "r14" | "r14d" | "r14w" | "r14b" => 15,
        "r15" | "r15d" | "r15w" | "r15b" => 16,
        "rip" | "eip" => 17,
        _ => return None,
    };
    Some(RegId(id))
}

impl RegId {
    /// Canonical display name for known ids; `r{id}` fallback for
    /// arch-specific / hashed ids from other architectures.
    pub fn name(&self) -> String {
        match self.0 {
            1 => "rax".into(),
            2 => "rcx".into(),
            3 => "rdx".into(),
            4 => "rbx".into(),
            5 => "rsp".into(),
            6 => "rbp".into(),
            7 => "rsi".into(),
            8 => "rdi".into(),
            9 => "r8".into(),
            10 => "r9".into(),
            11 => "r10".into(),
            12 => "r11".into(),
            13 => "r12".into(),
            14 => "r13".into(),
            15 => "r14".into(),
            16 => "r15".into(),
            17 => "rip".into(),
            id if (100..116).contains(&id) => format!("xmm{}", id - 100),
            id if (200..216).contains(&id) => format!("ymm{}", id - 200),
            id if (300..316).contains(&id) => format!("zmm{}", id - 300),
            id => format!("r{}", id),
        }
    }
}

impl std::fmt::Display for RegId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
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
