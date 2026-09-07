//! Core types for x86/x64 disassembly.

/// Decoded instruction.
#[derive(Debug, Clone)]
pub struct Instruction {
    pub mnemonic: Mnemonic,
    pub operands: Vec<Operand>,
    pub prefixes: Prefixes,
    pub rex: Option<RexPrefix>,
    pub length: usize,
    pub address: u64,
    /// Raw encoded bytes (first `length` entries are valid, rest zeroed).
    pub bytes: [u8; 15],
}

impl Instruction {
    /// Raw encoded bytes of this instruction.
    #[inline]
    pub fn byte_slice(&self) -> &[u8] {
        &self.bytes[..self.length.min(15)]
    }

    /// Absolute target of a direct branch/call (`Operand::Rel`), if any.
    #[inline]
    pub fn branch_target(&self) -> Option<u64> {
        self.operands.iter().find_map(|op| match op {
            Operand::Rel(t) => Some(*t),
            _ => None,
        })
    }

    #[inline]
    pub fn is_call(&self) -> bool {
        self.mnemonic.is_call()
    }

    #[inline]
    pub fn is_ret(&self) -> bool {
        self.mnemonic.is_ret()
    }

    #[inline]
    pub fn is_branch(&self) -> bool {
        self.mnemonic.is_branch()
    }

    /// True for any control-flow transfer (call/jump/branch/ret).
    #[inline]
    pub fn is_control_flow(&self) -> bool {
        self.mnemonic.is_control_flow()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mnemonic {
    // Data movement
    Mov,
    Movzx,
    Movsx,
    Movsxd,
    Lea,
    Push,
    Pop,
    Xchg,
    Cmovcc,
    // Arithmetic
    Add,
    Sub,
    Inc,
    Dec,
    Mul,
    Imul,
    Div,
    Idiv,
    Neg,
    Adc,
    Sbb,
    // Logic
    And,
    Or,
    Xor,
    Not,
    Shl,
    Shr,
    Sar,
    Sal,
    Rol,
    Ror,
    Bsf,
    Bsr,
    Bt,
    Bts,
    Btr,
    Btc,
    // Compare & test
    Cmp,
    Test,
    // Control flow
    Jmp,
    Jcc,
    Call,
    Ret,
    Int,
    Syscall,
    Nop,
    Hlt,
    Ud2,
    // Flags
    Setcc,
    Lahf,
    Sahf,
    Pushfd,
    Popfd,
    Pushfq,
    Popfq_,
    Stc,
    Clc,
    Cmc,
    Std,
    Cld,
    Sti,
    Cli,
    // String ops
    Movsb,
    Movsw,
    Movsd,
    Movsq,
    Stosb,
    Stosw,
    Stosd,
    Stosq,
    Lodsb,
    Lodsw,
    Lodsd,
    Lodsq,
    Scasb,
    Scasw,
    Scasd,
    Scasq,
    Cmpsb,
    Cmpsw,
    Cmpsd,
    Cmpsq,
    Rep,
    Repne,
    // Stack frame
    Enter,
    Leave,
    // Misc
    Cdq,
    Cwd,
    Cbw,
    Cwde,
    Cdqe,
    Bswap,
    Xlat,
    Cpuid,
    Rdtsc,
    // Conditional
    Cmova,
    Cmovae,
    Cmovb,
    Cmovbe,
    Cmove,
    Cmovg,
    Cmovge,
    Cmovl,
    Cmovle,
    Cmovna,
    Cmovnae,
    Cmovnb,
    Cmovnbe,
    Cmovne,
    Cmovng,
    Cmovnge,
    Cmovnl,
    Cmovnle,
    Cmovno,
    Cmovnp,
    Cmovns,
    Cmovnz,
    Cmovo,
    Cmovp,
    Cmovpe,
    Cmovpo,
    Cmovs,
    Cmovz,
    Ja,
    Jae,
    Jb,
    Jbe,
    Je,
    Jg,
    Jge,
    Jl,
    Jle,
    Jna,
    Jnae,
    Jnb,
    Jnbe,
    Jne,
    Jng,
    Jnge,
    Jnl,
    Jnle,
    Jno,
    Jnp,
    Jns,
    Jnz,
    Jo,
    Jp,
    Js,
    Jz,
    // x87 FPU (escape 0xD8..0xDF) and flag/string extras
    Xadd,
    Cmpxchg,
    Cmpxchg8b,
    Loop,
    Loope,
    Loopne,
    Jecxz,
    // Catch-all for mnemonics without a dedicated variant (SSE/AVX/FPU/...).
    Raw(String),
    // Unknown / unimplemented
    Unknown,
}

impl Mnemonic {
    /// True for direct/indirect calls.
    #[inline]
    pub fn is_call(&self) -> bool {
        matches!(self, Self::Call)
    }

    /// True for returns (far returns included; `leave` is NOT a return).
    #[inline]
    pub fn is_ret(&self) -> bool {
        matches!(self, Self::Ret)
    }

    /// True for unconditional jumps (`jmp` only).
    #[inline]
    pub fn is_unconditional_jump(&self) -> bool {
        matches!(self, Self::Jmp)
    }

    /// True for conditional branches (`jcc` family, all `j<cc>` aliases,
    /// loop variants and `jecxz`).
    #[inline]
    pub fn is_conditional_branch(&self) -> bool {
        matches!(
            self,
            Self::Jcc
                | Self::Ja
                | Self::Jae
                | Self::Jb
                | Self::Jbe
                | Self::Je
                | Self::Jg
                | Self::Jge
                | Self::Jl
                | Self::Jle
                | Self::Jna
                | Self::Jnae
                | Self::Jnb
                | Self::Jnbe
                | Self::Jne
                | Self::Jng
                | Self::Jnge
                | Self::Jnl
                | Self::Jnle
                | Self::Jno
                | Self::Jnp
                | Self::Jns
                | Self::Jnz
                | Self::Jo
                | Self::Jp
                | Self::Js
                | Self::Jz
                | Self::Loop
                | Self::Loope
                | Self::Loopne
                | Self::Jecxz
        )
    }

    /// True for any branch (conditional or unconditional).
    #[inline]
    pub fn is_branch(&self) -> bool {
        self.is_unconditional_jump() || self.is_conditional_branch()
    }

    /// True for any control-flow transfer (call/branch/ret).
    ///
    /// Single source of truth — downstream crates (`capstone-ffi`,
    /// `cfg-builder`) must use these helpers instead of their own
    /// mnemonic matches so classifications never drift again.
    #[inline]
    pub fn is_control_flow(&self) -> bool {
        self.is_call() || self.is_branch() || self.is_ret()
    }

    pub fn as_str(&self) -> String {
        let s: &'static str = match self {
            Self::Mov => "mov",
            Self::Movzx => "movzx",
            Self::Movsx => "movsx",
            Self::Movsxd => "movsxd",
            Self::Lea => "lea",
            Self::Push => "push",
            Self::Pop => "pop",
            Self::Xchg => "xchg",
            Self::Add => "add",
            Self::Sub => "sub",
            Self::Inc => "inc",
            Self::Dec => "dec",
            Self::Mul => "mul",
            Self::Imul => "imul",
            Self::Div => "div",
            Self::Idiv => "idiv",
            Self::Neg => "neg",
            Self::Adc => "adc",
            Self::Sbb => "sbb",
            Self::And => "and",
            Self::Or => "or",
            Self::Xor => "xor",
            Self::Not => "not",
            Self::Shl => "shl",
            Self::Shr => "shr",
            Self::Sar => "sar",
            Self::Sal => "sal",
            Self::Rol => "rol",
            Self::Ror => "ror",
            Self::Bsf => "bsf",
            Self::Bsr => "bsr",
            Self::Bt => "bt",
            Self::Bts => "bts",
            Self::Btr => "btr",
            Self::Btc => "btc",
            Self::Cmp => "cmp",
            Self::Test => "test",
            Self::Jmp => "jmp",
            Self::Call => "call",
            Self::Ret => "ret",
            Self::Int => "int",
            Self::Syscall => "syscall",
            Self::Nop => "nop",
            Self::Hlt => "hlt",
            Self::Ud2 => "ud2",
            Self::Setcc => "setcc",
            Self::Lahf => "lahf",
            Self::Sahf => "sahf",
            Self::Stc => "stc",
            Self::Clc => "clc",
            Self::Cmc => "cmc",
            Self::Std => "std",
            Self::Cld => "cld",
            Self::Sti => "sti",
            Self::Cli => "cli",
            Self::Movsb => "movsb",
            Self::Movsw => "movsw",
            Self::Movsd => "movsd",
            Self::Movsq => "movsq",
            Self::Stosb => "stosb",
            Self::Stosw => "stosw",
            Self::Stosd => "stosd",
            Self::Stosq => "stosq",
            Self::Lodsb => "lodsb",
            Self::Lodsw => "lodsw",
            Self::Lodsd => "lodsd",
            Self::Lodsq => "lodsq",
            Self::Enter => "enter",
            Self::Leave => "leave",
            Self::Cdq => "cdq",
            Self::Cwd => "cwd",
            Self::Cbw => "cbw",
            Self::Cwde => "cwde",
            Self::Cdqe => "cdqe",
            Self::Bswap => "bswap",
            Self::Xlat => "xlat",
            Self::Cpuid => "cpuid",
            Self::Rdtsc => "rdtsc",
            Self::Ja => "ja",
            Self::Jae => "jae",
            Self::Jb => "jb",
            Self::Jbe => "jbe",
            Self::Je => "je",
            Self::Jg => "jg",
            Self::Jge => "jge",
            Self::Jl => "jl",
            Self::Jle => "jle",
            Self::Jna => "jna",
            Self::Jnae => "jnae",
            Self::Jnb => "jnb",
            Self::Jnbe => "jnbe",
            Self::Jne => "jne",
            Self::Jng => "jng",
            Self::Jnge => "jnge",
            Self::Jnl => "jnl",
            Self::Jnle => "jnle",
            Self::Jno => "jno",
            Self::Jnp => "jnp",
            Self::Jns => "jns",
            Self::Jnz => "jnz",
            Self::Jo => "jo",
            Self::Jp => "jp",
            Self::Js => "js",
            Self::Jz => "jz",
            Self::Cmova => "cmova",
            Self::Cmovae => "cmovae",
            Self::Cmovb => "cmovb",
            Self::Cmovbe => "cmovbe",
            Self::Cmove => "cmove",
            Self::Cmovg => "cmovg",
            Self::Cmovge => "cmovge",
            Self::Cmovl => "cmovl",
            Self::Cmovle => "cmovle",
            Self::Cmovna => "cmovna",
            Self::Cmovnae => "cmovnae",
            Self::Cmovnb => "cmovnb",
            Self::Cmovnbe => "cmovnbe",
            Self::Cmovne => "cmovne",
            Self::Cmovng => "cmovng",
            Self::Cmovnge => "cmovnge",
            Self::Cmovnl => "cmovnl",
            Self::Cmovnle => "cmovnle",
            Self::Cmovno => "cmovno",
            Self::Cmovnp => "cmovnp",
            Self::Cmovns => "cmovns",
            Self::Cmovnz => "cmovnz",
            Self::Cmovo => "cmovo",
            Self::Cmovp => "cmovp",
            Self::Cmovpe => "cmovpe",
            Self::Cmovpo => "cmovpo",
            Self::Cmovs => "cmovs",
            Self::Cmovz => "cmovz",
            Self::Rep => "rep",
            Self::Repne => "repne",
            Self::Pushfd => "pushfd",
            Self::Popfd => "popfd",
            Self::Pushfq => "pushfq",
            Self::Popfq_ => "popfq",
            Self::Scasb => "scasb",
            Self::Scasw => "scasw",
            Self::Scasd => "scasd",
            Self::Scasq => "scasq",
            Self::Cmpsb => "cmpsb",
            Self::Cmpsw => "cmpsw",
            Self::Cmpsd => "cmpsd",
            Self::Cmpsq => "cmpsq",
            Self::Jcc => "jcc",
            Self::Cmovcc => "cmovcc",
            Self::Xadd => "xadd",
            Self::Cmpxchg => "cmpxchg",
            Self::Cmpxchg8b => "cmpxchg8b",
            Self::Loop => "loop",
            Self::Loope => "loope",
            Self::Loopne => "loopne",
            Self::Jecxz => "jecxz",
            Self::Raw(r) => return r.clone(),
            Self::Unknown => "db",
        };
        s.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    Reg(Register),
    Imm(i64),
    Mem(MemOperand),
    /// Relative offset (for jumps/calls)
    Rel(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    Al,
    Cl,
    Dl,
    Bl,
    Ah,
    Ch,
    Dh,
    Bh,
    Spl,
    Bpl,
    Sil,
    Dil,
    Ax,
    Cx,
    Dx,
    Bx,
    Sp,
    Bp,
    Si,
    Di,
    Eax,
    Ecx,
    Edx,
    Ebx,
    Esp,
    Ebp,
    Esi,
    Edi,
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    R8d,
    R9d,
    R10d,
    R11d,
    R12d,
    R13d,
    R14d,
    R15d,
    R8w,
    R9w,
    R10w,
    R11w,
    R12w,
    R13w,
    R14w,
    R15w,
    R8b,
    R9b,
    R10b,
    R11b,
    R12b,
    R13b,
    R14b,
    R15b,
    Rip,
    Eip,
    Cs,
    Ds,
    Es,
    Fs,
    Gs,
    Ss,
    // SIMD / FPU / system
    Xmm(u8),
    Ymm(u8),
    Zmm(u8),
    Mm(u8),
    St(u8),
    K(u8),
    Cr(u8),
    Dr(u8),
    Tr(u8),
}

impl Register {
    pub fn name(&self) -> String {
        match self {
            Self::Xmm(n) => format!("xmm{}", n),
            Self::Ymm(n) => format!("ymm{}", n),
            Self::Zmm(n) => format!("zmm{}", n),
            Self::Mm(n) => format!("mm{}", n),
            Self::St(n) => format!("st({})", n),
            Self::K(n) => format!("k{}", n),
            Self::Cr(n) => format!("cr{}", n),
            Self::Dr(n) => format!("dr{}", n),
            Self::Tr(n) => format!("tr{}", n),
            other => {
                let s: &'static str = match other {
                    Self::Al => "al",
                    Self::Cl => "cl",
                    Self::Dl => "dl",
                    Self::Bl => "bl",
                    Self::Ah => "ah",
                    Self::Ch => "ch",
                    Self::Dh => "dh",
                    Self::Bh => "bh",
                    Self::Spl => "spl",
                    Self::Bpl => "bpl",
                    Self::Sil => "sil",
                    Self::Dil => "dil",
                    Self::Ax => "ax",
                    Self::Cx => "cx",
                    Self::Dx => "dx",
                    Self::Bx => "bx",
                    Self::Sp => "sp",
                    Self::Bp => "bp",
                    Self::Si => "si",
                    Self::Di => "di",
                    Self::Eax => "eax",
                    Self::Ecx => "ecx",
                    Self::Edx => "edx",
                    Self::Ebx => "ebx",
                    Self::Esp => "esp",
                    Self::Ebp => "ebp",
                    Self::Esi => "esi",
                    Self::Edi => "edi",
                    Self::Rax => "rax",
                    Self::Rcx => "rcx",
                    Self::Rdx => "rdx",
                    Self::Rbx => "rbx",
                    Self::Rsp => "rsp",
                    Self::Rbp => "rbp",
                    Self::Rsi => "rsi",
                    Self::Rdi => "rdi",
                    Self::R8 => "r8",
                    Self::R9 => "r9",
                    Self::R10 => "r10",
                    Self::R11 => "r11",
                    Self::R12 => "r12",
                    Self::R13 => "r13",
                    Self::R14 => "r14",
                    Self::R15 => "r15",
                    Self::R8d => "r8d",
                    Self::R9d => "r9d",
                    Self::R10d => "r10d",
                    Self::R11d => "r11d",
                    Self::R12d => "r12d",
                    Self::R13d => "r13d",
                    Self::R14d => "r14d",
                    Self::R15d => "r15d",
                    Self::R8w => "r8w",
                    Self::R9w => "r9w",
                    Self::R10w => "r10w",
                    Self::R11w => "r11w",
                    Self::R12w => "r12w",
                    Self::R13w => "r13w",
                    Self::R14w => "r14w",
                    Self::R15w => "r15w",
                    Self::R8b => "r8b",
                    Self::R9b => "r9b",
                    Self::R10b => "r10b",
                    Self::R11b => "r11b",
                    Self::R12b => "r12b",
                    Self::R13b => "r13b",
                    Self::R14b => "r14b",
                    Self::R15b => "r15b",
                    Self::Rip => "rip",
                    Self::Eip => "eip",
                    Self::Cs => "cs",
                    Self::Ds => "ds",
                    Self::Es => "es",
                    Self::Fs => "fs",
                    Self::Gs => "gs",
                    Self::Ss => "ss",
                    _ => "?",
                };
                s.to_string()
            }
        }
    }

    pub fn size(&self) -> Option<OperandSize> {
        match self {
            Self::Al
            | Self::Cl
            | Self::Dl
            | Self::Bl
            | Self::Ah
            | Self::Ch
            | Self::Dh
            | Self::Bh
            | Self::Spl
            | Self::Bpl
            | Self::Sil
            | Self::Dil
            | Self::R8b
            | Self::R9b
            | Self::R10b
            | Self::R11b
            | Self::R12b
            | Self::R13b
            | Self::R14b
            | Self::R15b => Some(OperandSize::Byte),
            Self::Ax
            | Self::Cx
            | Self::Dx
            | Self::Bx
            | Self::Sp
            | Self::Bp
            | Self::Si
            | Self::Di
            | Self::R8w
            | Self::R9w
            | Self::R10w
            | Self::R11w
            | Self::R12w
            | Self::R13w
            | Self::R14w
            | Self::R15w => Some(OperandSize::Word),
            Self::Eax
            | Self::Ecx
            | Self::Edx
            | Self::Ebx
            | Self::Esp
            | Self::Ebp
            | Self::Esi
            | Self::Edi
            | Self::R8d
            | Self::R9d
            | Self::R10d
            | Self::R11d
            | Self::R12d
            | Self::R13d
            | Self::R14d
            | Self::R15d => Some(OperandSize::Dword),
            Self::Rax
            | Self::Rcx
            | Self::Rdx
            | Self::Rbx
            | Self::Rsp
            | Self::Rbp
            | Self::Rsi
            | Self::Rdi
            | Self::R8
            | Self::R9
            | Self::R10
            | Self::R11
            | Self::R12
            | Self::R13
            | Self::R14
            | Self::R15
            | Self::Rip
            | Self::Eip => Some(OperandSize::Qword),
            Self::Xmm(_) => Some(OperandSize::Oword),
            Self::Ymm(_) => Some(OperandSize::Yword),
            Self::Zmm(_) => Some(OperandSize::Zword),
            Self::Mm(_) => Some(OperandSize::Qword),
            Self::St(_) => Some(OperandSize::Qword),
            Self::K(_) | Self::Cr(_) | Self::Dr(_) | Self::Tr(_) => Some(OperandSize::Qword),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemOperand {
    pub base: Option<Register>,
    pub index: Option<Register>,
    pub scale: u8, // 1, 2, 4, or 8
    pub displacement: i64,
    pub segment: Option<Register>,
    pub size: OperandSize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperandSize {
    Byte,
    Word,
    Dword,
    Qword,
    Fword,
    Tbyte,
    Oword,
    Yword,
    Zword,
    Unknown,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Prefixes {
    pub lock: bool,
    pub rep: bool,
    pub repne: bool,
    pub cs: bool,
    pub ds: bool,
    pub es: bool,
    pub fs: bool,
    pub gs: bool,
    pub ss: bool,
    pub operand_size_override: bool,
    pub address_size_override: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct RexPrefix {
    pub w: bool,
    pub r: bool,
    pub x: bool,
    pub b: bool,
}

/// Disassembly mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    X16, // 16-bit real mode (DOS/MBR/bootloaders)
    X86, // 32-bit
    X64, // 64-bit
}

impl Mode {
    /// Default operand width in bits for this mode.
    #[inline]
    pub fn default_operand_bits(self) -> u8 {
        match self {
            Mode::X16 => 16,
            Mode::X86 => 32,
            Mode::X64 => 32, // 64-bit needs REX.W for 64-bit operands
        }
    }

    /// Default address width in bits for this mode.
    #[inline]
    pub fn default_address_bits(self) -> u8 {
        match self {
            Mode::X16 => 16,
            Mode::X86 => 32,
            // In long mode 0x67 toggles 64 -> 32 (never to 16).
            Mode::X64 => 64,
        }
    }
}

/// Decode error (never panics).
#[derive(Debug, Clone)]
pub enum DecodeError {
    TooShort,
    InvalidOpcode,
    InvalidModrm,
    InvalidSib,
    MaxLengthExceeded,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort => write!(f, "input too short"),
            Self::InvalidOpcode => write!(f, "invalid opcode"),
            Self::InvalidModrm => write!(f, "invalid ModR/M"),
            Self::InvalidSib => write!(f, "invalid SIB"),
            Self::MaxLengthExceeded => write!(f, "instruction exceeds 15 bytes"),
        }
    }
}

impl std::error::Error for DecodeError {}
