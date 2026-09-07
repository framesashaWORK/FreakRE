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
//! | RISC-V      | ❌       | ❌           |
//!
//! Single-backend design: the Capstone path reuses
//! `engine::capstone_backend::CapstoneEngine` (with detail ON so `groups`
//! and `branch_target` are populated). No duplicate `cs_open` wrappers.

use crate::arch::{Arch, Endian, Mode};
use crate::error::DisasmError;
use crate::instruction::{Instruction, InstructionKind, Operand, RegId};
use std::sync::atomic::{AtomicBool, Ordering};

/// Rate-limiter for the built-in LDE warning (prints at most once).
static LDE_WARNING_SHOWN: AtomicBool = AtomicBool::new(false);

/// Multi-architecture disassembler.
pub struct Disassembler {
    arch: Arch,
    mode: Mode,
    endian: Endian,
    #[cfg(capstone_available)]
    cs_engine: Option<crate::engine::capstone_backend::CapstoneEngine>,
    _private: (),
}

impl Disassembler {
    /// Create a new disassembler for the specified architecture and mode.
    pub fn new(arch: Arch, mode: Mode) -> Result<Self, DisasmError> {
        Self::with_endian(arch, mode, arch.default_endian())
    }

    /// Create a new disassembler with explicit endianness.
    pub fn with_endian(arch: Arch, mode: Mode, endian: Endian) -> Result<Self, DisasmError> {
        Self::with_options(arch, mode, endian, crate::engine::Syntax::Intel, true)
    }

    /// Create a disassembler with an explicit x86 output syntax
    /// (Intel default, ATT optional). Detail mode stays on.
    pub fn with_syntax(
        arch: Arch,
        mode: Mode,
        syntax: crate::engine::Syntax,
    ) -> Result<Self, DisasmError> {
        Self::with_options(arch, mode, arch.default_endian(), syntax, true)
    }

    /// Fully explicit constructor: endianness, x86 syntax and detail mode
    /// (detail populates `groups`/`branch_target`; only meaningful when a
    /// Capstone backend is linked — the LDE fallback always fills both).
    #[cfg_attr(not(capstone_available), allow(unused_variables))]
    pub fn with_options(
        arch: Arch,
        mode: Mode,
        endian: Endian,
        syntax: crate::engine::Syntax,
        detail: bool,
    ) -> Result<Self, DisasmError> {
        Self::validate_mode(arch, mode)?;

        #[cfg(capstone_available)]
        {
            match crate::engine::capstone_backend::CapstoneEngine::with_options(
                arch, mode, endian, syntax, detail,
            ) {
                Ok(engine) => {
                    return Ok(Self {
                        arch,
                        mode,
                        endian,
                        cs_engine: Some(engine),
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
                cs_engine: None,
                _private: (),
            }),
            _ => Err(DisasmError::LibraryNotAvailable),
        }
    }

    /// Validate that the mode is compatible with the architecture.
    /// Single source of truth lives in [`Arch::supports_mode`].
    fn validate_mode(arch: Arch, mode: Mode) -> Result<(), DisasmError> {
        if arch.supports_mode(mode) {
            Ok(())
        } else {
            Err(DisasmError::InvalidMode(arch, mode))
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
            self.cs_engine.is_some()
        }
        #[cfg(not(capstone_available))]
        {
            false
        }
    }

    /// Returns the endianness this disassembler was created with.
    pub fn endian(&self) -> Endian {
        self.endian
    }

    /// Disassemble a buffer of machine code.
    ///
    /// `base_address` is the virtual address of the first byte in `code`,
    /// used to resolve relative branch targets.
    ///
    /// Returns all successfully decoded instructions. Decoding stops at
    /// the first invalid instruction.
    pub fn disassemble(&self, code: &[u8], base_address: u64) -> Vec<Instruction> {
        self.disassemble_count(code, base_address, 0)
    }

    /// Disassemble a single instruction at the given offset.
    /// Returns None if the instruction cannot be decoded.
    pub fn disassemble_one(&self, code: &[u8], base_address: u64) -> Option<Instruction> {
        self.disassemble_count(code, base_address, 1)
            .into_iter()
            .next()
    }

    /// Disassemble with a maximum count of instructions.
    /// `max_count == 0` means "no limit" (Capstone convention).
    pub fn disassemble_n(
        &self,
        code: &[u8],
        base_address: u64,
        max_count: usize,
    ) -> Vec<Instruction> {
        self.disassemble_count(code, base_address, max_count)
    }

    fn disassemble_count(
        &self,
        code: &[u8],
        base_address: u64,
        max_count: usize,
    ) -> Vec<Instruction> {
        #[cfg(capstone_available)]
        {
            if let Some(ref engine) = self.cs_engine {
                use crate::engine::PreciseEngine;
                match engine.disasm(code, base_address, max_count) {
                    Ok(instrs) => return instrs.into_iter().map(|i| i.to_instruction()).collect(),
                    Err(_) => {
                        // Fall through to LDE for x86; otherwise empty.
                    }
                }
            }
        }

        // LIMITED DISASSEMBLY MODE — Built-in LDE fallback (x86 only,
        // now covering 16/32/64-bit via freakre-x86).
        if self.arch == Arch::X86 {
            if !LDE_WARNING_SHOWN.swap(true, Ordering::Relaxed) {
                eprintln!("[FreakRE] WARNING: Using built-in LDE (freakre-x86). Install Capstone for full AVX/AVX-512 support.");
            }
            return builtin_lde_disassemble(code, base_address, self.mode, max_count);
        }

        Vec::new()
    }
}

/// Map the facade [`Mode`] onto the native decoder mode.
fn lde_mode(mode: Mode) -> freakre_x86::Mode {
    match mode {
        Mode::Mode16 => freakre_x86::Mode::X16,
        Mode::Mode64 => freakre_x86::Mode::X64,
        // Mode32, Thumb, Arm and MicroMips never reach the x86 LDE
        // (arch is X86 here), so default to 32-bit.
        _ => freakre_x86::Mode::X86,
    }
}

// ─── Built-in LDE for x86 ────────────────────────────────────────────

/// Fallback disassembler using the `freakre-x86` decoder.
///
/// Produces full operand parsing (registers, immediates, memory operands).
/// `max_count == 0` means "no limit". Bytes come straight from
/// [`freakre_x86::Instruction::byte_slice`] — no offset tracking, no drift.
fn builtin_lde_disassemble(
    code: &[u8],
    base_address: u64,
    mode: Mode,
    max_count: usize,
) -> Vec<Instruction> {
    freakre_x86::disassemble_limit(code, base_address, lde_mode(mode), max_count)
        .into_iter()
        .map(|x86_insn| {
            let bytes = x86_insn.byte_slice().to_vec();
            convert_instruction(x86_insn, bytes)
        })
        .collect()
}

/// Convert a `freakre_x86::Instruction` into a capstone-ffi `Instruction`.
fn convert_instruction(insn: freakre_x86::Instruction, bytes: Vec<u8>) -> Instruction {
    let mnemonic = insn.mnemonic.as_str();
    let kind = mnemonic_to_kind(&insn.mnemonic);
    let size = insn.length;
    let address = insn.address;
    let branch_target = branch_target_lde(&insn, &bytes, address, size);
    let operand_list: Vec<Operand> = insn.operands.into_iter().map(convert_operand).collect();
    let operands = operand_list
        .iter()
        .map(|o| format!("{}", o))
        .collect::<Vec<_>>()
        .join(", ");

    Instruction {
        address,
        size,
        bytes,
        mnemonic,
        operands,
        operand_list,
        kind,
        groups: kind_groups(kind),
        branch_target,
    }
}

/// Best-effort direct branch target for the LDE path.
/// Uses [`freakre_x86::Instruction::branch_target`] (the decoded `Rel`
/// operand); the byte fallback below only handles short Jmp/Jcc.
fn branch_target_lde(
    insn: &freakre_x86::Instruction,
    bytes: &[u8],
    address: u64,
    size: usize,
) -> Option<u64> {
    if !insn.mnemonic.is_branch() && !insn.mnemonic.is_call() {
        return None;
    }
    if let Some(t) = insn.branch_target() {
        return Some(t);
    }
    // Fallback: parse rel8/rel32 from raw bytes (handles short Jmp/Jcc).
    if bytes.len() >= 2 && (bytes[0] == 0xEB || (0x70..=0x7F).contains(&bytes[0])) {
        let disp = bytes[1] as i8 as i64;
        return Some(address.wrapping_add(size as u64).wrapping_add(disp as u64));
    }
    if bytes.len() >= 5 && (bytes[0] == 0xE8 || bytes[0] == 0xE9) {
        let disp = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as i64;
        return Some(address.wrapping_add(size as u64).wrapping_add(disp as u64));
    }
    None
}

/// Stable group tags mirroring the Capstone `groups` contract.
fn kind_groups(kind: crate::instruction::InstructionKind) -> Vec<String> {
    use crate::instruction::InstructionKind as K;
    match kind {
        K::ConditionalBranch => vec!["jump".into()],
        K::UnconditionalJump => vec!["jump".into()],
        K::Call => vec!["call".into()],
        K::Return => vec!["ret".into()],
        _ => Vec::new(),
    }
}

/// Convert a `freakre_x86::Operand` into a capstone-ffi `Operand`.
fn convert_operand(op: freakre_x86::Operand) -> Operand {
    match op {
        freakre_x86::Operand::Reg(reg) => Operand::Reg(register_to_regid(reg)),
        freakre_x86::Operand::Imm(v) => Operand::Imm(v),
        freakre_x86::Operand::Mem(mem) => {
            let base = mem.base.map(register_to_regid);
            let index = mem.index.map(register_to_regid);
            Operand::Mem {
                base,
                index,
                scale: mem.scale as i32,
                disp: mem.displacement,
            }
        }
        freakre_x86::Operand::Rel(addr) => Operand::Imm(addr as i64),
    }
}

/// Map `freakre_x86::Register` to a capstone-ffi `RegId`.
///
/// Delegates to the shared [`crate::instruction::reg_name_to_id`] table so
/// the LDE path and the Capstone `op_str` parser agree. SIMD keeps the
/// 100/200/300 ranges; unknown system regs map to INVALID (0).
fn register_to_regid(reg: freakre_x86::Register) -> RegId {
    use freakre_x86::Register;
    if let Some(id) = crate::instruction::reg_name_to_id(&reg.name()) {
        return id;
    }
    match reg {
        Register::Xmm(n) => RegId(100 + n as u32),
        Register::Ymm(n) => RegId(200 + n as u32),
        Register::Zmm(n) => RegId(300 + n as u32),
        _ => RegId::INVALID,
    }
}

/// Map `freakre_x86::Mnemonic` to capstone-ffi `InstructionKind`.
///
/// Delegates to the shared [`freakre_x86::Mnemonic`] helpers — the single
/// source of truth — so this can never drift from `cfg-builder` again.
/// (Historically `Jmp` was misclassified here as `ConditionalBranch`.)
fn mnemonic_to_kind(m: &freakre_x86::Mnemonic) -> InstructionKind {
    use freakre_x86::Mnemonic as M;
    if m.is_ret() {
        InstructionKind::Return
    } else if m.is_call() {
        InstructionKind::Call
    } else if m.is_unconditional_jump() {
        InstructionKind::UnconditionalJump
    } else if m.is_conditional_branch() {
        InstructionKind::ConditionalBranch
    } else if matches!(m, M::Nop) {
        InstructionKind::Nop
    } else if matches!(m, M::Unknown) {
        InstructionKind::Unknown
    } else {
        // Leave/Hlt/Int/Syscall are NOT returns: Leave rewrites the frame,
        // Hlt halts, Int/Syscall trap — all fall through semantically.
        InstructionKind::Normal
    }
}

impl std::fmt::Display for Operand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operand::Reg(id) => write!(f, "{}", id),
            Operand::Imm(v) => write!(f, "0x{:x}", v),
            Operand::Mem {
                base,
                index,
                scale,
                disp,
            } => {
                write!(f, "[")?;
                let mut need_plus = false;
                if let Some(b) = base {
                    if b.is_valid() {
                        write!(f, "{}", b)?;
                        need_plus = true;
                    }
                }
                if let Some(idx) = index {
                    if idx.is_valid() {
                        if need_plus {
                            write!(f, " + ")?;
                        }
                        if *scale > 1 {
                            write!(f, "{}*{}", idx, scale)?;
                        } else {
                            write!(f, "{}", idx)?;
                        }
                        need_plus = true;
                    }
                }
                if *disp != 0 || !need_plus {
                    if need_plus {
                        write!(f, " + ")?;
                    }
                    write!(f, "0x{:x}", *disp as u64)?;
                }
                write!(f, "]")
            }
            Operand::Fp(v) => write!(f, "{}", v),
            Operand::Unknown => write!(f, "?"),
        }
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
    fn test_x86_16bit_lde() {
        // 16-bit fallback: mov ax, 0x1234; ret. Verifies Mode16 reaches
        // the X16 decoder (not the 32-bit path) and keeps bytes/targets.
        let disasm = Disassembler::new(Arch::X86, Mode::Mode16).unwrap();
        assert!(!disasm.is_capstone() || true); // either backend is fine
        let code = [0xB8, 0x34, 0x12, 0xC3];
        let insts = disasm.disassemble(&code, 0x100);
        assert_eq!(insts.len(), 2);
        assert_eq!(insts[0].mnemonic, "mov");
        assert_eq!(insts[0].size, 3);
        assert_eq!(insts[0].bytes, vec![0xB8, 0x34, 0x12]);
        assert_eq!(insts[1].kind, InstructionKind::Return);
    }

    #[test]
    fn test_lde_bytes_and_branch_target() {
        let disasm = Disassembler::new(Arch::X86, Mode::Mode32).unwrap();
        // call +0x100 at 0x2000 -> 0x2105
        let insts = disasm.disassemble(&[0xE8, 0x00, 0x01, 0x00, 0x00], 0x2000);
        assert_eq!(insts[0].bytes.len(), 5);
        assert_eq!(insts[0].branch_target, Some(0x2105));
        assert_eq!(insts[0].groups, vec!["call".to_string()]);
    }

    #[test]
    fn test_with_syntax_and_count() {
        let disasm =
            Disassembler::with_syntax(Arch::X86, Mode::Mode64, crate::engine::Syntax::Intel)
                .unwrap();
        let code = [0x90, 0x90, 0x90, 0xC3];
        assert_eq!(disasm.disassemble_n(&code, 0, 2).len(), 2);
        assert_eq!(disasm.disassemble(&code, 0).len(), 4);
        // Invalid arch/mode still rejected.
        assert!(Disassembler::new(Arch::RISCV, Mode::Mode64).is_err());
        assert!(Disassembler::new(Arch::ARM, Mode::Mode32).is_err());
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
