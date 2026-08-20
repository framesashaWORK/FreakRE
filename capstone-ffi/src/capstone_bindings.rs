//! Raw FFI bindings to the Capstone disassembly engine.
//!
//! These bindings are only compiled when `capstone_available` cfg is set
//! (determined by build.rs). They provide a safe Rust wrapper around the
//! C Capstone API.

#![cfg(capstone_available)]

use crate::arch::{Arch, Endian, Mode};
use crate::error::DisasmError;
use crate::instruction::{Instruction, InstructionKind, Operand, RegId};

// ─── Raw C FFI declarations ──────────────────────────────────────────

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct CsDetail {
    _opaque: [u8; 0],
}

type CsHandle = *mut CsDetail;
type CsErr = i32;

// Capstone architecture IDs
const CS_ARCH_ARM: i32 = 0;
const CS_ARCH_ARM64: i32 = 1;
const CS_ARCH_MIPS: i32 = 2;
const CS_ARCH_X86: i32 = 3;
const CS_ARCH_PPC: i32 = 4;
const CS_ARCH_SPARC: i32 = 5;
const CS_ARCH_RISCV: i32 = 6;

// Capstone mode flags
const CS_MODE_LITTLE_ENDIAN: u32 = 0;
const CS_MODE_ARM: u32 = 0;
const CS_MODE_16: u32 = 1 << 1;
const CS_MODE_32: u32 = 1 << 2;
const CS_MODE_64: u32 = 1 << 3;
const CS_MODE_THUMB: u32 = 1 << 4;
const CS_MODE_BIG_ENDIAN: u32 = 1 << 31;
const CS_MODE_MICRO: u32 = 1 << 4; // MicroMIPS

// Capstone instruction group IDs for control flow classification
const CS_GRP_JUMP: u8 = 1;
const CS_GRP_CALL: u8 = 2;
const CS_GRP_RET: u8 = 3;
const CS_GRP_INT: u8 = 4;
const CS_GRP_BRANCH_RELATIVE: u8 = 5;

/// Capstone instruction structure matching the REAL cs_insn layout.
/// Verified against capstone.h for v4.x/v5.x on 64-bit platforms.
/// Total size: 248 bytes with natural alignment.
#[repr(C)]
struct CsInsn {
    /// Instruction ID (architecture-specific).
    id: u32,
    // 4 bytes implicit padding for u64 alignment
    _pad0: u32,
    /// Address of this instruction.
    address: u64,
    /// Size of this instruction in bytes.
    size: u16,
    // 6 bytes implicit padding to align bytes array isn't needed since u8[]
    // but we need explicit padding to match C struct where size is followed
    // by bytes[24] with no gap in practice. However, to be safe and match
    // exact 248-byte layout, we keep the field order identical to C.
    /// Raw bytes (up to 24 bytes in Capstone 4.x/5.x).
    bytes: [u8; 24],
    /// Mnemonic string (up to 32 chars).
    mnemonic: [u8; 32],
    /// Operands string (up to 160 chars).
    op_str: [u8; 160],
    /// Pointer to detailed architecture-specific info (if CS_OPT_DETAIL is on).
    detail: *const u8,
}

extern "C" {
    fn cs_open(arch: i32, mode: u32, handle: *mut CsHandle) -> CsErr;
    fn cs_close(handle: *mut CsHandle) -> CsErr;
    fn cs_disasm(
        handle: CsHandle,
        code: *const u8,
        code_size: usize,
        address: u64,
        count: usize,
        insn: *mut *mut CsInsn,
    ) -> usize;
    fn cs_free(insn: *mut CsInsn, count: usize);
    fn cs_option(handle: CsHandle, opt_type: i32, value: usize) -> CsErr;
}

// cs_option types
const CS_OPT_DETAIL: i32 = 1;
const CS_OPT_ON: usize = 3;

// ─── Safe wrapper ────────────────────────────────────────────────────

pub struct CapstoneHandle {
    handle: CsHandle,
    arch: Arch,
    mode: Mode,
}

impl CapstoneHandle {
    pub fn new(arch: Arch, mode: Mode, endian: Endian) -> Result<Self, DisasmError> {
        let cs_arch = match arch {
            Arch::X86 => CS_ARCH_X86,
            Arch::ARM => CS_ARCH_ARM,
            Arch::ARM64 => CS_ARCH_ARM64,
            Arch::MIPS => CS_ARCH_MIPS,
            Arch::PPC => CS_ARCH_PPC,
            Arch::SPARC => CS_ARCH_SPARC,
            Arch::RISCV => CS_ARCH_RISCV,
        };

        let mut cs_mode: u32 = match mode {
            Mode::Mode16 => CS_MODE_16,
            Mode::Mode32 => CS_MODE_32,
            Mode::Mode64 => CS_MODE_64,
            Mode::Thumb => CS_MODE_THUMB,
            Mode::Arm => CS_MODE_ARM,
            Mode::MicroMips => CS_MODE_MICRO | CS_MODE_32,
        };

        // Apply endianness
        match endian {
            Endian::Little => cs_mode |= CS_MODE_LITTLE_ENDIAN,
            Endian::Big => cs_mode |= CS_MODE_BIG_ENDIAN,
        }

        let mut handle: CsHandle = std::ptr::null_mut();
        let err = unsafe { cs_open(cs_arch, cs_mode, &mut handle) };
        if err != 0 || handle.is_null() {
            return Err(DisasmError::InitFailed(format!(
                "cs_open failed with error code {}",
                err
            )));
        }

        // Enable detail mode for instruction classification
        unsafe {
            cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
        }

        Ok(Self { handle, arch, mode })
    }

    pub fn disassemble(&self, code: &[u8], base_address: u64) -> Vec<Instruction> {
        if code.is_empty() {
            return Vec::new();
        }

        let mut insn_ptr: *mut CsInsn = std::ptr::null_mut();
        let count = unsafe {
            cs_disasm(
                self.handle,
                code.as_ptr(),
                code.len(),
                base_address,
                0, // 0 = disassemble all
                &mut insn_ptr,
            )
        };

        if count == 0 || insn_ptr.is_null() {
            return Vec::new();
        }

        let mut instructions = Vec::with_capacity(count);
        let insn_slice = unsafe { std::slice::from_raw_parts(insn_ptr, count) };

        for cs_insn in insn_slice {
            // Safety: clamp size to prevent OOB read from malformed/truncated cs_insn
            let safe_size = (cs_insn.size as usize).min(cs_insn.bytes.len());
            let bytes = cs_insn.bytes[..safe_size].to_vec();
            let mnemonic = cstr_to_string(&cs_insn.mnemonic);
            let operands = cstr_to_string(&cs_insn.op_str);

            let kind = classify_cs_instruction(cs_insn.id, self.arch);

            instructions.push(Instruction {
                address: cs_insn.address,
                size: cs_insn.size as usize,
                bytes,
                mnemonic,
                operands,
                operand_list: Vec::new(), // TODO: parse detail struct for operands
                kind,
            });
        }

        unsafe {
            cs_free(insn_ptr, count);
        }

        instructions
    }
}

impl Drop for CapstoneHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                cs_close(&mut self.handle);
            }
        }
    }
}

// Note: Capstone handles are NOT guaranteed thread-safe for concurrent disassembly.
// We intentionally do NOT implement Send/Sync to prevent data races.
// If sharing is needed, wrap in Mutex or use per-thread handles.

// ─── Helper functions ────────────────────────────────────────────────

fn cstr_to_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Classify a Capstone instruction ID into InstructionKind.
///
/// Capstone provides architecture-specific instruction IDs. We use known
/// ranges and groups to classify control flow instructions. For full
/// accuracy, we'd need the generated instruction enum headers.
fn classify_cs_instruction(id: u32, arch: Arch) -> InstructionKind {
    match arch {
        Arch::X86 => classify_x86(id),
        Arch::ARM => classify_arm(id),
        Arch::ARM64 => classify_arm64(id),
        Arch::MIPS => classify_mips(id),
        _ => InstructionKind::Normal, // Other architectures default to Normal
    }
}

fn classify_x86(id: u32) -> InstructionKind {
    // X86 instruction IDs from Capstone's x86.h
    // X86_INS_RET = 537
    // X86_INS_CALL = 59 (relative), various indirect call IDs exist
    // X86_INS_JMP = 301
    // X86_INS_JA..JG..JLE = range 265-296
    // X86_INS_NOP = 378
    // X86_INS_LOOP.. = 329..331
    match id {
        537 => InstructionKind::Return,    // RET
        59 | 58 => InstructionKind::Call,  // CALL rel, CALL indirect
        301 => InstructionKind::UnconditionalJump, // JMP
        265..=296 => InstructionKind::ConditionalBranch, // Jcc
        329..=331 => InstructionKind::ConditionalBranch, // LOOPcc
        378 => InstructionKind::Nop,       // NOP
        _ => InstructionKind::Normal,
    }
}

fn classify_arm(id: u32) -> InstructionKind {
    // ARM_INS_BX = 25, ARM_INS_BLX = 17, ARM_INS_B = 12, ARM_INS_BL = 13
    // ARM_BX_RET variants etc.
    match id {
        12 | 13 => InstructionKind::ConditionalBranch, // B / BL (conditional in ARM)
        17 => InstructionKind::Call,                    // BLX
        25 => InstructionKind::Return,                  // BX LR (common return pattern)
        _ => InstructionKind::Normal,
    }
}

fn classify_arm64(id: u32) -> InstructionKind {
    // AArch64_INS_BL = 31, AArch64_INS_B = 21, AArch64_INS_RET = 196
    match id {
        31 => InstructionKind::Call,
        196 => InstructionKind::Return,
        21 => InstructionKind::ConditionalBranch,
        _ => InstructionKind::Normal,
    }
}

fn classify_mips(id: u32) -> InstructionKind {
    match id {
        26 => InstructionKind::Call,   // JAL
        25 => InstructionKind::UnconditionalJump, // J
        32 => InstructionKind::Return, // JR $ra
        _ => InstructionKind::Normal,
    }
}
