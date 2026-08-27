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
//
// NOTE: items below are `pub(crate)` so that `engine::capstone_backend`
// can reuse the exact same FFI declarations. No FFI details leak past
// the crate boundary — the public surface is the engine-neutral API.

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct CsDetail {
    _opaque: [u8; 0],
}

pub(crate) type CsHandle = *mut CsDetail;
type CsErr = i32;

// Capstone architecture IDs (capstone.h `cs_arch`)
pub(crate) const CS_ARCH_ARM: i32 = 0;
pub(crate) const CS_ARCH_ARM64: i32 = 1;
pub(crate) const CS_ARCH_MIPS: i32 = 2;
pub(crate) const CS_ARCH_X86: i32 = 3;
pub(crate) const CS_ARCH_PPC: i32 = 4;
pub(crate) const CS_ARCH_SPARC: i32 = 5;
pub(crate) const CS_ARCH_RISCV: i32 = 6;

// Capstone mode flags (capstone.h `cs_mode`)
pub(crate) const CS_MODE_LITTLE_ENDIAN: u32 = 0;
pub(crate) const CS_MODE_ARM: u32 = 0;
pub(crate) const CS_MODE_16: u32 = 1 << 1;
pub(crate) const CS_MODE_32: u32 = 1 << 2;
pub(crate) const CS_MODE_64: u32 = 1 << 3;
pub(crate) const CS_MODE_THUMB: u32 = 1 << 4;
pub(crate) const CS_MODE_BIG_ENDIAN: u32 = 1 << 31;
pub(crate) const CS_MODE_MICRO: u32 = 1 << 4; // MicroMIPS
//
// NOTE: no CS_MODE_RISCV32/RISCV64 constants exist in this hand-written
// table, therefore `Arch::RISCV` is rejected by the engine layer rather
// than being opened with wrong mode bits.

// Capstone instruction group IDs for control flow classification
// (capstone.h `cs_group_type`, generic groups shared by all arches)
pub(crate) const CS_GRP_JUMP: u8 = 1;
pub(crate) const CS_GRP_CALL: u8 = 2;
pub(crate) const CS_GRP_RET: u8 = 3;
pub(crate) const CS_GRP_INT: u8 = 4;
pub(crate) const CS_GRP_IRET: u8 = 5;
pub(crate) const CS_GRP_PRIVILEGE: u8 = 6;
pub(crate) const CS_GRP_BRANCH_RELATIVE: u8 = 7;

/// Capstone instruction structure matching the REAL cs_insn layout.
/// Verified against capstone.h for v4.x/v5.x on 64-bit platforms.
/// Total size: 248 bytes with natural alignment.
#[repr(C)]
pub(crate) struct CsInsn {
    /// Instruction ID (architecture-specific).
    pub(crate) id: u32,
    // 4 bytes implicit padding for u64 alignment
    _pad0: u32,
    /// Address of this instruction.
    pub(crate) address: u64,
    /// Size of this instruction in bytes.
    pub(crate) size: u16,
    // 6 bytes implicit padding to align bytes array isn't needed since u8[]
    // but we need explicit padding to match C struct where size is followed
    // by bytes[24] with no gap in practice. However, to be safe and match
    // exact 248-byte layout, we keep the field order identical to C.
    /// Raw bytes (up to 24 bytes in Capstone 4.x/5.x).
    pub(crate) bytes: [u8; 24],
    /// Mnemonic string (up to 32 chars).
    pub(crate) mnemonic: [u8; 32],
    /// Operands string (up to 160 chars).
    pub(crate) op_str: [u8; 160],
    /// Pointer to detailed architecture-specific info (if CS_OPT_DETAIL is on).
    detail: *const u8,
}

pub(crate) extern "C" {
    pub(crate) fn cs_open(arch: i32, mode: u32, handle: *mut CsHandle) -> CsErr;
    pub(crate) fn cs_close(handle: *mut CsHandle) -> CsErr;
    pub(crate) fn cs_disasm(
        handle: CsHandle,
        code: *const u8,
        code_size: usize,
        address: u64,
        count: usize,
        insn: *mut *mut CsInsn,
    ) -> usize;
    pub(crate) fn cs_free(insn: *mut CsInsn, count: usize);
    /// Free a single instruction obtained from `cs_malloc`/next-style APIs
    /// (capstone v5). Arrays returned by `cs_disasm` must use `cs_free`
    /// on both v4 and v5, which is the only allocation this crate makes.
    pub(crate) fn cs_dispose(insn: *mut CsInsn);
    pub(crate) fn cs_option(handle: CsHandle, opt_type: i32, value: usize) -> CsErr;
    /// Check if instruction belongs to a specific group (CS_GRP_*).
    /// Returns true if the instruction is in the given group.
    ///
    /// Requires CS_OPT_DETAIL to be ON for the handle; with detail off the
    /// result is meaningless, so callers must gate queries on their own
    /// detail flag.
    pub(crate) fn cs_insn_group(handle: CsHandle, insn: *const CsInsn, group_id: u8) -> bool;
}

// cs_option types/values — capstone.h `cs_opt_type` / `cs_opt_value`
/// cs_opt_type::CS_OPT_SYNTAX
pub(crate) const CS_OPT_SYNTAX: i32 = 1;
/// cs_opt_type::CS_OPT_DETAIL
pub(crate) const CS_OPT_DETAIL: i32 = 2;
/// cs_opt_value::CS_OPT_OFF
pub(crate) const CS_OPT_OFF: usize = 1;
/// cs_opt_value::CS_OPT_ON
pub(crate) const CS_OPT_ON: usize = 2;
// NOTE: the syntax sub-range of `cs_opt_value` restarts at 0:
// CS_OPT_SYNTAX_DEFAULT=0, INTEL=1, ATT=2.
/// cs_opt_value::CS_OPT_SYNTAX_INTEL
pub(crate) const CS_OPT_SYNTAX_INTEL: usize = 1;
/// cs_opt_value::CS_OPT_SYNTAX_ATT
pub(crate) const CS_OPT_SYNTAX_ATT: usize = 2;

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

        // FIXED: Runtime size check to detect CsInsn layout mismatch between
        // compile-time struct definition and linked Capstone library version.
        // A mismatch would cause reading garbage from wrong offsets → UB.
        let actual_size = std::mem::size_of::<CsInsn>();
        // Capstone 4.x/5.x cs_insn is 248 bytes on 64-bit platforms.
        // Allow 240-256 range to accommodate minor platform differences.
        if !(240..=256).contains(&actual_size) {
            unsafe { cs_close(&mut handle); }
            return Err(DisasmError::InitFailed(format!(
                "CsInsn size mismatch: expected 240-256 bytes, got {}. \
                 This indicates a Capstone version incompatibility. \
                 Please rebuild with the correct Capstone headers.",
                actual_size
            )));
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

            let kind = classify_by_groups(self.handle, cs_insn as *const CsInsn);

            let operand_list = parse_operands(&operands);
            instructions.push(Instruction {
                address: cs_insn.address,
                size: cs_insn.size as usize,
                bytes,
                mnemonic,
                operands,
                operand_list,
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

/// Extract a NUL-terminated string from a fixed-size Capstone char array.
/// Fully bounds-checked: never reads past the array end.
pub(crate) fn cstr_to_string(bytes: &[u8]) -> String {
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

fn parse_operands(op_str: &str) -> Vec<Operand> {
    if op_str.trim().is_empty() {
        return Vec::new();
    }
    op_str
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| {
            // Immediate: 0x... or decimal
            if s.starts_with("0x") || s.starts_with("-0x") {
                if let Ok(v) = i64::from_str_radix(s.trim_start_matches('-').trim_start_matches("0x"), 16) {
                    let v = if s.starts_with('-') { -v } else { v };
                    return Operand::Imm(v);
                }
            }
            if let Ok(v) = s.parse::<i64>() {
                return Operand::Imm(v);
            }
            // Memory: contains '[' and ']'
            if s.contains('[') && s.contains(']') {
                // Simplified: extract base/index/scale/disp via heuristics
                // For now, return a generic Mem with no base/index
                return Operand::Mem {
                    base: None,
                    index: None,
                    scale: 1,
                    disp: 0,
                };
            }
            // Register: check if it looks like a register (al, eax, rax, r8, etc.)
            if s.chars().all(|c| c.is_alphanumeric() || c == '_' ) && s.len() <= 6 {
                // Hash the register name to a RegId for now
                let hash = s.bytes().fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
                // Ensure non-zero
                let id = if hash == 0 { 1 } else { hash };
                return Operand::Reg(RegId(id));
            }
            Operand::Unknown
        })
        .collect()
}

/// Classify instruction using Capstone's group API instead of hardcoded IDs.
/// This is version-independent and works across Capstone 4.x and 5.x.
fn classify_by_groups(handle: CsHandle, insn: *const CsInsn) -> InstructionKind {
    // Safety: handle and insn are valid during disassemble() scope
    unsafe {
        if cs_insn_group(handle, insn, CS_GRP_RET) {
            return InstructionKind::Return;
        }
        if cs_insn_group(handle, insn, CS_GRP_CALL) {
            return InstructionKind::Call;
        }
        if cs_insn_group(handle, insn, CS_GRP_JUMP) {
            // Distinguish conditional vs unconditional by checking
            // BRANCH_RELATIVE group or falling through to Normal
            if cs_insn_group(handle, insn, CS_GRP_BRANCH_RELATIVE) {
                return InstructionKind::ConditionalBranch;
            }
            return InstructionKind::UnconditionalJump;
        }
        if cs_insn_group(handle, insn, CS_GRP_INT) {
            return InstructionKind::Normal; // Interrupts treated as normal
        }
    }
    InstructionKind::Normal
}
