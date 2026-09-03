//! Raw FFI bindings to the Capstone disassembly engine.
//!
//! Only compiled when `capstone_available` is set (see build.rs).
//! Single source of truth for the C ABI; the only safe wrapper lives in
//! `engine::capstone_backend` (owns `InsnGuard` + `cs_free` discipline).
//! `disassembler::Disassembler` reuses that backend — no duplicate handles.

#![cfg(capstone_available)]

use crate::instruction::{InstructionKind, Operand, RegId};

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

// Note: Capstone handles are NOT thread-safe for concurrent disassembly.
// We intentionally do NOT implement Send/Sync. Wrap in Mutex or use
// per-thread handles.

// ─── Shared helpers (used by engine::capstone_backend) ───────────────

/// Extract a NUL-terminated string from a fixed-size Capstone char array.
/// Fully bounds-checked: never reads past the array end.
pub(crate) fn cstr_to_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Parse Capstone `op_str` into structured operands.
///
/// Uses the shared [`crate::instruction::reg_name_to_id`] table so ids match
/// the LDE path. Memory operands extract base/index/scale/disp with a small
/// heuristic parser instead of returning an empty stub.
pub(crate) fn parse_operands(op_str: &str) -> Vec<Operand> {
    if op_str.trim().is_empty() {
        return Vec::new();
    }
    // Split top-level commas (ignore commas inside brackets).
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut cur = String::new();
    for ch in op_str.chars() {
        match ch {
            '[' => { depth += 1; cur.push(ch); }
            ']' => { depth = depth.saturating_sub(1); cur.push(ch); }
            ',' if depth == 0 => { parts.push(cur.trim().to_string()); cur.clear(); }
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() {
        parts.push(cur.trim().to_string());
    }
    parts.into_iter().filter(|s| !s.is_empty()).map(|s| parse_single_operand(&s)).collect()
}

fn parse_single_operand(s: &str) -> Operand {
    let t = s.trim();
    // Strip segment prefix ("es:[eax]" -> "[eax]").
    let inner_mem = mem_inner(t);
    if let Some(inner) = inner_mem {
        return parse_mem_inner(&inner);
    }
    // Hex immediate (allow trailing comments stripped by caller).
    let first = t.split_whitespace().next().unwrap_or(t);
    let (neg, hex) = match first.strip_prefix("-0x").or(first.strip_prefix("-0X")) {
        Some(h) => (true, h),
        None => match first.strip_prefix("0x").or(first.strip_prefix("0X")) {
            Some(h) => (false, h),
            None => (false, ""),
        },
    };
    if !hex.is_empty() {
        // Stop at first non-hex char (e.g. "0x10+" cases).
        let digits: String = hex.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
        if !digits.is_empty() {
            if let Ok(v) = i64::from_str_radix(&digits, 16) {
                return Operand::Imm(if neg { -v } else { v });
            }
        }
    }
    if let Ok(v) = first.parse::<i64>() {
        return Operand::Imm(v);
    }
    // '#' immediates (ARM: "#-8", "#0x10").
    if let Some(rest) = first.strip_prefix('#') {
        return parse_single_operand(rest);
    }
    // Known register name -> stable id.
    if let Some(id) = crate::instruction::reg_name_to_id(first) {
        return Operand::Reg(id);
    }
    // Short alphanumeric token: likely a register on another arch.
    // Deterministic hash fallback (non-zero, stable across runs).
    if first.len() <= 8 && first.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '.') {
        let hash = first.bytes().fold(0x811c_9dc5u32, |acc, b| {
            acc.wrapping_mul(0x0100_0193).wrapping_add(b as u32)
        });
        return Operand::Reg(RegId(if hash == 0 { 1 } else { hash }));
    }
    Operand::Unknown
}

/// If `t` contains a `[...]` memory expression, return its inner text.
fn mem_inner(t: &str) -> Option<String> {
    let l = t.find('[')?;
    let r = t.rfind(']')?;
    if r > l {
        Some(t[l + 1..r].to_string())
    } else {
        None
    }
}

fn parse_mem_inner(inner: &str) -> Operand {
    let mut base: Option<RegId> = None;
    let mut index: Option<RegId> = None;
    let mut scale: i32 = 1;
    let mut disp: i64 = 0;
    // Split on '+' first, keep '-' attached to displacement.
    for part in inner.split('+') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        // index*scale form.
        if let Some((reg, sc)) = p.split_once('*') {
            let reg = reg.trim();
            let sc = sc.trim().parse::<i32>().unwrap_or(1);
            if let Some(id) = crate::instruction::reg_name_to_id(reg) {
                if base.is_none() {
                    base = Some(id);
                } else if index.is_none() {
                    index = Some(id);
                    scale = sc;
                }
                continue;
            }
        }
        // rip-relative / plain displacement.
        if p.starts_with("0x") || p.starts_with("-0x") || p.parse::<i64>().is_ok() {
            let v = parse_single_operand(p);
            if let Operand::Imm(d) = v {
                disp = disp.wrapping_add(d);
                continue;
            }
        }
        // "reg - 0x10" inside brackets.
        if let Some((reg, rest)) = p.split_once('-') {
            let reg = reg.trim();
            if let Some(id) = crate::instruction::reg_name_to_id(reg) {
                if base.is_none() {
                    base = Some(id);
                } else if index.is_none() {
                    index = Some(id);
                }
                let v = parse_single_operand(rest.trim());
                if let Operand::Imm(d) = v {
                    disp = disp.wrapping_sub(d);
                }
                continue;
            }
        }
        if let Some(id) = crate::instruction::reg_name_to_id(p) {
            if base.is_none() {
                base = Some(id);
            } else if index.is_none() {
                index = Some(id);
            }
            continue;
        }
    }
    Operand::Mem { base, index, scale, disp }
}

/// Classify via Capstone groups + mnemonic fallback.
///
/// Groups are authoritative for ret/call/int. For jumps the generic group
/// cannot separate cond/uncond (both are `JUMP`), so `jmp`/`b` (bare) map to
/// `UnconditionalJump` and any other jump mnemonic to `ConditionalBranch`.
pub(crate) fn classify_by_groups(handle: CsHandle, insn: *const CsInsn, mnemonic: &str) -> InstructionKind {
    unsafe {
        if cs_insn_group(handle, insn, CS_GRP_RET) {
            return InstructionKind::Return;
        }
        if cs_insn_group(handle, insn, CS_GRP_CALL) {
            return InstructionKind::Call;
        }
        if cs_insn_group(handle, insn, CS_GRP_JUMP) {
            let m = mnemonic.to_ascii_lowercase();
            if m == "jmp" || m == "b" || m == "bx" {
                return InstructionKind::UnconditionalJump;
            }
            return InstructionKind::ConditionalBranch;
        }
        // int/iret/privilege: no dedicated InstructionKind — Normal.
    }
    InstructionKind::Normal
}

/// Parse a direct branch target from `op_str` when Capstone renders it as an
/// absolute address (`"0x401005"`). Returns `None` for indirect branches.
pub(crate) fn parse_branch_target(kind: InstructionKind, op_str: &str) -> Option<u64> {
    if !matches!(
        kind,
        InstructionKind::ConditionalBranch | InstructionKind::UnconditionalJump | InstructionKind::Call
    ) {
        return None;
    }
    let first = op_str.split(',').next()?.trim();
    let first = first.split_whitespace().next()?;
    let hex = first.strip_prefix("0x").or_else(|| first.strip_prefix("0X"))?;
    let digits: String = hex.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    if digits.is_empty() {
        return None;
    }
    u64::from_str_radix(&digits, 16).ok()
}
