//! Dalvik (DEX) bytecode lifter — decodes the 16-bit code-unit instruction
//! stream of a `code_item` into IR.
//!
//! Registers map to `v0..vN`; wide (64-bit) values use the even register of
//! the pair. Method/field/string references stay symbolic (`method@N`) when
//! no resolver is supplied — the scanner layer resolves them against the
//! DEX tables when wiring `/api/decompile`.
//!
//! Unhandled opcodes lift as `Nop` (riscv/ppc lifter convention).

use crate::ir::{IrFunction, IrInst, OpCode, Value};
use crate::lifter::{Lifter, LifterError};
use crate::types::Ty;

/// Optional name resolution for DEX index references.
#[derive(Default)]
pub struct DexNames<'a> {
    pub method: Option<&'a dyn Fn(u32) -> String>,
    pub field: Option<&'a dyn Fn(u32) -> String>,
    pub string: Option<&'a dyn Fn(u32) -> String>,
}

fn method_name(names: &DexNames, idx: u32) -> Value {
    match names.method {
        Some(f) => Value::Symbol(f(idx)),
        None => Value::Symbol(format!("method@{}", idx)),
    }
}

fn field_name(names: &DexNames, idx: u32) -> String {
    match names.field {
        Some(f) => f(idx),
        None => format!("field@{}", idx),
    }
}

fn string_value(names: &DexNames, idx: u32) -> Value {
    match names.string {
        Some(f) => Value::StringRef(f(idx)),
        None => Value::Symbol(format!("string@{}", idx)),
    }
}

fn vreg(n: u16) -> Value {
    Value::Register {
        name: format!("v{}", n),
        ty: Ty::i32(),
    }
}

fn vreg_wide(n: u16) -> Value {
    Value::Register {
        name: format!("v{}", n),
        ty: Ty::i64(),
    }
}

/// The pseudo-register that receives the result of the most recent
/// `invoke`; `move-result` copies it out.
fn retval() -> Value {
    Value::Register {
        name: "retval".to_string(),
        ty: Ty::i32(),
    }
}

/// The pseudo-register holding the condition of the most recent `if` —
/// distinct from `v0..vN` so IR temporaries never shadow dalvik registers.
fn cmp_flag() -> Value {
    Value::Register {
        name: "cmp".to_string(),
        ty: Ty::Bool,
    }
}

/// Instruction size in code units for one opcode (payload pseudo-ops are
/// never decoded linearly — their lead unit reads as `nop` with a non-zero
/// high byte and lands in the `_` arm with size 1).
fn dex_inst_size(opcode: u8) -> usize {
    match opcode {
        0x00 => 1,
        0x01..=0x03 => {
            if opcode == 0x03 {
                3
            } else {
                2
            }
        }
        0x04..=0x06 => {
            if opcode == 0x06 {
                3
            } else {
                2
            }
        }
        0x07..=0x09 => {
            if opcode == 0x09 {
                3
            } else {
                2
            }
        }
        0x0a..=0x0d => 2,
        0x0e..=0x11 => 1,
        0x12 => 1,
        0x13 | 0x15 | 0x16 | 0x19 | 0x1a | 0x1c | 0x1d | 0x1e | 0x1f | 0x21 | 0x22 | 0x60..=0x6d => 2,
        0x14 => 3,
        0x17 => 3,
        0x18 => 5,
        0x1b => 3,
        0x20 | 0x23 | 0x24 => 3,
        0x25 => 3,
        0x26 | 0x2b | 0x2c => 3,
        0x27 => 1,
        0x28 => 1,
        0x29 => 2,
        0x2a => 3,
        0x2d..=0x31 => 3,
        0x32..=0x37 => 2,
        0x38..=0x3d => 2,
        0x44..=0x51 => 2,
        0x52..=0x5f => 2,
        0x6e..=0x72 => 3,
        0x74..=0x78 => 3,
        0x7b..=0x8f => 1,
        0x90..=0xaf => 2,
        0xb0..=0xcf => 1,
        0xd0..=0xd7 => 2,
        0xd8..=0xe2 => 2,
        _ => 1,
    }
}

/// First pass: collect branch-target positions (in code units) so block
/// boundaries are placed where control actually arrives.
fn scan_branch_targets(insns: &[u16]) -> std::collections::HashSet<usize> {
    let mut targets = std::collections::HashSet::new();
    let mut i = 0usize;
    while i < insns.len() {
        let unit = insns[i];
        let opcode = (unit & 0xFF) as u8;
        let size = dex_inst_size(opcode);
        let next = i + size;
        match opcode {
            0x28 => {
                targets.insert((i as i64 + s8(unit >> 8)) as usize);
            }
            0x29 => {
                if let Some(off) = insns.get(i + 1) {
                    targets.insert((i as i64 + s16(*off)) as usize);
                }
            }
            0x2a => {
                if insns.len() >= i + 3 {
                    let off = s32(insns[i + 1], insns[i + 2]);
                    targets.insert((i as i64 + off) as usize);
                }
            }
            0x32..=0x3d => {
                if let Some(off) = insns.get(i + 1) {
                    targets.insert((i as i64 + s16(*off)) as usize);
                }
            }
            _ => {}
        }
        i = next;
    }
    targets
}

fn s4(v: u16) -> i64 {
    ((v as i8) >> 4) as i64
}

fn s8(v: u16) -> i64 {
    v as i8 as i64
}

fn s16(v: u16) -> i64 {
    v as i16 as i64
}

fn s32(lo: u16, hi: u16) -> i64 {
    ((lo as u32) | ((hi as u32) << 16)) as i32 as i64
}

fn u16s_at(insns: &[u16], i: usize) -> Option<u16> {
    insns.get(i).copied()
}

/// Lift one dalvik method's instruction stream.
///
/// `insns` are the code units of a `code_item`; `registers`/`ins` carry the
/// frame shape (parameters occupy the last `ins` registers).
pub fn lift_dex_method(
    insns: &[u16],
    registers: usize,
    name: &str,
    names: &DexNames,
) -> IrFunction {
    let _ = registers;
    let mut func = IrFunction::new(name, 0);
    let mut current_block = func.entry_block;
    let mut block_at: std::collections::HashMap<usize, crate::ir::BlockId> = std::collections::HashMap::new();
    let targets = scan_branch_targets(insns);
    let mut i = 0usize;

    while i < insns.len() {
        // A branch arrives at this position: open a fresh block here (or
        // reuse the one already created for this target).
        if targets.contains(&i) {
            let tb = *block_at.entry(i).or_insert_with(|| {
                func.add_block(&format!("loc_{:04X}", i))
            });
            let needs_fallthrough = func
                .block(current_block)
                .is_some_and(|b| b.terminator().is_none() && !b.insts.is_empty());
            if needs_fallthrough {
                func.push_inst(current_block, IrInst::Branch { target: tb });
            }
            current_block = tb;
        }
        let unit = insns[i];
        let opcode = (unit & 0xFF) as u8;
        let aa = unit >> 8; // 8-bit register / count field
        let a4 = (unit >> 8) & 0xF; // low nibble of byte 2
        let b4 = (unit >> 12) & 0xF; // high nibble of byte 2
        let fmt_units = dex_inst_size(opcode);
        let next = i + fmt_units;
        // Helper: the block starting at `pos`, created on demand.
        let mut block_for =
            |func: &mut IrFunction, pos: usize| -> crate::ir::BlockId {
            if let Some(&b) = block_at.get(&pos) {
                b
            } else {
                let b = func.add_block(&format!("bb_{}", pos));
                block_at.insert(pos, b);
                b
            }
        };

        match opcode {
            0x00 => {
                func.push_inst(current_block, IrInst::Nop);
            }
            // ── moves ─────────────────────────────────────────
            0x01 | 0x04 | 0x07 => {
                // move[-wide|-object] vA, vB (12x)
                func.push_inst(
                    current_block,
                    IrInst::Unary {
                        dst: vreg(a4),
                        op: OpCode::Copy,
                        src: vreg(b4),
                    },
                );
            }
            0x02 | 0x05 | 0x08 => {
                // move/from16 vAA, vBBBB (22x)
                if let Some(src) = u16s_at(insns, i + 1) {
                    func.push_inst(
                        current_block,
                        IrInst::Unary {
                            dst: vreg(aa),
                            op: OpCode::Copy,
                            src: vreg(src),
                        },
                    );
                }
            }
            0x03 | 0x06 | 0x09 => {
                // move/16 vAAAA, vBBBB (32x)
                if let (Some(dst), Some(src)) = (u16s_at(insns, i + 1), u16s_at(insns, i + 2)) {
                    func.push_inst(
                        current_block,
                        IrInst::Unary {
                            dst: vreg(dst),
                            op: OpCode::Copy,
                            src: vreg(src),
                        },
                    );
                }
            }
            0x0a..=0x0c => {
                // move-result[-wide|-object] vAA (11x)
                let dst = if opcode == 0x0b {
                    vreg_wide(aa)
                } else {
                    vreg(aa)
                };
                func.push_inst(
                    current_block,
                    IrInst::Unary {
                        dst,
                        op: OpCode::Copy,
                        src: retval(),
                    },
                );
            }
            0x0d => {
                // move-exception vAA — keep the value visible.
                func.push_inst(
                    current_block,
                    IrInst::Unary {
                        dst: vreg(aa),
                        op: OpCode::Copy,
                        src: Value::Symbol("exception".to_string()),
                    },
                );
            }
            // ── returns ───────────────────────────────────────
            0x0e => {
                func.push_inst(current_block, IrInst::Return { value: None });
            }
            0x0f..=0x11 => {
                func.push_inst(
                    current_block,
                    IrInst::Return {
                        value: Some(vreg(aa)),
                    },
                );
            }
            // ── constants ─────────────────────────────────────
            0x12 => {
                // const/4 vA, #+B (11n, signed 4-bit in the high nibble)
                func.push_inst(
                    current_block,
                    IrInst::Unary {
                        dst: vreg(a4),
                        op: OpCode::Copy,
                        src: Value::Const(s4(unit >> 8)),
                    },
                );
            }
            0x13 => {
                // const/16 vAA, #+BBBB (21s)
                if let Some(imm) = u16s_at(insns, i + 1) {
                    func.push_inst(
                        current_block,
                        IrInst::Unary {
                            dst: vreg(aa),
                            op: OpCode::Copy,
                            src: Value::Const(s16(imm)),
                        },
                    );
                }
            }
            0x14 => {
                // const vAA, #+BBBBBBBB (31i)
                if let (Some(lo), Some(hi)) =
                    (u16s_at(insns, i + 1), u16s_at(insns, i + 2))
                {
                    func.push_inst(
                        current_block,
                        IrInst::Unary {
                            dst: vreg(aa),
                            op: OpCode::Copy,
                            src: Value::Const(s32(lo, hi)),
                        },
                    );
                }
            }
            0x15 => {
                // const/high16 vAA, #+BBBB0000 (21h)
                if let Some(imm) = u16s_at(insns, i + 1) {
                    func.push_inst(
                        current_block,
                        IrInst::Unary {
                            dst: vreg(aa),
                            op: OpCode::Copy,
                            src: Value::Const((imm as i64) << 16),
                        },
                    );
                }
            }
            0x16 => {
                // const-wide/16 vAA, #+BBBB (21s)
                if let Some(imm) = u16s_at(insns, i + 1) {
                    func.push_inst(
                        current_block,
                        IrInst::Unary {
                            dst: vreg_wide(aa),
                            op: OpCode::Copy,
                            src: Value::Const(s16(imm)),
                        },
                    );
                }
            }
            0x17 => {
                // const-wide/32 vAA, #+BBBBBBBB (31i)
                if let (Some(lo), Some(hi)) =
                    (u16s_at(insns, i + 1), u16s_at(insns, i + 2))
                {
                    func.push_inst(
                        current_block,
                        IrInst::Unary {
                            dst: vreg_wide(aa),
                            op: OpCode::Copy,
                            src: Value::Const(s32(lo, hi)),
                        },
                    );
                }
            }
            0x18 => {
                // const-wide vAA, #+BBBBBBBBBBBBBBBB (51l)
                if insns.len() >= i + 5 {
                    let w = (insns[i + 1] as u64)
                        | ((insns[i + 2] as u64) << 16)
                        | ((insns[i + 3] as u64) << 32)
                        | ((insns[i + 4] as u64) << 48);
                    func.push_inst(
                        current_block,
                        IrInst::Unary {
                            dst: vreg_wide(aa),
                            op: OpCode::Copy,
                            src: Value::Const(w as i64),
                        },
                    );
                }
            }
            0x19 => {
                // const-wide/high16 vAA, #+BBBB000000000000 (21h)
                if let Some(imm) = u16s_at(insns, i + 1) {
                    func.push_inst(
                        current_block,
                        IrInst::Unary {
                            dst: vreg_wide(aa),
                            op: OpCode::Copy,
                            src: Value::Const((imm as i64) << 48),
                        },
                    );
                }
            }
            0x1a => {
                // const-string vAA, string@BBBB (21c)
                if let Some(idx) = u16s_at(insns, i + 1) {
                    func.push_inst(
                        current_block,
                        IrInst::Unary {
                            dst: vreg(aa),
                            op: OpCode::Copy,
                            src: string_value(names, idx as u32),
                        },
                    );
                }
            }
            0x1b => {
                // const-string/jumbo vAA, string@BBBBBBBB (31c)
                if let (Some(lo), Some(hi)) =
                    (u16s_at(insns, i + 1), u16s_at(insns, i + 2))
                {
                    let idx = (lo as u32) | ((hi as u32) << 16);
                    func.push_inst(
                        current_block,
                        IrInst::Unary {
                            dst: vreg(aa),
                            op: OpCode::Copy,
                            src: string_value(names, idx),
                        },
                    );
                }
            }
            0x1c => {
                // const-class vAA, type@BBBB (21c)
                if let Some(idx) = u16s_at(insns, i + 1) {
                    func.push_inst(
                        current_block,
                        IrInst::Unary {
                            dst: vreg(aa),
                            op: OpCode::Copy,
                            src: Value::Symbol(format!("class@{}", idx)),
                        },
                    );
                }
            }
            // ── monitor / throw ───────────────────────────────
            0x1d | 0x1e => {
                // monitor-enter/exit vAA — modeled as an opaque call so the
                // operation is not lost.
                func.push_inst(
                    current_block,
                    IrInst::Call {
                        dst: None,
                        target: Value::Symbol(if opcode == 0x1d {
                            "monitor_enter".to_string()
                        } else {
                            "monitor_exit".to_string()
                        }),
                        args: vec![vreg(aa)],
                    },
                );
            }
            0x1f => {
                // check-cast vAA, type@BBBB (21c) — type assertion, no-op
                // in IR.
                func.push_inst(current_block, IrInst::Nop);
            }
            0x20 => {
                // instance-of vA, vB, type@CCCC (22c)
                if let Some(idx) = u16s_at(insns, i + 1) {
                    let cond = func.alloc_var(Ty::Bool);
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: cond.clone(),
                            op: OpCode::Eq,
                            lhs: Value::Symbol(format!("instanceof@{}", idx)),
                            rhs: vreg(b4),
                        },
                    );
                    func.push_inst(
                        current_block,
                        IrInst::Unary {
                            dst: vreg(a4),
                            op: OpCode::Copy,
                            src: cond,
                        },
                    );
                }
            }
            0x21 => {
                // array-length vA, vB (12x)
                let len = func.alloc_var(Ty::i32());
                func.push_inst(
                    current_block,
                    IrInst::Unary {
                        dst: len.clone(),
                        op: OpCode::Copy,
                        src: Value::Register {
                            name: format!("len_{}", b4),
                            ty: Ty::i32(),
                        },
                    },
                );
                func.push_inst(
                    current_block,
                    IrInst::Unary {
                        dst: vreg(a4),
                        op: OpCode::Copy,
                        src: len,
                    },
                );
            }
            0x22 => {
                // new-instance vAA, type@BBBB (21c)
                if let Some(idx) = u16s_at(insns, i + 1) {
                    func.push_inst(
                        current_block,
                        IrInst::Call {
                            dst: Some(vreg(aa)),
                            target: Value::Symbol(format!("new@{}", idx)),
                            args: vec![],
                        },
                    );
                }
            }
            0x23 => {
                // new-array vA, vB, type@CCCC (22c)
                if let Some(idx) = u16s_at(insns, i + 1) {
                    func.push_inst(
                        current_block,
                        IrInst::Call {
                            dst: Some(vreg(a4)),
                            target: Value::Symbol(format!("new_array@{}", idx)),
                            args: vec![vreg(b4)],
                        },
                    );
                }
            }
            0x24 | 0x25 => {
                // filled-new-array[-range] — count + type index.
                func.push_inst(current_block, IrInst::Nop);
            }
            0x26 => {
                // fill-array-data vAA, +BBBBBBBB (31t) — payload
                // initialization; modeled as a memset-style call.
                func.push_inst(
                    current_block,
                    IrInst::Call {
                        dst: None,
                        target: Value::Symbol("fill_array_data".to_string()),
                        args: vec![vreg(aa)],
                    },
                );
            }
            0x27 => {
                // throw vAA
                func.push_inst(
                    current_block,
                    IrInst::Call {
                        dst: None,
                        target: Value::Symbol("throw".to_string()),
                        args: vec![vreg(aa)],
                    },
                );
            }
            // ── branches ──────────────────────────────────────
            0x28 => {
                // goto +AA (10t)
                let target_unit = (i as i64 + s8(aa)) as usize;
                let target = block_for(&mut func, target_unit);
                func.push_inst(current_block, IrInst::Branch { target });
                current_block = block_for(&mut func, next);
            }
            0x29 => {
                // goto/16 +AAAA (20t)
                if let Some(off) = u16s_at(insns, i + 1) {
                    let target_unit = (i as i64 + s16(off)) as usize;
                    let target = block_for(&mut func, target_unit);
                    func.push_inst(current_block, IrInst::Branch { target });
                    current_block = block_for(&mut func, next);
                }
            }
            0x2a => {
                // goto/32 +AAAAAAAA (30t)
                if let (Some(lo), Some(hi)) =
                    (u16s_at(insns, i + 1), u16s_at(insns, i + 2))
                {
                    let target_unit = (i as i64 + s32(lo, hi)) as usize;
                    let target = block_for(&mut func, target_unit);
                    func.push_inst(current_block, IrInst::Branch { target });
                    current_block = block_for(&mut func, next);
                }
            }
            0x2b | 0x2c => {
                // packed/sparse-switch vAA, +BBBBBBBB (31t)
                if let (Some(_lo), Some(_hi)) =
                    (u16s_at(insns, i + 1), u16s_at(insns, i + 2))
                {
                    // The payload tables are not walked here: the lifter
                    // emits an indirect branch so the structuring layer sees
                    // a dispatch point (jump-table recovery happens later,
                    // as with x86).
                    let target = func.alloc_var(Ty::i32());
                    func.push_inst(
                        current_block,
                        IrInst::Unary {
                            dst: target.clone(),
                            op: OpCode::Copy,
                            src: vreg(aa),
                        },
                    );
                    func.push_inst(current_block, IrInst::IndirectBranch { target });
                    current_block = block_for(&mut func, next);
                }
            }
            // ── compares ──────────────────────────────────────
            0x2d..=0x31 => {
                // cmpl/cmpg/cmp-long: vAA = signum(vBB - vCC)
                if let Some(u1) = u16s_at(insns, i + 1) {
                    let bb = u1 & 0xFF;
                    let cc = u1 >> 8;
                    let lt = func.alloc_var(Ty::Bool);
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: lt.clone(),
                            op: if opcode == 0x31 { OpCode::LtS } else { OpCode::LtU },
                            lhs: vreg(bb),
                            rhs: vreg(cc),
                        },
                    );
                    func.push_inst(
                        current_block,
                        IrInst::Unary {
                            dst: vreg(aa),
                            op: OpCode::Copy,
                            src: Value::Symbol(format!("cmp_{}", lt.var_id().unwrap_or(0))),
                        },
                    );
                }
            }
            // ── if-tests (two registers) ──────────────────────
            0x32..=0x37 => {
                if let Some(off) = u16s_at(insns, i + 1) {
                    let op = match opcode {
                        0x32 => OpCode::Eq,
                        0x33 => OpCode::Ne,
                        0x34 => OpCode::LtS,
                        0x35 => OpCode::GeS,
                        0x36 => OpCode::GtS,
                        _ => OpCode::LeS,
                    };
                    let cond = cmp_flag();
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: cond.clone(),
                            op,
                            lhs: vreg(a4),
                            rhs: vreg(b4),
                        },
                    );
                    let target_unit = (i as i64 + s16(off)) as usize;
                    let taken = block_for(&mut func, target_unit);
                    let not_taken = block_for(&mut func, next);
                    func.push_inst(
                        current_block,
                        IrInst::CBranch {
                            cond,
                            target_true: taken,
                            target_false: not_taken,
                        },
                    );
                    current_block = not_taken;
                }
            }
            // ── if-tests (vs zero) ────────────────────────────
            0x38..=0x3d => {
                if let Some(off) = u16s_at(insns, i + 1) {
                    let op = match opcode {
                        0x38 => OpCode::Eq,
                        0x39 => OpCode::Ne,
                        0x3a => OpCode::LtS,
                        0x3b => OpCode::GeS,
                        0x3c => OpCode::GtS,
                        _ => OpCode::LeS,
                    };
                    let cond = cmp_flag();
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: cond.clone(),
                            op,
                            lhs: vreg(aa),
                            rhs: Value::Const(0),
                        },
                    );
                    let target_unit = (i as i64 + s16(off)) as usize;
                    let taken = block_for(&mut func, target_unit);
                    let not_taken = block_for(&mut func, next);
                    func.push_inst(
                        current_block,
                        IrInst::CBranch {
                            cond,
                            target_true: taken,
                            target_false: not_taken,
                        },
                    );
                    current_block = not_taken;
                }
            }
            // ── array element access ──────────────────────────
            0x44..=0x51 => {
                if let Some(u1) = u16s_at(insns, i + 1) {
                    let bb = u1 & 0xFF;
                    let cc = u1 >> 8;
                    let size = match opcode {
                        0x45 | 0x4c => 8, // wide
                        0x4a | 0x47 => 1, // byte
                        0x49 | 0x46 => 2, // char/short
                        _ => 4,
                    };
                    if (0x44..=0x4a).contains(&opcode) {
                        // aget vAA, vBB, vCC
                        func.push_inst(
                            current_block,
                            IrInst::Load {
                                dst: vreg(aa),
                                addr: vreg(bb),
                                size,
                            },
                        );
                    } else {
                        // aput vAA, vBB, vCC (value, array, index)
                        let _ = cc;
                        func.push_inst(
                            current_block,
                            IrInst::Store {
                                addr: vreg(bb),
                                value: vreg(aa),
                                size,
                            },
                        );
                    }
                }
            }
            // ── instance fields ───────────────────────────────
            0x52..=0x5f => {
                if let Some(idx) = u16s_at(insns, i + 1) {
                    let field = field_name(names, idx as u32);
                    if (0x52..=0x58).contains(&opcode) {
                        // iget vA, vB, field@CCCC
                        let src = func.alloc_var(Ty::i32());
                        func.push_inst(
                            current_block,
                            IrInst::Load {
                                dst: src.clone(),
                                addr: Value::Symbol(field),
                                size: 4,
                            },
                        );
                        func.push_inst(
                            current_block,
                            IrInst::Unary {
                                dst: vreg(a4),
                                op: OpCode::Copy,
                                src,
                            },
                        );
                        let _ = b4;
                    } else {
                        // iput vA, vB, field@CCCC
                        func.push_inst(
                            current_block,
                            IrInst::Store {
                                addr: Value::Symbol(field),
                                value: vreg(a4),
                                size: 4,
                            },
                        );
                    }
                }
            }
            // ── static fields ─────────────────────────────────
            0x60..=0x6d => {
                if let Some(idx) = u16s_at(insns, i + 1) {
                    let field = field_name(names, idx as u32);
                    if (0x60..=0x66).contains(&opcode) {
                        // sget vAA, field@BBBB
                        let src = func.alloc_var(Ty::i32());
                        func.push_inst(
                            current_block,
                            IrInst::Load {
                                dst: src.clone(),
                                addr: Value::Symbol(field),
                                size: 4,
                            },
                        );
                        func.push_inst(
                            current_block,
                            IrInst::Unary {
                                dst: vreg(aa),
                                op: OpCode::Copy,
                                src,
                            },
                        );
                    } else {
                        // sput vAA, field@BBBB
                        func.push_inst(
                            current_block,
                            IrInst::Store {
                                addr: Value::Symbol(field),
                                value: vreg(aa),
                                size: 4,
                            },
                        );
                    }
                }
            }
            // ── invocations ───────────────────────────────────
            0x6e..=0x72 => {
                // invoke-kind {vD..vG}, meth@BBBB (35c)
                if insns.len() >= i + 3 {
                    let idx = insns[i + 1];
                    let g = (unit >> 12) & 0xF; // 5th register
                    let c = insns[i + 2] & 0xFF;
                    let d = insns[i + 2] >> 8;
                    let e = insns[i + 3] & 0xFF;
                    let f = insns[i + 3] >> 8;
                    let mut args: Vec<Value> =
                        [c, d, e, f].iter().map(|&r| vreg(r)).collect();
                    if a4 > 4 {
                        args.push(vreg(g));
                    }
                    args.truncate(a4 as usize);
                    func.push_inst(
                        current_block,
                        IrInst::Call {
                            dst: Some(retval()),
                            target: method_name(names, idx as u32),
                            args,
                        },
                    );
                }
            }
            0x74..=0x78 => {
                // invoke-kind/range {vCCCC..vNNNN}, meth@BBBB (3rc)
                if insns.len() >= i + 2 {
                    let idx = insns[i + 1];
                    let first = insns[i + 2];
                    let args: Vec<Value> = (0..aa)
                        .map(|k| vreg(first.wrapping_add(k)))
                        .collect();
                    func.push_inst(
                        current_block,
                        IrInst::Call {
                            dst: Some(retval()),
                            target: method_name(names, idx as u32),
                            args,
                        },
                    );
                }
            }
            // ── unary ops ─────────────────────────────────────
            0x7b => {
                // neg-int vA, vB
                func.push_inst(
                    current_block,
                    IrInst::Binary {
                        dst: vreg(a4),
                        op: OpCode::Sub,
                        lhs: Value::Const(0),
                        rhs: vreg(b4),
                    },
                );
            }
            0x7c => {
                // not-int vA, vB
                func.push_inst(
                    current_block,
                    IrInst::Binary {
                        dst: vreg(a4),
                        op: OpCode::Xor,
                        lhs: vreg(b4),
                        rhs: Value::Const(-1),
                    },
                );
            }
            0x7d => {
                // neg-long
                func.push_inst(
                    current_block,
                    IrInst::Binary {
                        dst: vreg_wide(a4),
                        op: OpCode::Sub,
                        lhs: Value::Const(0),
                        rhs: vreg_wide(b4),
                    },
                );
            }
            0x7e => {
                // not-long
                func.push_inst(
                    current_block,
                    IrInst::Binary {
                        dst: vreg_wide(a4),
                        op: OpCode::Xor,
                        lhs: vreg_wide(b4),
                        rhs: Value::Const(-1),
                    },
                );
            }
            0x7f..=0x8c => {
                // FP conversions — modeled as integer copies; the IR has no
                // FP conversion opcode yet.
                let wide = matches!(opcode, 0x81 | 0x83 | 0x85 | 0x86 | 0x88 | 0x89 | 0x8b);
                func.push_inst(
                    current_block,
                    IrInst::Unary {
                        dst: if wide { vreg_wide(a4) } else { vreg(a4) },
                        op: OpCode::Copy,
                        src: if opcode == 0x81 || opcode == 0x83 || opcode == 0x86 || opcode == 0x89 {
                            vreg(b4)
                        } else {
                            vreg_wide(b4)
                        },
                    },
                );
            }
            0x8d..=0x8f => {
                // int-to-byte/char/short — width threading picks this up
                // from the mask.
                let mask = match opcode {
                    0x8d => 0xFF,
                    0x8e => 0xFFFF,
                    _ => 0xFFFF,
                };
                func.push_inst(
                    current_block,
                    IrInst::Binary {
                        dst: vreg(a4),
                        op: OpCode::And,
                        lhs: vreg(b4),
                        rhs: Value::Const(mask),
                    },
                );
            }
            // ── binary ops ────────────────────────────────────
            0x90..=0xaf => {
                // binop vAA, vBB, vCC (23x)
                if let Some(u1) = u16s_at(insns, i + 1) {
                    let bb = u1 & 0xFF;
                    let cc = u1 >> 8;
                    let op = binop_code(opcode);
                    let wide = (0x9b..=0xa5).contains(&opcode);
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: if wide { vreg_wide(aa) } else { vreg(aa) },
                            op,
                            lhs: if wide { vreg_wide(bb) } else { vreg(bb) },
                            rhs: if wide { vreg_wide(cc) } else { vreg(cc) },
                        },
                    );
                }
            }
            0xb0..=0xcf => {
                // binop/2addr vA, vB (12x)
                let op = binop_code(opcode - 0x20);
                let wide = (0xbb..=0xc5).contains(&opcode);
                func.push_inst(
                    current_block,
                    IrInst::Binary {
                        dst: if wide { vreg_wide(a4) } else { vreg(a4) },
                        op,
                        lhs: if wide { vreg_wide(a4) } else { vreg(a4) },
                        rhs: if wide { vreg_wide(b4) } else { vreg(b4) },
                    },
                );
            }
            0xd0..=0xd7 => {
                // binop/lit16 vA, vB, #+CCCC (22s)
                if let Some(imm) = u16s_at(insns, i + 1) {
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: vreg(a4),
                            op: binop_lit_code(opcode),
                            lhs: vreg(b4),
                            rhs: Value::Const(s16(imm)),
                        },
                    );
                }
            }
            0xd8..=0xe2 => {
                // binop/lit8 vAA, vBB, #+CC (22b)
                if let Some(u1) = u16s_at(insns, i + 1) {
                    let bb = u1 & 0xFF;
                    let cc = s8(u1 >> 8);
                    func.push_inst(
                        current_block,
                        IrInst::Binary {
                            dst: vreg(aa),
                            op: binop_lit_code(opcode),
                            lhs: vreg(bb),
                            rhs: Value::Const(cc),
                        },
                    );
                }
            }
            _ => {
                func.push_inst(current_block, IrInst::Nop);
            }
        }

        // Block-boundary bookkeeping is handled by `block_for` and the
        // targets pre-scan above.
        i = next;
    }

    // Guarantee a terminator for CFG validity.
    if func
        .block(current_block)
        .is_some_and(|b| b.terminator().is_none())
    {
        func.push_inst(current_block, IrInst::Return { value: None });
    }

    func.build_cfg();
    func
}

fn binop_code(opcode: u8) -> OpCode {
    match opcode {
        0x90 => OpCode::Add,
        0x91 => OpCode::Sub,
        0x92 => OpCode::Mul,
        0x93 => OpCode::Div,
        0x94 => OpCode::Mod,
        0x95 => OpCode::And,
        0x96 => OpCode::Or,
        0x97 => OpCode::Xor,
        0x98 => OpCode::Shl,
        0x99 => OpCode::Sar,
        0x9a => OpCode::Shr,
        0x9b => OpCode::Add,
        0x9c => OpCode::Sub,
        0x9d => OpCode::Mul,
        0x9e => OpCode::Div,
        0x9f => OpCode::Mod,
        0xa0 => OpCode::And,
        0xa1 => OpCode::Or,
        0xa2 => OpCode::Xor,
        0xa3 => OpCode::Shl,
        0xa4 => OpCode::Sar,
        0xa5 => OpCode::Shr,
        0xa6 => OpCode::Add,
        0xa7 => OpCode::Sub,
        0xa8 => OpCode::Mul,
        0xa9 => OpCode::Div,
        0xaa => OpCode::Mod,
        0xab => OpCode::Add,
        0xac => OpCode::Sub,
        0xad => OpCode::Mul,
        0xae => OpCode::Div,
        _ => OpCode::Mod,
    }
}

fn binop_lit_code(opcode: u8) -> OpCode {
    match opcode {
        0xd0 | 0xd8 => OpCode::Add,
        0xd1 | 0xd9 => OpCode::Sub,
        0xd2 | 0xda => OpCode::Mul,
        0xd3 | 0xdb => OpCode::Div,
        0xd4 | 0xdc => OpCode::Mod,
        0xd5 | 0xdd => OpCode::And,
        0xd6 | 0xde => OpCode::Or,
        0xd7 | 0xdf => OpCode::Xor,
        0xe0 => OpCode::Shl,
        0xe1 => OpCode::Sar,
        _ => OpCode::Shr,
    }
}

/// Registry adapter: lifts a raw little-endian u16 stream as a dalvik
/// method (used by smoke tooling; the scanner calls `lift_dex_method`
/// directly with resolved names).
pub struct DexLifter {
    max_instructions: usize,
}

impl DexLifter {
    pub fn new() -> Self {
        Self {
            max_instructions: 100_000,
        }
    }
}

impl Default for DexLifter {
    fn default() -> Self {
        Self::new()
    }
}

impl Lifter for DexLifter {
    fn arch_name(&self) -> &str {
        "dex"
    }

    fn max_instructions(&self) -> usize {
        self.max_instructions
    }

    fn lift_function(
        &self,
        code: &[u8],
        base_address: u64,
        function_name: &str,
    ) -> Result<IrFunction, LifterError> {
        // See x86_lifter: clamp hostile base addresses once, up front.
        let _base_address = crate::lifter::clamp_base_address(base_address, code.len());
        let insns: Vec<u16> = code
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let names = DexNames::default();
        let mut func = lift_dex_method(&insns, 16, function_name, &names);
        func.entry_address = _base_address;
        Ok(func)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn const4_add_return() {
        // const/4 v0, #5; const/4 v1, #3; add-int v2, v0, v1; return v2
        let insns: Vec<u16> = vec![
            0x12 | (5 << 12), // 0x5012
            0x12 | (1 << 8) | (3 << 12), // 0x3012
            0x90 | (2 << 8), 0x0100, // add-int v2, v0, v1
            0x0f | (2 << 8),             // return v2
        ];
        let func = lift_dex_method(&insns, 4, "t", &DexNames::default());
        let entry = func.block(func.entry_block).unwrap();
        assert!(matches!(
            entry.insts[0],
            IrInst::Unary { src: Value::Const(5), .. }
        ));
        assert!(matches!(
            entry.insts[2],
            IrInst::Binary { op: OpCode::Add, .. }
        ));
        assert!(matches!(entry.terminator(), Some(IrInst::Return { .. })));
    }

    #[test]
    fn if_eqz_branch() {
        // const/4 v0, #0; if-eqz v0, +4; const/4 v1, #1; return-void
        let insns: Vec<u16> = vec![
            0x12,
            0x38, 4, // if-eqz v0, +4
            0x12 | (1 << 8) | (1 << 12),
            0x0e, // return-void
        ];
        let func = lift_dex_method(&insns, 4, "t", &DexNames::default());
        let entry = func.block(func.entry_block).unwrap();
        assert!(matches!(
            entry.terminator(),
            Some(IrInst::CBranch { .. })
        ));
        assert!(func.blocks.len() >= 3);
    }

    #[test]
    fn invoke_move_result() {
        // invoke-static {}, method@7; move-result v0; return v0
        let insns: Vec<u16> = vec![
            0x71, 7, 0, 0, // invoke-static {} (count 0), method@7
            0x0a, // move-result v0
            0x0f, // return v0
        ];
        let resolve = |idx: u32| format!("java.lang.Math.abs#{}", idx);
        let names = DexNames {
            method: Some(&resolve),
            ..Default::default()
        };
        let func = lift_dex_method(&insns, 4, "t", &names);
        let entry = func.block(func.entry_block).unwrap();
        let call = entry
            .insts
            .iter()
            .find_map(|i| match i {
                IrInst::Call { target, .. } => Some(target.clone()),
                _ => None,
            })
            .expect("call must be lifted");
        match &call {
            Value::Symbol(s) => assert!(s.contains("Math.abs"), "resolver names must flow through: {s}"),
            other => panic!("expected Symbol, got {other:?}"),
        }
    }

    #[test]
    fn string_const_uses_resolver_or_symbol() {
        // const-string v0, string@3
        let insns: Vec<u16> = vec![0x1a, 3, 0x0e];
        let resolve = |idx: u32| format!("str{}", idx);
        let names = DexNames {
            string: Some(&resolve),
            ..Default::default()
        };
        let func = lift_dex_method(&insns, 2, "t", &names);
        let entry = func.block(func.entry_block).unwrap();
        assert!(matches!(
            entry.insts[0],
            IrInst::Unary { src: Value::StringRef(ref s), .. } if s == "str3"
        ));

        let func2 = lift_dex_method(&insns, 2, "t", &DexNames::default());
        let entry2 = func2.block(func2.entry_block).unwrap();
        assert!(matches!(
            entry2.insts[0],
            IrInst::Unary { src: Value::Symbol(ref s), .. } if s == "string@3"
        ));
    }

    #[test]
    fn goto_backward_loop_shape() {
        // const/4 v0, #0; goto +2; const/4 v1, #1; return-void
        let insns: Vec<u16> = vec![0x12, 0x28 | (2 << 8), 0x12 | (1 << 8) | (1 << 12), 0x0e];
        let func = lift_dex_method(&insns, 4, "t", &DexNames::default());
        let entry = func.block(func.entry_block).unwrap();
        assert!(matches!(entry.terminator(), Some(IrInst::Branch { .. })));
    }

    #[test]
    fn aget_load_aput_store() {
        // aget v2, v0, v1; aput v2, v0, v1
        let insns: Vec<u16> = vec![
            0x44 | (2 << 8), 0x0100,
            0x4b | (2 << 8), 0x0100,
            0x0e,
        ];
        let func = lift_dex_method(&insns, 4, "t", &DexNames::default());
        let entry = func.block(func.entry_block).unwrap();
        assert!(entry.insts.iter().any(|i| matches!(i, IrInst::Load { .. })));
        assert!(entry.insts.iter().any(|i| matches!(i, IrInst::Store { .. })));
    }

    #[test]
    fn sget_sput_fields() {
        // sget v0, field@9; sput v0, field@9
        let insns: Vec<u16> = vec![0x60, 9, 0x67, 9, 0x0e];
        let func = lift_dex_method(&insns, 4, "t", &DexNames::default());
        let entry = func.block(func.entry_block).unwrap();
        let has_field = entry.insts.iter().any(|i| match i {
            IrInst::Load { addr, .. } | IrInst::Store { addr, .. } => {
                matches!(addr, Value::Symbol(s) if s == "field@9")
            }
            _ => false,
        });
        assert!(has_field, "field refs must survive as symbols");
    }

    #[test]
    fn binop_lit8() {
        // add-int/lit8 v0, v0, #10
        let insns: Vec<u16> = vec![0xd8, 0x0A00, 0x0e];
        let func = lift_dex_method(&insns, 4, "t", &DexNames::default());
        let entry = func.block(func.entry_block).unwrap();
        assert!(matches!(
            entry.insts[0],
            IrInst::Binary { op: OpCode::Add, rhs: Value::Const(10), .. }
        ));
    }

    #[test]
    fn registry_lifter_by_bytes() {
        let lifter = DexLifter::new();
        let bytes: Vec<u8> = vec![0x12, 0x50, 0x0f, 0x00]; // const/4 v0,#5; return v0
        let func = lifter.lift_function(&bytes, 0, "t").unwrap();
        assert_eq!(func.name, "t");
        assert!(!func.blocks.is_empty());
    }
}
