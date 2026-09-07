//! IR-level cleanups that dramatically improve C readability:
//! - fold CMP/JCC flag patterns into direct comparisons (`a < b`)
//! - eliminate dead flag definitions
//! - propagate single-def copy temporaries within blocks
//! - fuse `t = Load(addr); r = Copy(t)` pairs into a single load

use freakre_ir::{IrFunction, IrInst, OpCode, Ty, Value};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, PartialEq)]
enum FlagBits {
    Zf,
    Cf,
    Sf,
}

fn classify_flag(name: &str) -> Option<FlagBits> {
    match name {
        "flag_zf" => Some(FlagBits::Zf),
        "flag_cf" => Some(FlagBits::Cf),
        "flag_sf" => Some(FlagBits::Sf),
        _ => None,
    }
}

fn is_atom(v: &Value) -> bool {
    matches!(
        v,
        Value::Const(_) | Value::Var { .. } | Value::Register { .. }
    )
}

fn var_id(v: &Value) -> Option<u32> {
    v.var_id()
}

fn negate(op: OpCode) -> OpCode {
    match op {
        OpCode::Eq => OpCode::Ne,
        OpCode::Ne => OpCode::Eq,
        OpCode::LtU => OpCode::GeU,
        OpCode::GeU => OpCode::LtU,
        OpCode::LtS => OpCode::GeS,
        OpCode::GeS => OpCode::LtS,
        other => other,
    }
}

/// One definition site of a flag register (`flag_zf = (a == b)` etc.) as
/// emitted by the lifter after a CMP/SUB.
#[derive(Clone)]
struct FlagDefSite {
    block: freakre_ir::BlockId,
    idx: usize,
    op: OpCode,
    lhs: Value,
    rhs: Value,
}

/// Collect every kind-consistent flag definition in the function:
/// `flag_zf = (a == b)`, `flag_cf = (a <u b)`, `flag_sf = (a <s b)`.
fn collect_flag_defs(func: &IrFunction) -> HashMap<String, Vec<FlagDefSite>> {
    let mut defs: HashMap<String, Vec<FlagDefSite>> = HashMap::new();
    for b in &func.blocks {
        for (idx, inst) in b.insts.iter().enumerate() {
            if let IrInst::Binary {
                dst: Value::Register { name, .. },
                op: def_op @ (OpCode::Eq | OpCode::LtU | OpCode::LtS),
                lhs,
                rhs,
            } = inst
            {
                let consistent = match classify_flag(name) {
                    Some(FlagBits::Zf) => *def_op == OpCode::Eq,
                    Some(FlagBits::Cf) => *def_op == OpCode::LtU,
                    Some(FlagBits::Sf) => *def_op == OpCode::LtS,
                    None => false,
                };
                if consistent && is_atom(lhs) && is_atom(rhs) {
                    defs.entry(name.clone()).or_default().push(FlagDefSite {
                        block: b.id,
                        idx,
                        op: *def_op,
                        lhs: lhs.clone(),
                        rhs: rhs.clone(),
                    });
                }
            }
        }
    }
    defs
}

/// Reverse-postorder ranks (entry = 0); blocks unreachable from entry are
/// absent from the map.
fn rpo_ranks(func: &IrFunction) -> HashMap<freakre_ir::BlockId, usize> {
    let mut postorder: Vec<freakre_ir::BlockId> = Vec::new();
    let mut visited: HashSet<freakre_ir::BlockId> = HashSet::new();
    visited.insert(func.entry_block);
    let mut stack: Vec<(freakre_ir::BlockId, usize)> = vec![(func.entry_block, 0)];
    while let Some(top) = stack.last_mut() {
        let succs = func
            .block(top.0)
            .map(|b| b.successors.clone())
            .unwrap_or_default();
        if top.1 < succs.len() {
            let s = succs[top.1];
            top.1 += 1;
            if visited.insert(s) {
                stack.push((s, 0));
            }
        } else {
            postorder.push(top.0);
            stack.pop();
        }
    }
    postorder
        .into_iter()
        .rev()
        .enumerate()
        .map(|(rank, b)| (b, rank))
        .collect()
}

/// Choose the flag definition that applies at a given use site: among the
/// definitions dominating the use, the latest one wins (by reverse-postorder
/// rank of the defining block, then by position within a shared block).
///
/// When NO definition dominates — loop back-edges reading a flag set later in
/// the body — fall back to the unique global definition, if there is exactly
/// one: reading an architectural flag that was never set on this path is
/// meaningless in pseudocode anyway, and substituting keeps the condition
/// readable instead of leaking `flag_*`.
fn resolve_flag_def(
    defs: &[FlagDefSite],
    use_block: freakre_ir::BlockId,
    use_idx: usize,
    ranks: &HashMap<freakre_ir::BlockId, usize>,
    idom: &HashMap<freakre_ir::BlockId, freakre_ir::BlockId>,
) -> Option<FlagDefSite> {
    ranks.get(&use_block)?;
    let mut best: Option<&FlagDefSite> = None;
    for d in defs {
        let dominates_use = if d.block == use_block {
            d.idx < use_idx
        } else {
            crate::structuring::dominates_with_idom(d.block, use_block, idom)
        };
        if !dominates_use {
            continue;
        }
        let better = match best {
            None => true,
            Some(cur) => {
                let dr = ranks.get(&d.block).copied().unwrap_or(usize::MAX);
                let cr = ranks.get(&cur.block).copied().unwrap_or(usize::MAX);
                (dr, d.idx) > (cr, cur.idx)
            }
        };
        if better {
            best = Some(d);
        }
    }
    if let Some(b) = best {
        return Some(b.clone());
    }
    if defs.len() == 1 {
        return Some(defs[0].clone());
    }
    None
}

/// Decompose `vN = (flag_x OP 0|1)` (either operand order — the lifter may
/// swap them) into `(dst var id, cmp opcode, flag name, tested bit)`.
fn match_flag_cond(inst: &IrInst) -> Option<(u32, OpCode, String, i64)> {
    let dst_id = match inst.dst() {
        Some(Value::Var { id, .. }) => *id,
        _ => return None,
    };
    match inst {
        IrInst::Binary {
            dst: _,
            op: o @ (OpCode::Eq | OpCode::Ne),
            lhs,
            rhs,
        } => {
            let (reg, bit) = match (lhs, rhs) {
                (Value::Register { name, .. }, Value::Const(c)) => (name.clone(), *c),
                (Value::Const(c), Value::Register { name, .. }) => (name.clone(), *c),
                _ => return None,
            };
            if (bit != 0 && bit != 1) || classify_flag(&reg).is_none() {
                return None;
            }
            Some((dst_id, *o, reg, bit))
        }
        _ => None,
    }
}

/// Decompose `vN = And/Or(tA, tB)` over two single-flag comparisons — the
/// lifter's shape for `ja` (`(cf!=1) && (zf!=1)`) and `jbe`
/// (`(cf==1) || (zf==1)`) after a CMP.
fn match_combined_cond(inst: &IrInst) -> Option<(u32, OpCode, u32, u32)> {
    match inst {
        IrInst::Binary {
            dst: Value::Var { id, .. },
            op: o @ (OpCode::And | OpCode::Or),
            lhs: Value::Var { id: a, .. },
            rhs: Value::Var { id: b, .. },
        } => Some((*id, *o, *a, *b)),
        _ => None,
    }
}

/// Rewrite the carry operand of `adc`/`sbb` into the unsigned-carry
/// comparison (`a <u b`) that produced it.
///
/// The x86 lifter emits `adc` with `carry = flag_cf`, i.e. it reads the
/// global carry flag. That single read keeps every `flag_cf = (...)` write
/// in the function "live" (the dead-flag pass keys on the flag *name*), which
/// is the root of the thousands of `flag_cf = ...` lines in decompiled C.
///
/// Replacing the carry with the concrete `(a <u b)` comparison makes `adc`
/// stop reading `flag_cf`; once nothing else reads it either, the defs are
/// removed by `eliminate_dead_flag_defs`.
pub fn fold_adc_carries(func: &mut IrFunction) -> usize {
    let flag_defs = collect_flag_defs(func);
    let ranks = rpo_ranks(func);
    let idom = freakre_ir::ssa::compute_dominators(func);
    let cf_defs = match flag_defs.get("flag_cf") {
        Some(d) if !d.is_empty() => d,
        _ => return 0,
    };

    let mut rewritten = 0usize;
    for bi in 0..func.blocks.len() {
        let bid = func.blocks[bi].id;
        let mut new_insts: Vec<IrInst> = Vec::with_capacity(func.blocks[bi].insts.len());
        for ii in 0..func.blocks[bi].insts.len() {
            // Clone the instruction so we don't hold an immutable borrow of
            // `func` across the `func.alloc_var` call below.
            let inst = func.blocks[bi].insts[ii].clone();
            let (dst, a, b, carry, is_adc) = match inst {
                IrInst::Adc {
                    ref dst,
                    ref a,
                    ref b,
                    ref carry,
                } => (dst, a, b, carry, true),
                IrInst::Sbb {
                    ref dst,
                    ref a,
                    ref b,
                    ref carry,
                } => (dst, a, b, carry, false),
                _ => {
                    new_insts.push(inst.clone());
                    continue;
                }
            };
            // Only rewrite the global-flag carry form; already-folded carries
            // (a SSA var) are left untouched.
            let is_cf = matches!(carry, Value::Register { name, .. } if name == "flag_cf");
            if !is_cf {
                new_insts.push(inst.clone());
                continue;
            }
            let Some(def) = resolve_flag_def(cf_defs, bid, ii, &ranks, &idom) else {
                new_insts.push(inst.clone());
                continue;
            };
            let c = func.alloc_var(Ty::Bool);
            new_insts.push(IrInst::Binary {
                dst: c.clone(),
                op: OpCode::LtU,
                lhs: def.lhs.clone(),
                rhs: def.rhs.clone(),
            });
            if is_adc {
                new_insts.push(IrInst::Adc {
                    dst: dst.clone(),
                    a: a.clone(),
                    b: b.clone(),
                    carry: c.clone(),
                });
            } else {
                new_insts.push(IrInst::Sbb {
                    dst: dst.clone(),
                    a: a.clone(),
                    b: b.clone(),
                    carry: c.clone(),
                });
            }
            rewritten += 1;
        }
        func.blocks[bi].insts = new_insts;
    }
    rewritten
}

pub fn fold_flag_comparisons(func: &mut IrFunction) -> usize {
    let flag_defs = collect_flag_defs(func);
    let ranks = rpo_ranks(func);
    let idom = freakre_ir::ssa::compute_dominators(func);

    // Definition site + count per SSA-ish temp; cond vars must be
    // single-definition to be rewritten in place safely.
    let mut var_sites: HashMap<u32, (usize, usize)> = HashMap::new();
    let mut var_def_counts: HashMap<u32, usize> = HashMap::new();
    for (bi, b) in func.blocks.iter().enumerate() {
        for (ii, inst) in b.insts.iter().enumerate() {
            if let Some(Value::Var { id, .. }) = inst.dst() {
                var_sites.insert(*id, (bi, ii));
                *var_def_counts.entry(*id).or_insert(0) += 1;
            }
        }
    }

    // Collect rewrites against the ORIGINAL instructions first, then apply:
    // rewriting a sub-temp in place would otherwise hide it from the combined
    // condition that still needs to read its flag-comparison shape.
    let mut plans: Vec<(usize, usize, IrInst)> = Vec::new();

    for bi in 0..func.blocks.len() {
        let bid = func.blocks[bi].id;
        for ii in 0..func.blocks[bi].insts.len() {
            // ── Single-flag condition: `vN = (flag_x OP 0|1)` ──
            if let Some((dst_id, op, flag_reg, bit)) = match_flag_cond(&func.blocks[bi].insts[ii]) {
                if var_def_counts.get(&dst_id).copied().unwrap_or(0) != 1 {
                    continue;
                }
                let def = match flag_defs
                    .get(&flag_reg)
                    .and_then(|d| resolve_flag_def(d, bid, ii, &ranks, &idom))
                {
                    Some(d) => d,
                    None => {
                        if std::env::var("FOLD_DEBUG").is_ok() {
                            let ds = flag_defs
                                .get(&flag_reg)
                                .map(|ds| {
                                    ds.iter()
                                        .map(|d| {
                                            format!(
                                                "b{}i{} {:?} {:?} op {:?}",
                                                d.block.0, d.idx, d.lhs, d.rhs, d.op
                                            )
                                        })
                                        .collect::<Vec<_>>()
                                        .join(" | ")
                                })
                                .unwrap_or_default();
                            eprintln!(
                                "[fold] b{} i{}: no applicable def for {} (use blk reaches entry={}); defs: {}",
                                bid.0,
                                ii,
                                flag_reg,
                                ranks.contains_key(&bid),
                                ds
                            );
                        }
                        continue;
                    }
                };
                let set = (bit == 1) != (op == OpCode::Ne);
                let new_op = if set { def.op } else { negate(def.op) };
                plans.push((
                    bi,
                    ii,
                    IrInst::Binary {
                        dst: Value::var(dst_id, Ty::Bool),
                        op: new_op,
                        lhs: def.lhs,
                        rhs: def.rhs,
                    },
                ));
                continue;
            }

            // ── Combined two-flag condition (`ja` / `jbe`) ──
            let (dst_id, comb_op, ta, tb) = match match_combined_cond(&func.blocks[bi].insts[ii]) {
                Some(x) => x,
                None => continue,
            };
            if ta == tb || var_def_counts.get(&dst_id).copied().unwrap_or(0) != 1 {
                continue;
            }
            let ca = var_sites
                .get(&ta)
                .and_then(|&(x, y)| match_flag_cond(&func.blocks[x].insts[y]));
            let cb = var_sites
                .get(&tb)
                .and_then(|&(x, y)| match_flag_cond(&func.blocks[x].insts[y]));
            let ((_, op_a, flag_a, bit_a), (_, op_b, flag_b, bit_b)) = match (ca, cb) {
                (Some(a), Some(b)) => (a, b),
                _ => continue,
            };
            // Only the carry/zero pair maps onto one machine comparison
            // (`a <=u b` / `a >u b`); sf/of pairs would need flag_of, which
            // the lifter never defines.
            let pair_ok = matches!(
                (classify_flag(&flag_a), classify_flag(&flag_b)),
                (Some(FlagBits::Cf), Some(FlagBits::Zf)) | (Some(FlagBits::Zf), Some(FlagBits::Cf))
            );
            if !pair_ok {
                continue;
            }
            let set_a = (bit_a == 1) != (op_a == OpCode::Ne);
            let set_b = (bit_b == 1) != (op_b == OpCode::Ne);
            let result_op = match (comb_op, set_a, set_b) {
                (OpCode::Or, true, true) => OpCode::LeU,
                (OpCode::And, false, false) => OpCode::GtU,
                _ => continue,
            };
            let da = match flag_defs
                .get(&flag_a)
                .and_then(|d| resolve_flag_def(d, bid, ii, &ranks, &idom))
            {
                Some(d) => d,
                None => continue,
            };
            let db = match flag_defs
                .get(&flag_b)
                .and_then(|d| resolve_flag_def(d, bid, ii, &ranks, &idom))
            {
                Some(d) => d,
                None => continue,
            };
            // Both flags must come from the very same CMP/SUB.
            if da.lhs != db.lhs || da.rhs != db.rhs {
                continue;
            }
            plans.push((
                bi,
                ii,
                IrInst::Binary {
                    dst: Value::var(dst_id, Ty::Bool),
                    op: result_op,
                    lhs: da.lhs,
                    rhs: da.rhs,
                },
            ));
        }
    }

    let folded = plans.len();
    for (bi, ii, inst) in plans {
        func.blocks[bi].insts[ii] = inst;
    }
    folded
}

fn flag_used_except(func: &IrFunction, name: &str, except: (usize, usize)) -> bool {
    func.blocks.iter().enumerate().any(|(bi, b)| {
        b.insts.iter().enumerate().any(|(jj, inst)| {
            (bi, jj) != except
                && inst
                    .sources()
                    .iter()
                    .any(|s| matches!(s, Value::Register { name: n, .. } if *n == name))
        })
    })
}

pub fn eliminate_dead_flag_defs(func: &mut IrFunction) -> usize {
    let mut removed = 0;
    loop {
        let mut changed = false;

        // Phase A: dead flag-register definitions.
        // Collect all candidates, verify usage excluding self, then remove
        // bottom-up so indices stay valid (batch instead of one-at-a-time).
        let mut candidates: Vec<(usize, usize)> = Vec::new();
        for (bi, b) in func.blocks.iter().enumerate() {
            for (ii, inst) in b.insts.iter().enumerate() {
                let flag_def = matches!(
                    inst.dst(),
                    Some(Value::Register { name, .. }) if name.starts_with("flag_")
                ) && matches!(inst, IrInst::Binary { .. } | IrInst::Unary { .. });
                if flag_def {
                    candidates.push((bi, ii));
                }
            }
        }
        candidates.sort_unstable_by(|a, b| b.cmp(a)); // descending → safe removal
        for &(bi, ii) in &candidates {
            let name = match &func.blocks[bi].insts[ii].dst() {
                Some(Value::Register { name, .. }) => name.clone(),
                _ => continue,
            };
            if !flag_used_except(func, &name, (bi, ii)) {
                func.blocks[bi].insts.remove(ii);
                removed += 1;
                changed = true;
            }
        }
        if changed {
            continue;
        }

        const FOLDABLE: &[OpCode] = &[
            OpCode::Eq,
            OpCode::Ne,
            OpCode::LtU,
            OpCode::LeU,
            OpCode::GtU,
            OpCode::GeU,
            OpCode::LtS,
            OpCode::LeS,
            OpCode::GtS,
            OpCode::GeS,
        ];

        // Phase B: dead pure/comparison Var temps.
        let mut candidates: Vec<(usize, usize, u32)> = Vec::new();
        for (bi, b) in func.blocks.iter().enumerate() {
            for (ii, inst) in b.insts.iter().enumerate() {
                if inst.is_terminator() {
                    continue;
                }
                let removable = match inst {
                    IrInst::Binary { op, .. } => PURE.contains(op) || FOLDABLE.contains(op),
                    IrInst::Unary {
                        op: OpCode::Copy,
                        src,
                        ..
                    } => is_atom(src),
                    _ => false,
                };
                if !removable {
                    continue;
                }
                if let Some(Value::Var { id, .. }) = inst.dst() {
                    candidates.push((bi, ii, *id));
                }
            }
        }
        candidates.sort_unstable_by(|a, b| b.cmp(a));
        for &(bi, ii, vid) in &candidates {
            let still_used = func.blocks.iter().any(|bb| {
                bb.insts
                    .iter()
                    .any(|i2| i2.sources().iter().any(|s| var_id(s) == Some(vid)))
            });
            if !still_used {
                func.blocks[bi].insts.remove(ii);
                removed += 1;
                changed = true;
            }
        }

        if !changed {
            break;
        }
    }
    removed
}

/// True when the only remaining users of `vid` are other instructions that are
/// themselves queued for removal in the current batch.
fn used_only_by_batch(
    batch: &[(usize, usize, u32)],
    func: &IrFunction,
    self_bi: usize,
    self_ii: usize,
    vid: u32,
) -> bool {
    let mut any_user = false;
    for (bj, bb) in func.blocks.iter().enumerate() {
        for (jj, inst) in bb.insts.iter().enumerate() {
            if bj == self_bi && jj == self_ii {
                continue;
            }
            if inst.sources().iter().any(|s| var_id(s) == Some(vid)) {
                if batch.iter().any(|&(b2, j2, _)| b2 == bj && j2 == jj) {
                    // This user will disappear too — keep checking others.
                    any_user = true;
                } else {
                    return false;
                }
            }
        }
    }
    any_user
}

const PURE: &[OpCode] = &[
    OpCode::Add,
    OpCode::Sub,
    OpCode::And,
    OpCode::Or,
    OpCode::Xor,
    OpCode::Shl,
    OpCode::Shr,
    OpCode::Sar,
];

/// Propagate single-def copy temps within their defining block.
/// Only atomic sources (Const/Var/Register), only same-block uses after the def.
pub fn propagate_block_temps(func: &mut IrFunction) -> usize {
    let mut global_defs: HashMap<u32, usize> = HashMap::new();
    for b in &func.blocks {
        for inst in &b.insts {
            if let Some(Value::Var { id, .. }) = inst.dst() {
                *global_defs.entry(*id).or_insert(0) += 1;
            }
        }
    }

    let mut substituted = 0;
    for bi in 0..func.blocks.len() {
        let mut repl: HashMap<u32, (usize, Value)> = HashMap::new();
        {
            let b = &func.blocks[bi];
            for (ii, inst) in b.insts.iter().enumerate() {
                let dst_id = match inst.dst() {
                    Some(Value::Var { id, .. }) => *id,
                    _ => continue,
                };
                let eligible = match inst {
                    IrInst::Unary {
                        op: OpCode::Copy,
                        src,
                        ..
                    } => is_atom(src),
                    // NOTE: Binary temps are NOT substituted: taking
                    // `sources().first()` would drop the opcode and the rhs,
                    // collapsing `t = rbp - 8` into a bare `rbp`.
                    _ => false,
                };
                if !eligible {
                    continue;
                }
                if global_defs.get(&dst_id).copied().unwrap_or(0) != 1 {
                    continue;
                }
                let src = match inst.sources().first() {
                    Some(&v) if is_atom(v) => v.clone(),
                    _ => continue,
                };
                repl.insert(dst_id, (ii, src));
            }
        }
        if repl.is_empty() {
            continue;
        }

        let b = &mut func.blocks[bi];
        let mut seen_defs: HashSet<u32> = HashSet::new();
        for ii in 0..b.insts.len() {
            match b.insts[ii].dst() {
                Some(Value::Var { id, .. }) => {
                    seen_defs.insert(*id);
                }
                Some(Value::Register { name, .. }) => {
                    // A register written between the copy and its use
                    // invalidates the pending substitution: later uses must
                    // observe the NEW value, not the stale one.
                    repl.retain(
                        |_, (_, src)| !matches!(src, Value::Register { name: n, .. } if n == name),
                    );
                }
                _ => {}
            }
            for s in mutable_sources(&mut b.insts[ii]) {
                if let Value::Var { id, .. } = s {
                    if seen_defs.contains(id) {
                        if let Some((def_ii, v)) = repl.get(id).cloned() {
                            if def_ii < ii {
                                *s = v;
                                substituted += 1;
                            }
                        }
                    }
                }
            }
        }

        // Drop now-unused candidate defs.
        let mut ii = 0;
        while ii < func.blocks[bi].insts.len() {
            let cand_id = match &func.blocks[bi].insts[ii] {
                IrInst::Unary {
                    op: OpCode::Copy,
                    dst,
                    ..
                } => var_id(dst),
                _ => None,
            };
            let drop_here = match cand_id {
                Some(id) => {
                    repl.contains_key(&id) && {
                        let used_elsewhere = func.blocks.iter().enumerate().any(|(bj, bb)| {
                            bb.insts.iter().enumerate().any(|(jj, inst)| {
                                !(bj == bi && jj == ii)
                                    && inst.sources().iter().any(|s| var_id(s) == Some(id))
                            })
                        });
                        !used_elsewhere
                    }
                }
                None => false,
            };
            if drop_here {
                func.blocks[bi].insts.remove(ii);
                continue;
            }
            ii += 1;
        }
    }
    substituted
}

/// Fuse `t = Load{addr}` + `r = Unary{Copy, src: t}` within one block into a
/// single `r = Load{addr}`.
///
/// Safe when `t` has exactly ONE definition in the whole function and is not
/// used anywhere except by that Copy (this covers re-writes between the Load
/// and the Copy as well as stray uses before or after it). The Load keeps its
/// position; its dst becomes `r` and the Copy instruction disappears.
pub fn fuse_load_copies(func: &mut IrFunction) -> usize {
    let mut global_defs: HashMap<u32, usize> = HashMap::new();
    for b in &func.blocks {
        for inst in &b.insts {
            if let Some(Value::Var { id, .. }) = inst.dst() {
                *global_defs.entry(*id).or_insert(0) += 1;
            }
        }
    }

    // Collect fusable (load_idx, copy_idx) pairs per block first, then apply
    // bottom-up so indices stay valid. Pairs are disjoint: the "no other use
    // of t" rule guarantees at most one Copy reads a given temp.
    struct Pair {
        bi: usize,
        load_ii: usize,
        copy_ii: usize,
        new_dst: Value,
    }
    let mut pairs: Vec<Pair> = Vec::new();

    for bi in 0..func.blocks.len() {
        let insts = &func.blocks[bi].insts;
        for (li, inst) in insts.iter().enumerate() {
            let t_id = match inst {
                IrInst::Load {
                    dst: Value::Var { id, .. },
                    ..
                } => *id,
                _ => continue,
            };
            if global_defs.get(&t_id).copied().unwrap_or(0) != 1 {
                continue;
            }
            let ci = match insts[li + 1..].iter().position(|i| {
                matches!(
                    i,
                    IrInst::Unary { op: OpCode::Copy, src, .. }
                        if var_id(src) == Some(t_id)
                )
            }) {
                Some(off) => li + 1 + off,
                None => continue,
            };
            // No other instruction may read t: neither strictly between the
            // Load and the Copy nor anywhere else in the function.
            let used_elsewhere = func.blocks.iter().enumerate().any(|(bj, bb)| {
                bb.insts.iter().enumerate().any(|(jj, i2)| {
                    !(bj == bi && jj == ci) && i2.sources().iter().any(|s| var_id(s) == Some(t_id))
                })
            });
            if used_elsewhere {
                continue;
            }
            let new_dst = match &insts[ci] {
                IrInst::Unary { dst, .. } => dst.clone(),
                _ => continue,
            };
            pairs.push(Pair {
                bi,
                load_ii: li,
                copy_ii: ci,
                new_dst,
            });
        }
    }

    // Remove bottom-up (by copy position within a block) so earlier indices
    // stay valid while applying.
    pairs.sort_unstable_by(|a, b| {
        let ka = (a.bi, a.copy_ii);
        let kb = (b.bi, b.copy_ii);
        kb.cmp(&ka)
    });
    let mut fused = 0;
    for p in &pairs {
        let block = &mut func.blocks[p.bi];
        if let IrInst::Load { dst, .. } = &mut block.insts[p.load_ii] {
            *dst = p.new_dst.clone();
        } else {
            continue;
        }
        block.insts.remove(p.copy_ii);
        fused += 1;
    }
    fused
}

fn mutable_sources(inst: &mut IrInst) -> Vec<&mut Value> {
    match inst {
        IrInst::Binary { lhs, rhs, .. } => vec![lhs, rhs],
        IrInst::Adc { a, b, carry, .. } => vec![a, b, carry],
        IrInst::Sbb { a, b, carry, .. } => vec![a, b, carry],
        IrInst::Unary { src, .. } => vec![src],
        IrInst::Load { addr, .. } => vec![addr],
        IrInst::Store { addr, value, .. } => vec![addr, value],
        IrInst::CBranch { cond, .. } => vec![cond],
        IrInst::Call { target, args, .. } => {
            let mut v = vec![target];
            v.extend(args.iter_mut());
            v
        }
        IrInst::Return { value: Some(v) } => vec![v],
        IrInst::IndirectBranch { target } => vec![target],
        IrInst::Switch { index, .. } => vec![index],
        IrInst::Phi { incoming, .. } => incoming.iter_mut().map(|(_, v)| v).collect(),
        IrInst::Syscall { number, args } => {
            let mut v: Vec<&mut Value> = args.iter_mut().collect();
            if let Some(n) = number {
                v.push(n);
            }
            v
        }
        IrInst::Branch { .. } | IrInst::Nop | IrInst::Return { value: None } => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// t0 = rbp - 8; t1 = Load(t0); rdx = Copy(t1)
    ///
    /// propagate_block_temps must NOT fold the address computation into the
    /// load: substituting `sources().first()` of a Binary would turn
    /// `t0 = rbp + (-8)` into a bare `rbp` and lose the displacement.
    #[test]
    fn test_propagate_does_not_drop_binary_ops() {
        let mut func = IrFunction::new("t", 0x1000);
        let t0 = func.alloc_var(Ty::i64());
        let t1 = func.alloc_var(Ty::i64());
        let rbp = Value::reg("rbp", Ty::i64());
        let rdx = Value::reg("rdx", Ty::i64());

        func.push_inst(
            func.entry_block,
            IrInst::Binary {
                dst: t0.clone(),
                op: OpCode::Add,
                lhs: rbp.clone(),
                rhs: Value::Const(-8),
            },
        );
        func.push_inst(
            func.entry_block,
            IrInst::Load {
                dst: t1.clone(),
                addr: t0.clone(),
                size: 8,
            },
        );
        func.push_inst(
            func.entry_block,
            IrInst::Unary {
                dst: rdx.clone(),
                op: OpCode::Copy,
                src: t1.clone(),
            },
        );
        func.push_inst(func.entry_block, IrInst::Return { value: None });

        propagate_block_temps(&mut func);

        let b = &func.blocks[func.entry_block.0 as usize];
        let addr_is_bare_rbp = b.insts.iter().any(|inst| {
            matches!(
                inst,
                IrInst::Load { addr, .. } if *addr == rbp
            )
        });
        assert!(
            !addr_is_bare_rbp,
            "load address must not be collapsed to a bare register"
        );
        let add_kept = b.insts.iter().any(|inst| match inst {
            IrInst::Binary {
                op: OpCode::Add,
                lhs,
                rhs,
                ..
            } => *lhs == rbp && *rhs == Value::Const(-8),
            _ => false,
        });
        assert!(add_kept, "Binary{{Add, rbp, -8}} must survive propagation");
    }

    /// t1 = Load(rbp); rdx = Copy(t1)  →  rdx = Load(rbp), Copy removed.
    #[test]
    fn test_fuse_load_copy() {
        let mut func = IrFunction::new("t", 0x1000);
        let t1 = func.alloc_var(Ty::i64());
        let rbp = Value::reg("rbp", Ty::i64());
        let rdx = Value::reg("rdx", Ty::i64());
        let entry = func.entry_block;

        func.push_inst(
            entry,
            IrInst::Load {
                dst: t1.clone(),
                addr: rbp.clone(),
                size: 8,
            },
        );
        func.push_inst(
            entry,
            IrInst::Unary {
                dst: rdx.clone(),
                op: OpCode::Copy,
                src: t1.clone(),
            },
        );
        func.push_inst(entry, IrInst::Return { value: None });

        let fused = fuse_load_copies(&mut func);
        assert_eq!(fused, 1);

        let b = &func.blocks[entry.0 as usize];
        assert!(
            !b.insts.iter().any(|i| matches!(
                i,
                IrInst::Unary {
                    op: OpCode::Copy,
                    ..
                }
            )),
            "the copy must be gone"
        );
        let loads: Vec<&IrInst> = b
            .insts
            .iter()
            .filter(|i| matches!(i, IrInst::Load { .. }))
            .collect();
        assert_eq!(loads.len(), 1, "exactly one load must remain");
        assert!(
            matches!(loads[0], IrInst::Load { dst, addr, .. } if *dst == rdx && *addr == rbp),
            "load must now target rdx directly"
        );
    }

    /// A second use of the temp between the Load and the Copy blocks fusion.
    #[test]
    fn test_fuse_load_copy_rejects_intermediate_use() {
        let mut func = IrFunction::new("t", 0x1000);
        let t1 = func.alloc_var(Ty::i64());
        let rbp = Value::reg("rbp", Ty::i64());
        let rdx = Value::reg("rdx", Ty::i64());
        let entry = func.entry_block;

        func.push_inst(
            entry,
            IrInst::Load {
                dst: t1.clone(),
                addr: rbp.clone(),
                size: 8,
            },
        );
        func.push_inst(
            entry,
            IrInst::Store {
                addr: rbp.clone(),
                value: t1.clone(),
                size: 8,
            },
        );
        func.push_inst(
            entry,
            IrInst::Unary {
                dst: rdx.clone(),
                op: OpCode::Copy,
                src: t1.clone(),
            },
        );
        func.push_inst(entry, IrInst::Return { value: None });

        let fused = fuse_load_copies(&mut func);
        assert_eq!(
            fused, 0,
            "temp is used by the Store — fusion must be skipped"
        );
        assert!(
            func.blocks[entry.0 as usize].insts.iter().any(|i| matches!(
                i,
                IrInst::Unary {
                    op: OpCode::Copy,
                    ..
                }
            )),
            "copy must remain untouched"
        );
    }

    /// A temp with more than one definition in the function is never fused.
    #[test]
    fn test_fuse_load_copy_rejects_multi_def() {
        let mut func = IrFunction::new("t", 0x1000);
        let t1 = func.alloc_var(Ty::i64());
        let t2 = func.alloc_var(Ty::i64());
        let rbp = Value::reg("rbp", Ty::i64());
        let rdx = Value::reg("rdx", Ty::i64());
        let entry = func.entry_block;

        // t1 is defined twice (same id used as dst of both loads).
        func.push_inst(
            entry,
            IrInst::Load {
                dst: t1.clone(),
                addr: rbp.clone(),
                size: 8,
            },
        );
        func.push_inst(
            entry,
            IrInst::Load {
                dst: t1.clone(),
                addr: Value::Const(0x40),
                size: 8,
            },
        );
        func.push_inst(
            entry,
            IrInst::Unary {
                dst: t2.clone(),
                op: OpCode::Copy,
                src: t1.clone(),
            },
        );
        func.push_inst(
            entry,
            IrInst::Unary {
                dst: rdx.clone(),
                op: OpCode::Copy,
                src: t2,
            },
        );
        func.push_inst(entry, IrInst::Return { value: None });

        let fused = fuse_load_copies(&mut func);
        assert_eq!(fused, 0, "double-defined temp must not be fused");
    }

    /// The CMP lives in the predecessor block, the Jcc reads the flag in the
    /// next block: `b0 { flag_zf = rax == rcx; } b1 { v = flag_zf != 1; ... }`
    /// must fold to `v = (rax != rcx)` even though def and use differ.
    #[test]
    fn test_fold_across_predecessor_block() {
        let mut func = IrFunction::new("t", 0x1000);
        let cond = func.alloc_var(Ty::Bool);
        let use_b = func.add_block("use");
        let t_b = func.add_block("then");
        let f_b = func.add_block("else");
        let rax = Value::reg("rax", Ty::i64());
        let rcx = Value::reg("rcx", Ty::i64());

        func.push_inst(
            func.entry_block,
            IrInst::Binary {
                dst: Value::reg("flag_zf", Ty::Bool),
                op: OpCode::Eq,
                lhs: rax.clone(),
                rhs: rcx.clone(),
            },
        );
        func.push_inst(func.entry_block, IrInst::Branch { target: use_b });
        // Swapped operand order (const on the left) must match as well.
        func.push_inst(
            use_b,
            IrInst::Binary {
                dst: cond.clone(),
                op: OpCode::Ne,
                lhs: Value::Const(1),
                rhs: Value::reg("flag_zf", Ty::Bool),
            },
        );
        func.push_inst(
            use_b,
            IrInst::CBranch {
                cond: cond.clone(),
                target_true: t_b,
                target_false: f_b,
            },
        );
        func.push_inst(t_b, IrInst::Return { value: None });
        func.push_inst(f_b, IrInst::Return { value: None });
        func.build_cfg();

        let folded = fold_flag_comparisons(&mut func);
        assert_eq!(folded, 1);

        let b = &func.blocks[use_b.0 as usize];
        assert!(
            matches!(
                &b.insts[0],
                IrInst::Binary { dst: _, op: OpCode::Ne, lhs, rhs }
                    if *lhs == rax && *rhs == rcx
            ),
            "cond must fold to (rax != rcx): {:?}",
            b.insts[0]
        );

        // Pipeline parity: dead flag defs are removed right after folding.
        eliminate_dead_flag_defs(&mut func);
        assert!(
            !format!("{:?}", func).contains("flag_zf"),
            "the flag read and its now-dead def must be gone"
        );
    }

    /// Demo-style loop: the entry block tests a flag that the loop body sets
    /// later, so no definition dominates the test. With a unique global
    /// definition the fold still applies (stale-flag semantics are
    /// meaningless in pseudocode).
    #[test]
    fn test_fold_loop_backedge_unique_def() {
        let mut func = IrFunction::new("t", 0x1000);
        let cond = func.alloc_var(Ty::Bool);
        let body_b = func.add_block("body");
        let exit_b = func.add_block("exit");

        func.push_inst(
            func.entry_block,
            IrInst::Binary {
                dst: cond.clone(),
                op: OpCode::Ne,
                lhs: Value::reg("flag_zf", Ty::Bool),
                rhs: Value::Const(1),
            },
        );
        func.push_inst(
            func.entry_block,
            IrInst::CBranch {
                cond: cond.clone(),
                target_true: body_b,
                target_false: exit_b,
            },
        );
        func.push_inst(
            body_b,
            IrInst::Binary {
                dst: Value::reg("flag_zf", Ty::Bool),
                op: OpCode::Eq,
                lhs: Value::reg("rax", Ty::i64()),
                rhs: Value::reg("rcx", Ty::i64()),
            },
        );
        func.push_inst(
            body_b,
            IrInst::Branch {
                target: func.entry_block,
            },
        );
        func.push_inst(exit_b, IrInst::Return { value: None });
        func.build_cfg();

        let folded = fold_flag_comparisons(&mut func);
        assert_eq!(
            folded, 1,
            "unique global def must fold even without dominance"
        );
        let entry = &func.blocks[func.entry_block.0 as usize];
        assert!(
            matches!(
                &entry.insts[0],
                IrInst::Binary { op: OpCode::Ne, lhs, .. }
                    if *lhs == Value::reg("rax", Ty::i64())
            ),
            "cond must become a direct comparison: {:?}",
            entry.insts[0]
        );

        eliminate_dead_flag_defs(&mut func);
        assert!(
            !format!("{:?}", func).contains("flag_"),
            "dead flag defs must be removed after folding:\n{:?}",
            func
        );
    }

    /// Two sequential CMPs redefine the flag; a later test must pick the most
    /// recent dominating definition (the second one), not the first.
    #[test]
    fn test_fold_picks_most_recent_dominating_def() {
        let mut func = IrFunction::new("t", 0x1000);
        let cond = func.alloc_var(Ty::Bool);
        let mid_b = func.add_block("mid");
        let tail_b = func.add_block("tail");
        let t_b = func.add_block("then");
        let f_b = func.add_block("else");

        func.push_inst(
            func.entry_block,
            IrInst::Binary {
                dst: Value::reg("flag_zf", Ty::Bool),
                op: OpCode::Eq,
                lhs: Value::reg("rax", Ty::i64()),
                rhs: Value::reg("rbx", Ty::i64()),
            },
        );
        func.push_inst(func.entry_block, IrInst::Branch { target: mid_b });
        func.push_inst(
            mid_b,
            IrInst::Binary {
                dst: Value::reg("flag_zf", Ty::Bool),
                op: OpCode::Eq,
                lhs: Value::reg("rcx", Ty::i64()),
                rhs: Value::reg("rdx", Ty::i64()),
            },
        );
        func.push_inst(mid_b, IrInst::Branch { target: tail_b });
        func.push_inst(
            tail_b,
            IrInst::Binary {
                dst: cond.clone(),
                op: OpCode::Eq,
                lhs: Value::reg("flag_zf", Ty::Bool),
                rhs: Value::Const(1),
            },
        );
        func.push_inst(
            tail_b,
            IrInst::CBranch {
                cond: cond.clone(),
                target_true: t_b,
                target_false: f_b,
            },
        );
        func.push_inst(t_b, IrInst::Return { value: None });
        func.push_inst(f_b, IrInst::Return { value: None });
        func.build_cfg();

        let folded = fold_flag_comparisons(&mut func);
        assert_eq!(folded, 1);
        let tail = &func.blocks[tail_b.0 as usize];
        assert!(
            matches!(
                &tail.insts[0],
                IrInst::Binary { dst: _, op: OpCode::Eq, lhs, rhs }
                    if *lhs == Value::reg("rcx", Ty::i64())
                        && *rhs == Value::reg("rdx", Ty::i64())
            ),
            "the nearest dominating def must win: {:?}",
            tail.insts[0]
        );
    }

    /// A diamond where BOTH arms define the flag and neither dominates the
    /// join is ambiguous with more than one def — the fold must be skipped
    /// rather than guess an operand pair.
    #[test]
    fn test_fold_skips_ambiguous_non_dominating_defs() {
        let mut func = IrFunction::new("t", 0x1000);
        let cond_in = func.alloc_var(Ty::Bool);
        let cond_out = func.alloc_var(Ty::Bool);
        let arm_a = func.add_block("arm_a");
        let arm_b = func.add_block("arm_b");
        let join_b = func.add_block("join");
        let t_b = func.add_block("then");
        let f_b = func.add_block("else");

        func.push_inst(
            func.entry_block,
            IrInst::CBranch {
                cond: cond_in.clone(),
                target_true: arm_a,
                target_false: arm_b,
            },
        );
        for (blk, reg_name) in [(arm_a, "rax"), (arm_b, "rbx")] {
            func.push_inst(
                blk,
                IrInst::Binary {
                    dst: Value::reg("flag_zf", Ty::Bool),
                    op: OpCode::Eq,
                    lhs: Value::reg(reg_name, Ty::i64()),
                    rhs: Value::Const(0),
                },
            );
            func.push_inst(blk, IrInst::Branch { target: join_b });
        }
        func.push_inst(
            join_b,
            IrInst::Binary {
                dst: cond_out.clone(),
                op: OpCode::Ne,
                lhs: Value::reg("flag_zf", Ty::Bool),
                rhs: Value::Const(1),
            },
        );
        func.push_inst(
            join_b,
            IrInst::CBranch {
                cond: cond_out.clone(),
                target_true: t_b,
                target_false: f_b,
            },
        );
        func.push_inst(t_b, IrInst::Return { value: None });
        func.push_inst(f_b, IrInst::Return { value: None });
        func.build_cfg();

        let folded = fold_flag_comparisons(&mut func);
        assert_eq!(folded, 0, "ambiguous defs must not fold");
        assert!(
            format!("{:?}", func).contains("flag_zf"),
            "the condition must stay untouched"
        );
    }

    /// `jbe` lifts to `(cf==1) | (zf==1)` over two sub-temps; both flags come
    /// from the same CMP, so the combined condition folds to `a <=u b`.
    #[test]
    fn test_fold_combined_jbe_condition() {
        let mut func = IrFunction::new("t", 0x1000);
        let t_cf = func.alloc_var(Ty::Bool);
        let t_zf = func.alloc_var(Ty::Bool);
        let comb = func.alloc_var(Ty::Bool);
        let next_b = func.add_block("next");
        let t_b = func.add_block("then");
        let f_b = func.add_block("else");
        let rax = Value::reg("rax", Ty::i64());
        let rbx = Value::reg("rbx", Ty::i64());

        func.push_inst(
            func.entry_block,
            IrInst::Binary {
                dst: Value::reg("flag_cf", Ty::Bool),
                op: OpCode::LtU,
                lhs: rax.clone(),
                rhs: rbx.clone(),
            },
        );
        func.push_inst(
            func.entry_block,
            IrInst::Binary {
                dst: Value::reg("flag_zf", Ty::Bool),
                op: OpCode::Eq,
                lhs: rax.clone(),
                rhs: rbx.clone(),
            },
        );
        func.push_inst(func.entry_block, IrInst::Branch { target: next_b });
        func.push_inst(
            next_b,
            IrInst::Binary {
                dst: t_cf.clone(),
                op: OpCode::Eq,
                lhs: Value::reg("flag_cf", Ty::Bool),
                rhs: Value::Const(1),
            },
        );
        func.push_inst(
            next_b,
            IrInst::Binary {
                dst: t_zf.clone(),
                op: OpCode::Eq,
                lhs: Value::reg("flag_zf", Ty::Bool),
                rhs: Value::Const(1),
            },
        );
        func.push_inst(
            next_b,
            IrInst::Binary {
                dst: comb.clone(),
                op: OpCode::Or,
                lhs: t_cf.clone(),
                rhs: t_zf.clone(),
            },
        );
        func.push_inst(
            next_b,
            IrInst::CBranch {
                cond: comb.clone(),
                target_true: t_b,
                target_false: f_b,
            },
        );
        func.push_inst(t_b, IrInst::Return { value: None });
        func.push_inst(f_b, IrInst::Return { value: None });
        func.build_cfg();

        let folded = fold_flag_comparisons(&mut func);
        assert_eq!(folded, 3, "two sub-temps + combined cond all fold");
        let next = &func.blocks[next_b.0 as usize];
        assert!(
            matches!(
                &next.insts[2],
                IrInst::Binary { dst: _, op: OpCode::LeU, lhs, rhs }
                    if *lhs == rax && *rhs == rbx
            ),
            "combined cond must become (rax <=u rbx): {:?}",
            next.insts[2]
        );
    }

    /// The root cause of `flag_cf = ...` noise in decompiled C: every `add`
    /// wrote the global carry flag, and every `adc` read it, so the dead-flag
    /// pass (keyed on the flag *name*) kept all those writes alive. Once `adc`
    /// is a first-class op whose carry is rewritten to the comparison that
    /// produced it, `flag_cf` has no readers and is eliminated.
    #[test]
    fn test_adc_carry_fold_kills_flag_cf_noise() {
        let mut func = IrFunction::new("adc_chain", 0x1000);
        let rax = Value::reg("rax", Ty::i64());
        let rbx = Value::reg("rbx", Ty::i64());
        let rdx = Value::reg("rdx", Ty::i64());
        let rcx = Value::reg("rcx", Ty::i64());

        // add rax, rbx  →  writes flag_cf = (rax <u rbx)
        func.push_inst(
            func.entry_block,
            IrInst::Binary {
                dst: rax.clone(),
                op: OpCode::Add,
                lhs: rax.clone(),
                rhs: rbx.clone(),
            },
        );
        func.push_inst(
            func.entry_block,
            IrInst::Binary {
                dst: Value::reg("flag_cf", Ty::Bool),
                op: OpCode::LtU,
                lhs: rax.clone(),
                rhs: rbx.clone(),
            },
        );
        // adc rdx, rcx  →  reads flag_cf
        func.push_inst(
            func.entry_block,
            IrInst::Adc {
                dst: rdx.clone(),
                a: rdx.clone(),
                b: rcx.clone(),
                carry: Value::reg("flag_cf", Ty::Bool),
            },
        );
        func.push_inst(func.entry_block, IrInst::Return { value: None });

        // Before folding the carry, flag_cf is referenced by the adc.
        let before = format!("{:?}", func);
        assert!(
            before.contains("flag_cf"),
            "adc must reference flag_cf before folding:\n{}",
            before
        );

        fold_adc_carries(&mut func);
        eliminate_dead_flag_defs(&mut func);

        // The adc's carry is now the concrete (rax <u rbx) comparison and the
        // global flag_cf definition has been removed.
        let after = format!("{:?}", func);
        assert!(
            !after.contains("flag_cf"),
            "flag_cf must be gone after folding the adc carry:\n{}",
            after
        );
        let rdx_b = &func.blocks[func.entry_block.0 as usize].insts;
        let adc = rdx_b
            .iter()
            .find(|i| matches!(i, IrInst::Adc { .. }))
            .expect("adc must still be present");
        assert!(
            matches!(
                adc,
                IrInst::Adc { carry, .. }
                    if matches!(carry, Value::Var { .. })
            ),
            "adc carry must be a folded SSA var, not flag_cf: {:?}",
            adc
        );
    }
}
