//! Sparse Conditional Constant Propagation (SCCP) over [`SsaFunction`].
//!
//! Classic WegmanвЂ“Zadeck lattice over SSA values driven by an executable-edge
//! worklist:
//!
//! - `Top` вЂ” value not yet computed,
//! - `Const(i64)` вЂ” known constant,
//! - `Over` вЂ” overdefined (loads, calls, memory, conflicting constants).
//!
//! At fixpoint the pass rewrites the SSA in place:
//!
//! 1. Non-executable blocks are removed (dead branches disappear before CFG
//!    structuring, which means fewer gotos in the output C).
//! 2. Every use of a constant value is substituted with the literal.
//! 3. Conditional branches with constant conditions become unconditional
//!    branches to the live successor.
//! 4. Phis whose executable inputs collapsed to a single value are removed
//!    and their uses substituted (the remaining phi would be trivial).
//!
//! Semantics deliberately mirror [`crate::optimize::constfold`]: the same
//! binary op set folds to the same results, so SCCP never disagrees with the
//! plain IR-level folder. Anything it cannot prove constant is left alone.
//!
//! Soundness: memory (Load/Store), calls and syscalls are always
//! overdefined; an indirect branch kills nothing but marks no new edges
//! (its block keeps whatever edges it had вЂ” conservative).

use crate::ir::{BlockId, OpCode};
use crate::ssa::{SsaFunction, SsaInst, SsaVal, VersionedVar};
use std::collections::{HashMap, HashSet, VecDeque};

/// Lattice value for one SSA version.
#[derive(Clone, Debug, PartialEq)]
enum Lattice {
    /// Not computed yet.
    Top,
    /// Known constant.
    Const(i64),
    /// Overdefined: not a constant (or conflicting constants).
    Over,
}

/// Counters describing what the pass changed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SccpStats {
    /// Blocks removed as non-executable.
    pub blocks_removed: usize,
    /// Operand slots rewritten from variable to constant.
    pub constants_substituted: usize,
    /// Conditional branches lowered to unconditional.
    pub branches_folded: usize,
    /// Phis removed (collapsed to a single input value).
    pub phis_removed: usize,
}

/// Run SCCP over `ssa`, rewriting it in place.
pub fn sccp(ssa: &mut SsaFunction) -> SccpStats {
    let mut lat: HashMap<VersionedVar, Lattice> = HashMap::new();
    let mut exec_edges: HashSet<(BlockId, BlockId)> = HashSet::new();
    let mut exec_blocks: HashSet<BlockId> = HashSet::new();

    // Use map: versioned var -> uses (block id). Phi inputs count as uses of
    // the incoming value inside the *predecessor* edge, tracked via (pred,
    // block) so edge executability can re-trigger phi evaluation.
    let mut uses: HashMap<VersionedVar, Vec<BlockId>> = HashMap::new();
    for b in &ssa.blocks {
        for p in &b.phis {
            for (_, v) in &p.inputs {
                uses.entry(v.clone()).or_default().push(b.id);
            }
        }
        for i in &b.insts {
            for src in ssa_inst_sources(i) {
                if let SsaVal::Ver(vv) = src {
                    uses.entry(vv.clone()).or_default().push(b.id);
                }
            }
        }
    }

    let mut block_wl: VecDeque<BlockId> = VecDeque::new();
    let mut in_block_wl: HashSet<BlockId> = HashSet::new();
    let queue_block = |b: BlockId,
                           wl: &mut VecDeque<BlockId>,
                           seen: &mut HashSet<BlockId>| {
        if seen.insert(b) {
            wl.push_back(b);
        }
    };

    queue_block(ssa.entry_block, &mut block_wl, &mut in_block_wl);
    exec_blocks.insert(ssa.entry_block);

    // When a CBranch condition refines Top -> Const on a *second* visit, the
    // first visit already marked both out-edges speculatively. SCCP never
    // retracts edges, so restart each round from an empty executable set
    // (the lattice is monotonic, so conds only refine) until the round stops
    // changing the edge set.
    let mut prev_edges: Option<usize> = None;
    loop {
        exec_edges.clear();
        exec_blocks.clear();
        exec_blocks.insert(ssa.entry_block);
        queue_block(ssa.entry_block, &mut block_wl, &mut in_block_wl);
        while let Some(bid) = block_wl.pop_front() {
            in_block_wl.remove(&bid);
            exec_blocks.insert(bid);
            let Some(block) = ssa.block(bid).cloned() else {
                continue;
            };

            // (Re-)evaluate phis first: each executable incoming edge contributes.
            for p in &block.phis {
                let new = eval_phi(p, bid, &exec_edges, &lat);
                merge_lattice(&mut lat, &p.dst, new, &uses, &mut block_wl, &mut in_block_wl);
            }

            for inst in &block.insts {
                match inst {
                    SsaInst::Branch { target } => {
                        mark_edge(bid, *target, &mut exec_edges, &mut exec_blocks, &mut block_wl, &mut in_block_wl);
                    }
                    SsaInst::CBranch { cond, target_true, target_false } => {
                        match ssa_lattice(cond, &lat) {
                            Lattice::Const(0) => {
                                mark_edge(bid, *target_false, &mut exec_edges, &mut exec_blocks, &mut block_wl, &mut in_block_wl);
                            }
                            Lattice::Const(c) if c != 0 => {
                                mark_edge(bid, *target_true, &mut exec_edges, &mut exec_blocks, &mut block_wl, &mut in_block_wl);
                            }
                            _ => {
                                mark_edge(bid, *target_true, &mut exec_edges, &mut exec_blocks, &mut block_wl, &mut in_block_wl);
                                mark_edge(bid, *target_false, &mut exec_edges, &mut exec_blocks, &mut block_wl, &mut in_block_wl);
                            }
                        }
                    }
                    SsaInst::Switch { index, cases, default } => {
                        if let Lattice::Const(c) = ssa_lattice(index, &lat) {
                            // Only the matching case edge is executable; a
                            // known index also proves the default is dead
                            // unless no case value matches.
                            let hit = cases.iter().find(|(v, _)| *v == c).map(|(_, t)| *t);
                            match hit.or(*default) {
                                Some(t) => mark_edge(bid, t, &mut exec_edges, &mut exec_blocks, &mut block_wl, &mut in_block_wl),
                                None => {}
                            }
                        } else {
                            for (_, t) in cases.iter() {
                                mark_edge(bid, *t, &mut exec_edges, &mut exec_blocks, &mut block_wl, &mut in_block_wl);
                            }
                            if let Some(d) = default {
                                mark_edge(bid, *d, &mut exec_edges, &mut exec_blocks, &mut block_wl, &mut in_block_wl);
                            }
                        }
                    }
                    _ => {
                        if let Some(dst) = ssa_inst_dst(inst) {
                            let new = eval_inst(inst, &lat);
                            merge_lattice(&mut lat, &dst, new, &uses, &mut block_wl, &mut in_block_wl);
                        }
                    }
                }
            }
        }
        let n = exec_edges.len();
        if prev_edges == Some(n) {
            break;
        }
        prev_edges = Some(n);
    }

    // в”Ђв”Ђв”Ђ Rewrite в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
    let mut stats = SccpStats::default();

    // 1. Drop non-executable blocks; fix predecessor/successor caches.
    let before = ssa.blocks.len();
    ssa.blocks.retain(|b| exec_blocks.contains(&b.id));
    stats.blocks_removed = before - ssa.blocks.len();
    for b in &mut ssa.blocks {
        b.predecessors.retain(|p| exec_blocks.contains(p));
        b.successors.retain(|s| exec_blocks.contains(s));
    }

    // 2. Substitute constants everywhere + prune const CBranches + drop phis
    //    that collapsed. Iterate to fixpoint: removing a phi frees its uses
    //    to be substituted with the phi's single surviving value.
    loop {
        let mut changed = false;

        // (a) collapsed phi -> substitution map (collect first, mutate after
        // to avoid aliasing `ssa.blocks`).
        let mut phi_value: HashMap<VersionedVar, SsaVal> = HashMap::new();
        let mut dropped_phis: Vec<BlockId> = Vec::new();
        let mut kept_phis: Vec<Vec<crate::ssa::Phi>> = Vec::new();
        for b in &ssa.blocks {
            let mut keep = Vec::with_capacity(b.phis.len());
            for p in &b.phis {
                // Resolve each executable-edge input after constant
                // substitution; a phi collapses when exactly one distinct
                // value survives.
                let mut resolved: Vec<SsaVal> = Vec::new();
                for (pred, v) in &p.inputs {
                    if !exec_edges.contains(&(*pred, b.id)) {
                        continue;
                    }
                    let r = substitute_ver(v, &lat);
                    if !resolved.contains(&r) {
                        resolved.push(r);
                    }
                }
                if !p.inputs.is_empty() && resolved.len() == 1 {
                    phi_value.insert(p.dst.clone(), resolved[0].clone());
                    stats.phis_removed += 1;
                    changed = true;
                } else {
                    keep.push(p.clone());
                }
            }
            if keep.len() != b.phis.len() {
                dropped_phis.push(b.id);
                kept_phis.push(keep);
            }
        }
        for (id, keep) in dropped_phis.into_iter().zip(kept_phis.into_iter()) {
            if let Some(dst) = ssa.blocks.iter_mut().find(|bb| bb.id == id) {
                dst.phis = keep;
            }
        }

        // (b) substitute constants + phi values in every operand
        for b in &mut ssa.blocks {
            for p in &mut b.phis {
                for (_, v) in &mut p.inputs {
                    let nv = match phi_value.get(v) {
                        Some(val) => val.clone(),
                        None => substitute_ver(v, &lat),
                    };
                    if let SsaVal::Ver(vv) = &nv {
                        if *v != *vv {
                            *v = vv.clone();
                            stats.constants_substituted += 1;
                            changed = true;
                        }
                    }
                }
            }
            for inst in &mut b.insts {
                if substitute_inst(inst, &lat, &phi_value, &mut stats.constants_substituted) {
                    changed = true;
                }
                // (c) fold constant conditional branches
                if let SsaInst::CBranch { cond, target_true, target_false } = inst {
                    if let SsaVal::Const(c) = *cond {
                        let target = if c != 0 { *target_true } else { *target_false };
                        *inst = SsaInst::Branch { target };
                        stats.branches_folded += 1;
                        changed = true;
                    }
                }
            }
        }

        if !changed {
            break;
        }
    }

    stats
}

// в”Ђв”Ђв”Ђ Lattice helpers в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

fn mark_edge(
    from: BlockId,
    to: BlockId,
    exec_edges: &mut HashSet<(BlockId, BlockId)>,
    exec_blocks: &mut HashSet<BlockId>,
    wl: &mut VecDeque<BlockId>,
    seen: &mut HashSet<BlockId>,
) {
    if exec_edges.insert((from, to)) {
        if exec_blocks.insert(to) {
            if seen.insert(to) {
                wl.push_back(to);
            }
        }
    }
}

fn ssa_lattice(v: &SsaVal, lat: &HashMap<VersionedVar, Lattice>) -> Lattice {
    match v {
        SsaVal::Const(c) => Lattice::Const(*c),
        SsaVal::Ver(vv) => lat.get(vv).cloned().unwrap_or(Lattice::Top),
        // Wide constants, strings and symbols are not i64-foldable.
        SsaVal::WideConst(_) | SsaVal::StringRef(_) | SsaVal::Symbol(_) => Lattice::Over,
    }
}

fn merge_lattice(
    lat: &mut HashMap<VersionedVar, Lattice>,
    dst: &VersionedVar,
    new: Lattice,
    uses: &HashMap<VersionedVar, Vec<BlockId>>,
    wl: &mut VecDeque<BlockId>,
    seen: &mut HashSet<BlockId>,
) {
    let entry = lat.entry(dst.clone()).or_insert(Lattice::Top);
    // Monotone meet over Top < Const < Over. Never downgrade Over, never
    // oscillate Const vs Over.
    let cur = entry.clone();
    let merged = match (&cur, &new) {
        (Lattice::Over, _) | (_, Lattice::Top) => None,      // Over wins; Top adds nothing
        (Lattice::Top, _) => Some(new.clone()),              // refine
        (Lattice::Const(a), Lattice::Const(b)) if a == b => None,
        _ => Some(Lattice::Over),                            // conflicting const -> Over
    };
    if let Some(merged) = merged {
        *entry = merged;
        notify_uses(dst, uses, wl, seen);
    }
}

fn notify_uses(
    v: &VersionedVar,
    uses: &HashMap<VersionedVar, Vec<BlockId>>,
    wl: &mut VecDeque<BlockId>,
    seen: &mut HashSet<BlockId>,
) {
    if let Some(blocks) = uses.get(v) {
        for &b in blocks {
            if seen.insert(b) {
                wl.push_back(b);
            }
        }
    }
}

fn eval_phi(
    p: &crate::ssa::Phi,
    pblock: BlockId,
    exec_edges: &HashSet<(BlockId, BlockId)>,
    lat: &HashMap<VersionedVar, Lattice>,
) -> Lattice {
    let mut result = Lattice::Top;
    let mut any = false;
    for (pred, v) in &p.inputs {
        if !exec_edges.contains(&(*pred, pblock)) {
            continue;
        }
        any = true;
        let l = lattice_of_ver(v, lat);
        result = match (&result, &l) {
            (Lattice::Top, x) => x.clone(),
            (x, Lattice::Top) => x.clone(),
            (Lattice::Const(a), Lattice::Const(b)) if a == b => result,
            _ => Lattice::Over,
        };
    }
    if any {
        result
    } else {
        // No executable input yet: keep top; the edge worklist will revisit.
        Lattice::Top
    }
}

/// Lattice for a phi input (plain `VersionedVar`, not wrapped in `SsaVal`).
fn lattice_of_ver(v: &VersionedVar, lat: &HashMap<VersionedVar, Lattice>) -> Lattice {
    lat.get(v).cloned().unwrap_or(Lattice::Top)
}

/// Resolve a phi input after constant propagation. Returns `SsaVal` so a
/// fully-constant phi can collapse to a literal.
fn substitute_ver(v: &VersionedVar, lat: &HashMap<VersionedVar, Lattice>) -> SsaVal {
    match lat.get(v) {
        Some(Lattice::Const(c)) => SsaVal::Const(*c),
        _ => SsaVal::Ver(v.clone()),
    }
}

fn eval_inst(inst: &SsaInst, lat: &HashMap<VersionedVar, Lattice>) -> Lattice {
    fn two(a: &SsaVal, b: &SsaVal, lat: &HashMap<VersionedVar, Lattice>) -> (Lattice, Lattice) {
        (ssa_lattice(a, lat), ssa_lattice(b, lat))
    }
    match inst {
        SsaInst::Binary { op, lhs, rhs, .. } => {
            let (a, b) = two(lhs, rhs, lat);
            match (a, b) {
                (Lattice::Const(x), Lattice::Const(y)) => crate::optimize::eval_const_binop_public(*op, x, y)
                    .map(Lattice::Const)
                    .unwrap_or(Lattice::Over),
                (Lattice::Over, _) | (_, Lattice::Over) => Lattice::Over,
                _ => Lattice::Top,
            }
        }
        SsaInst::Unary { op, src, .. } => {
            let l = ssa_lattice(src, lat);
            match l {
                Lattice::Const(c) => match op {
                    OpCode::Not => Lattice::Const(!c),
                    OpCode::Neg => Lattice::Const(c.wrapping_neg()),
                    OpCode::Copy => Lattice::Const(c),
                    _ => Lattice::Over,
                },
                Lattice::Over => Lattice::Over,
                Lattice::Top => Lattice::Top,
            }
        }
        SsaInst::Adc { a, b, carry, .. } => {
            let (la, lb, lc) = (
                ssa_lattice(a, lat),
                ssa_lattice(b, lat),
                ssa_lattice(carry, lat),
            );
            match (la, lb, lc) {
                (Lattice::Const(x), Lattice::Const(y), Lattice::Const(z)) => {
                    Lattice::Const(x.wrapping_add(y).wrapping_add(z))
                }
                (Lattice::Over, _, _) | (_, Lattice::Over, _) | (_, _, Lattice::Over) => Lattice::Over,
                _ => Lattice::Top,
            }
        }
        SsaInst::Sbb { a, b, carry, .. } => {
            let (la, lb, lc) = (
                ssa_lattice(a, lat),
                ssa_lattice(b, lat),
                ssa_lattice(carry, lat),
            );
            match (la, lb, lc) {
                (Lattice::Const(x), Lattice::Const(y), Lattice::Const(z)) => {
                    Lattice::Const(x.wrapping_sub(y).wrapping_sub(z))
                }
                (Lattice::Over, _, _) | (_, Lattice::Over, _) | (_, _, Lattice::Over) => Lattice::Over,
                _ => Lattice::Top,
            }
        }
        // Memory, calls and syscalls are never constant.
        SsaInst::Load { .. }
        | SsaInst::Call { dst: Some(_), .. }
        | SsaInst::Syscall { .. } => Lattice::Over,
        _ => Lattice::Top,
    }
}

fn ssa_inst_dst(inst: &SsaInst) -> Option<VersionedVar> {
    match inst {
        SsaInst::Binary { dst, .. }
        | SsaInst::Unary { dst, .. }
        | SsaInst::Adc { dst, .. }
        | SsaInst::Sbb { dst, .. }
        | SsaInst::Load { dst, .. } => Some(dst.clone()),
        SsaInst::Call { dst, .. } => dst.clone(),
        _ => None,
    }
}

fn ssa_inst_sources(inst: &SsaInst) -> Vec<&SsaVal> {
    match inst {
        SsaInst::Binary { lhs, rhs, .. } => vec![lhs, rhs],
        SsaInst::Unary { src, .. } => vec![src],
        SsaInst::Adc { a, b, carry, .. } => vec![a, b, carry],
        SsaInst::Sbb { a, b, carry, .. } => vec![a, b, carry],
        SsaInst::Load { addr, .. } => vec![addr],
        SsaInst::Store { addr, value, .. } => vec![addr, value],
        SsaInst::CBranch { cond, .. } => vec![cond],
        SsaInst::Call { target, args, .. } => {
            let mut v = vec![target];
            v.extend(args);
            v
        }
        SsaInst::Return { value: Some(v) } => vec![v],
        SsaInst::IndirectBranch { target } => vec![target],
        SsaInst::Switch { index, .. } => vec![index],
        SsaInst::Syscall { number, args } => {
            let mut v = Vec::new();
            if let Some(n) = number {
                v.push(n);
            }
            v.extend(args);
            v
        }
        _ => Vec::new(),
    }
}

fn substitute_val(v: &SsaVal, lat: &HashMap<VersionedVar, Lattice>) -> SsaVal {
    match v {
        SsaVal::Ver(vv) => match lat.get(vv) {
            Some(Lattice::Const(c)) => SsaVal::Const(*c),
            _ => v.clone(),
        },
        _ => v.clone(),
    }
}

fn substitute_inst(
    inst: &mut SsaInst,
    lat: &HashMap<VersionedVar, Lattice>,
    phi_value: &HashMap<VersionedVar, SsaVal>,
    counter: &mut usize,
) -> bool {
    let mut changed = false;
    let sub = |v: &mut SsaVal| -> bool {
        let nv = match &*v {
            SsaVal::Ver(vv) => match phi_value.get(vv) {
                Some(val) => val.clone(),
                None => substitute_val(v, lat),
            },
            other => substitute_val(other, lat),
        };
        let differ = *v != nv;
        if differ {
            *v = nv;
        }
        differ
    };
    match inst {
        SsaInst::Binary { lhs, rhs, .. } => {
            changed |= sub(lhs);
            changed |= sub(rhs);
        }
        SsaInst::Unary { src, .. } => changed |= sub(src),
        SsaInst::Adc { a, b, carry, .. } | SsaInst::Sbb { a, b, carry, .. } => {
            changed |= sub(a);
            changed |= sub(b);
            changed |= sub(carry);
        }
        SsaInst::Load { addr, .. } => changed |= sub(addr),
        SsaInst::Store { addr, value, .. } => {
            changed |= sub(addr);
            changed |= sub(value);
        }
        SsaInst::CBranch { cond, .. } => changed |= sub(cond),
        SsaInst::Call { target, args, .. } => {
            changed |= sub(target);
            for a in args {
                changed |= sub(a);
            }
        }
        SsaInst::Return { value } => {
            if let Some(v) = value {
                changed |= sub(v);
            }
        }
        SsaInst::IndirectBranch { target } => changed |= sub(target),
        SsaInst::Switch { index, .. } => changed |= sub(index),
        SsaInst::Syscall { number, args } => {
            if let Some(n) = number {
                changed |= sub(n);
            }
            for a in args {
                changed |= sub(a);
            }
        }
        _ => {}
    }
    if changed {
        *counter += 1;
    }
    changed
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{IrFunction, IrInst, OpCode, Value};
    use crate::types::Ty;

    #[test]
    fn sccp_removes_dead_branch_and_propagates_const() {
        // c = 4 + 5 = 9; if (c != 9) is never taken -> the "then" arm is dead.
        let mut f = IrFunction::new("dead_branch", 0x0);
        let _c = f.alloc_var(Ty::i64());
        let then_b = f.add_block("then");
        let else_b = f.add_block("else");

        f.push_inst(
            f.entry_block,
            IrInst::Binary {
                dst: Value::reg("c", Ty::i64()),
                op: OpCode::Add,
                lhs: Value::int(4),
                rhs: Value::int(5),
            },
        );
        f.push_inst(
            f.entry_block,
            IrInst::CBranch {
                cond: Value::reg("c", Ty::i64()),
                target_true: then_b,
                target_false: else_b,
            },
        );
        f.push_inst(then_b, IrInst::Return { value: Some(Value::int(0)) });
        f.push_inst(else_b, IrInst::Return { value: Some(Value::reg("c", Ty::i64())) });
        f.build_cfg();

        let mut ssa = crate::ssa::to_ssa(&mut f).expect("to_ssa");
        let st = sccp(&mut ssa);
        assert!(st.constants_substituted >= 1, "const substitution: {st:?}");
        assert!(st.branches_folded >= 1, "branch fold: {st:?}");
        assert!(st.blocks_removed >= 1, "dead block removal: {st:?}");
    }

    #[test]
    fn sccp_keeps_overdefined_branches() {
        let mut f = IrFunction::new("over_branch", 0x0);
        let then_b = f.add_block("then");
        let else_b = f.add_block("else");
        f.push_inst(
            f.entry_block,
            IrInst::CBranch {
                cond: Value::reg("x", Ty::i64()),
                target_true: then_b,
                target_false: else_b,
            },
        );
        f.push_inst(then_b, IrInst::Return { value: Some(Value::int(1)) });
        f.push_inst(else_b, IrInst::Return { value: Some(Value::int(2)) });
        f.build_cfg();

        let mut ssa = crate::ssa::to_ssa(&mut f).expect("to_ssa");
        let st = sccp(&mut ssa);
        assert_eq!(st.blocks_removed, 0, "unknown cond keeps both arms: {st:?}");
        assert_eq!(st.branches_folded, 0);
    }

    #[test]
    fn sccp_folds_and_clears_flag_vars() {
        // zf = 5 - 5 == 0 (via Eq), then CBranch on zf -> always true.
        let mut f = IrFunction::new("flag_fold", 0x0);
        let _zf = f.alloc_var(Ty::Bool);
        let then_b = f.add_block("then");
        let else_b = f.add_block("else");

        f.push_inst(
            f.entry_block,
            IrInst::Binary {
                dst: Value::reg("zf", Ty::Bool),
                op: OpCode::Eq,
                lhs: Value::int(5),
                rhs: Value::int(5),
            },
        );
        f.push_inst(
            f.entry_block,
            IrInst::CBranch {
                cond: Value::reg("zf", Ty::Bool),
                target_true: then_b,
                target_false: else_b,
            },
        );
        f.push_inst(then_b, IrInst::Return { value: Some(Value::int(7)) });
        f.push_inst(else_b, IrInst::Return { value: Some(Value::int(8)) });
        f.build_cfg();

        let mut ssa = crate::ssa::to_ssa(&mut f).expect("to_ssa");
        let st = sccp(&mut ssa);
        assert!(st.branches_folded >= 1, "flag cond must fold: {st:?}");
        assert!(st.blocks_removed >= 1);
    }
}
