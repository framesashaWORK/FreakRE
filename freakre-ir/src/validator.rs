//! IR validator — checks invariants for `IrFunction` and `IrProgram`.

use crate::ir::{BlockId, IrFunction, IrInst};
use std::collections::{HashMap, HashSet};

/// Validation error with human-readable message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError(pub String);

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Validate a single function. Returns `Ok(())` if valid, `Err(errors)` otherwise.
pub fn validate_function(func: &IrFunction) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();
    let block_ids: HashSet<BlockId> = func.blocks.iter().map(|b| b.id).collect();

    // 1. entry_block must exist
    if !block_ids.contains(&func.entry_block) {
        errors.push(ValidationError(format!(
            "entry_block {} does not exist",
            func.entry_block
        )));
    }

    // 2. BlockIds must be unique
    if block_ids.len() != func.blocks.len() {
        errors.push(ValidationError("duplicate BlockId found".into()));
    }

    // 3. Check each block
    for block in &func.blocks {
        // a) terminator must be last (if present), only one terminator
        let term_positions: Vec<usize> = block
            .insts
            .iter()
            .enumerate()
            .filter_map(|(idx, inst)| inst.is_terminator().then_some(idx))
            .collect();
        let term_count = term_positions.len();
        if term_count > 1 {
            errors.push(ValidationError(format!(
                "{} has {} terminators (expected 0 or 1)",
                block.id, term_count
            )));
        }
        if let Some(&term_idx) = term_positions.first() {
            if term_idx + 1 != block.insts.len() {
                errors.push(ValidationError(format!(
                    "{} terminator is not last instruction",
                    block.id
                )));
            }
        }
        if let Some(term) = block.terminator() {
            // b) branch targets must exist
            match term {
                IrInst::Branch { target } => {
                    if !block_ids.contains(target) {
                        errors.push(ValidationError(format!(
                            "{} Branch target {} does not exist",
                            block.id, target
                        )));
                    }
                }
                IrInst::CBranch {
                    target_true,
                    target_false,
                    ..
                } => {
                    if !block_ids.contains(target_true) {
                        errors.push(ValidationError(format!(
                            "{} CBranch true target {} does not exist",
                            block.id, target_true
                        )));
                    }
                    if !block_ids.contains(target_false) {
                        errors.push(ValidationError(format!(
                            "{} CBranch false target {} does not exist",
                            block.id, target_false
                        )));
                    }
                }
                IrInst::Switch { cases, default, .. } => {
                    for (v, t) in cases {
                        if !block_ids.contains(t) {
                            errors.push(ValidationError(format!(
                                "{} Switch case {} target {} does not exist",
                                block.id, v, t
                            )));
                        }
                    }
                    if let Some(d) = default {
                        if !block_ids.contains(d) {
                            errors.push(ValidationError(format!(
                                "{} Switch default target {} does not exist",
                                block.id, d
                            )));
                        }
                    }
                }
                _ => {}
            }
        }

        // c) Phi handling: warn if Phi not at expected position? Ir allows Phi but SSA form expects them in SsaFunction.phis.
        // In plain IrFunction, Phi should not appear (only after manual insertion). We allow but check successors.
        for inst in &block.insts {
            if let IrInst::Phi { dst: _, incoming } = inst {
                if incoming.is_empty() {
                    errors.push(ValidationError(format!(
                        "{} Phi with no incoming edges",
                        block.id
                    )));
                }
                for (pred, _) in incoming {
                    if !block_ids.contains(pred) {
                        errors.push(ValidationError(format!(
                            "{} Phi incoming from non-existent {}",
                            block.id, pred
                        )));
                    }
                }
            }
        }

        // d) successors/predecessors consistency vs build_cfg
        // We do not enforce strict equality (they are derived), but check that every successor is a known block.
        for succ in &block.successors {
            if !block_ids.contains(succ) {
                errors.push(ValidationError(format!(
                    "{} successor {} does not exist",
                    block.id, succ
                )));
            }
        }
        for pred in &block.predecessors {
            if !block_ids.contains(pred) {
                errors.push(ValidationError(format!(
                    "{} predecessor {} does not exist",
                    block.id, pred
                )));
            }
        }
    }

    // 4. Check for unreachable blocks (warning as error for SSA compatibility)
    // We reuse the same reachable logic as ssa::rpo_order but iterative BFS.
    if let Some(entry) = func.blocks.iter().find(|b| b.id == func.entry_block) {
        let _ = entry;
        let mut reachable = HashSet::new();
        let mut stack = vec![func.entry_block];
        reachable.insert(func.entry_block);
        // Build id -> block map for BFS over terminator edges (canonical, not stored successors)
        let id_to_block: HashMap<BlockId, &crate::ir::IrBlock> =
            func.blocks.iter().map(|b| (b.id, b)).collect();
        let mut idx = 0;
        while idx < stack.len() {
            let cur = stack[idx];
            idx += 1;
            if let Some(block) = id_to_block.get(&cur) {
                let succs: Vec<BlockId> = match block.terminator() {
                    Some(IrInst::Branch { target }) => vec![*target],
                    Some(IrInst::CBranch {
                        target_true,
                        target_false,
                        ..
                    }) => vec![*target_true, *target_false],
                    Some(IrInst::Switch { cases, default, .. }) => {
                        let mut v: Vec<BlockId> = cases.iter().map(|(_, t)| *t).collect();
                        if let Some(d) = default {
                            v.push(*d);
                        }
                        v
                    }
                    _ => block.successors.clone(),
                };
                for s in succs {
                    if reachable.insert(s) {
                        stack.push(s);
                    }
                }
            }
        }
        let unreachable: Vec<BlockId> = block_ids
            .iter()
            .copied()
            .filter(|id| !reachable.contains(id))
            .collect();
        if !unreachable.is_empty() {
            // Not a hard error for plain IR, but emit as validation error with specific tag
            // so callers can decide. We treat it as error to surface SSA incompatibility early.
            errors.push(ValidationError(format!(
                "unreachable blocks: {:?} (SSA construction will fail)",
                unreachable
            )));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Validate an entire program (each function).
pub fn validate_program(prog: &crate::ir::IrProgram) -> Result<(), Vec<ValidationError>> {
    let mut all = Vec::new();
    for func in &prog.functions {
        if let Err(mut e) = validate_function(func) {
            for err in e.drain(..) {
                all.push(ValidationError(format!("{}: {}", func.name, err.0)));
            }
        }
    }
    if all.is_empty() {
        Ok(())
    } else {
        Err(all)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BlockId, IrFunction, IrInst, OpCode, Value};
    use crate::types::Ty;

    #[test]
    fn test_valid_function() {
        let mut f = IrFunction::new("ok", 0x1000);
        let v0 = f.alloc_var(Ty::i64());
        f.push_inst(
            f.entry_block,
            IrInst::Binary {
                dst: v0.clone(),
                op: OpCode::Add,
                lhs: Value::int(1),
                rhs: Value::int(2),
            },
        );
        f.push_inst(f.entry_block, IrInst::Return { value: Some(v0) });
        f.build_cfg();
        assert!(validate_function(&f).is_ok());
    }

    #[test]
    fn test_invalid_branch_target() {
        let mut f = IrFunction::new("bad", 0x1000);
        f.push_inst(
            f.entry_block,
            IrInst::Branch {
                target: BlockId(99),
            },
        );
        // Do not call build_cfg in debug (it debug_asserts on unknown targets);
        // validator must catch it directly via terminator scan.
        let err = validate_function(&f).unwrap_err();
        assert!(err.iter().any(|e| e.0.contains("does not exist")));
    }

    #[test]
    fn test_unreachable_block_detected() {
        let mut f = IrFunction::new("unreach", 0x1000);
        let _b1 = f.add_block("isolated");
        f.push_inst(f.entry_block, IrInst::Return { value: None });
        f.build_cfg();
        let err = validate_function(&f).unwrap_err();
        assert!(err.iter().any(|e| e.0.contains("unreachable")));
    }

    #[test]
    fn test_duplicate_terminator() {
        let mut f = IrFunction::new("dupterm", 0x1000);
        let b1 = f.add_block("b1");
        f.push_inst(f.entry_block, IrInst::Branch { target: b1 });
        // manually push second terminator (illegal)
        f.blocks[0].insts.push(IrInst::Branch { target: b1 });
        let err = validate_function(&f).unwrap_err();
        assert!(err.iter().any(|e| e.0.contains("terminators")));
    }

    #[test]
    fn test_terminator_in_middle_detected() {
        let mut f = IrFunction::new("middle_term", 0x1000);
        let target = f.add_block("target");
        f.push_inst(f.entry_block, IrInst::Branch { target });
        f.blocks[0].insts.push(IrInst::Nop);
        let err = validate_function(&f).unwrap_err();
        assert!(err.iter().any(|e| e.0.contains("not last instruction")));
    }

    #[test]
    fn test_switch_target_validated() {
        let mut f = IrFunction::new("sw_bad", 0x1000);
        let idx = f.alloc_var(Ty::i32());
        f.push_inst(
            f.entry_block,
            IrInst::Switch {
                index: idx,
                cases: vec![(0, BlockId(42)), (1, BlockId(43))],
                default: Some(BlockId(44)),
            },
        );
        let err = validate_function(&f).unwrap_err();
        assert!(err.iter().any(|e| e.0.contains("Switch case 0 target bb42 does not exist")));
        assert!(err.iter().any(|e| e.0.contains("Switch default target bb44 does not exist")));
    }

    #[test]
    fn test_switch_target_ok() {
        let mut f = IrFunction::new("sw_ok", 0x1000);
        let idx = f.alloc_var(Ty::i32());
        let c0 = f.add_block("c0");
        let c1 = f.add_block("c1");
        let d = f.add_block("dflt");
        f.push_inst(
            f.entry_block,
            IrInst::Switch {
                index: idx,
                cases: vec![(0, c0), (1, c1)],
                default: Some(d),
            },
        );
        f.build_cfg();
        assert!(validate_function(&f).is_ok());
    }
}
