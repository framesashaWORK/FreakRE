//! IR optimization passes: DCE, constant folding, CSE.

use crate::ir::{IrFunction, IrInst, OpCode, Value};
use std::collections::{HashMap, HashSet};

/// Constant folding for pure binary/unary ops with constant operands.
/// Returns number of folded instructions.
pub fn constfold(func: &mut IrFunction) -> usize {
    let mut folded = 0;
    for block in &mut func.blocks {
        for inst in &mut block.insts {
            match inst {
                IrInst::Binary { op, lhs, rhs, dst } if lhs.is_const() && rhs.is_const() => {
                    if let (Some(a), Some(b)) = (lhs.as_const(), rhs.as_const()) {
                        if let Some(v) = eval_const_binop(*op, a, b) {
                            *inst = IrInst::Unary {
                                dst: dst.clone(),
                                op: OpCode::Copy,
                                src: Value::Const(v),
                            };
                            folded += 1;
                        }
                    }
                }
                IrInst::Unary { op, src, dst } if src.is_const() => {
                    if let Some(c) = src.as_const() {
                        let v = match op {
                            OpCode::Not => Some(!c),
                            OpCode::Neg => Some(c.wrapping_neg()),
                            OpCode::Copy => Some(c),
                            _ => None,
                        };
                        if let Some(v) = v {
                            *inst = IrInst::Unary {
                                dst: dst.clone(),
                                op: OpCode::Copy,
                                src: Value::Const(v),
                            };
                            folded += 1;
                        }
                    }
                }
                _ => {}
            }
        }
    }
    folded
}

fn eval_const_binop(op: OpCode, a: i64, b: i64) -> Option<i64> {
    match op {
        OpCode::Add => Some(a.wrapping_add(b)),
        OpCode::Sub => Some(a.wrapping_sub(b)),
        OpCode::Mul => Some(a.wrapping_mul(b)),
        OpCode::And => Some(a & b),
        OpCode::Or => Some(a | b),
        OpCode::Xor => Some(a ^ b),
        OpCode::Shl => Some(a.wrapping_shl(b as u32)),
        OpCode::Shr => Some((a as u64).wrapping_shr(b as u32) as i64),
        OpCode::Sar => Some(a.wrapping_shr(b as u32)),
        OpCode::Eq => Some(if a == b { 1 } else { 0 }),
        OpCode::Ne => Some(if a != b { 1 } else { 0 }),
        _ => None,
    }
}

/// Dead code elimination for pure temps (no side effects).
/// Removes `Binary`/`Unary Copy` Var defs that have no users.
pub fn dce(func: &mut IrFunction) -> usize {
    let mut removed = 0;
    loop {
        let mut used: HashSet<u32> = HashSet::new();
        for block in &func.blocks {
            for inst in &block.insts {
                for src in inst.sources() {
                    if let Some(id) = src.var_id() {
                        used.insert(id);
                    }
                }
                // Return value is considered used
                if let IrInst::Return { value: Some(v) } = inst {
                    if let Some(id) = v.var_id() {
                        used.insert(id);
                    }
                }
            }
        }
        let mut changed = false;
        for block in &mut func.blocks {
            let mut i = 0;
            while i < block.insts.len() {
                let is_pure = matches!(
                    &block.insts[i],
                    IrInst::Binary { op, .. } if matches!(op, OpCode::Add | OpCode::Sub | OpCode::Mul | OpCode::And | OpCode::Or | OpCode::Xor | OpCode::Shl | OpCode::Shr | OpCode::Sar | OpCode::Eq | OpCode::Ne)
                ) || matches!(&block.insts[i], IrInst::Unary { op: OpCode::Copy, .. });
                if is_pure {
                    if let Some(dst) = block.insts[i].dst() {
                        if let Some(id) = dst.var_id() {
                            if !used.contains(&id) {
                                block.insts.remove(i);
                                removed += 1;
                                changed = true;
                                continue;
                            }
                        }
                    }
                }
                i += 1;
            }
        }
        if !changed {
            break;
        }
    }
    removed
}

/// Common subexpression elimination (simple within-block).
/// Deduplicates identical pure Binary ops.
pub fn cse(func: &mut IrFunction) -> usize {
    let mut eliminated = 0;
    for block in &mut func.blocks {
        let mut seen: HashMap<(OpCode, Value, Value), Value> = HashMap::new();
        let mut new_insts = Vec::with_capacity(block.insts.len());
        for inst in std::mem::take(&mut block.insts) {
            match &inst {
                IrInst::Binary { op, lhs, rhs, dst } if is_pure_binop(*op) => {
                    let key = (*op, lhs.clone(), rhs.clone());
                    if let Some(prev_dst) = seen.get(&key) {
                        // Replace with copy from previous dst
                        new_insts.push(IrInst::Unary {
                            dst: dst.clone(),
                            op: OpCode::Copy,
                            src: prev_dst.clone(),
                        });
                        eliminated += 1;
                    } else {
                        seen.insert(key, dst.clone());
                        new_insts.push(inst);
                    }
                }
                _ => {
                    new_insts.push(inst);
                }
            }
        }
        block.insts = new_insts;
    }
    eliminated
}

fn is_pure_binop(op: OpCode) -> bool {
    matches!(
        op,
        OpCode::Add | OpCode::Sub | OpCode::Mul | OpCode::And | OpCode::Or | OpCode::Xor
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{IrInst, IrFunction, OpCode, Value};
    use crate::types::Ty;

    #[test]
    fn test_constfold_add() {
        let mut func = IrFunction::new("test", 0x1000);
        let v0 = func.alloc_var(Ty::i32());
        let v1 = Value::Const(2);
        let v2 = Value::Const(3);
        func.push_inst(
            func.entry_block,
            IrInst::Binary {
                dst: v0.clone(),
                op: OpCode::Add,
                lhs: v1,
                rhs: v2,
            },
        );
        let folded = constfold(&mut func);
        assert_eq!(folded, 1);
        assert!(matches!(
            &func.blocks[0].insts[0],
            IrInst::Unary { op: OpCode::Copy, src: Value::Const(5), .. }
        ));
    }

    #[test]
    fn test_dce_removes_dead() {
        let mut func = IrFunction::new("test", 0x1000);
        let v0 = func.alloc_var(Ty::i32());
        let v1 = func.alloc_var(Ty::i32());
        func.push_inst(
            func.entry_block,
            IrInst::Binary {
                dst: v0.clone(),
                op: OpCode::Add,
                lhs: Value::Const(1),
                rhs: Value::Const(2),
            },
        );
        func.push_inst(
            func.entry_block,
            IrInst::Binary {
                dst: v1.clone(),
                op: OpCode::Add,
                lhs: Value::Const(3),
                rhs: Value::Const(4),
            },
        );
        func.push_inst(func.entry_block, IrInst::Return { value: Some(v1) });
        let removed = dce(&mut func);
        assert_eq!(removed, 1);
        assert_eq!(func.blocks[0].insts.len(), 2);
    }

    #[test]
    fn test_cse_dedup() {
        let mut func = IrFunction::new("test", 0x1000);
        let v0 = func.alloc_var(Ty::i32());
        let v1 = func.alloc_var(Ty::i32());
        let a = Value::Const(10);
        let b = Value::Const(20);
        func.push_inst(
            func.entry_block,
            IrInst::Binary {
                dst: v0.clone(),
                op: OpCode::Add,
                lhs: a.clone(),
                rhs: b.clone(),
            },
        );
        func.push_inst(
            func.entry_block,
            IrInst::Binary {
                dst: v1.clone(),
                op: OpCode::Add,
                lhs: a,
                rhs: b,
            },
        );
        let eliminated = cse(&mut func);
        assert_eq!(eliminated, 1);
        assert!(matches!(
            &func.blocks[0].insts[1],
            IrInst::Unary { op: OpCode::Copy, .. }
        ));
    }
}
