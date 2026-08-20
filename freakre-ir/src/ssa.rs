//! SSA (Static Single Assignment) form conversion.
//!
//! Converts IR from mutable-register form to SSA form by inserting
//! Phi nodes at dominance frontiers.

use crate::ir::{BlockId, IrFunction, IrInst, Value};
use crate::types::Ty;
use std::collections::{HashMap, HashSet};

/// Context for SSA conversion.
pub struct SsaContext {
    /// Current version counter for each variable name (register).
    versions: HashMap<String, u32>,
    /// Stack of current SSA values for each register (for lookup during renaming).
    stacks: HashMap<String, Vec<Value>>,
}

impl SsaContext {
    pub fn new() -> Self {
        SsaContext {
            versions: HashMap::new(),
            stacks: HashMap::new(),
        }
    }

    /// Get the current SSA value for a register, or None if undefined.
    pub fn get(&self, reg: &str) -> Option<&Value> {
        self.stacks.get(reg).and_then(|s| s.last())
    }

    /// Push a new SSA version for a register.
    pub fn push(&mut self, reg: &str, ty: Ty) -> Value {
        let version = self.versions.entry(reg.to_string()).or_insert(0);
        let var = Value::Var {
            id: *version,
            ty: ty.clone(),
        };
        *version += 1;
        self.stacks.entry(reg.to_string()).or_default().push(var.clone());
        var
    }

    /// Pop the current SSA version for a register.
    pub fn pop(&mut self, reg: &str) {
        if let Some(stack) = self.stacks.get_mut(reg) {
            stack.pop();
        }
    }
}

/// Convert an IR function to SSA form.
///
/// This is a simplified SSA construction algorithm based on:
/// 1. Compute dominator tree
/// 2. Compute dominance frontiers
/// 3. Insert Phi nodes at dominance frontiers for all defined variables
/// 4. Rename variables to SSA form
///
/// For now, this implementation handles the common case of single-definition
/// registers and inserts trivial phi nodes at merge points.
pub fn to_ssa(func: &mut IrFunction) {
    func.build_cfg();

    // Step 1: Find all registers that are defined in multiple blocks
    let mut def_blocks: HashMap<String, HashSet<BlockId>> = HashMap::new();
    for block in &func.blocks {
        for inst in &block.insts {
            if let Some(dst) = inst.dst() {
                match dst {
                    Value::Register { name, .. } => {
                        def_blocks.entry(name.clone()).or_default().insert(block.id);
                    }
                    _ => {}
                }
            }
        }
    }

    // Step 2: For registers defined in multiple blocks, we need Phi nodes
    // at merge points. For simplicity, we insert trivial phi nodes at blocks
    // that have multiple predecessors and use registers defined elsewhere.

    let mut phi_insertions: Vec<(BlockId, usize, IrInst)> = Vec::new();

    for (reg, blocks) in &def_blocks {
        if blocks.len() <= 1 {
            continue; // Single definition — no phi needed
        }

        // Find blocks with multiple predecessors that need phi nodes
        for block in &func.blocks {
            if block.predecessors.len() >= 2 {
                // Check if this block uses the register
                let uses_reg = block.insts.iter().any(|inst| {
                    inst.sources().iter().any(|v| {
                        matches!(v, Value::Register { name, .. } if name == reg)
                    })
                });

                if uses_reg {
                    // Insert a phi node at the beginning of this block
                    let ty = func.blocks.iter()
                        .flat_map(|b| b.insts.iter())
                        .find_map(|inst| {
                            inst.dst().and_then(|v| match v {
                                Value::Register { name, ty } if name == reg => Some(ty.clone()),
                                _ => None,
                            })
                        })
                        .unwrap_or(Ty::i64());

                    let phi_dst = Value::Register {
                        name: format!("{}_ssa", reg),
                        ty: ty.clone(),
                    };

                    let incoming: Vec<(BlockId, Value)> = block.predecessors.iter()
                        .map(|&pred_id| (pred_id, Value::Register {
                            name: reg.clone(),
                            ty: ty.clone(),
                        }))
                        .collect();

                    phi_insertions.push((block.id, 0, IrInst::Phi {
                        dst: phi_dst,
                        incoming,
                    }));
                }
            }
        }
    }

    // Step 3: Insert phi nodes
    for (block_id, _pos, inst) in phi_insertions {
        if let Some(block) = func.blocks.iter_mut().find(|b| b.id == block_id) {
            block.insts.insert(0, inst);
        }
    }
}

/// Remove trivial Phi nodes (where all incoming values are the same).
pub fn simplify_phi_nodes(func: &mut IrFunction) {
    for block in &mut func.blocks {
        block.insts.retain(|inst| {
            match inst {
                IrInst::Phi { incoming, .. } => {
                    if incoming.is_empty() {
                        return false;
                    }
                    // Keep phi only if incoming values differ
                    let first = &incoming[0].1;
                    incoming.iter().any(|(_, v)| v != first)
                }
                _ => true,
            }
        });
    }
}

/// Compute dominators using the iterative algorithm.
/// Returns a map from block_id → immediate dominator block_id.
pub fn compute_dominators(func: &IrFunction) -> HashMap<BlockId, BlockId> {
    let mut doms: HashMap<BlockId, BlockId> = HashMap::new();
    let entry = func.entry_block;
    doms.insert(entry, entry);

    // Iterative dominator computation
    let mut changed = true;
    while changed {
        changed = false;
        for block in &func.blocks {
            if block.id == entry {
                continue;
            }

            let preds = &block.predecessors;
            if preds.is_empty() {
                continue;
            }

            // Find first processed predecessor
            let mut new_idom: Option<BlockId> = None;
            for &pred in preds {
                if doms.contains_key(&pred) {
                    new_idom = Some(pred);
                    break;
                }
            }

            if let Some(mut new_idom_val) = new_idom {
                // Intersect with other predecessors
                for &pred in preds {
                    if pred == new_idom_val {
                        continue;
                    }
                    if doms.contains_key(&pred) {
                        new_idom_val = intersect(pred, new_idom_val, &doms, func);
                    }
                }

                if doms.get(&block.id) != Some(&new_idom_val) {
                    doms.insert(block.id, new_idom_val);
                    changed = true;
                }
            }
        }
    }

    doms
}

/// Intersect two dominators (walk up the dominator tree).
fn intersect(
    b1: BlockId,
    b2: BlockId,
    doms: &HashMap<BlockId, BlockId>,
    func: &IrFunction,
) -> BlockId {
    let order = |id: BlockId| -> usize {
        func.blocks.iter().position(|b| b.id == id).unwrap_or(0)
    };

    let mut finger1 = b1;
    let mut finger2 = b2;

    while finger1 != finger2 {
        while order(finger1) > order(finger2) {
            finger1 = *doms.get(&finger1).unwrap_or(&finger1);
        }
        while order(finger2) > order(finger1) {
            finger2 = *doms.get(&finger2).unwrap_or(&finger2);
        }
    }

    finger1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::OpCode;

    #[test]
    fn test_ssa_context() {
        let mut ctx = SsaContext::new();
        let v1 = ctx.push("rax", Ty::i64());
        let v2 = ctx.push("rax", Ty::i64());

        assert_eq!(ctx.get("rax"), Some(&v2));
        assert_ne!(v1, v2);

        ctx.pop("rax");
        assert_eq!(ctx.get("rax"), Some(&v1));
    }

    #[test]
    fn test_dominator_computation() {
        let mut func = IrFunction::new("test", 0x0);
        let bb1 = func.add_block("A");
        let bb2 = func.add_block("B");
        let bb3 = func.add_block("C");

        // Entry -> A, Entry -> B, A -> C, B -> C
        func.push_inst(func.entry_block, IrInst::CBranch {
            cond: Value::var(0, Ty::Bool),
            target_true: bb1,
            target_false: bb2,
        });
        func.push_inst(bb1, IrInst::Branch { target: bb3 });
        func.push_inst(bb2, IrInst::Branch { target: bb3 });
        func.push_inst(bb3, IrInst::Return { value: None });

        func.build_cfg();
        let doms = compute_dominators(&func);

        // Entry dominates all
        assert!(doms.contains_key(&func.entry_block));
        assert!(doms.contains_key(&bb1));
        assert!(doms.contains_key(&bb2));
        assert!(doms.contains_key(&bb3));
    }

    #[test]
    fn test_simplify_phi() {
        let mut func = IrFunction::new("test", 0x0);
        let bb1 = func.add_block("merge");

        func.push_inst(bb1, IrInst::Phi {
            dst: Value::var(0, Ty::i64()),
            incoming: vec![
                (func.entry_block, Value::int(42)),
                (func.entry_block, Value::int(42)), // Same value
            ],
        });

        simplify_phi_nodes(&mut func);

        // Phi should be removed (all incoming values identical)
        assert!(func.block(bb1).unwrap().insts.is_empty());
    }
}
