//! Live Variables Analysis
//!
//! For each program point, determines which variables are "live" — meaning
//! they will be used before being redefined. This is a backward may-analysis.

use crate::worklist::{Direction, Fact, Framework, WorklistSolver};
use bibleteks_ir::{BlockId, IrFunction, Value};
use std::collections::{BTreeSet, HashMap};

/// Live variables analysis result
#[derive(Debug, Clone)]
pub struct LiveVariables {
    /// IN[block_id] = variables live at block entry
    pub in_sets: HashMap<BlockId, BTreeSet<Value>>,
    /// OUT[block_id] = variables live at block exit
    pub out_sets: HashMap<BlockId, BTreeSet<Value>>,
}

/// Framework for live variables analysis
struct LiveVarFramework<'a> {
    func: &'a IrFunction,
    /// Map from block_id to block index
    block_indices: HashMap<BlockId, usize>,
    /// USE[block_idx] = variables used before being defined in this block
    use_sets: Vec<BTreeSet<Value>>,
    /// DEF[block_idx] = variables defined in this block
    def_sets: Vec<BTreeSet<Value>>,
}

impl<'a> LiveVarFramework<'a> {
    fn new(func: &'a IrFunction) -> Self {
        let mut block_indices = HashMap::new();
        let mut use_sets = Vec::new();
        let mut def_sets = Vec::new();

        for (idx, block) in func.blocks.iter().enumerate() {
            block_indices.insert(block.id, idx);

            let mut use_set = BTreeSet::new();
            let mut def_set = BTreeSet::new();

            // Scan instructions to compute USE and DEF
            for inst in &block.insts {
                // First, add all used variables that haven't been defined yet
                for src in inst.sources() {
                    if !def_set.contains(src) {
                        use_set.insert(src.clone());
                    }
                }

                // Then, add the defined variable
                if let Some(dst) = inst.dst() {
                    def_set.insert(dst.clone());
                }
            }

            use_sets.push(use_set);
            def_sets.push(def_set);
        }

        LiveVarFramework {
            func,
            block_indices,
            use_sets,
            def_sets,
        }
    }
}

impl<'a> Framework for LiveVarFramework<'a> {
    type Element = Value;

    fn direction(&self) -> Direction {
        Direction::Backward
    }

    fn boundary_fact(&self) -> Fact<Value> {
        // Exit blocks have no live variables (or could include return value)
        Fact::new()
    }

    fn transfer(&self, block_idx: usize, output: &Fact<Value>) -> Fact<Value> {
        // IN = USE ∪ (OUT - DEF)
        let mut input = self.use_sets[block_idx].clone();
        for var in output {
            if !self.def_sets[block_idx].contains(var) {
                input.insert(var.clone());
            }
        }
        input
    }

    fn confluence(&self, facts: &[&Fact<Value>]) -> Fact<Value> {
        // Union for may-analysis
        let mut result = Fact::new();
        for fact in facts {
            result.extend(fact.iter().cloned());
        }
        result
    }
}

impl LiveVariables {
    /// Analyze live variables for a function
    pub fn analyze(func: &IrFunction) -> Self {
        let framework = LiveVarFramework::new(func);

        // Build dependency graph (successors for backward analysis)
        let mut deps = vec![Vec::new(); func.blocks.len()];
        for (idx, block) in func.blocks.iter().enumerate() {
            for succ in &block.successors {
                if let Some(&succ_idx) = framework.block_indices.get(succ) {
                    deps[idx].push(succ_idx);
                }
            }
        }

        let mut solver = WorklistSolver::new(framework, func.blocks.len(), deps);
        solver.solve();

        // Convert results back to BlockId-indexed maps
        let mut in_sets = HashMap::new();
        let mut out_sets = HashMap::new();

        for (idx, block) in func.blocks.iter().enumerate() {
            in_sets.insert(block.id, solver.in_fact(idx).clone());
            out_sets.insert(block.id, solver.out_fact(idx).clone());
        }

        LiveVariables {
            in_sets,
            out_sets,
        }
    }

    /// Check if a variable is live at block entry
    pub fn is_live_at_entry(&self, block_id: BlockId, var: &Value) -> bool {
        self.in_sets
            .get(&block_id)
            .map(|vars| vars.contains(var))
            .unwrap_or(false)
    }

    /// Check if a variable is live at block exit
    pub fn is_live_at_exit(&self, block_id: BlockId, var: &Value) -> bool {
        self.out_sets
            .get(&block_id)
            .map(|vars| vars.contains(var))
            .unwrap_or(false)
    }

    /// Get all variables live at block entry
    pub fn live_at_entry(&self, block_id: BlockId) -> BTreeSet<Value> {
        self.in_sets.get(&block_id).cloned().unwrap_or_default()
    }

    /// Get all variables live at block exit
    pub fn live_at_exit(&self, block_id: BlockId) -> BTreeSet<Value> {
        self.out_sets.get(&block_id).cloned().unwrap_or_default()
    }

    /// Find dead variables (defined but never used)
    pub fn dead_variables(&self, func: &IrFunction) -> Vec<Value> {
        let mut dead = Vec::new();

        for block in &func.blocks {
            for inst in &block.insts {
                if let Some(dst) = inst.dst() {
                    // Check if this variable is live after this instruction
                    // For simplicity, check if it's live at block exit
                    if !self.is_live_at_exit(block.id, dst) {
                        // Also check if it's used later in the same block
                        let mut used_later = false;
                        let mut found_this_inst = false;

                        for other_inst in &block.insts {
                            if std::ptr::eq(other_inst, inst) {
                                found_this_inst = true;
                                continue;
                            }
                            if found_this_inst {
                                if other_inst.sources().contains(&dst) {
                                    used_later = true;
                                    break;
                                }
                            }
                        }

                        if !used_later {
                            dead.push(dst.clone());
                        }
                    }
                }
            }
        }

        dead
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bibleteks_ir::{OpCode, Ty};

    #[test]
    fn test_simple_live_vars() {
        // Create a simple function:
        // entry:
        //   v0 = ADD v1, v2  (v1, v2 are used, v0 is defined)
        //   v3 = ADD v0, v1  (v0, v1 are used, v3 is defined)
        //   RETURN v3        (v3 is used)
        let mut func = IrFunction::new("test", 0x1000);
        let v0 = func.alloc_var(Ty::i32());
        let v1 = Value::reg("v1", Ty::i32());
        let v2 = Value::reg("v2", Ty::i32());
        let v3 = func.alloc_var(Ty::i32());

        func.push_inst(func.entry_block, IrInst::Binary {
            dst: v0.clone(),
            op: OpCode::Add,
            lhs: v1.clone(),
            rhs: v2.clone(),
        });
        func.push_inst(func.entry_block, IrInst::Binary {
            dst: v3.clone(),
            op: OpCode::Add,
            lhs: v0.clone(),
            rhs: v1.clone(),
        });
        func.push_inst(func.entry_block, IrInst::Return {
            value: Some(v3.clone()),
        });

        let lv = LiveVariables::analyze(&func);

        // At entry, v1 and v2 should be live (used before defined)
        let in_vars = lv.live_at_entry(func.entry_block);
        assert!(in_vars.contains(&v1));
        assert!(in_vars.contains(&v2));

        // v0 should NOT be live at entry (defined before used)
        assert!(!in_vars.contains(&v0));
    }

    #[test]
    fn test_dead_code_detection() {
        // Create a function with dead code:
        // entry:
        //   v0 = ADD v1, v2  (v0 is never used - dead!)
        //   v3 = ADD v1, v2
        //   RETURN v3
        let mut func = IrFunction::new("test", 0x1000);
        let v0 = func.alloc_var(Ty::i32());
        let v1 = Value::reg("v1", Ty::i32());
        let v2 = Value::reg("v2", Ty::i32());
        let v3 = func.alloc_var(Ty::i32());

        func.push_inst(func.entry_block, IrInst::Binary {
            dst: v0.clone(),
            op: OpCode::Add,
            lhs: v1.clone(),
            rhs: v2.clone(),
        });
        func.push_inst(func.entry_block, IrInst::Binary {
            dst: v3.clone(),
            op: OpCode::Add,
            lhs: v1.clone(),
            rhs: v2.clone(),
        });
        func.push_inst(func.entry_block, IrInst::Return {
            value: Some(v3.clone()),
        });

        let lv = LiveVariables::analyze(&func);
        let dead = lv.dead_variables(&func);

        // v0 should be detected as dead
        assert!(dead.contains(&v0));
        // v3 should NOT be dead (it's returned)
        assert!(!dead.contains(&v3));
    }
}
