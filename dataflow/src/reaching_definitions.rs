//! Reaching Definitions Analysis
//!
//! For each program point, determines which variable definitions may reach that point.
//! This is a forward may-analysis using the worklist algorithm.

use crate::worklist::{Direction, Fact, Framework, WorklistSolver};
use bibleteks_ir::{BlockId, IrFunction, Value};
use std::collections::{BTreeSet, HashMap};

/// A definition: (variable, instruction_id where it's defined)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Definition {
    pub var: Value,
    pub inst_id: u64,
}

/// Reaching definitions analysis result
#[derive(Debug, Clone)]
pub struct ReachingDefinitions {
    /// IN[block_id] = definitions reaching block entry
    pub in_sets: HashMap<BlockId, BTreeSet<Definition>>,
    /// OUT[block_id] = definitions reaching block exit
    pub out_sets: HashMap<BlockId, BTreeSet<Definition>>,
    /// All definitions in the function
    pub all_defs: BTreeSet<Definition>,
}

/// Framework for reaching definitions
struct ReachingDefFramework<'a> {
    func: &'a IrFunction,
    /// Map from block_id to block index
    block_indices: HashMap<BlockId, usize>,
    /// GEN[block_idx] = definitions in this block
    gen_sets: Vec<BTreeSet<Definition>>,
    /// KILL[block_idx] = definitions killed by this block
    kill_sets: Vec<BTreeSet<Definition>>,
}

impl<'a> ReachingDefFramework<'a> {
    fn new(func: &'a IrFunction) -> Self {
        let mut block_indices = HashMap::new();
        let mut gen_sets = Vec::new();
        let mut kill_sets = Vec::new();
        let mut all_defs = BTreeSet::new();

        for (idx, block) in func.blocks.iter().enumerate() {
            block_indices.insert(block.id, idx);

            let mut gen = BTreeSet::new();
            let kill = BTreeSet::new();

            // Collect all definitions in this block
            for (inst_offset, inst) in block.insts.iter().enumerate() {
                let inst_id = (block.id.0 as u64) * 10000 + inst_offset as u64;

                if let Some(dst) = inst.dst() {
                    let def = Definition {
                        var: dst.clone(),
                        inst_id,
                    };
                    gen.insert(def.clone());
                    all_defs.insert(def.clone());

                    // This definition kills all other definitions of the same variable
                    // (We'll compute kill sets after collecting all definitions)
                }
            }

            gen_sets.push(gen);
            kill_sets.push(kill);
        }

        // Compute kill sets: for each definition in a block, kill all other
        // definitions of the same variable from other blocks
        for (block_idx, gen) in gen_sets.iter().enumerate() {
            for def in gen {
                // Find all definitions of the same variable in other blocks
                for (other_idx, other_gen) in gen_sets.iter().enumerate() {
                    if other_idx != block_idx {
                        for other_def in other_gen {
                            if other_def.var == def.var {
                                kill_sets[block_idx].insert(other_def.clone());
                            }
                        }
                    }
                }
            }
        }

        ReachingDefFramework {
            func,
            block_indices,
            gen_sets,
            kill_sets,
        }
    }
}

impl<'a> Framework for ReachingDefFramework<'a> {
    type Element = Definition;

    fn direction(&self) -> Direction {
        Direction::Forward
    }

    fn boundary_fact(&self) -> Fact<Definition> {
        // Entry block has no incoming definitions (or could include function params)
        Fact::new()
    }

    fn transfer(&self, block_idx: usize, input: &Fact<Definition>) -> Fact<Definition> {
        // OUT = GEN ∪ (IN - KILL)
        let mut out = self.gen_sets[block_idx].clone();
        for def in input {
            if !self.kill_sets[block_idx].contains(def) {
                out.insert(def.clone());
            }
        }
        out
    }

    fn confluence(&self, facts: &[&Fact<Definition>]) -> Fact<Definition> {
        // Union for may-analysis
        let mut result = Fact::new();
        for fact in facts {
            result.extend(fact.iter().cloned());
        }
        result
    }
}

impl ReachingDefinitions {
    /// Analyze reaching definitions for a function
    pub fn analyze(func: &IrFunction) -> Self {
        let framework = ReachingDefFramework::new(func);
        let all_defs = framework.gen_sets.iter().flatten().cloned().collect();

        // Build dependency graph (predecessors for forward analysis)
        let mut deps = vec![Vec::new(); func.blocks.len()];
        for (idx, block) in func.blocks.iter().enumerate() {
            for pred in &block.predecessors {
                if let Some(&pred_idx) = framework.block_indices.get(pred) {
                    deps[idx].push(pred_idx);
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

        ReachingDefinitions {
            in_sets,
            out_sets,
            all_defs,
        }
    }

    /// Get definitions reaching a specific instruction
    pub fn reaching_at(&self, func: &IrFunction, block_id: BlockId, inst_offset: usize) -> BTreeSet<Definition> {
        // Start with IN[block]
        let mut reaching = self.in_sets.get(&block_id).cloned().unwrap_or_default();

        // Apply transfer function for instructions before this one
        if let Some(block) = func.block(block_id) {
            for (offset, inst) in block.insts.iter().enumerate() {
                if offset >= inst_offset {
                    break;
                }

                let inst_id = (block_id.0 as u64) * 10000 + offset as u64;

                // Add this definition
                if let Some(dst) = inst.dst() {
                    reaching.insert(Definition {
                        var: dst.clone(),
                        inst_id,
                    });

                    // Remove other definitions of the same variable
                    reaching.retain(|def| def.var != *dst || def.inst_id == inst_id);
                }
            }
        }

        reaching
    }

    /// Find all definitions of a variable that reach a given point
    pub fn definitions_of(&self, var: &Value, block_id: BlockId) -> Vec<&Definition> {
        self.in_sets
            .get(&block_id)
            .map(|defs| {
                defs.iter()
                    .filter(|def| def.var == *var)
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bibleteks_ir::{OpCode, Ty};

    #[test]
    fn test_simple_reaching_defs() {
        // Create a simple function:
        // entry:
        //   v0 = ADD v1, v2
        //   v3 = ADD v0, v1
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
            lhs: v0.clone(),
            rhs: v1.clone(),
        });
        func.push_inst(func.entry_block, IrInst::Return {
            value: Some(v3.clone()),
        });

        let rd = ReachingDefinitions::analyze(&func);

        // Entry block should have no incoming definitions
        assert!(rd.in_sets.get(&func.entry_block).unwrap().is_empty());

        // Exit should have definitions of v0 and v3
        let out_defs = rd.out_sets.get(&func.entry_block).unwrap();
        assert!(out_defs.iter().any(|d| d.var == v0));
        assert!(out_defs.iter().any(|d| d.var == v3));
    }
}
