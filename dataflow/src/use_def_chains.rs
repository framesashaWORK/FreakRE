//! Use-Def Chains
//!
//! For each use of a variable, find all possible definitions that could reach that use.
//! This builds on the reaching definitions analysis.

use crate::reaching_definitions::{Definition, ReachingDefinitions};
use freakre_ir::{BlockId, IrFunction, Value};
use std::collections::{BTreeSet, HashMap};

/// A use of a variable: (block_id, instruction_offset, variable)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Use {
    pub block_id: BlockId,
    pub inst_offset: usize,
    pub var: Value,
}

/// Use-def chains: for each use, the set of possible definitions
#[derive(Debug, Clone)]
pub struct UseDefChains {
    /// Map from use to set of possible definitions
    pub chains: HashMap<Use, BTreeSet<Definition>>,
    /// All uses in the function
    pub all_uses: Vec<Use>,
}

impl UseDefChains {
    /// Build use-def chains for a function using reaching definitions
    pub fn build(func: &IrFunction, reaching_defs: &ReachingDefinitions) -> Self {
        let mut chains = HashMap::new();
        let mut all_uses = Vec::new();

        for block in &func.blocks {
            for (offset, inst) in block.insts.iter().enumerate() {
                // Find all variables used by this instruction
                for src in inst.sources() {
                    let use_site = Use {
                        block_id: block.id,
                        inst_offset: offset,
                        var: src.clone(),
                    };

                    all_uses.push(use_site.clone());

                    // Find reaching definitions at this point
                    let reaching = reaching_defs.reaching_at(func, block.id, offset);

                    // Filter to definitions of the used variable
                    let defs: BTreeSet<Definition> =
                        reaching.into_iter().filter(|def| def.var == *src).collect();

                    chains.insert(use_site, defs);
                }
            }
        }

        UseDefChains { chains, all_uses }
    }

    /// Get definitions that reach a specific use
    pub fn defs_for_use(&self, use_site: &Use) -> Option<&BTreeSet<Definition>> {
        self.chains.get(use_site)
    }

    /// Find all uses of a specific variable
    pub fn uses_of(&self, var: &Value) -> Vec<&Use> {
        self.all_uses.iter().filter(|u| u.var == *var).collect()
    }

    /// Check if a use has no reaching definitions (use before def)
    pub fn is_use_before_def(&self, use_site: &Use) -> bool {
        self.chains
            .get(use_site)
            .map(|defs| defs.is_empty())
            .unwrap_or(true)
    }

    /// Find all uses that have no reaching definitions
    pub fn uses_before_def(&self) -> Vec<&Use> {
        self.all_uses
            .iter()
            .filter(|u| self.is_use_before_def(u))
            .collect()
    }

    /// Check if a use has exactly one reaching definition
    pub fn has_unique_def(&self, use_site: &Use) -> bool {
        self.chains
            .get(use_site)
            .map(|defs| defs.len() == 1)
            .unwrap_or(false)
    }

    /// Get the unique definition for a use (if it exists)
    pub fn unique_def(&self, use_site: &Use) -> Option<&Definition> {
        self.chains.get(use_site).and_then(|defs| {
            if defs.len() == 1 {
                defs.iter().next()
            } else {
                None
            }
        })
    }

    /// Find all uses with multiple possible definitions
    pub fn ambiguous_uses(&self) -> Vec<&Use> {
        self.all_uses
            .iter()
            .filter(|u| {
                self.chains
                    .get(u)
                    .map(|defs| defs.len() > 1)
                    .unwrap_or(false)
            })
            .collect()
    }

    /// Detect suspicious patterns:
    /// - Use before definition
    /// - Use of uninitialized register
    /// - Multiple conflicting definitions
    pub fn suspicious_patterns(&self) -> Vec<String> {
        let mut patterns = Vec::new();

        // Use before definition
        for use_site in self.uses_before_def() {
            patterns.push(format!(
                "Use before definition: {:?} at {}:{} ",
                use_site.var, use_site.block_id, use_site.inst_offset
            ));
        }

        // Ambiguous definitions (multiple possible sources)
        for use_site in self.ambiguous_uses() {
            if let Some(defs) = self.chains.get(use_site) {
                patterns.push(format!(
                    "Ambiguous definition for {:?} at {}:{} ({} possible defs)",
                    use_site.var,
                    use_site.block_id,
                    use_site.inst_offset,
                    defs.len()
                ));
            }
        }

        patterns
    }
}

/// Def-Use Chains (reverse direction)
/// For each definition, find all uses that it may reach
#[derive(Debug, Clone)]
pub struct DefUseChains {
    /// Map from definition to set of uses it reaches
    pub chains: HashMap<Definition, Vec<Use>>,
}

impl DefUseChains {
    /// Build def-use chains from use-def chains
    pub fn build(use_def: &UseDefChains) -> Self {
        let mut chains: HashMap<Definition, Vec<Use>> = HashMap::new();

        for (use_site, defs) in &use_def.chains {
            for def in defs {
                chains
                    .entry(def.clone())
                    .or_default()
                    .push(use_site.clone());
            }
        }

        DefUseChains { chains }
    }

    /// Get all uses of a specific definition
    pub fn uses_of_def(&self, def: &Definition) -> Option<&Vec<Use>> {
        self.chains.get(def)
    }

    /// Find definitions that are never used (dead definitions)
    pub fn dead_definitions(&self, all_defs: &BTreeSet<Definition>) -> Vec<Definition> {
        all_defs
            .iter()
            .filter(|def| {
                self.chains
                    .get(def)
                    .map(|uses| uses.is_empty())
                    .unwrap_or(true)
            })
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use freakre_ir::{IrInst, OpCode, Ty};

    #[test]
    fn test_use_def_chains() {
        // Create a simple function:
        // entry:
        //   v0 = ADD v1, v2
        //   v3 = ADD v0, v1  (v0 used here)
        //   RETURN v3
        let mut func = IrFunction::new("test", 0x1000);
        let v0 = func.alloc_var(Ty::i32());
        let v1 = Value::reg("v1", Ty::i32());
        let v2 = Value::reg("v2", Ty::i32());
        let v3 = func.alloc_var(Ty::i32());

        func.push_inst(
            func.entry_block,
            IrInst::Binary {
                dst: v0.clone(),
                op: OpCode::Add,
                lhs: v1.clone(),
                rhs: v2.clone(),
            },
        );
        func.push_inst(
            func.entry_block,
            IrInst::Binary {
                dst: v3.clone(),
                op: OpCode::Add,
                lhs: v0.clone(),
                rhs: v1.clone(),
            },
        );
        func.push_inst(
            func.entry_block,
            IrInst::Return {
                value: Some(v3.clone()),
            },
        );

        let rd = ReachingDefinitions::analyze(&func);
        let ud = UseDefChains::build(&func, &rd);

        // Find the use of v0 at instruction 1
        let v0_use = Use {
            block_id: func.entry_block,
            inst_offset: 1,
            var: v0.clone(),
        };

        // Should have exactly one definition (from instruction 0)
        assert!(ud.has_unique_def(&v0_use));
        let def = ud.unique_def(&v0_use).unwrap();
        assert_eq!(def.var, v0);
    }

    #[test]
    fn test_use_before_def() {
        // Create a function where v0 is used before being defined:
        // entry:
        //   v3 = ADD v0, v1  (v0 used but not yet defined!)
        //   v0 = ADD v1, v2
        //   RETURN v3
        let mut func = IrFunction::new("test", 0x1000);
        let v0 = func.alloc_var(Ty::i32());
        let v1 = Value::reg("v1", Ty::i32());
        let v2 = Value::reg("v2", Ty::i32());
        let v3 = func.alloc_var(Ty::i32());

        func.push_inst(
            func.entry_block,
            IrInst::Binary {
                dst: v3.clone(),
                op: OpCode::Add,
                lhs: v0.clone(),
                rhs: v1.clone(),
            },
        );
        func.push_inst(
            func.entry_block,
            IrInst::Binary {
                dst: v0.clone(),
                op: OpCode::Add,
                lhs: v1.clone(),
                rhs: v2.clone(),
            },
        );
        func.push_inst(
            func.entry_block,
            IrInst::Return {
                value: Some(v3.clone()),
            },
        );

        let rd = ReachingDefinitions::analyze(&func);
        let ud = UseDefChains::build(&func, &rd);

        // The first use of v0 (at instruction 0) should have no reaching definitions
        let v0_use = Use {
            block_id: func.entry_block,
            inst_offset: 0,
            var: v0.clone(),
        };

        assert!(ud.is_use_before_def(&v0_use));

        // Should detect this as suspicious
        let suspicious = ud.suspicious_patterns();
        assert!(!suspicious.is_empty());
        assert!(suspicious[0].contains("Use before definition"));
    }

    #[test]
    fn test_def_use_chains() {
        let mut func = IrFunction::new("test", 0x1000);
        let v0 = func.alloc_var(Ty::i32());
        let v1 = Value::reg("v1", Ty::i32());
        let v2 = Value::reg("v2", Ty::i32());
        let v3 = func.alloc_var(Ty::i32());

        func.push_inst(
            func.entry_block,
            IrInst::Binary {
                dst: v0.clone(),
                op: OpCode::Add,
                lhs: v1.clone(),
                rhs: v2.clone(),
            },
        );
        func.push_inst(
            func.entry_block,
            IrInst::Binary {
                dst: v3.clone(),
                op: OpCode::Add,
                lhs: v0.clone(),
                rhs: v1.clone(),
            },
        );
        func.push_inst(
            func.entry_block,
            IrInst::Return {
                value: Some(v3.clone()),
            },
        );

        let rd = ReachingDefinitions::analyze(&func);
        let ud = UseDefChains::build(&func, &rd);
        let du = DefUseChains::build(&ud);

        // Find the definition of v0
        let v0_def = Definition {
            var: v0.clone(),
            inst_id: 0, // First instruction in first block
        };

        // Should have one use (at instruction 1)
        let uses = du.uses_of_def(&v0_def).unwrap();
        assert_eq!(uses.len(), 1);
        assert_eq!(uses[0].inst_offset, 1);
    }
}
