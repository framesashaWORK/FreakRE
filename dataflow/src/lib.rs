#![allow(dead_code, unused_assignments)]
//! # freakre-dataflow — Data Flow Analysis
//!
//! Static data flow analysis for the freakre-ir intermediate representation.
//! Provides:
//!
//! - **Reaching Definitions**: Which assignments can reach each program point
//! - **Live Variables**: Which variables are live (will be used) at each point
//! - **Use-Def Chains**: For each variable use, find all possible definitions
//!
//! ## Architecture
//!
//! ```text
//! IR Program ──→ Reaching Definitions ──→ Use-Def Chains
//!                    │
//!                    └──→ Live Variables
//! ```
//!
//! All analyses use worklist algorithms with monotone frameworks.

pub mod live_variables;
pub mod reaching_definitions;
pub mod use_def_chains;
pub mod value_set;
pub mod worklist;
pub mod taint;

pub use live_variables::LiveVariables;
pub use reaching_definitions::ReachingDefinitions;
pub use use_def_chains::UseDefChains;
pub use value_set::{AbstractValue, ValueSetAnalysis};
pub use taint::{analyze_taint, TaintConfig, TaintReport, TaintSink, TaintSource};

use freakre_ir::IrFunction;

/// Combined data flow analysis result
#[derive(Debug, Clone)]
pub struct DataFlowAnalysis {
    pub reaching_defs: ReachingDefinitions,
    pub live_vars: LiveVariables,
    pub use_def: UseDefChains,
    pub value_sets: ValueSetAnalysis,
}

impl DataFlowAnalysis {
    /// Run all data flow analyses on a function
    pub fn analyze(func: &IrFunction) -> Self {
        let reaching_defs = ReachingDefinitions::analyze(func);
        let live_vars = LiveVariables::analyze(func);
        let use_def = UseDefChains::build(func, &reaching_defs);
        let value_sets = ValueSetAnalysis::analyze(func);

        DataFlowAnalysis {
            reaching_defs,
            live_vars,
            use_def,
            value_sets,
        }
    }

    /// Get all suspicious patterns detected during analysis
    pub fn suspicious_patterns(&self) -> Vec<String> {
        let mut patterns = Vec::new();

        // Detect use before def
        for (use_site, defs) in &self.use_def.chains {
            if defs.is_empty() {
                patterns.push(format!(
                    "Use before definition: {:?} at instruction {}",
                    use_site.var, use_site.inst_offset
                ));
            }
        }

        // Detect dead code (definitions never used)
        // This would require reverse analysis (def-use chains)

        patterns
    }
}
