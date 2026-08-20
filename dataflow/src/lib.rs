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

pub mod reaching_definitions;
pub mod live_variables;
pub mod use_def_chains;
pub mod worklist;

pub use reaching_definitions::ReachingDefinitions;
pub use live_variables::LiveVariables;
pub use use_def_chains::UseDefChains;

use bibleteks_ir::IrFunction;

/// Combined data flow analysis result
#[derive(Debug, Clone)]
pub struct DataFlowAnalysis {
    pub reaching_defs: ReachingDefinitions,
    pub live_vars: LiveVariables,
    pub use_def: UseDefChains,
}

impl DataFlowAnalysis {
    /// Run all data flow analyses on a function
    pub fn analyze(func: &IrFunction) -> Self {
        let reaching_defs = ReachingDefinitions::analyze(func);
        let live_vars = LiveVariables::analyze(func);
        let use_def = UseDefChains::build(func, &reaching_defs);
        
        DataFlowAnalysis {
            reaching_defs,
            live_vars,
            use_def,
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


