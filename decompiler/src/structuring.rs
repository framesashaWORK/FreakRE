//! Control flow structuring: convert unstructured CFG to structured AST.
//!
//! Recovers high-level control flow constructs (if/else, while, for, switch)
//! from the control flow graph.

use crate::ast::*;
use crate::ir_to_ast::IrToAstConverter;
use bibleteks_ir::{BlockId, IrFunction, IrInst};
use std::collections::{HashSet, VecDeque};

/// Structure the control flow of a function into AST statements
pub fn structure_control_flow(func: &IrFunction, converter: &mut IrToAstConverter) -> Vec<Stmt> {
    let structurer = ControlFlowStructurer::new(func);
    structurer.structure(converter)
}

struct ControlFlowStructurer<'a> {
    func: &'a IrFunction,
}

impl<'a> ControlFlowStructurer<'a> {
    fn new(func: &'a IrFunction) -> Self {
        ControlFlowStructurer { func }
    }
    
    fn structure(&self, converter: &mut IrToAstConverter) -> Vec<Stmt> {
        // Start from entry block
        let entry = self.func.entry_block;
        self.process_block(entry, converter, &mut HashSet::new(), 0)
    }
    
    /// Process a block and its successors
    fn process_block(
        &self,
        block_id: BlockId,
        converter: &mut IrToAstConverter,
        visited: &mut HashSet<BlockId>,
        depth: usize,
    ) -> Vec<Stmt> {
        const MAX_STRUCTURING_DEPTH: usize = 256;
        if depth > MAX_STRUCTURING_DEPTH {
            // Prevent stack overflow on deeply nested/degenerate CFGs
            return vec![Stmt::Expr(Expr::Call {
                func: "__structuring_depth_limit_reached".to_string(),
                args: vec![],
            })];
        }

        if visited.contains(&block_id) {
            return vec![];
        }
        visited.insert(block_id);
        
        let block = match self.func.block(block_id) {
            Some(b) => b,
            None => return vec![],
        };
        
        let mut stmts = Vec::new();
        
        // Convert all non-terminator instructions
        for inst in &block.insts {
            if !inst.is_terminator() {
                stmts.extend(converter.convert_inst(inst));
            }
        }
        
        // Handle terminator
        if let Some(terminator) = block.terminator() {
            match terminator {
                IrInst::Branch { target } => {
                    // Unconditional branch
                    stmts.extend(self.process_block(*target, converter, visited, depth + 1));
                }
                
                IrInst::CBranch { cond, target_true, target_false } => {
                    // Conditional branch → if/else
                    let cond_expr = converter.convert_value_to_expr(cond);
                    
                    let then_body = self.process_block(*target_true, converter, visited, depth + 1);
                    let else_body = self.process_block(*target_false, converter, visited, depth + 1);
                    
                    let else_body = if else_body.is_empty() {
                        None
                    } else {
                        Some(else_body)
                    };
                    
                    stmts.push(Stmt::If {
                        cond: cond_expr,
                        then_body,
                        else_body,
                    });
                }
                
                IrInst::Return { value } => {
                    let ret_value = value.as_ref().map(|v| converter.convert_value_to_expr(v));
                    stmts.push(Stmt::Return { value: ret_value });
                }
                
                IrInst::IndirectBranch { target } => {
                    let target_expr = converter.convert_value_to_expr(target);
                    stmts.push(Stmt::Expr(Expr::Call {
                        func: "goto".to_string(),
                        args: vec![target_expr],
                    }));
                }
                
                _ => {}
            }
        }
        
        stmts
    }
}

/// Detect loops in the CFG
pub fn detect_loops(func: &IrFunction) -> Vec<LoopInfo> {
    let mut loops = Vec::new();
    
    // Simple loop detection: find back edges
    for block in &func.blocks {
        for succ in &block.successors {
            // Check if successor dominates this block (back edge)
            if dominates(func, *succ, block.id) {
                loops.push(LoopInfo {
                    header: *succ,
                    back_edge_from: block.id,
                });
            }
        }
    }
    
    loops
}

/// Loop information
#[derive(Debug, Clone)]
pub struct LoopInfo {
    pub header: BlockId,
    pub back_edge_from: BlockId,
}

/// Check if block A dominates block B
fn dominates(func: &IrFunction, a: BlockId, b: BlockId) -> bool {
    if a == b {
        return true;
    }
    
    // Simple dominance check using BFS from entry
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    
    queue.push_back(func.entry_block);
    visited.insert(func.entry_block);
    
    while let Some(current) = queue.pop_front() {
        if current == b {
            return false; // Found path to B without going through A
        }
        
        if current == a {
            continue; // Don't explore successors of A
        }
        
        if let Some(block) = func.block(current) {
            for succ in &block.successors {
                if !visited.contains(succ) {
                    visited.insert(*succ);
                    queue.push_back(*succ);
                }
            }
        }
    }
    
    true
}

/// Detect if-else patterns
pub fn detect_if_else(func: &IrFunction, block_id: BlockId) -> Option<IfElsePattern> {
    let block = func.block(block_id)?;
    
    // Check if block ends with conditional branch
    let terminator = block.terminator()?;
    if let IrInst::CBranch { cond: _, target_true, target_false } = terminator {
        Some(IfElsePattern {
            cond_block: block_id,
            then_block: *target_true,
            else_block: *target_false,
        })
    } else {
        None
    }
}

/// If-else pattern
#[derive(Debug, Clone)]
pub struct IfElsePattern {
    pub cond_block: BlockId,
    pub then_block: BlockId,
    pub else_block: BlockId,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bibleteks_ir::{OpCode, Ty, Value};
    
    #[test]
    fn test_simple_structuring() {
        let mut func = IrFunction::new("test", 0x1000);
        let v0 = func.alloc_var(Ty::i32());
        
        func.push_inst(func.entry_block, IrInst::Return {
            value: Some(v0.clone()),
        });
        
        let mut converter = IrToAstConverter::new(&func);
        let stmts = structure_control_flow(&func, &mut converter);
        
        assert_eq!(stmts.len(), 1);
        assert!(matches!(stmts[0], Stmt::Return { .. }));
    }
    
    #[test]
    fn test_if_else_detection() {
        let mut func = IrFunction::new("test", 0x1000);
        let cond = Value::var(0, Ty::Bool);
        let then_block = func.add_block("then");
        let else_block = func.add_block("else");
        
        func.push_inst(func.entry_block, IrInst::CBranch {
            cond: cond.clone(),
            target_true: then_block,
            target_false: else_block,
        });
        
        let pattern = detect_if_else(&func, func.entry_block);
        assert!(pattern.is_some());
        
        let pattern = pattern.unwrap();
        assert_eq!(pattern.cond_block, func.entry_block);
        assert_eq!(pattern.then_block, then_block);
        assert_eq!(pattern.else_block, else_block);
    }
}
