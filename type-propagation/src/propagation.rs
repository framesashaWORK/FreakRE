//! Type propagation across IR functions.
//!
//! High-level API for type inference on IR functions and programs.

use crate::constraints::{ConstraintSystem, TypeVar};
use crate::inference::{InferenceError, TypeInference};
use bibleteks_ir::{IrFunction, IrInst, OpCode, Ty, Value};
use std::collections::HashMap;

/// Type propagator for IR functions
#[derive(Debug)]
pub struct TypePropagator {
    /// Constraint system
    cs: ConstraintSystem,
    
    /// Type inference result
    inference: Option<TypeInference>,
}

impl TypePropagator {
    /// Create a new type propagator
    pub fn new() -> Self {
        TypePropagator {
            cs: ConstraintSystem::new(),
            inference: None,
        }
    }
    
    /// Analyze a function and infer types
    pub fn analyze(&mut self, func: &IrFunction) -> Result<(), InferenceError> {
        // Generate constraints from all instructions
        for block in &func.blocks {
            for inst in &block.insts {
                self.generate_constraints_from_inst(inst);
            }
        }
        
        // Solve constraints
        self.inference = Some(TypeInference::solve(&self.cs)?);
        
        Ok(())
    }
    
    /// Generate constraints from a single instruction
    fn generate_constraints_from_inst(&mut self, inst: &IrInst) {
        match inst {
            IrInst::Binary { dst, op, lhs, rhs } => {
                let dst_var = self.cs.var_for_value(dst);
                let lhs_var = self.cs.var_for_value(lhs);
                let rhs_var = self.cs.var_for_value(rhs);
                
                self.cs.generate_from_op(*op, dst_var, &[lhs_var, rhs_var]);
                
                // Additional constraints based on operation
                match op {
                    OpCode::Add | OpCode::Sub | OpCode::Mul | OpCode::Div | OpCode::Mod => {
                        // Operands must be integers or floats
                        // Result has same type as operands
                    }
                    OpCode::And | OpCode::Or | OpCode::Xor => {
                        // Operands must be integers
                    }
                    OpCode::Shl | OpCode::Shr | OpCode::Sar => {
                        // First operand is value, second is shift amount
                        self.cs.add_same_width(lhs_var, dst_var);
                    }
                    _ => {}
                }
            }
            
            IrInst::Unary { dst, op, src } => {
                let dst_var = self.cs.var_for_value(dst);
                let src_var = self.cs.var_for_value(src);
                
                self.cs.generate_from_op(*op, dst_var, &[src_var]);
                
                match op {
                    OpCode::Zext | OpCode::Sext | OpCode::Trunc => {
                        // Source and dest are integers, but different widths
                        // We can't infer exact widths without more context
                    }
                    OpCode::Not => {
                        // Operand must be integer
                    }
                    OpCode::Neg => {
                        // Operand must be numeric
                    }
                    _ => {}
                }
            }
            
            IrInst::Load { dst, addr, size } => {
                let dst_var = self.cs.var_for_value(dst);
                let addr_var = self.cs.var_for_value(addr);
                
                // Address must be a pointer
                let inner_var = self.cs.fresh_var();
                self.cs.add_ptr_to(addr_var, inner_var);
                
                // Loaded value has the pointed-to type
                self.cs.add_equal(dst_var, inner_var);
                
                // Size constraint
                match size {
                    1 => self.cs.add_int_width(dst_var, 8),
                    2 => self.cs.add_int_width(dst_var, 16),
                    4 => self.cs.add_int_width(dst_var, 32),
                    8 => self.cs.add_int_width(dst_var, 64),
                    _ => {}
                }
            }
            
            IrInst::Store { addr, value, size } => {
                let addr_var = self.cs.var_for_value(addr);
                let value_var = self.cs.var_for_value(value);
                
                // Address must be a pointer
                let inner_var = self.cs.fresh_var();
                self.cs.add_ptr_to(addr_var, inner_var);
                
                // Stored value has the pointed-to type
                self.cs.add_equal(value_var, inner_var);
                
                // Size constraint
                match size {
                    1 => self.cs.add_int_width(value_var, 8),
                    2 => self.cs.add_int_width(value_var, 16),
                    4 => self.cs.add_int_width(value_var, 32),
                    8 => self.cs.add_int_width(value_var, 64),
                    _ => {}
                }
            }
            
            IrInst::Call { dst, target: _, args } => {
                // If we have a return value, it's some type
                if let Some(dst_val) = dst {
                    let _dst_var = self.cs.var_for_value(dst_val);
                    // Type will be inferred from function signature or usage
                }
                
                // Arguments have types based on function signature
                for arg in args {
                    let _arg_var = self.cs.var_for_value(arg);
                    // Type will be inferred from function signature or usage
                }
            }
            
            IrInst::Return { value } => {
                if let Some(val) = value {
                    let _val_var = self.cs.var_for_value(val);
                    // Return type will be inferred from usage
                }
            }
            
            IrInst::CBranch { cond, .. } => {
                let cond_var = self.cs.var_for_value(cond);
                self.cs.add_must_be(cond_var, Ty::Bool);
            }
            
            IrInst::Phi { dst, incoming } => {
                let dst_var = self.cs.var_for_value(dst);
                
                // All incoming values must have the same type as dst
                for (_, val) in incoming {
                    let val_var = self.cs.var_for_value(val);
                    self.cs.add_equal(dst_var, val_var);
                }
            }
            
            _ => {}
        }
    }
    
    /// Get the inferred type for a value
    pub fn get_type(&self, value: &Value) -> Option<Ty> {
        self.inference.as_ref().and_then(|inf| {
            self.cs.value_to_var.get(value).and_then(|&var| {
                inf.get_type(var).cloned()
            })
        })
    }
    
    /// Get all inferred types
    pub fn all_types(&self) -> HashMap<Value, Ty> {
        let mut result = HashMap::new();
        
        if let Some(ref inf) = self.inference {
            for (value, &var) in &self.cs.value_to_var {
                if let Some(ty) = inf.get_type(var) {
                    if *ty != Ty::Unknown {
                        result.insert(value.clone(), ty.clone());
                    }
                }
            }
        }
        
        result
    }
    
    /// Get unresolved type variables
    pub fn unresolved_variables(&self) -> Vec<TypeVar> {
        self.inference
            .as_ref()
            .map(|inf| inf.unresolved.clone())
            .unwrap_or_default()
    }
    
    /// Check if all types were successfully inferred
    pub fn is_fully_typed(&self) -> bool {
        self.unresolved_variables().is_empty()
    }
    
    /// Generate a type report
    pub fn report(&self) -> TypeReport {
        let all_types = self.all_types();
        let unresolved = self.unresolved_variables();
        
        TypeReport {
            inferred_types: all_types.len(),
            unresolved_types: unresolved.len(),
            total_variables: self.cs.value_to_var.len(),
        }
    }
}

impl Default for TypePropagator {
    fn default() -> Self {
        Self::new()
    }
}

/// Report on type inference results
#[derive(Debug, Clone)]
pub struct TypeReport {
    /// Number of successfully inferred types
    pub inferred_types: usize,
    
    /// Number of unresolved type variables
    pub unresolved_types: usize,
    
    /// Total number of type variables
    pub total_variables: usize,
}

impl TypeReport {
    /// Coverage percentage
    pub fn coverage(&self) -> f64 {
        if self.total_variables == 0 {
            100.0
        } else {
            (self.inferred_types as f64 / self.total_variables as f64) * 100.0
        }
    }
}

impl std::fmt::Display for TypeReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Type inference: {}/{} types inferred ({:.1}%), {} unresolved",
            self.inferred_types,
            self.total_variables,
            self.coverage(),
            self.unresolved_types
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bibleteks_ir::BlockId;
    
    #[test]
    fn test_simple_propagation() {
        let mut func = IrFunction::new("test", 0x1000);
        let v0 = func.alloc_var(Ty::Unknown);
        let v1 = func.alloc_var(Ty::Unknown);
        let v2 = func.alloc_var(Ty::Unknown);
        
        func.push_inst(func.entry_block, IrInst::Binary {
            dst: v2.clone(),
            op: OpCode::Add,
            lhs: v0.clone(),
            rhs: v1.clone(),
        });
        
        let mut prop = TypePropagator::new();
        prop.analyze(&func).unwrap();
        
        // All three should have the same type (though we don't know what it is yet)
        let report = prop.report();
        assert!(report.total_variables > 0);
    }
    
    #[test]
    fn test_load_store() {
        let mut func = IrFunction::new("test", 0x1000);
        let addr = Value::reg("rbp", Ty::Unknown);
        let val = func.alloc_var(Ty::Unknown);
        
        func.push_inst(func.entry_block, IrInst::Load {
            dst: val.clone(),
            addr: addr.clone(),
            size: 8,
        });
        
        let mut prop = TypePropagator::new();
        prop.analyze(&func).unwrap();
        
        // addr should be inferred as pointer
        let types = prop.all_types();
        assert!(!types.is_empty());
    }
}
