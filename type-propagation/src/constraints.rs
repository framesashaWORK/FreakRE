//! Type constraints for type inference.
//!
//! Constraints represent relationships between types that must be satisfied.

use bibleteks_ir::{OpCode, Ty, Value};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A type variable (placeholder for an unknown type)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TypeVar(pub u32);

impl std::fmt::Display for TypeVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "t{}", self.0)
    }
}

/// A type constraint
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Constraint {
    /// Two types must be equal
    Equal(TypeVar, TypeVar),
    
    /// Type must be a specific concrete type
    MustBe(TypeVar, Ty),
    
    /// Type must be a subtype of another
    Subtype(TypeVar, TypeVar),
    
    /// Type must be a pointer to another type
    PtrTo(TypeVar, TypeVar),
    
    /// Type must be an integer of specific width
    IntWidth(TypeVar, u32),
    
    /// Type must be a float of specific width
    FloatWidth(TypeVar, u32),
    
    /// Two types must have the same width
    SameWidth(TypeVar, TypeVar),
}

impl std::fmt::Display for Constraint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Constraint::Equal(a, b) => write!(f, "{} = {}", a, b),
            Constraint::MustBe(v, ty) => write!(f, "{} = {}", v, ty),
            Constraint::Subtype(a, b) => write!(f, "{} <: {}", a, b),
            Constraint::PtrTo(ptr, inner) => write!(f, "{} = ptr<{}>", ptr, inner),
            Constraint::IntWidth(v, w) => write!(f, "{} : int({})", v, w),
            Constraint::FloatWidth(v, w) => write!(f, "{} : float({})", v, w),
            Constraint::SameWidth(a, b) => write!(f, "width({}) = width({})", a, b),
        }
    }
}

/// A system of type constraints
#[derive(Debug, Clone, Default)]
pub struct ConstraintSystem {
    /// All constraints
    pub constraints: Vec<Constraint>,
    
    /// Map from Value to TypeVar
    pub value_to_var: HashMap<Value, TypeVar>,
    
    /// Next type variable ID
    next_var_id: u32,
}

impl ConstraintSystem {
    /// Create a new empty constraint system
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Allocate a new type variable
    pub fn fresh_var(&mut self) -> TypeVar {
        let var = TypeVar(self.next_var_id);
        self.next_var_id += 1;
        var
    }
    
    /// Get or create a type variable for a value
    pub fn var_for_value(&mut self, value: &Value) -> TypeVar {
        if let Some(&var) = self.value_to_var.get(value) {
            var
        } else {
            let var = self.fresh_var();
            self.value_to_var.insert(value.clone(), var);
            var
        }
    }
    
    /// Add an equality constraint
    pub fn add_equal(&mut self, a: TypeVar, b: TypeVar) {
        if a != b {
            self.constraints.push(Constraint::Equal(a, b));
        }
    }
    
    /// Add a must-be constraint
    pub fn add_must_be(&mut self, var: TypeVar, ty: Ty) {
        self.constraints.push(Constraint::MustBe(var, ty));
    }
    
    /// Add a pointer constraint
    pub fn add_ptr_to(&mut self, ptr: TypeVar, inner: TypeVar) {
        self.constraints.push(Constraint::PtrTo(ptr, inner));
    }
    
    /// Add an integer width constraint
    pub fn add_int_width(&mut self, var: TypeVar, width: u32) {
        self.constraints.push(Constraint::IntWidth(var, width));
    }
    
    /// Add a float width constraint
    pub fn add_float_width(&mut self, var: TypeVar, width: u32) {
        self.constraints.push(Constraint::FloatWidth(var, width));
    }
    
    /// Add a same-width constraint
    pub fn add_same_width(&mut self, a: TypeVar, b: TypeVar) {
        self.constraints.push(Constraint::SameWidth(a, b));
    }
    
    /// Generate constraints from an operation
    pub fn generate_from_op(&mut self, op: OpCode, dst: TypeVar, srcs: &[TypeVar]) {
        match op {
            // Arithmetic operations: all operands must be same type
            OpCode::Add | OpCode::Sub | OpCode::Mul | OpCode::Div | OpCode::Mod => {
                for &src in srcs {
                    self.add_equal(dst, src);
                }
            }
            
            // Bitwise operations: operands must be integers
            OpCode::And | OpCode::Or | OpCode::Xor | OpCode::Not |
            OpCode::Shl | OpCode::Shr | OpCode::Sar | OpCode::Ror | OpCode::Rol => {
                self.add_equal(dst, srcs[0]);
                if srcs.len() > 1 {
                    self.add_equal(dst, srcs[1]);
                }
            }
            
            // Comparison operations: operands must be same type, result is bool
            OpCode::Eq | OpCode::Ne |
            OpCode::LtU | OpCode::LeU | OpCode::GtU | OpCode::GeU |
            OpCode::LtS | OpCode::LeS | OpCode::GtS | OpCode::GeS => {
                self.add_must_be(dst, Ty::Bool);
                if srcs.len() >= 2 {
                    self.add_equal(srcs[0], srcs[1]);
                }
            }
            
            // Type conversions
            OpCode::Zext | OpCode::Sext | OpCode::Trunc => {
                // Source and dest are both integers, but different widths
                // We don't constrain widths here, let inference handle it
            }
            
            // Float operations
            OpCode::FloatAdd | OpCode::FloatSub | OpCode::FloatMul | OpCode::FloatDiv => {
                for &src in srcs {
                    self.add_equal(dst, src);
                }
            }
            
            OpCode::FloatNeg | OpCode::FloatAbs | OpCode::FloatSqrt => {
                self.add_equal(dst, srcs[0]);
            }
            
            // Conversions between int and float
            OpCode::IntToFloat => {
                // Source is int, dest is float
            }
            
            OpCode::FloatToInt => {
                // Source is float, dest is int
            }
            
            OpCode::Copy => {
                self.add_equal(dst, srcs[0]);
            }
            
            _ => {}
        }
    }
    
    /// Number of constraints
    pub fn len(&self) -> usize {
        self.constraints.len()
    }
    
    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.constraints.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fresh_var() {
        let mut cs = ConstraintSystem::new();
        let v1 = cs.fresh_var();
        let v2 = cs.fresh_var();
        assert_ne!(v1, v2);
        assert_eq!(v1.0, 0);
        assert_eq!(v2.0, 1);
    }
    
    #[test]
    fn test_add_constraints() {
        let mut cs = ConstraintSystem::new();
        let v1 = cs.fresh_var();
        let v2 = cs.fresh_var();
        
        cs.add_equal(v1, v2);
        cs.add_must_be(v1, Ty::i32());
        
        assert_eq!(cs.len(), 2);
    }
    
    #[test]
    fn test_var_for_value() {
        let mut cs = ConstraintSystem::new();
        let val = Value::reg("rax", Ty::i64());
        
        let v1 = cs.var_for_value(&val);
        let v2 = cs.var_for_value(&val);
        
        // Should return the same variable for the same value
        assert_eq!(v1, v2);
    }
}
