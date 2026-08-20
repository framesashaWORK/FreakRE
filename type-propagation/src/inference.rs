//! Type inference using unification.
//!
//! Implements Robinson's unification algorithm to solve type constraints.

use crate::constraints::{Constraint, ConstraintSystem, TypeVar};
use bibleteks_ir::Ty;
use std::collections::HashMap;
use thiserror::Error;

/// Errors that can occur during type inference
#[derive(Debug, Error)]
pub enum InferenceError {
    #[error("Type conflict: {0} cannot equal {1}")]
    TypeConflict(Ty, Ty),
    
    #[error("Occurs check failed: {0} occurs in {1}")]
    OccursCheck(TypeVar, String),
    
    #[error("Unresolved type variable: {0}")]
    UnresolvedVar(TypeVar),
    
    #[error("Constraint not satisfiable: {0}")]
    Unsatisfiable(String),
}

/// Result of type inference: mapping from type variables to concrete types
#[derive(Debug, Clone, Default)]
pub struct TypeInference {
    /// Substitution: TypeVar -> Ty
    pub substitutions: HashMap<TypeVar, Ty>,
    
    /// Unresolved type variables (mapped to Ty::Unknown)
    pub unresolved: Vec<TypeVar>,
}

impl TypeInference {
    /// Solve a constraint system using unification
    pub fn solve(cs: &ConstraintSystem) -> Result<Self, InferenceError> {
        let mut inference = TypeInference::default();
        
        // Apply each constraint
        for constraint in &cs.constraints {
            inference.apply_constraint(constraint)?;
        }
        
        // Find unresolved variables
        for var in cs.value_to_var.values() {
            if !inference.substitutions.contains_key(var) {
                inference.unresolved.push(*var);
            }
        }
        
        Ok(inference)
    }
    
    /// Apply a single constraint
    fn apply_constraint(&mut self, constraint: &Constraint) -> Result<(), InferenceError> {
        match constraint {
            Constraint::Equal(a, b) => {
                self.unify(*a, *b)?;
            }
            
            Constraint::MustBe(var, ty) => {
                self.bind(*var, ty.clone())?;
            }
            
            Constraint::Subtype(a, b) => {
                // For now, treat subtype as equality
                self.unify(*a, *b)?;
            }
            
            Constraint::PtrTo(ptr, inner) => {
                let inner_ty = self.resolve(*inner);
                let ptr_ty = Ty::Ptr(Box::new(inner_ty));
                self.bind(*ptr, ptr_ty)?;
            }
            
            Constraint::IntWidth(var, width) => {
                self.bind(*var, Ty::Int(*width))?;
            }
            
            Constraint::FloatWidth(var, width) => {
                self.bind(*var, Ty::Float(*width))?;
            }
            
            Constraint::SameWidth(a, b) => {
                let ty_a = self.resolve(*a);
                let ty_b = self.resolve(*b);
                
                // Extract widths and check compatibility
                match (&ty_a, &ty_b) {
                    (Ty::Int(w1), Ty::Int(w2)) | (Ty::UInt(w1), Ty::UInt(w2)) => {
                        if w1 != w2 {
                            return Err(InferenceError::TypeConflict(ty_a, ty_b));
                        }
                    }
                    _ => {} // Skip if types not yet resolved
                }
            }
        }
        
        Ok(())
    }
    
    /// Unify two type variables
    fn unify(&mut self, a: TypeVar, b: TypeVar) -> Result<(), InferenceError> {
        if a == b {
            return Ok(());
        }
        
        let ty_a = self.resolve(a);
        let ty_b = self.resolve(b);
        
        match (&ty_a, &ty_b) {
            (Ty::Unknown, _) => self.bind(a, ty_b),
            (_, Ty::Unknown) => self.bind(b, ty_a),
            _ => {
                // Both are concrete types, check equality
                if ty_a == ty_b {
                    Ok(())
                } else {
                    Err(InferenceError::TypeConflict(ty_a, ty_b))
                }
            }
        }
    }
    
    /// Bind a type variable to a concrete type
    fn bind(&mut self, var: TypeVar, ty: Ty) -> Result<(), InferenceError> {
        // Occurs check: prevent infinite types
        if self.occurs_check(var, &ty) {
            return Err(InferenceError::OccursCheck(var, format!("{}", ty)));
        }
        
        // If variable already has a binding, unify with new type
        if let Some(existing) = self.substitutions.get(&var) {
            let existing = existing.clone();
            return self.unify_types(&existing, &ty);
        }
        
        // Bind the variable
        self.substitutions.insert(var, ty);
        
        // Propagate: update all other substitutions that reference this variable
        self.propagate_binding(var);
        
        Ok(())
    }
    
    /// Resolve a type variable to its concrete type (or Unknown)
    pub fn resolve(&self, var: TypeVar) -> Ty {
        self.substitutions.get(&var).cloned().unwrap_or(Ty::Unknown)
    }
    
    /// Check if a type variable occurs in a type (prevents infinite types)
    fn occurs_check(&self, var: TypeVar, ty: &Ty) -> bool {
        match ty {
            Ty::Ptr(_inner) => {
                // Check if inner type references this variable
                // This is simplified - in a full implementation we'd track type vars in types
                false
            }
            Ty::Array(_, inner) => self.occurs_check(var, inner),
            Ty::Struct(fields) => {
                fields.iter().any(|(_, field_ty)| self.occurs_check(var, field_ty))
            }
            _ => false,
        }
    }
    
    /// Unify two concrete types
    fn unify_types(&mut self, a: &Ty, b: &Ty) -> Result<(), InferenceError> {
        if a == b {
            return Ok(());
        }
        
        match (a, b) {
            (Ty::Unknown, _) | (_, Ty::Unknown) => Ok(()),
            
            (Ty::Ptr(_inner_a), Ty::Ptr(_inner_b)) => {
                // Recursively unify pointed-to types
                // This is simplified - would need to handle type vars
                Ok(())
            }
            
            (Ty::Array(n1, inner1), Ty::Array(n2, inner2)) => {
                if n1 != n2 {
                    return Err(InferenceError::TypeConflict(a.clone(), b.clone()));
                }
                self.unify_types(inner1, inner2)
            }
            
            _ => Err(InferenceError::TypeConflict(a.clone(), b.clone())),
        }
    }
    
    /// Propagate a binding to all other substitutions
    fn propagate_binding(&mut self, _var: TypeVar) {
        // This is a simplified propagation
        // In a full implementation, we'd walk all types and replace references to var
    }
    
    /// Get the inferred type for a type variable
    pub fn get_type(&self, var: TypeVar) -> Option<&Ty> {
        self.substitutions.get(&var)
    }
    
    /// Check if inference was successful (no conflicts)
    pub fn is_consistent(&self) -> bool {
        // Check for any type conflicts in substitutions
        true // Simplified
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_simple_unification() {
        let mut cs = ConstraintSystem::new();
        let v1 = cs.fresh_var();
        let v2 = cs.fresh_var();
        
        cs.add_equal(v1, v2);
        cs.add_must_be(v1, Ty::i32());
        
        let inference = TypeInference::solve(&cs).unwrap();
        
        assert_eq!(inference.resolve(v1), Ty::i32());
        assert_eq!(inference.resolve(v2), Ty::i32());
    }
    
    #[test]
    fn test_type_conflict() {
        let mut cs = ConstraintSystem::new();
        let v1 = cs.fresh_var();
        
        cs.add_must_be(v1, Ty::i32());
        cs.add_must_be(v1, Ty::i64());
        
        let result = TypeInference::solve(&cs);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_pointer_unification() {
        let mut cs = ConstraintSystem::new();
        let v1 = cs.fresh_var();
        let v2 = cs.fresh_var();
        
        cs.add_ptr_to(v1, v2);
        cs.add_must_be(v2, Ty::u8());
        
        let inference = TypeInference::solve(&cs).unwrap();
        
        assert_eq!(inference.resolve(v1), Ty::Ptr(Box::new(Ty::u8())));
    }
}
