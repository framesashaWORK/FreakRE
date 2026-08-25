//! Type inference using unification.
//!
//! Implements Robinson's unification algorithm to solve type constraints.

use crate::constraints::{Constraint, ConstraintSystem, TypeVar};
use freakre_ir::Ty;
use std::collections::{HashMap, HashSet};
use thiserror::Error;

/// Errors that can occur during type inference
#[derive(Debug, Error)]
pub enum InferenceError {
    #[error("Type conflict: {0} cannot equal {1}")]
    TypeConflict(Ty, Ty),

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
    
    /// Whether unification reached a fixed point. `false` means the
    /// safety iteration cap was exhausted and the substitutions may be
    /// partial — consumers should treat results with suspicion.
    pub converged: bool,
}

impl TypeInference {
    /// Solve a constraint system using iterative Robinson's unification.
    ///
    /// Runs constraint application plus propagation passes until the
    /// substitution map reaches a fixed point (or a safety iteration cap).
    pub fn solve(cs: &ConstraintSystem) -> Result<Self, InferenceError> {
        let mut inference = TypeInference::default();

        let max_iterations = cs.constraints.len() * 3 + 100;
        let mut iteration = 0;
        let mut prev: Option<HashMap<TypeVar, Ty>> = None;
        let mut converged = false;

        loop {
            iteration += 1;

            for constraint in &cs.constraints {
                inference.apply_constraint(constraint)?;
            }

            // Re-run propagation every pass: bindings discovered later in
            // the constraint list can resolve variables bound earlier.
            inference.propagate_all(cs);

            let snapshot = inference.substitutions.clone();
            if prev.as_ref() == Some(&snapshot) {
                converged = true;
                break;
            }
            if iteration >= max_iterations {
                // Cap exhausted without a fixed point: results may be
                // partial. Report via `converged` instead of silently
                // returning Ok as if the solve were complete.
                break;
            }
            prev = Some(snapshot);
        }

        inference.converged = converged;

        // Variables with no binding (or still bound to the placeholder
        // `Ty::Unknown`) are genuinely unresolved.
        let seen_vars: HashSet<TypeVar> = cs.value_to_var.values().copied().collect();
        inference.unresolved = seen_vars
            .into_iter()
            .filter(|var| match inference.substitutions.get(var) {
                Some(Ty::Unknown) | None => true,
                Some(_) => false,
            })
            .collect();

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
                    (Ty::Unknown, _) | (_, Ty::Unknown) => {
                        // Propagate width if one side is known
                        match (&ty_a, &ty_b) {
                            (Ty::Int(w), Ty::Unknown) => self.bind(*b, Ty::Int(*w))?,
                            (Ty::UInt(w), Ty::Unknown) => self.bind(*b, Ty::UInt(*w))?,
                            (Ty::Float(w), Ty::Unknown) => self.bind(*b, Ty::Float(*w))?,
                            (Ty::Unknown, Ty::Int(w)) => self.bind(*a, Ty::Int(*w))?,
                            (Ty::Unknown, Ty::UInt(w)) => self.bind(*a, Ty::UInt(*w))?,
                            (Ty::Unknown, Ty::Float(w)) => self.bind(*a, Ty::Float(*w))?,
                            _ => {}
                        }
                    }
                    _ => {
                        // Both resolved: widths must agree regardless of
                        // kind. Same width with different kinds (i32 vs
                        // f32 / u32) is accepted; a width mismatch across
                        // kinds (i32 vs f64) is a conflict — matching the
                        // strictness of `is_consistent`.
                        if let (Some(w1), Some(w2)) = (numeric_width(&ty_a), numeric_width(&ty_b))
                        {
                            if w1 != w2 {
                                return Err(InferenceError::TypeConflict(ty_a, ty_b));
                            }
                        }
                    }
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
            (Ty::Unknown, Ty::Unknown) => {
                // Bind one to the other (representative)
                self.substitutions.insert(a, Ty::Unknown);
                self.substitutions.insert(b, Ty::Unknown);
                Ok(())
            }
            (Ty::Unknown, _) => self.bind(a, ty_b),
            (_, Ty::Unknown) => self.bind(b, ty_a),
            _ => {
                // Both are concrete types: reconcile through `merge_types`,
                // which implements the Int <-> Ptr "pointer wins" policy and
                // still rejects genuinely impossible combinations. The merged
                // type is written back to both variables so later passes see
                // a single consistent binding.
                let merged = self.merge_types(&ty_a, &ty_b)?;
                self.substitutions.insert(a, merged.clone());
                self.substitutions.insert(b, merged);
                Ok(())
            }
        }
    }

    /// Bind a type variable to a concrete type.
    ///
    /// No occurs check is needed: `Ty` contains no type variables, so a
    /// binding can never create an infinite (recursive) type.
    fn bind(&mut self, var: TypeVar, ty: Ty) -> Result<(), InferenceError> {
        // If variable already has a binding, merge with the new type
        if let Some(existing) = self.substitutions.get(&var).cloned() {
            if existing == ty {
                return Ok(());
            }
            let merged = self.merge_types(&existing, &ty)?;
            self.substitutions.insert(var, merged);
            return Ok(());
        }

        // Bind the variable
        self.substitutions.insert(var, ty);

        Ok(())
    }

    /// Merge two types, preferring the more specific one (Unknown is least specific).
    fn merge_types(&self, a: &Ty, b: &Ty) -> Result<Ty, InferenceError> {
        match (a, b) {
            (Ty::Unknown, _) => Ok(b.clone()),
            (_, Ty::Unknown) => Ok(a.clone()),
            (Ty::Ptr(inner_a), Ty::Ptr(inner_b)) => {
                // Merge pointees when they agree; on disagreement the
                // existing pointee stays ("pointer wins" applies
                // recursively) instead of aborting the whole analysis —
                // e.g. a qword load followed by a byte-sized deref of the
                // same variable yields Ptr(Int(64)) vs Ptr(Int(8)).
                match self.merge_types(inner_a, inner_b) {
                    Ok(m) => Ok(Ty::Ptr(Box::new(m))),
                    Err(_) => Ok(Ty::Ptr(Box::new(inner_a.as_ref().clone()))),
                }
            }
            (Ty::Array(n1, inner1), Ty::Array(n2, inner2)) => {
                if n1 != n2 {
                    return Err(InferenceError::TypeConflict(a.clone(), b.clone()));
                }
                Ok(Ty::Array(*n1, Box::new(self.merge_types(inner1, inner2)?)))
            }
            (Ty::Struct(fields_a), Ty::Struct(fields_b)) => {
                if fields_a.len() != fields_b.len() {
                    return Err(InferenceError::TypeConflict(a.clone(), b.clone()));
                }
                let mut merged = Vec::with_capacity(fields_a.len());
                for ((name_a, ty_a), (name_b, ty_b)) in fields_a.iter().zip(fields_b.iter()) {
                    if name_a != name_b {
                        return Err(InferenceError::TypeConflict(a.clone(), b.clone()));
                    }
                    merged.push((name_a.clone(), self.merge_types(ty_a, ty_b)?));
                }
                Ok(Ty::Struct(merged))
            }
            // Integer vs pointer: the pointer wins. Loads and stores emit
            // integer width hints for memory traffic, but memory frequently
            // holds pointers (`mov rax,[rbp+x]; mov rbx,[rax]`): a later
            // PtrTo constraint must refine such a variable into a pointer,
            // not abort the entire function analysis with TypeConflict.
            // An unknown pointee adopts the integer's width so no size
            // information is lost; a concrete pointee stays untouched.
            (Ty::Int(_) | Ty::UInt(_), Ty::Ptr(inner)) => {
                Ok(Ty::Ptr(Box::new(int_as_pointee(inner, a))))
            }
            (Ty::Ptr(inner), Ty::Int(_) | Ty::UInt(_)) => {
                Ok(Ty::Ptr(Box::new(int_as_pointee(inner, b))))
            }
            _ => {
                if a == b {
                    Ok(a.clone())
                } else {
                    Err(InferenceError::TypeConflict(a.clone(), b.clone()))
                }
            }
        }
    }

    /// Resolve a type variable to its concrete type (or `Unknown`).
    ///
    /// `Ty` contains no embedded type variables, so resolution is a single
    /// lookup in the substitution map — there are no chains to follow and
    /// no cycles to detect.
    pub fn resolve(&self, var: TypeVar) -> Ty {
        match self.substitutions.get(&var) {
            Some(ty) => ty.clone(),
            None => Ty::Unknown,
        }
    }

    /// Propagate resolved types across the constraint system.
    ///
    /// `Ty` contains no type variables, so compound types are fully resolved
    /// at bind time and there is no substitution composition to perform.
    /// What remains meaningful is refining leftover unknowns: for every
    /// relational constraint (`Equal`, `Subtype`, `SameWidth`, `PtrTo`,
    /// width constraints, `MustBe`) the resolved side is merged into the
    /// unresolved side, replacing `Unknown` (whole binding or embedded
    /// holes like `Ptr(Unknown)`) with the concrete type.
    ///
    /// Returns the number of `Unknown -> concrete` refinements made.
    pub fn propagate_all(&mut self, cs: &ConstraintSystem) -> usize {
        let mut refined = 0;

        for constraint in &cs.constraints {
            match constraint {
                Constraint::Equal(a, b) | Constraint::Subtype(a, b) => {
                    let ty_a = self.resolve(*a);
                    let ty_b = self.resolve(*b);
                    refined += self.refine_binding(*a, &ty_b);
                    refined += self.refine_binding(*b, &ty_a);
                }

                Constraint::SameWidth(a, b) => {
                    let ty_a = self.resolve(*a);
                    let ty_b = self.resolve(*b);
                    refined += self.refine_binding(*a, &ty_b);
                    refined += self.refine_binding(*b, &ty_a);
                }

                Constraint::PtrTo(ptr, inner) => {
                    let inner_ty = self.resolve(*inner);
                    if inner_ty != Ty::Unknown {
                        let ptr_ty = Ty::Ptr(Box::new(inner_ty));
                        refined += self.refine_binding(*ptr, &ptr_ty);
                    }
                }

                Constraint::IntWidth(var, width) => {
                    refined += self.refine_binding(*var, &Ty::Int(*width));
                }

                Constraint::FloatWidth(var, width) => {
                    refined += self.refine_binding(*var, &Ty::Float(*width));
                }

                Constraint::MustBe(var, ty) => {
                    if *ty != Ty::Unknown {
                        refined += self.refine_binding(*var, ty);
                    }
                }
            }
        }

        refined
    }

    /// Merge an inferred type into a variable's current binding, replacing
    /// `Unknown` (fully or partially). Returns 1 if the binding improved,
    /// 0 if nothing changed or the merge conflicted (conflicts are reported
    /// by `apply_constraint` during solving instead).
    fn refine_binding(&mut self, var: TypeVar, info: &Ty) -> usize {
        let current = self.resolve(var);
        let merged = match self.merge_types(&current, info) {
            Ok(m) => m,
            Err(_) => return 0,
        };
        if merged != current {
            self.substitutions.insert(var, merged);
            return 1;
        }
        0
    }

    /// Get the inferred type for a type variable
    pub fn get_type(&self, var: TypeVar) -> Option<&Ty> {
        self.substitutions.get(&var)
    }

    /// Check whether the solved substitution map satisfies every equality
    /// and same-width constraint in the system.
    ///
    /// Two resolved types are compatible when they are structurally equal
    /// (with `Unknown` treated as compatible with anything); notably this
    /// rejects conflicts like `Int(32)` vs `Float(32)` — same width, but
    /// different kinds. `SameWidth` constraints only require the numeric
    /// widths to agree, mirroring how the solver treats them.
    pub fn is_consistent(&self, cs: &ConstraintSystem) -> bool {
        cs.constraints.iter().all(|constraint| match constraint {
            Constraint::Equal(a, b) | Constraint::Subtype(a, b) => {
                let ty_a = self.resolve(*a);
                let ty_b = self.resolve(*b);
                types_compatible(&ty_a, &ty_b)
            }
            Constraint::SameWidth(a, b) => {
                let ty_a = self.resolve(*a);
                let ty_b = self.resolve(*b);
                match (numeric_width(&ty_a), numeric_width(&ty_b)) {
                    (Some(w1), Some(w2)) => w1 == w2,
                    _ => true,
                }
            }
            _ => true,
        })
    }
}

/// Structural compatibility check used by [`TypeInference::is_consistent`].
fn types_compatible(a: &Ty, b: &Ty) -> bool {
    match (a, b) {
        (Ty::Unknown, _) | (_, Ty::Unknown) => true,
        (Ty::Ptr(x), Ty::Ptr(y)) => types_compatible(x, y),
        (Ty::Array(n1, x), Ty::Array(n2, y)) => n1 == n2 && types_compatible(x, y),
        (Ty::Struct(f1), Ty::Struct(f2)) => {
            f1.len() == f2.len()
                && f1.iter().zip(f2.iter()).all(|((n1, t1), (n2, t2))| {
                    n1 == n2 && types_compatible(t1, t2)
                })
        }
        _ => a == b,
    }
}

/// Bit width of a numeric type (`Int` / `UInt` / `Float`), `None` for
/// anything else.
fn numeric_width(ty: &Ty) -> Option<u32> {
    match ty {
        Ty::Int(w) | Ty::UInt(w) | Ty::Float(w) => Some(*w),
        _ => None,
    }
}

/// Pointee type resulting from merging an integer width hint into a
/// pointer: an `Unknown` interior absorbs the integer (keeping its
/// width), a concrete interior wins outright.
fn int_as_pointee(pointee: &Ty, int_ty: &Ty) -> Ty {
    if matches!(pointee, Ty::Unknown) {
        int_ty.clone()
    } else {
        pointee.clone()
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

    #[test]
    fn test_solve_result_is_consistent() {
        let mut cs = ConstraintSystem::new();
        let v1 = cs.fresh_var();
        let v2 = cs.fresh_var();
        let v3 = cs.fresh_var();

        cs.add_equal(v1, v2);
        cs.add_must_be(v1, Ty::i32());
        cs.add_int_width(v3, 64);

        let inference = TypeInference::solve(&cs).unwrap();
        assert!(inference.is_consistent(&cs));
        assert_eq!(inference.resolve(v3), Ty::i64());
    }

    #[test]
    fn test_is_consistent_detects_conflicting_bindings() {
        let mut cs = ConstraintSystem::new();
        let v1 = cs.fresh_var();
        let v2 = cs.fresh_var();
        cs.add_equal(v1, v2);

        // Manually constructed substitution map with a same-width
        // int-vs-float conflict must be reported as inconsistent.
        let mut inference = TypeInference::default();
        inference.substitutions.insert(v1, Ty::i32());
        inference.substitutions.insert(v2, Ty::f32());
        assert!(!inference.is_consistent(&cs));

        inference.substitutions.insert(v2, Ty::i32());
        assert!(inference.is_consistent(&cs));
    }

    #[test]
    fn test_propagate_all_replaces_unknown_bindings() {
        let mut cs = ConstraintSystem::new();
        let v1 = cs.fresh_var();
        let v2 = cs.fresh_var();
        cs.add_equal(v1, v2);

        let mut inference = TypeInference::default();
        inference.substitutions.insert(v1, Ty::i32());
        inference.substitutions.insert(v2, Ty::Unknown);

        let replaced = inference.propagate_all(&cs);
        assert_eq!(replaced, 1);
        assert_eq!(inference.resolve(v2), Ty::i32());
    }

    #[test]
    fn test_int_ptr_merge_prefers_pointer() {
        // A width hint (e.g. from an 8-byte load) followed by pointer
        // evidence (e.g. the value is used as an address): the variable
        // must end up as a pointer instead of raising TypeConflict.
        let mut cs = ConstraintSystem::new();
        let p = cs.fresh_var();
        cs.add_must_be(p, Ty::i64());
        cs.add_must_be(p, Ty::Ptr(Box::new(Ty::Unknown)));
        let inf = TypeInference::solve(&cs).unwrap();
        assert!(matches!(inf.resolve(p), Ty::Ptr(_)));

        // Same in reverse order.
        let mut cs = ConstraintSystem::new();
        let p = cs.fresh_var();
        cs.add_must_be(p, Ty::Ptr(Box::new(Ty::Unknown)));
        cs.add_must_be(p, Ty::i64());
        let inf = TypeInference::solve(&cs).unwrap();
        assert!(matches!(inf.resolve(p), Ty::Ptr(_)));
    }

    #[test]
    fn test_ptr_to_overrides_int_width_hint() {
        for (first, second) in [(true, false), (false, true)] {
            let mut cs = ConstraintSystem::new();
            let p = cs.fresh_var();
            let inner = cs.fresh_var();

            if first {
                cs.add_int_width(p, 64);
                cs.add_ptr_to(p, inner);
            } else {
                cs.add_ptr_to(p, inner);
                cs.add_int_width(p, 64);
            }
            cs.add_must_be(inner, Ty::u32());

            let inf = TypeInference::solve(&cs).unwrap();
            let p_ty = inf.resolve(p);
            assert!(
                matches!(p_ty, Ty::Ptr(_)),
                "constraint order {:?}: expected pointer, got {}",
                (first, second),
                p_ty
            );
        }
    }

    #[test]
    fn test_same_width_diagnoses_cross_kind_width_mismatch() {
        // i32 vs f64: widths differ across kinds -> conflict.
        let mut cs = ConstraintSystem::new();
        let a = cs.fresh_var();
        let b = cs.fresh_var();
        cs.add_same_width(a, b);
        cs.add_must_be(a, Ty::i32());
        cs.add_must_be(b, Ty::f64());
        assert!(TypeInference::solve(&cs).is_err());

        // i32 vs u64: widths differ across kinds -> conflict.
        let mut cs = ConstraintSystem::new();
        let a = cs.fresh_var();
        let b = cs.fresh_var();
        cs.add_same_width(a, b);
        cs.add_must_be(a, Ty::i32());
        cs.add_must_be(b, Ty::u64());
        assert!(TypeInference::solve(&cs).is_err());

        // Same width, different kinds (i32 vs f32): accepted.
        let mut cs = ConstraintSystem::new();
        let a = cs.fresh_var();
        let b = cs.fresh_var();
        cs.add_same_width(a, b);
        cs.add_must_be(a, Ty::i32());
        cs.add_must_be(b, Ty::f32());
        let inf = TypeInference::solve(&cs).unwrap();
        assert_eq!(inf.resolve(a), Ty::i32());
        assert_eq!(inf.resolve(b), Ty::f32());
    }

    #[test]
    fn test_solve_reports_convergence() {
        let mut cs = ConstraintSystem::new();
        let v1 = cs.fresh_var();
        let v2 = cs.fresh_var();
        cs.add_equal(v1, v2);
        cs.add_must_be(v1, Ty::i32());

        let inf = TypeInference::solve(&cs).unwrap();
        assert!(inf.converged);

        // Fresh results default to "not converged".
        assert!(!TypeInference::default().converged);
    }

    #[test]
    fn test_is_consistent_validates_same_width() {
        let mut cs = ConstraintSystem::new();
        let a = cs.fresh_var();
        let b = cs.fresh_var();
        cs.add_same_width(a, b);

        let mut inf = TypeInference::default();
        inf.substitutions.insert(a, Ty::i32());
        inf.substitutions.insert(b, Ty::f64());
        assert!(!inf.is_consistent(&cs));

        inf.substitutions.insert(b, Ty::f32());
        assert!(inf.is_consistent(&cs));
    }
}
