#![allow(dead_code, unused_assignments)]
//! # bibleteks-type-propagation — Type Inference for Binary IR
//!
//! Constraint-based type propagation and inference for the bibleteks-ir.
//! Infers types from machine code using constraint solving and unification.
//!
//! ## Features
//!
//! - **Constraint generation**: Generate type constraints from IR instructions
//! - **Unification**: Solve constraints using Robinson's unification algorithm
//! - **Type inference**: Infer types for all values in the IR
//! - **Type error detection**: Detect type conflicts and inconsistencies
//!
//! ## Example
//!
//! ```rust
//! use bibleteks_type_propagation::TypePropagator;
//! use bibleteks_ir::{IrFunction, Ty};
//!
//! let func = /* ... */;
//! let mut propagator = TypePropagator::new();
//! propagator.analyze(&func);
//!
//! // Get inferred type for a value
//! if let Some(ty) = propagator.get_type(&value) {
//!     println!("Inferred type: {}", ty);
//! }
//! ```

pub mod constraints;
pub mod inference;
pub mod propagation;

pub use constraints::{Constraint, ConstraintSystem};
pub use inference::{TypeInference, InferenceError};
pub use propagation::TypePropagator;


