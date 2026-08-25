//! Type reconstruction engine for decompiled code.
//!
//! Performs constraint-based type inference on the AST to recover:
//! - Variable types from usage patterns
//! - Structure layouts from offset-based accesses
//! - Pointer types from dereference operations
//! - Function signatures from call sites

use crate::ast::*;
use freakre_ir::Ty;
use std::collections::{BTreeMap, HashMap};

/// Run type reconstruction on an AST function (in-place).
pub fn reconstruct_types(func: &mut AstFunction) {
    let mut engine = TypeEngine::new();

    // Phase 1: Collect constraints from all statements
    engine.collect_from_stmts(&func.body);

    // Phase 2: Solve constraints via unification
    engine.solve();

    // Phase 3: Recover structures from offset patterns
    let structs = engine.recover_structures();

    // Phase 4: Apply inferred types back to locals
    for local in func.locals.iter_mut() {
        if let Some(inferred) = engine.get_type(&local.name) {
            if inferred != &Ty::Unknown && inferred != &local.ty {
                local.ty = inferred.clone();
            }
        }
    }

    // Phase 5: Update struct types in locals
    for (var_name, struct_ty) in &structs {
        for local in func.locals.iter_mut() {
            if &local.name == var_name {
                local.ty = Ty::Ptr(Box::new(struct_ty.clone()));
            }
        }
    }
}

// ─── Constraint Types ───────────────────────────────────────────────

#[derive(Debug, Clone)]
enum TypeConstraint {
    /// Variable must be exactly this type
    Exact(String, Ty),
    /// Variable must be a pointer to this type
    PointerTo(String, Ty),
    /// Variable is accessed at offset N → part of a structure
    StructAccess(String, u64, Ty),
    /// Two variables must have the same type
    Equal(String, String),
    /// Variable is used as integer
    Integer(String),
    /// Variable is used as boolean
    Boolean(String),
}

// ─── Type Engine ────────────────────────────────────────────────────

struct TypeEngine {
    /// Inferred types per variable name
    var_types: HashMap<String, Ty>,
    /// Collected constraints
    constraints: Vec<TypeConstraint>,
    /// Struct access patterns: var_name → { offset → field_type }
    struct_accesses: HashMap<String, BTreeMap<u64, Ty>>,
}

impl TypeEngine {
    fn new() -> Self {
        TypeEngine {
            var_types: HashMap::new(),
            constraints: Vec::new(),
            struct_accesses: HashMap::new(),
        }
    }

    // ── Constraint Collection ────────────────────────────────────────

    fn collect_from_stmts(&mut self, stmts: &[Stmt]) {
        for stmt in stmts {
            self.collect_from_stmt(stmt);
        }
    }

    fn collect_from_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Assign { target, value } => {
                self.collect_from_expr(value);
                self.collect_assignment_constraints(target, value);
            }
            Stmt::If { cond, then_body, else_body } => {
                self.add_constraint(TypeConstraint::Boolean(expr_var_name(cond).unwrap_or_default()));
                self.collect_from_expr(cond);
                self.collect_from_stmts(then_body);
                if let Some(eb) = else_body { self.collect_from_stmts(eb); }
            }
            Stmt::While { cond, body } | Stmt::DoWhile { body, cond } => {
                self.add_constraint(TypeConstraint::Boolean(expr_var_name(cond).unwrap_or_default()));
                self.collect_from_expr(cond);
                self.collect_from_stmts(body);
            }
            Stmt::For { init, cond, update, body } => {
                if let Some(i) = init { self.collect_from_stmt(i); }
                if let Some(c) = cond {
                    self.add_constraint(TypeConstraint::Boolean(expr_var_name(c).unwrap_or_default()));
                    self.collect_from_expr(c);
                }
                if let Some(u) = update { self.collect_from_stmt(u); }
                self.collect_from_stmts(body);
            }
            Stmt::Switch { expr, cases, default } => {
                self.collect_from_expr(expr);
                if let Some(name) = expr_var_name(expr) {
                    self.add_constraint(TypeConstraint::Integer(name));
                }
                for c in cases { self.collect_from_stmts(&c.body); }
                if let Some(d) = default { self.collect_from_stmts(d); }
            }
            Stmt::Return { value: Some(v) } => { self.collect_from_expr(v); }
            Stmt::Call { args, .. } => { for a in args { self.collect_from_expr(a); } }
            Stmt::Expr(e) => { self.collect_from_expr(e); }
            Stmt::Block(inner) => { self.collect_from_stmts(inner); }
            Stmt::Decl { name, ty, init } => {
                if *ty != Ty::Unknown {
                    self.add_constraint(TypeConstraint::Exact(name.clone(), ty.clone()));
                }
                if let Some(e) = init { self.collect_from_expr(e); }
            }
            Stmt::TryCatch { try_body, catch_body, .. } => {
                self.collect_from_stmts(try_body);
                self.collect_from_stmts(catch_body);
            }
            _ => {}
        }
    }

    fn collect_from_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Binary { op, lhs, rhs } => {
                self.collect_from_expr(lhs);
                self.collect_from_expr(rhs);

                // Arithmetic ops → integer constraint
                if matches!(op, BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div |
                           BinOp::Mod | BinOp::And | BinOp::Or | BinOp::Xor |
                           BinOp::Shl | BinOp::Shr) {
                    if let Some(name) = expr_var_name(lhs) {
                        self.add_constraint(TypeConstraint::Integer(name));
                    }
                    if let Some(name) = expr_var_name(rhs) {
                        self.add_constraint(TypeConstraint::Integer(name));
                    }
                }

                // Comparison ops → integer constraint on operands, bool result
                if matches!(op, BinOp::Eq | BinOp::Ne | BinOp::Lt | BinOp::Le |
                           BinOp::Gt | BinOp::Ge) {
                    if let Some(name) = expr_var_name(lhs) {
                        self.add_constraint(TypeConstraint::Integer(name));
                    }
                }

                // Logical ops → boolean constraint
                if matches!(op, BinOp::LogAnd | BinOp::LogOr) {
                    if let Some(name) = expr_var_name(lhs) {
                        self.add_constraint(TypeConstraint::Boolean(name));
                    }
                    if let Some(name) = expr_var_name(rhs) {
                        self.add_constraint(TypeConstraint::Boolean(name));
                    }
                }
            }
            Expr::Unary { op, operand } => {
                self.collect_from_expr(operand);
                if matches!(op, UnOp::LogNot) {
                    if let Some(name) = expr_var_name(operand) {
                        self.add_constraint(TypeConstraint::Boolean(name));
                    }
                }
                if matches!(op, UnOp::Neg | UnOp::Not) {
                    if let Some(name) = expr_var_name(operand) {
                        self.add_constraint(TypeConstraint::Integer(name));
                    }
                }
            }
            Expr::Deref(inner) => {
                // *ptr → ptr is a pointer
                if let Some(name) = expr_var_name(inner) {
                    self.add_constraint(TypeConstraint::PointerTo(name, Ty::Unknown));
                }
                self.collect_from_expr(inner);
            }
            Expr::AddrOf(inner) => {
                // &x → result is pointer
                self.collect_from_expr(inner);
            }
            Expr::Index { base, index } => {
                // base[index] → base is pointer or array
                if let Some(name) = expr_var_name(base) {
                    self.add_constraint(TypeConstraint::PointerTo(name, Ty::Unknown));
                }
                if let Some(name) = expr_var_name(index) {
                    self.add_constraint(TypeConstraint::Integer(name));
                }
                self.collect_from_expr(base);
                self.collect_from_expr(index);
            }
            Expr::Member { base, field: _ } => {
                // base.field → base is struct
                self.collect_from_expr(base);
            }
            Expr::Cast { ty: _, expr: inner } => {
                // Cast gives us exact type info
                if let Some(_name) = expr_var_name(inner) {
                    // The source might be different, but we know the target
                }
                self.collect_from_expr(inner);
            }
            Expr::Call { args, .. } => {
                for a in args { self.collect_from_expr(a); }
            }
            Expr::Ternary { cond, then_expr, else_expr } => {
                self.add_constraint(TypeConstraint::Boolean(expr_var_name(cond).unwrap_or_default()));
                self.collect_from_expr(cond);
                self.collect_from_expr(then_expr);
                self.collect_from_expr(else_expr);
            }
            _ => {}
        }
    }

    fn collect_assignment_constraints(&mut self, target: &Expr, value: &Expr) {
        // If assigning a constant, infer type from constant range
        if let Expr::Var(name) = target {
            if let Expr::IntLit(val) = value {
                let ty = infer_int_type(*val);
                self.add_constraint(TypeConstraint::Exact(name.clone(), ty));
            }
            if let Expr::BoolLit(_) = value {
                self.add_constraint(TypeConstraint::Exact(name.clone(), Ty::Bool));
            }
            if let Expr::StringLit(_) = value {
                self.add_constraint(TypeConstraint::Exact(
                    name.clone(),
                    Ty::Ptr(Box::new(Ty::u8())),
                ));
            }
        }

        // Detect struct access pattern: var = *(base + offset)
        if let Expr::Var(_target_name) = target {
            if let Expr::Deref(addr_expr) = value {
                if let Some((base_name, offset)) = extract_base_offset(addr_expr) {
                    let field_ty = target.ty_from_expr();
                    self.struct_accesses
                        .entry(base_name)
                        .or_default()
                        .insert(offset, field_ty);
                }
            }
        }
    }

    fn add_constraint(&mut self, c: TypeConstraint) {
        // Skip empty-name constraints
        match &c {
            TypeConstraint::Exact(n, _) | TypeConstraint::PointerTo(n, _) |
            TypeConstraint::Integer(n) | TypeConstraint::Boolean(n) |
            TypeConstraint::StructAccess(n, _, _) | TypeConstraint::Equal(n, _)
                if n.is_empty() => return,
            _ => {}
        }
        self.constraints.push(c);
    }

    // ── Constraint Solving ───────────────────────────────────────────

    fn solve(&mut self) {
        // Apply constraints iteratively until fixed point
        let mut changed = true;
        let mut iterations = 0;

        while changed && iterations < 100 {
            changed = false;
            iterations += 1;

            for constraint in self.constraints.clone() {
                match constraint {
                    TypeConstraint::Exact(name, ty) => {
                        let entry = self.var_types.entry(name).or_insert(Ty::Unknown);
                        if (*entry == Ty::Unknown || unify_types(entry, &ty))
                            && *entry != ty {
                                *entry = ty;
                                changed = true;
                            }
                    }
                    TypeConstraint::Integer(name) => {
                        let entry = self.var_types.entry(name).or_insert(Ty::Unknown);
                        if *entry == Ty::Unknown {
                            *entry = Ty::i32(); // Default integer width
                            changed = true;
                        } else if *entry == Ty::Bool {
                            // Bool can be used as integer — widen
                            *entry = Ty::i32();
                            changed = true;
                        }
                    }
                    TypeConstraint::Boolean(name) => {
                        let entry = self.var_types.entry(name).or_insert(Ty::Unknown);
                        if *entry == Ty::Unknown {
                            *entry = Ty::Bool;
                            changed = true;
                        }
                    }
                    TypeConstraint::PointerTo(name, _pointee) => {
                        let entry = self.var_types.entry(name).or_insert(Ty::Unknown);
                        if *entry == Ty::Unknown {
                            *entry = Ty::Ptr(Box::new(Ty::u8()));
                            changed = true;
                        } else if !entry.is_pointer() {
                            // Widen to pointer
                            *entry = Ty::Ptr(Box::new(entry.clone()));
                            changed = true;
                        }
                    }
                    TypeConstraint::Equal(a, b) => {
                        let ty_a = self.var_types.get(&a).cloned().unwrap_or(Ty::Unknown);
                        let ty_b = self.var_types.get(&b).cloned().unwrap_or(Ty::Unknown);
                        if ty_a != Ty::Unknown && ty_b == Ty::Unknown {
                            self.var_types.insert(b, ty_a);
                            changed = true;
                        } else if ty_b != Ty::Unknown && ty_a == Ty::Unknown {
                            self.var_types.insert(a, ty_b);
                            changed = true;
                        }
                    }
                    TypeConstraint::StructAccess(_, _, _) => {
                        // Handled in recover_structures
                    }
                }
            }
        }
    }

    // ── Structure Recovery ───────────────────────────────────────────

    fn recover_structures(&self) -> HashMap<String, Ty> {
        let mut result = HashMap::new();

        for (var_name, offsets) in &self.struct_accesses {
            if offsets.len() < 2 {
                continue; // Need at least 2 fields to justify a struct
            }

            // Build struct type from collected offsets
            let mut fields: Vec<(String, Ty)> = Vec::new();
            let mut prev_offset = 0u64;

            for (&offset, field_ty) in offsets {
                // Add padding field if there's a gap
                if offset > prev_offset {
                    let gap = offset - prev_offset;
                    if gap > 0 && !fields.is_empty() {
                        // Only add explicit padding for large gaps
                        if gap > 8 {
                            fields.push((format!("_pad_0x{:X}", prev_offset), Ty::Array(gap as u32, Box::new(Ty::u8()))));
                        }
                    }
                }

                let field_name = format!("field_0x{:X}", offset);
                fields.push((field_name, field_ty.clone()));
                prev_offset = offset + field_ty.size_bytes().unwrap_or(4) as u64;
            }

            if fields.len() >= 2 {
                let struct_ty = Ty::Struct(fields);
                result.insert(var_name.clone(), struct_ty);
            }
        }

        result
    }

    fn get_type(&self, name: &str) -> Option<&Ty> {
        self.var_types.get(name)
    }
}

// ─── Helpers ────────────────────────────────────────────────────────

fn expr_var_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Var(name) => Some(name.clone()),
        _ => None,
    }
}

fn infer_int_type(val: i64) -> Ty {
    // Zero is by far the most common constant (NULL pointers, counters,
    // zero-init). Sizing it as u8 pollutes declarations; use the machine word.
    if val == 0 {
        return Ty::u32();
    }
    if val >= 0 {
        if val <= u8::MAX as i64 { Ty::u8() }
        else if val <= u16::MAX as i64 { Ty::u16() }
        else if val <= u32::MAX as i64 { Ty::u32() }
        else { Ty::u64() }
    } else {
        if val >= i8::MIN as i64 { Ty::i8() }
        else if val >= i16::MIN as i64 { Ty::i16() }
        else if val >= i32::MIN as i64 { Ty::i32() }
        else { Ty::i64() }
    }
}

/// Extract (base_var_name, offset) from expressions like `var + const` or `const + var`.
fn extract_base_offset(expr: &Expr) -> Option<(String, u64)> {
    match expr {
        Expr::Binary { op: BinOp::Add, lhs, rhs } => {
            if let (Expr::Var(name), Expr::IntLit(off)) = (lhs.as_ref(), rhs.as_ref()) {
                Some((name.clone(), *off as u64))
            } else if let (Expr::IntLit(off), Expr::Var(name)) = (lhs.as_ref(), rhs.as_ref()) {
                Some((name.clone(), *off as u64))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Simple unification: returns true if types are compatible and `existing` was updated.
fn unify_types(existing: &mut Ty, new: &Ty) -> bool {
    if existing == new {
        return false;
    }
    if *existing == Ty::Unknown {
        *existing = new.clone();
        return true;
    }
    if *new == Ty::Unknown {
        return false;
    }
    // Widen: smaller int → larger int
    if existing.is_integer() && new.is_integer() {
        let old_bits = existing.size_bits().unwrap_or(32);
        let new_bits = new.size_bits().unwrap_or(32);
        if new_bits > old_bits {
            *existing = new.clone();
            return true;
        }
        return false;
    }
    // Int ↔ UInt compatibility
    if existing.is_integer() && new.is_integer() {
        return false; // Same size, different signedness — keep existing
    }
    false
}

/// Helper trait to extract approximate type from an expression node.
trait ExprTypeHelper {
    fn ty_from_expr(&self) -> Ty;
}

impl ExprTypeHelper for Expr {
    fn ty_from_expr(&self) -> Ty {
        match self {
            Expr::IntLit(v) => infer_int_type(*v),
            Expr::BoolLit(_) => Ty::Bool,
            Expr::FloatLit(_) => Ty::f64(),
            Expr::StringLit(_) => Ty::Ptr(Box::new(Ty::u8())),
            Expr::Var(_) => Ty::Unknown,
            Expr::Binary { op, .. } => {
                if op.is_comparison() { Ty::Bool } else { Ty::Unknown }
            }
            Expr::Unary { op: UnOp::LogNot, .. } => Ty::Bool,
            Expr::Deref(_) => Ty::Unknown,
            Expr::Cast { ty, .. } => ty.clone(),
            _ => Ty::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infer_int_type() {
        assert_eq!(infer_int_type(0), Ty::u32());
        assert_eq!(infer_int_type(255), Ty::u8());
        assert_eq!(infer_int_type(256), Ty::u16());
        assert_eq!(infer_int_type(-1), Ty::i8());
        assert_eq!(infer_int_type(-129), Ty::i16());
    }

    #[test]
    fn test_extract_base_offset() {
        let expr = Expr::Binary {
            op: BinOp::Add,
            lhs: Box::new(Expr::Var("ptr".into())),
            rhs: Box::new(Expr::IntLit(16)),
        };
        let result = extract_base_offset(&expr);
        assert_eq!(result, Some(("ptr".into(), 16)));
    }

    #[test]
    fn test_unify_types() {
        let mut t = Ty::Unknown;
        assert!(unify_types(&mut t, &Ty::i32()));
        assert_eq!(t, Ty::i32());

        // Widen i32 → i64
        assert!(unify_types(&mut t, &Ty::i64()));
        assert_eq!(t, Ty::i64());

        // No shrink
        assert!(!unify_types(&mut t, &Ty::i32()));
        assert_eq!(t, Ty::i64());
    }
}
