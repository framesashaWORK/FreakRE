//! String-literal annotation for decompiled functions.
//!
//! Address constants that point at known strings in the analyzed image are
//! rewritten from raw integers (`f(0x14001000)`) into C string literals
//! (`f("C:\\windows")`), which is how every production decompiler presents
//! them. The table itself is built by the caller (the scanner knows the PE
//! layout); this module only owns the AST rewrite.

use crate::ast::*;
use std::collections::HashMap;

/// Virtual-address → string map for one analyzed image.
#[derive(Debug, Clone, Default)]
pub struct StringTable {
    map: HashMap<u64, String>,
}

/// Minimum string length accepted into the table. Shorter matches are far
/// more likely to be coincidental constants that happen to alias a string
/// address than real references.
const MIN_STRING_LEN: usize = 4;

impl StringTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a string at `va`. Entries that would render poorly as a C
    /// literal (too short, non-printable-heavy) are rejected — a wall of
    /// `\xNN` escapes is less readable than the raw address.
    pub fn insert(&mut self, va: u64, s: String) {
        if s.chars().count() < MIN_STRING_LEN {
            return;
        }
        let printable = s
            .chars()
            .filter(|c| {
                c.is_ascii_graphic()
                    || matches!(c, '\t' | '\n' | '\r' | '\u{00A0}'..='\u{FFFF}')
            })
            .count();
        if printable * 10 < s.chars().count() * 9 {
            return; // < 90% printable
        }
        self.map.insert(va, s);
    }

    pub fn get(&self, va: u64) -> Option<&str> {
        self.map.get(&va).map(|s| s.as_str())
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Replace `IntLit(va)` with `StringLit("...")` wherever `va` is a known
/// string address. Returns the number of replacements.
///
/// `IntLit` directly under a `Deref` is left alone: `*(int32_t *)0x14001000`
/// is a *load* through the address, and printing `*(int32_t *)"str"` would
/// suggest a string read where the code reads raw bytes.
pub fn annotate_function(func: &mut AstFunction, table: &StringTable) -> usize {
    if table.is_empty() {
        return 0;
    }
    let mut count = 0usize;
    annotate_stmts(&mut func.body, table, &mut count);
    count
}

fn annotate_stmts(stmts: &mut [Stmt], table: &StringTable, count: &mut usize) {
    for stmt in stmts.iter_mut() {
        annotate_stmt(stmt, table, count);
    }
}

fn annotate_stmt(stmt: &mut Stmt, table: &StringTable, count: &mut usize) {
    match stmt {
        Stmt::Assign { target, value } => {
            annotate_expr(target, table, count);
            annotate_expr(value, table, count);
        }
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            annotate_expr(cond, table, count);
            annotate_stmts(then_body, table, count);
            if let Some(eb) = else_body {
                annotate_stmts(eb, table, count);
            }
        }
        Stmt::While { cond, body } | Stmt::DoWhile { body, cond } => {
            annotate_expr(cond, table, count);
            annotate_stmts(body, table, count);
        }
        Stmt::For {
            init,
            cond,
            update,
            body,
        } => {
            if let Some(i) = init {
                annotate_stmt(i, table, count);
            }
            if let Some(c) = cond {
                annotate_expr(c, table, count);
            }
            if let Some(u) = update {
                annotate_stmt(u, table, count);
            }
            annotate_stmts(body, table, count);
        }
        Stmt::Switch {
            expr,
            cases,
            default,
        } => {
            annotate_expr(expr, table, count);
            for case in cases.iter_mut() {
                annotate_expr(&mut case.value, table, count);
                annotate_stmts(&mut case.body, table, count);
            }
            if let Some(d) = default {
                annotate_stmts(d, table, count);
            }
        }
        Stmt::Return { value: Some(v) } => annotate_expr(v, table, count),
        Stmt::Call { args, .. } => {
            for a in args.iter_mut() {
                annotate_expr(a, table, count);
            }
        }
        Stmt::Expr(e) => annotate_expr(e, table, count),
        Stmt::Decl { init: Some(e), .. } => annotate_expr(e, table, count),
        Stmt::Block(inner) => annotate_stmts(inner, table, count),
        Stmt::TryCatch {
            try_body,
            catch_body,
            ..
        } => {
            annotate_stmts(try_body, table, count);
            annotate_stmts(catch_body, table, count);
        }
        _ => {}
    }
}

fn annotate_expr(expr: &mut Expr, table: &StringTable, count: &mut usize) {
    match expr {
        Expr::Binary { lhs, rhs, .. } => {
            annotate_expr(lhs, table, count);
            annotate_expr(rhs, table, count);
        }
        // `*IntLit` — load through a constant address, keep the integer.
        Expr::Deref(operand) => {
            if !matches!(operand.as_ref(), Expr::IntLit(_)) {
                annotate_expr(operand, table, count);
            }
        }
        Expr::Unary { operand, .. }
        | Expr::AddrOf(operand)
        | Expr::Sizeof(operand) => annotate_expr(operand, table, count),
        Expr::Call { args, .. } => {
            for a in args.iter_mut() {
                annotate_expr(a, table, count);
            }
        }
        Expr::Index { base, index } => {
            annotate_expr(base, table, count);
            annotate_expr(index, table, count);
        }
        Expr::Member { base, .. } => annotate_expr(base, table, count),
        Expr::Cast { expr, .. } => annotate_expr(expr, table, count),
        Expr::Ternary {
            cond,
            then_expr,
            else_expr,
        } => {
            annotate_expr(cond, table, count);
            annotate_expr(then_expr, table, count);
            annotate_expr(else_expr, table, count);
        }
        Expr::IntLit(va) => {
            if let Some(s) = table.get(*va as u64) {
                *expr = Expr::StringLit(s.to_string());
                *count += 1;
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> StringTable {
        let mut t = StringTable::new();
        t.insert(0x14001000, "C:\\windows\\system32".to_string());
        t.insert(0x14001040, "ab".to_string()); // too short — rejected
        t.insert(
            0x14001050,
            "\u{1}\u{2}\u{3}\u{4}\u{5}\u{6}\u{7}\u{8}\u{9}\u{a}".to_string(),
        ); // control-heavy — rejected
        t
    }

    #[test]
    fn test_table_gating() {
        let t = table();
        assert_eq!(t.get(0x14001000), Some("C:\\windows\\system32"));
        assert_eq!(t.get(0x14001040), None);
        assert_eq!(t.get(0x14001050), None);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn test_call_argument_becomes_string_literal() {
        let mut func = AstFunction::new("f");
        func.body.push(Stmt::Call {
            func: "CreateFileW".to_string(),
            args: vec![Expr::IntLit(0x14001000)],
        });
        let n = annotate_function(&mut func, &table());
        assert_eq!(n, 1);
        match &func.body[0] {
            Stmt::Call { args, .. } => {
                assert!(matches!(&args[0], Expr::StringLit(s) if s == "C:\\windows\\system32"));
            }
            _ => panic!("expected call statement"),
        }
    }

    #[test]
    fn test_deref_of_string_address_kept_as_integer() {
        let mut func = AstFunction::new("f");
        func.body.push(Stmt::Assign {
            target: Expr::Var("v1".to_string()),
            value: Expr::Deref(Box::new(Expr::IntLit(0x14001000))),
        });
        let n = annotate_function(&mut func, &table());
        assert_eq!(n, 0);
        match &func.body[0] {
            Stmt::Assign { value, .. } => {
                assert!(
                    matches!(value, Expr::Deref(inner) if matches!(&**inner, Expr::IntLit(0x14001000))),
                    "expected deref of the raw integer address"
                );
            }
            _ => panic!("expected assignment"),
        }
    }

    #[test]
    fn test_nested_expressions_annotated() {
        let mut func = AstFunction::new("f");
        func.body.push(Stmt::Return {
            value: Some(Expr::Binary {
                op: BinOp::Add,
                lhs: Box::new(Expr::IntLit(0x14001000)),
                rhs: Box::new(Expr::Var("v1".to_string())),
            }),
        });
        let n = annotate_function(&mut func, &table());
        assert_eq!(n, 1);
        match &func.body[0] {
            Stmt::Return { value: Some(v) } => {
                assert!(
                    matches!(v, Expr::Binary { lhs, .. } if matches!(&**lhs, Expr::StringLit(_))),
                    "expected string literal on the lhs"
                );
            }
            _ => panic!("expected return"),
        }
    }
}
