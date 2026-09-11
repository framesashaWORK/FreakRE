//! Abstract Syntax Tree for decompiled code.

use freakre_ir::Ty;
use serde::{Deserialize, Serialize};

/// A decompiled function
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AstFunction {
    pub name: String,
    pub return_type: Ty,
    pub params: Vec<Param>,
    pub body: Vec<Stmt>,
    pub locals: Vec<LocalVar>,
    /// Entry address in the original binary (0 when unknown). Used by
    /// `ast_to_c` only when `DecompilerConfig::annotate_addresses` is on.
    #[serde(default)]
    pub entry_address: u64,
    /// Canonical register name per recovered parameter (`rcx` for `a1`, ...).
    /// Register reads in the body render through this map so parameter
    /// variables print as `a1`, `a2`, ... instead of register names.
    #[serde(default)]
    pub param_register_names: Vec<String>,
}

/// Function parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Param {
    pub name: String,
    pub ty: Ty,
}

/// Local variable
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalVar {
    pub name: String,
    pub ty: Ty,
    pub is_used: bool,
    /// Recovered struct layout for pointer-typed locals (offset → (name, width)).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<(u64, String, u8)>,
}

impl Stmt {
    /// Visit every expression reachable from this statement (read-only).
    pub fn for_each_expr<'a>(&'a self, f: &mut impl FnMut(&'a Expr)) {
        match self {
            Stmt::Assign { target, value } => {
                target.for_each_subexpr(f);
                value.for_each_subexpr(f);
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                cond.for_each_subexpr(f);
                for s in then_body {
                    s.for_each_expr(f);
                }
                if let Some(eb) = else_body {
                    for s in eb {
                        s.for_each_expr(f);
                    }
                }
            }
            Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
                cond.for_each_subexpr(f);
                for s in body {
                    s.for_each_expr(f);
                }
            }
            Stmt::For {
                init,
                cond,
                update,
                body,
            } => {
                if let Some(s) = init {
                    s.for_each_expr(f);
                }
                if let Some(c) = cond {
                    c.for_each_subexpr(f);
                }
                if let Some(s) = update {
                    s.for_each_expr(f);
                }
                for s in body {
                    s.for_each_expr(f);
                }
            }
            Stmt::Switch {
                expr,
                cases,
                default,
            } => {
                expr.for_each_subexpr(f);
                for c in cases {
                    c.value.for_each_subexpr(f);
                    for s in &c.body {
                        s.for_each_expr(f);
                    }
                }
                if let Some(d) = default {
                    for s in d {
                        s.for_each_expr(f);
                    }
                }
            }
            Stmt::Return { value: Some(e) } => e.for_each_subexpr(f),
            Stmt::Call { args, .. } => {
                for a in args {
                    a.for_each_subexpr(f);
                }
            }
            Stmt::Expr(e) => e.for_each_subexpr(f),
            Stmt::Block(stmts) => {
                for s in stmts {
                    s.for_each_expr(f);
                }
            }
            Stmt::Decl { init: Some(e), .. } => e.for_each_subexpr(f),
            Stmt::TryCatch {
                try_body,
                catch_body,
                ..
            } => {
                for s in try_body {
                    s.for_each_expr(f);
                }
                for s in catch_body {
                    s.for_each_expr(f);
                }
            }
            _ => {}
        }
    }
}

/// A statement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Stmt {
    /// Variable assignment: `var = expr`
    Assign { target: Expr, value: Expr },

    /// If statement
    If {
        cond: Expr,
        then_body: Vec<Stmt>,
        else_body: Option<Vec<Stmt>>,
    },

    /// While loop
    While { cond: Expr, body: Vec<Stmt> },

    /// For loop
    For {
        init: Option<Box<Stmt>>,
        cond: Option<Expr>,
        update: Option<Box<Stmt>>,
        body: Vec<Stmt>,
    },

    /// Do-while loop
    DoWhile { body: Vec<Stmt>, cond: Expr },

    /// Switch statement
    Switch {
        expr: Expr,
        cases: Vec<SwitchCase>,
        default: Option<Vec<Stmt>>,
    },

    /// Return statement
    Return { value: Option<Expr> },

    /// Break
    Break,

    /// Continue
    Continue,

    /// Function call (as statement)
    Call { func: String, args: Vec<Expr> },

    /// Expression statement (e.g., function call with return value ignored)
    Expr(Expr),

    /// Block (compound statement)
    Block(Vec<Stmt>),

    /// Variable declaration
    Decl {
        name: String,
        ty: Ty,
        init: Option<Expr>,
    },

    /// Empty statement
    Empty,

    /// Try-catch block
    TryCatch {
        try_body: Vec<Stmt>,
        catch_var: Option<String>,
        catch_body: Vec<Stmt>,
    },

    /// Goto (fallback for unstructured edges)
    Goto { label: String },

    /// Label (for goto targets)
    Label { name: String },

    /// Comment (for annotations)
    Comment(String),
}

/// Switch case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchCase {
    pub value: Expr,
    pub body: Vec<Stmt>,
    pub fallthrough: bool,
}

/// An expression
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Expr {
    /// Integer literal
    IntLit(i64),

    /// Float literal
    FloatLit(f64),

    /// String literal
    StringLit(String),

    /// Boolean literal
    BoolLit(bool),

    /// Variable reference
    Var(String),

    /// Binary operation
    Binary {
        op: BinOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },

    /// Unary operation
    Unary { op: UnOp, operand: Box<Expr> },

    /// Function call
    Call { func: String, args: Vec<Expr> },

    /// Array/pointer indexing
    Index { base: Box<Expr>, index: Box<Expr> },

    /// Member access
    Member { base: Box<Expr>, field: String },

    /// Pointer dereference
    Deref(Box<Expr>),

    /// Struct field access: `base.field_name`. Produced by the struct-field
    /// recovery pass from `*(T*)(base + offset)` patterns.
    Field {
        base: Box<Expr>,
        field: String,
        /// Pointee type of the field (for casts/prints).
        ty: Ty,
    },

    /// Address-of
    AddrOf(Box<Expr>),

    /// Cast
    Cast { ty: Ty, expr: Box<Expr> },

    /// Conditional (ternary) operator
    Ternary {
        cond: Box<Expr>,
        then_expr: Box<Expr>,
        else_expr: Box<Expr>,
    },

    /// Sizeof
    Sizeof(Box<Expr>),
}

impl Expr {
    /// Visit every node of this expression tree (read-only), self last.
    pub fn for_each_subexpr<'a>(&'a self, f: &mut impl FnMut(&'a Expr)) {
        match self {
            Expr::Binary { lhs, rhs, .. } => {
                lhs.for_each_subexpr(f);
                rhs.for_each_subexpr(f);
            }
            Expr::Unary { operand, .. }
            | Expr::Deref(operand)
            | Expr::AddrOf(operand)
            | Expr::Sizeof(operand)
            | Expr::Cast { expr: operand, .. } => operand.for_each_subexpr(f),
            Expr::Call { args, .. } => {
                for a in args {
                    a.for_each_subexpr(f);
                }
            }
            Expr::Index { base, index } => {
                base.for_each_subexpr(f);
                index.for_each_subexpr(f);
            }
            Expr::Member { base, .. } | Expr::Field { base, .. } => base.for_each_subexpr(f),
            Expr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => {
                cond.for_each_subexpr(f);
                then_expr.for_each_subexpr(f);
                else_expr.for_each_subexpr(f);
            }
            _ => {}
        }
        f(self);
    }

    /// Rewrite this expression tree bottom-up: children first, then `self`.
    /// The closure sees every node exactly once, parents after children.
    pub fn rewrite_subexprs(&mut self, f: &mut impl FnMut(&mut Expr)) {
        match self {            Expr::Binary { lhs, rhs, .. } => {
                lhs.rewrite_subexprs(f);
                rhs.rewrite_subexprs(f);
            }
            Expr::Unary { operand, .. }
            | Expr::Deref(operand)
            | Expr::AddrOf(operand)
            | Expr::Sizeof(operand) => operand.rewrite_subexprs(f),
            Expr::Field { base, .. } => base.rewrite_subexprs(f),
            Expr::Call { args, .. } => {
                for a in args.iter_mut() {
                    a.rewrite_subexprs(f);
                }
            }
            Expr::Index { base, index } => {
                base.rewrite_subexprs(f);
                index.rewrite_subexprs(f);
            }
            Expr::Member { base, .. } => base.rewrite_subexprs(f),
            Expr::Cast { expr, .. } => expr.rewrite_subexprs(f),
            Expr::Ternary {
                cond,
                then_expr,
                else_expr,
            } => {
                cond.rewrite_subexprs(f);
                then_expr.rewrite_subexprs(f);
                else_expr.rewrite_subexprs(f);
            }
            _ => {}
        }
        f(self);
    }
}

/// Binary operators
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    LtU,
    LeU,
    GtU,
    GeU,
    LogAnd,
    LogOr,
}

impl BinOp {
    pub fn precedence(&self) -> u8 {
        match self {
            BinOp::Mul | BinOp::Div | BinOp::Mod => 13,
            BinOp::Add | BinOp::Sub => 12,
            BinOp::Shl | BinOp::Shr => 11,
            BinOp::Lt
            | BinOp::Le
            | BinOp::Gt
            | BinOp::Ge
            | BinOp::LtU
            | BinOp::LeU
            | BinOp::GtU
            | BinOp::GeU => 10,
            BinOp::Eq | BinOp::Ne => 9,
            BinOp::And => 8,
            BinOp::Xor => 7,
            BinOp::Or => 6,
            BinOp::LogAnd => 5,
            BinOp::LogOr => 4,
        }
    }

    pub fn is_comparison(&self) -> bool {
        matches!(
            self,
            BinOp::Eq
                | BinOp::Ne
                | BinOp::Lt
                | BinOp::Le
                | BinOp::Gt
                | BinOp::Ge
                | BinOp::LtU
                | BinOp::LeU
                | BinOp::GtU
                | BinOp::GeU
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            BinOp::Add => "+",
            BinOp::Sub => "-",
            BinOp::Mul => "*",
            BinOp::Div => "/",
            BinOp::Mod => "%",
            BinOp::And => "&",
            BinOp::Or => "|",
            BinOp::Xor => "^",
            BinOp::Shl => "<<",
            BinOp::Shr => ">>",
            BinOp::Eq => "==",
            BinOp::Ne => "!=",
            BinOp::Lt => "<",
            BinOp::Le => "<=",
            BinOp::Gt => ">",
            BinOp::Ge => ">=",
            BinOp::LtU => "<",
            BinOp::LeU => "<=",
            BinOp::GtU => ">",
            BinOp::GeU => ">=",
            BinOp::LogAnd => "&&",
            BinOp::LogOr => "||",
        }
    }
}

impl std::fmt::Display for BinOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Unary operators
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnOp {
    Neg,
    Not,
    LogNot,
    AddrOf,
    Deref,
}

impl UnOp {
    pub fn as_str(&self) -> &'static str {
        match self {
            UnOp::Neg => "-",
            UnOp::Not => "~",
            UnOp::LogNot => "!",
            UnOp::AddrOf => "&",
            UnOp::Deref => "*",
        }
    }
}

impl std::fmt::Display for UnOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AstFunction {
    /// Create a new empty function with unknown entry address
    pub fn new(name: &str) -> Self {
        AstFunction {
            name: name.to_string(),
            return_type: Ty::Void,
            params: Vec::new(),
            body: Vec::new(),
            locals: Vec::new(),
            entry_address: 0,
            param_register_names: Vec::new(),
        }
    }

    /// Rewrite every expression in the function, bottom-up: subexpressions
    /// are visited (and possibly rewritten) before their parent. The closure
    /// is applied to every `Expr` node exactly once.
    ///
    /// Shared by pattern recognition (rotate/bswap idioms) and string-literal
    /// annotation so all passes see the same traversal order.
    pub fn rewrite_exprs(&mut self, f: &mut impl FnMut(&mut Expr)) {
        rewrite_stmts_exprs(&mut self.body, f);
    }
}

fn rewrite_stmts_exprs(stmts: &mut [Stmt], f: &mut impl FnMut(&mut Expr)) {
    for stmt in stmts.iter_mut() {
        rewrite_stmt_exprs(stmt, f);
    }
}

fn rewrite_stmt_exprs(stmt: &mut Stmt, f: &mut impl FnMut(&mut Expr)) {
    match stmt {
        Stmt::Assign { target, value } => {
            target.rewrite_subexprs(f);
            value.rewrite_subexprs(f);
        }
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            cond.rewrite_subexprs(f);
            rewrite_stmts_exprs(then_body, f);
            if let Some(eb) = else_body {
                rewrite_stmts_exprs(eb, f);
            }
        }
        Stmt::While { cond, body } | Stmt::DoWhile { body, cond } => {
            cond.rewrite_subexprs(f);
            rewrite_stmts_exprs(body, f);
        }
        Stmt::For {
            init,
            cond,
            update,
            body,
        } => {
            if let Some(i) = init {
                rewrite_stmt_exprs(i, f);
            }
            if let Some(c) = cond {
                c.rewrite_subexprs(f);
            }
            if let Some(u) = update {
                rewrite_stmt_exprs(u, f);
            }
            rewrite_stmts_exprs(body, f);
        }
        Stmt::Switch {
            expr,
            cases,
            default,
        } => {
            expr.rewrite_subexprs(f);
            for case in cases.iter_mut() {
                case.value.rewrite_subexprs(f);
                rewrite_stmts_exprs(&mut case.body, f);
            }
            if let Some(d) = default {
                rewrite_stmts_exprs(d, f);
            }
        }
        Stmt::Return { value: Some(v) } => v.rewrite_subexprs(f),
        Stmt::Call { args, .. } => {
            for a in args.iter_mut() {
                a.rewrite_subexprs(f);
            }
        }
        Stmt::Expr(e) => e.rewrite_subexprs(f),
        Stmt::Decl { init: Some(e), .. } => e.rewrite_subexprs(f),
        Stmt::Block(inner) => rewrite_stmts_exprs(inner, f),
        Stmt::TryCatch {
            try_body,
            catch_body,
            ..
        } => {
            rewrite_stmts_exprs(try_body, f);
            rewrite_stmts_exprs(catch_body, f);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binop_precedence() {
        assert!(BinOp::Mul.precedence() > BinOp::Add.precedence());
        assert!(BinOp::Add.precedence() > BinOp::Eq.precedence());
        assert!(BinOp::Eq.precedence() > BinOp::LogAnd.precedence());
    }

    #[test]
    fn test_expr_creation() {
        let expr = Expr::Binary {
            op: BinOp::Add,
            lhs: Box::new(Expr::Var("x".to_string())),
            rhs: Box::new(Expr::IntLit(5)),
        };

        match expr {
            Expr::Binary { op, .. } => assert_eq!(op, BinOp::Add),
            _ => panic!("Wrong expression type"),
        }
    }
}
