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
        }
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
