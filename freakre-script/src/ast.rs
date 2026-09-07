//! AST for the sandbox DSL.

#[derive(Debug, Clone)]
pub enum Stmt {
    Assign {
        target: Expr,
        value: Expr,
    },
    LocalAssign {
        name: String,
        value: Option<Expr>,
    },
    If {
        cond: Expr,
        then_body: Vec<Stmt>,
        elseifs: Vec<(Expr, Vec<Stmt>)>,
        else_body: Option<Vec<Stmt>>,
    },
    While {
        cond: Expr,
        body: Vec<Stmt>,
    },
    ForNumeric {
        var: String,
        start: Expr,
        stop: Expr,
        step: Option<Expr>,
        body: Vec<Stmt>,
    },
    Return {
        values: Vec<Expr>,
    },
    Break,
    ExprStmt(Expr),
    FuncDef {
        name: String,
        params: Vec<String>,
        body: Vec<Stmt>,
    },
}

#[derive(Debug, Clone)]
pub enum Expr {
    Nil,
    Bool(bool),
    Integer(i64),
    Number(f64),
    StringLit(String),
    Ident(String),
    BinOp {
        left: Box<Expr>,
        op: BinOp,
        right: Box<Expr>,
    },
    UnOp {
        op: UnOp,
        operand: Box<Expr>,
    },
    Call {
        func: Box<Expr>,
        args: Vec<Expr>,
    },
    Index {
        table: Box<Expr>,
        key: Box<Expr>,
    },
    Field {
        table: Box<Expr>,
        name: String,
    },
    Table(Vec<(Option<Expr>, Expr)>), // None key = array element
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
    Concat,
    Eq,
    Neq,
    Lt,
    Gt,
    Lte,
    Gte,
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnOp {
    Neg,
    Not,
    Len,
}
