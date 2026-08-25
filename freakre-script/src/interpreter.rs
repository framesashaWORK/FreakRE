//! Sandboxed interpreter for the DSL.

use std::collections::HashMap;
use crate::ast::*;
use crate::sandbox::{SandboxConfig, Capabilities};
use crate::lexer::LexError;
use crate::parser::ParseError;

#[derive(Debug, Clone)]
pub enum Value {
    Nil,
    Bool(bool),
    Integer(i64),
    Number(f64),
    Str(String),
    Table(Vec<(Value, Value)>),
    Func(FuncDef),
}

#[derive(Debug, Clone)]
pub struct FuncDef {
    pub params: Vec<String>,
    pub body: Vec<Stmt>,
}

impl Value {
    pub fn is_truthy(&self) -> bool {
        !matches!(self, Value::Nil | Value::Bool(false))
    }

    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Value::Integer(n) => Some(*n),
            Value::Number(f) => Some(*f as i64),
            _ => None,
        }
    }

    pub fn as_number(&self) -> Option<f64> {
        match self {
            Value::Number(f) => Some(*f),
            Value::Integer(n) => Some(*n as f64),
            _ => None,
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Nil => "nil",
            Value::Bool(_) => "boolean",
            Value::Integer(_) => "integer",
            Value::Number(_) => "number",
            Value::Str(_) => "string",
            Value::Table(_) => "table",
            Value::Func(_) => "function",
        }
    }
}

impl core::fmt::Display for Value {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Value::Nil => write!(f, "nil"),
            Value::Bool(b) => write!(f, "{}", b),
            Value::Integer(n) => write!(f, "{}", n),
            Value::Number(n) => write!(f, "{}", n),
            Value::Str(s) => write!(f, "{}", s),
            Value::Table(_) => write!(f, "<table>"),
            Value::Func(_) => write!(f, "<function>"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ScriptError {
    InstructionLimit,
    MemoryLimit,
    CallDepthLimit,
    StringLengthLimit,
    TableSizeLimit,
    UndefinedVariable(String),
    CapabilityDenied(String),
    TypeError(String),
    RuntimeError(String),
    Return(Vec<Value>), // Internal: used to propagate return values
    LoopBreak,
}

impl core::fmt::Display for ScriptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InstructionLimit => write!(f, "instruction limit exceeded"),
            Self::MemoryLimit => write!(f, "memory limit exceeded"),
            Self::CallDepthLimit => write!(f, "call depth limit exceeded"),
            Self::StringLengthLimit => write!(f, "string length limit exceeded"),
            Self::TableSizeLimit => write!(f, "table size limit exceeded"),
            Self::UndefinedVariable(name) => write!(f, "undefined variable '{}'", name),
            Self::CapabilityDenied(api) => write!(f, "capability denied: {}", api),
            Self::TypeError(msg) => write!(f, "type error: {}", msg),
            Self::RuntimeError(msg) => write!(f, "runtime error: {}", msg),
            Self::Return(_) => write!(f, "unexpected return outside function"),
            Self::LoopBreak => write!(f, "unexpected break outside loop"),
        }
    }
}

impl std::error::Error for ScriptError {}

impl From<LexError> for ScriptError {
    fn from(e: LexError) -> Self {
        ScriptError::RuntimeError(format!("{}", e))
    }
}

impl From<ParseError> for ScriptError {
    fn from(e: ParseError) -> Self {
        ScriptError::RuntimeError(format!("{}", e))
    }
}

type Env = HashMap<String, Value>;

/// Host builtins dispatchable by bare name when no user binding shadows them.
/// The capability whitelist applies ONLY to these (fix: previously it ran on
/// every callee name before env lookup, breaking all user-defined calls).
const HOST_BUILTINS: [&str; 4] = ["print", "type", "read_bytes", "write_bytes"];

/// One segment of a compound assignment target (`t.a[i].b`).
enum PathSeg {
    Field(String),
    Index(Expr),
}

pub struct Interpreter {
    config: SandboxConfig,
    caps: Capabilities,
    instructions: u64,
    call_depth: usize,
    mem_used: usize,
    /// Lexical scope stack. `scopes[0]` is the global environment and always
    /// exists; each block pushes a lightweight child scope popped on exit,
    /// giving `local` proper block scoping without cloning the parent map.
    scopes: Vec<Env>,
}

impl Interpreter {
    pub fn new(config: SandboxConfig, caps: Capabilities) -> Self {
        Self {
            config,
            caps,
            instructions: 0,
            call_depth: 0,
            mem_used: 0,
            scopes: vec![Env::new()],
        }
    }

    pub fn execute(&mut self, stmts: &[Stmt]) -> Result<Value, ScriptError> {
        // Run against the interpreter's own global scope (scopes[0]) so that
        // top-level assignments and function definitions persist and stay
        // visible to later statements (recursion works). Previously this ran
        // in a throwaway clone of globals, discarding everything.
        match self.exec_block(stmts) {
            Ok(val) => Ok(val),
            Err(ScriptError::Return(mut vals)) => {
                if vals.is_empty() { Ok(Value::Nil) } else { Ok(vals.remove(0)) }
            }
            Err(e) => Err(e),
        }
    }

    fn tick(&mut self) -> Result<(), ScriptError> {
        self.instructions += 1;
        if self.instructions > self.config.max_instructions {
            Err(ScriptError::InstructionLimit)
        } else {
            Ok(())
        }
    }

    fn alloc(&mut self, bytes: usize) -> Result<(), ScriptError> {
        self.mem_used = self.mem_used.saturating_add(bytes);
        if self.mem_used > self.config.max_memory {
            Err(ScriptError::MemoryLimit)
        } else {
            Ok(())
        }
    }

    // ── Scope-chain helpers ────────────────────────────────────────

    fn push_scope(&mut self) {
        self.scopes.push(Env::new());
    }

    fn pop_scope(&mut self) {
        // scopes[0] (globals) is never popped.
        if self.scopes.len() > 1 {
            self.scopes.pop();
        }
    }

    /// Resolve a name walking innermost scope out to globals.
    fn lookup(&self, name: &str) -> Option<Value> {
        for scope in self.scopes.iter().rev() {
            if let Some(v) = scope.get(name) {
                return Some(v.clone());
            }
        }
        None
    }

    /// True if any visible scope binds `name`.
    fn is_defined(&self, name: &str) -> bool {
        self.scopes.iter().rev().any(|s| s.contains_key(name))
    }

    /// Assign to the nearest existing binding; create a global if unbound
    /// (Lua semantics for plain `x = v`).
    fn assign(&mut self, name: &str, val: Value) {
        for scope in self.scopes.iter_mut().rev() {
            if scope.contains_key(name) {
                scope.insert(name.to_string(), val);
                return;
            }
        }
        self.scopes[0].insert(name.to_string(), val);
    }

    /// Define a fresh `local` binding in the innermost open scope.
    fn define_local(&mut self, name: &str, val: Value) {
        let last = self.scopes.last_mut().expect("global scope always present");
        last.insert(name.to_string(), val);
    }

    fn exec_block(&mut self, stmts: &[Stmt]) -> Result<Value, ScriptError> {
        let mut last = Value::Nil;
        for stmt in stmts {
            self.tick()?;
            last = self.exec_stmt(stmt)?;
        }
        Ok(last)
    }

    /// Execute a block in its own child scope: `local` declarations inside
    /// are discarded on exit, while assignments to existing outer bindings
    /// still update them. Scope push/pop is O(1).
    fn exec_scoped_block(&mut self, stmts: &[Stmt]) -> Result<Value, ScriptError> {
        self.push_scope();
        let result = self.exec_block(stmts);
        self.pop_scope();
        result
    }

    fn exec_stmt(&mut self, stmt: &Stmt) -> Result<Value, ScriptError> {
        match stmt {
            Stmt::Assign { target, value } => {
                let val = self.eval_expr(value)?;
                self.alloc(value_mem(&val))?;
                match target {
                    Expr::Ident(name) => {
                        self.assign(name, val.clone());
                    }
                    other => {
                        // Support t.x = v, t[i] = v and nested paths like
                        // t.a[i].x = v rooted at a named variable.
                        let (root, segs) = flatten_target(other).ok_or_else(|| {
                            ScriptError::RuntimeError("invalid assignment target".into())
                        })?;
                        let mut keys = Vec::with_capacity(segs.len());
                        for seg in &segs {
                            keys.push(match seg {
                                PathSeg::Field(n) => Value::Str(n.clone()),
                                PathSeg::Index(e) => self.eval_expr(e)?,
                            });
                        }
                        self.alloc(value_mem(&val) + std::mem::size_of::<(Value, Value)>())?;
                        self.assign_path(&root, &keys, val.clone())?;
                    }
                }
                Ok(val)
            }
            Stmt::LocalAssign { name, value } => {
                let val = match value {
                    Some(expr) => self.eval_expr(expr)?,
                    None => Value::Nil,
                };
                self.alloc(value_mem(&val))?;
                self.define_local(name, val.clone());
                Ok(val)
            }
            Stmt::If { cond, then_body, elseifs, else_body } => {
                let c = self.eval_expr(cond)?;
                if c.is_truthy() {
                    return self.exec_scoped_block(then_body);
                }
                for (econd, ebody) in elseifs {
                    let ec = self.eval_expr(econd)?;
                    if ec.is_truthy() {
                        return self.exec_scoped_block(ebody);
                    }
                }
                if let Some(eb) = else_body {
                    return self.exec_scoped_block(eb);
                }
                Ok(Value::Nil)
            }
            Stmt::While { cond, body } => {
                loop {
                    self.tick()?;
                    let c = self.eval_expr(cond)?;
                    if !c.is_truthy() { break; }
                    match self.exec_scoped_block(body) {
                        Ok(_) => {}
                        Err(ScriptError::Return(v)) => return Err(ScriptError::Return(v)),
                        Err(ScriptError::LoopBreak) => break,
                        Err(e) => return Err(e),
                    }
                }
                Ok(Value::Nil)
            }
            Stmt::ForNumeric { var, start, stop, step, body } => {
                let s = self.eval_expr(start)?.as_integer()
                    .ok_or_else(|| ScriptError::TypeError("for start must be integer".into()))?;
                let e = self.eval_expr(stop)?.as_integer()
                    .ok_or_else(|| ScriptError::TypeError("for stop must be integer".into()))?;
                let st = match step {
                    Some(se) => self.eval_expr(se)?.as_integer()
                        .ok_or_else(|| ScriptError::TypeError("for step must be integer".into()))?,
                    None => 1,
                };
                if st == 0 {
                    return Err(ScriptError::RuntimeError("for step cannot be zero".into()));
                }
                // The control variable lives in a scope owned by the loop and
                // disappears with it; each iteration's body runs in a fresh
                // child scope so `local j` never leaks outward.
                self.push_scope();
                let mut i = s;
                let result = loop {
                    if !((st > 0 && i <= e) || (st < 0 && i >= e)) {
                        break Ok(Value::Nil);
                    }
                    self.tick()?;
                    self.define_local(var, Value::Integer(i));
                    match self.exec_scoped_block(body) {
                        Ok(_) => {}
                        Err(ScriptError::Return(v)) => break Err(ScriptError::Return(v)),
                        Err(ScriptError::LoopBreak) => break Ok(Value::Nil),
                        Err(err) => break Err(err),
                    }
                    i = match i.checked_add(st) {
                        Some(n) => n,
                        None => break Ok(Value::Nil),
                    };
                };
                self.pop_scope();
                result
            }
            Stmt::Return { values } => {
                let vals: Result<Vec<_>, _> = values.iter().map(|v| self.eval_expr(v)).collect();
                Err(ScriptError::Return(vals?))
            }
            Stmt::Break => Err(ScriptError::LoopBreak),
            Stmt::ExprStmt(expr) => self.eval_expr(expr),
            Stmt::FuncDef { name, params, body } => {
                let func = Value::Func(FuncDef {
                    params: params.clone(),
                    body: body.clone(),
                });
                // Lua semantics: `function name() end` ≡ `name = function...`
                // → nearest existing binding, else a new global.
                self.assign(name, func);
                Ok(Value::Nil)
            }
        }
    }

    /// Descend from the variable named `root` through `keys`, writing `val`.
    /// Missing intermediate tables are auto-created; missing final keys are
    /// appended (Lua-style upsert).
    fn assign_path(&mut self, root: &str, keys: &[Value], val: Value) -> Result<(), ScriptError> {
        for scope in self.scopes.iter_mut().rev() {
            if scope.contains_key(root) {
                let slot = scope.get_mut(root).expect("checked contains_key");
                return set_value_path(slot, keys, val);
            }
        }
        Err(ScriptError::RuntimeError(format!(
            "attempt to index undefined variable '{}'",
            root
        )))
    }

    fn eval_expr(&mut self, expr: &Expr) -> Result<Value, ScriptError> {
        self.tick()?;
        match expr {
            Expr::Nil => Ok(Value::Nil),
            Expr::Bool(b) => Ok(Value::Bool(*b)),
            Expr::Integer(n) => Ok(Value::Integer(*n)),
            Expr::Number(n) => Ok(Value::Number(*n)),
            Expr::StringLit(s) => {
                if s.len() > self.config.max_string_len {
                    return Err(ScriptError::StringLengthLimit);
                }
                Ok(Value::Str(s.clone()))
            }
            Expr::Ident(name) => self
                .lookup(name)
                .ok_or_else(|| ScriptError::UndefinedVariable(name.clone())),
            Expr::BinOp { left, op, right } => {
                // Short-circuit for and/or
                if *op == BinOp::And {
                    let l = self.eval_expr(left)?;
                    if !l.is_truthy() { return Ok(l); }
                    return self.eval_expr(right);
                }
                if *op == BinOp::Or {
                    let l = self.eval_expr(left)?;
                    if l.is_truthy() { return Ok(l); }
                    return self.eval_expr(right);
                }

                let l = self.eval_expr(left)?;
                let r = self.eval_expr(right)?;
                self.eval_binop(&l, *op, &r)
            }
            Expr::UnOp { op, operand } => {
                let val = self.eval_expr(operand)?;
                match op {
                    UnOp::Neg => match val {
                        Value::Integer(n) => n.checked_neg()
                            .map(Value::Integer)
                            .ok_or_else(|| ScriptError::RuntimeError("integer overflow".into())),
                        Value::Number(n) => Ok(Value::Number(-n)),
                        _ => Err(ScriptError::TypeError("cannot negate non-number".into())),
                    },
                    UnOp::Not => Ok(Value::Bool(!val.is_truthy())),
                    UnOp::Len => match val {
                        Value::Str(ref s) => Ok(Value::Integer(s.len() as i64)),
                        Value::Table(ref t) => Ok(Value::Integer(t.len() as i64)),
                        _ => Err(ScriptError::TypeError("cannot get length of non-string/table".into())),
                    },
                }
            }
            Expr::Call { func, args } => {
                // Resolve the callee BEFORE applying any capability check:
                // user-defined functions live in the environment and are
                // callable freely; only host builtins go through the
                // whitelist. (Previously the check ran on the callee NAME
                // first, so every user function failed CapabilityDenied.)
                enum Callee {
                    Builtin(&'static str),
                    Func(FuncDef),
                }
                let callee = match func.as_ref() {
                    Expr::Ident(name) => match self.lookup(name) {
                        Some(Value::Func(fdef)) => Callee::Func(fdef),
                        Some(_) => {
                            return Err(ScriptError::TypeError("attempt to call non-function".into()));
                        }
                        None if HOST_BUILTINS.contains(&name.as_str()) => {
                            if !self.caps.can_call(name) {
                                return Err(ScriptError::CapabilityDenied(name.clone()));
                            }
                            Callee::Builtin(match name.as_str() {
                                "print" => "print",
                                "type" => "type",
                                "read_bytes" => "read_bytes",
                                _ => "write_bytes",
                            })
                        }
                        None => {
                            return Err(ScriptError::UndefinedVariable(name.clone()));
                        }
                    },
                    other => match self.eval_expr(other)? {
                        Value::Func(fdef) => Callee::Func(fdef),
                        _ => {
                            return Err(ScriptError::TypeError("attempt to call non-function".into()));
                        }
                    },
                };

                let evaluated_args: Result<Vec<_>, _> = args.iter().map(|a| self.eval_expr(a)).collect();
                let evaluated_args = evaluated_args?;

                match callee {
                    Callee::Builtin(name) => match name {
                        "print" => {
                            let line: Vec<String> = evaluated_args.iter().map(value_to_string).collect();
                            self.tick()?;
                            // Never panic on closed/invalid stderr (GUI hosts):
                            // ignore write errors instead of using eprintln!.
                            use std::io::Write;
                            let _ = writeln!(std::io::stderr(), "{}", line.join("\t"));
                            Ok(Value::Nil)
                        }
                        "type" => {
                            let v = evaluated_args.first().cloned().unwrap_or(Value::Nil);
                            Ok(Value::Str(v.type_name().to_string()))
                        }
                        "read_bytes" => {
                            let path = match evaluated_args.first() {
                                Some(Value::Str(s)) => s.clone(),
                                Some(other) => {
                                    return Err(ScriptError::TypeError(format!(
                                        "read_bytes expects a string path, got {}",
                                        other.type_name()
                                    )))
                                }
                                None => {
                                    return Err(ScriptError::TypeError(
                                        "read_bytes expects a string path".into(),
                                    ))
                                }
                            };
                            self.builtin_read_bytes(&path)
                        }
                        "write_bytes" => {
                            let path = match evaluated_args.first() {
                                Some(Value::Str(s)) => s.clone(),
                                Some(other) => {
                                    return Err(ScriptError::TypeError(format!(
                                        "write_bytes expects a string path, got {}",
                                        other.type_name()
                                    )))
                                }
                                None => {
                                    return Err(ScriptError::TypeError(
                                        "write_bytes expects a string path".into(),
                                    ))
                                }
                            };
                            let data = match evaluated_args.get(1) {
                                Some(Value::Str(s)) => s.clone(),
                                Some(other) => {
                                    return Err(ScriptError::TypeError(format!(
                                        "write_bytes expects a string payload, got {}",
                                        other.type_name()
                                    )))
                                }
                                None => {
                                    return Err(ScriptError::TypeError(
                                        "write_bytes expects a second string argument".into(),
                                    ))
                                }
                            };
                            self.builtin_write_bytes(&path, &data)
                        }
                        _ => unreachable!("HOST_BUILTINS covers all builtin names"),
                    },
                    Callee::Func(fdef) => {
                        self.call_depth += 1;
                        if self.call_depth > self.config.max_call_depth {
                            self.call_depth -= 1;
                            return Err(ScriptError::CallDepthLimit);
                        }
                        // Function invocation is isolated from enclosing block
                        // scopes (no dynamic scoping, no closures): the frame
                        // sees only globals + parameters.
                        let mut frame = Env::new();
                        for (i, param) in fdef.params.iter().enumerate() {
                            let val = evaluated_args.get(i).cloned().unwrap_or(Value::Nil);
                            frame.insert(param.clone(), val);
                        }
                        let saved_len = self.scopes.len();
                        self.scopes.truncate(1);
                        self.scopes.push(frame);
                        let result = match self.exec_block(&fdef.body) {
                            Ok(v) => Ok(v),
                            Err(ScriptError::Return(vals)) => {
                                Ok(vals.into_iter().next().unwrap_or(Value::Nil))
                            }
                            // Function boundary for `break`: it must never act
                            // as cross-function control flow. (The parser also
                            // rejects this at compile time; kept as defense.)
                            Err(ScriptError::LoopBreak) => Err(ScriptError::RuntimeError(
                                "break outside loop".into(),
                            )),
                            Err(e) => Err(e),
                        };
                        self.call_depth -= 1;
                        if self.scopes.len() > saved_len {
                            self.scopes.truncate(saved_len);
                        }
                        result
                    }
                }
            }
            Expr::Index { table, key } => {
                let k = self.eval_expr(key)?;
                let t = self.eval_expr(table)?;
                // The whitelist gates host module namespaces only: when the
                // root identifier resolves to user data in scope, its fields
                // are the script's own property.
                if let (Expr::Ident(root), Value::Str(field)) = (table.as_ref(), &k) {
                    if !self.is_defined(root) && !self.caps.can_access_field(root, field) {
                        return Err(ScriptError::CapabilityDenied(format!(
                            "{}.{}",
                            root, field
                        )));
                    }
                }
                match t {
                    Value::Table(entries) => {
                        for (ek, ev) in &entries {
                            if values_equal(ek, &k) {
                                return Ok(ev.clone());
                            }
                        }
                        Ok(Value::Nil)
                    }
                    _ => Err(ScriptError::TypeError("attempt to index non-table".into())),
                }
            }
            Expr::Field { table, name } => {
                // Same rule as Expr::Index.
                if let Expr::Ident(root) = table.as_ref() {
                    if !self.is_defined(root) && !self.caps.can_access_field(root, name) {
                        return Err(ScriptError::CapabilityDenied(format!("{}.{}", root, name)));
                    }
                }
                let t = self.eval_expr(table)?;
                match t {
                    Value::Table(entries) => {
                        let key = Value::Str(name.clone());
                        for (ek, ev) in &entries {
                            if values_equal(ek, &key) {
                                return Ok(ev.clone());
                            }
                        }
                        Ok(Value::Nil)
                    }
                    _ => Err(ScriptError::TypeError("attempt to index non-table".into())),
                }
            }
            Expr::Table(entries) => {
                let mut result = Vec::new();
                let mut array_idx = 1i64;
                for (key, val) in entries {
                    let v = self.eval_expr(val)?;
                    let k = match key {
                        Some(k) => self.eval_expr(k)?,
                        None => {
                            let idx = array_idx;
                            array_idx += 1;
                            Value::Integer(idx)
                        }
                    };
                    result.push((k, v));
                }
                if result.len() > self.config.max_table_entries {
                    return Err(ScriptError::TableSizeLimit);
                }
                self.alloc(result.len() * std::mem::size_of::<(Value, Value)>())?;
                Ok(Value::Table(result))
            }
        }
    }

    fn eval_binop(&mut self, left: &Value, op: BinOp, right: &Value) -> Result<Value, ScriptError> {
        match op {
            BinOp::Add => checked_binop(left, right, i64::checked_add, |a, b| a + b),
            BinOp::Sub => checked_binop(left, right, i64::checked_sub, |a, b| a - b),
            BinOp::Mul => checked_binop(left, right, i64::checked_mul, |a, b| a * b),
            BinOp::Div => {
                if let (Some(a), Some(b)) = (left.as_number(), right.as_number()) {
                    if b == 0.0 { return Err(ScriptError::RuntimeError("division by zero".into())); }
                    Ok(Value::Number(a / b))
                } else {
                    Err(ScriptError::TypeError("arithmetic on non-numbers".into()))
                }
            }
            BinOp::Mod => {
                if let (Some(a), Some(b)) = (left.as_integer(), right.as_integer()) {
                    if b == 0 {
                        return Err(ScriptError::RuntimeError("modulo by zero".into()));
                    }
                    a.checked_rem(b)
                        .map(Value::Integer)
                        .ok_or_else(|| ScriptError::RuntimeError("modulo overflow".into()))
                } else {
                    Err(ScriptError::TypeError("modulo on non-integers".into()))
                }
            }
            BinOp::Pow => {
                if let (Some(a), Some(b)) = (left.as_number(), right.as_number()) {
                    Ok(Value::Number(a.powf(b)))
                } else {
                    Err(ScriptError::TypeError("pow on non-numbers".into()))
                }
            }
            BinOp::Concat => {
                let ls = value_to_string(left);
                let rs = value_to_string(right);
                if ls.len() + rs.len() > self.config.max_string_len {
                    return Err(ScriptError::StringLengthLimit);
                }
                self.alloc(ls.len() + rs.len())?;
                Ok(Value::Str(format!("{}{}", ls, rs)))
            }
            BinOp::Eq => Ok(Value::Bool(values_equal(left, right))),
            BinOp::Neq => Ok(Value::Bool(!values_equal(left, right))),
            // IEEE 754: any ordered comparison with a NaN operand is false
            // (compare_values yields None for unordered pairs). `~=` still
            // uses values_equal, so NaN ~= NaN is true as in Lua.
            BinOp::Lt => Ok(Value::Bool(matches!(
                compare_values(left, right)?,
                Some(core::cmp::Ordering::Less)
            ))),
            BinOp::Gt => Ok(Value::Bool(matches!(
                compare_values(left, right)?,
                Some(core::cmp::Ordering::Greater)
            ))),
            BinOp::Lte => Ok(Value::Bool(matches!(
                compare_values(left, right)?,
                Some(o) if o != core::cmp::Ordering::Greater
            ))),
            BinOp::Gte => Ok(Value::Bool(matches!(
                compare_values(left, right)?,
                Some(o) if o != core::cmp::Ordering::Less
            ))),
            BinOp::And | BinOp::Or => unreachable!("handled in eval_expr"),
        }
    }

    fn builtin_read_bytes(&mut self, path: &str) -> Result<Value, ScriptError> {
        if !self.caps.allow_file_io {
            return Err(ScriptError::CapabilityDenied("file_io".into()));
        }
        let full = resolve_script_path(path)?;
        // Stat BEFORE reading so an oversized file is refused without ever
        // loading it into memory (previously fs::read slurped it all first).
        // NOTE: canonicalizing the parent + stat + read is not atomic — a
        // symlink swapped in between (TOCTOU) is not defended here; OS-level
        // mitigations are out of scope by design.
        let meta = std::fs::metadata(&full)
            .map_err(|e| ScriptError::RuntimeError(format!("read_bytes failed: {}", e)))?;
        if !meta.is_file() {
            return Err(ScriptError::RuntimeError("read_bytes: not a regular file".into()));
        }
        if meta.len() > self.config.max_string_len as u64 {
            return Err(ScriptError::StringLengthLimit);
        }
        let data = std::fs::read(&full)
            .map_err(|e| ScriptError::RuntimeError(format!("read_bytes failed: {}", e)))?;
        if data.len() > self.config.max_string_len {
            return Err(ScriptError::StringLengthLimit);
        }
        self.alloc(data.len())?;
        Ok(Value::Str(String::from_utf8_lossy(&data).into_owned()))
    }

    fn builtin_write_bytes(&mut self, path: &str, data: &str) -> Result<Value, ScriptError> {
        if !self.caps.allow_file_io {
            return Err(ScriptError::CapabilityDenied("file_io".into()));
        }
        if data.len() > self.config.max_string_len {
            return Err(ScriptError::StringLengthLimit);
        }
        self.alloc(data.len())?;
        let full = resolve_script_path(path)?;
        std::fs::write(&full, data.as_bytes())
            .map_err(|e| ScriptError::RuntimeError(format!("write_bytes failed: {}", e)))?;
        Ok(Value::Integer(data.len() as i64))
    }
}

fn checked_binop(
    left: &Value, right: &Value,
    int_op: fn(i64, i64) -> Option<i64>,
    float_op: fn(f64, f64) -> f64,
) -> Result<Value, ScriptError> {
    match (left, right) {
        (Value::Integer(a), Value::Integer(b)) => int_op(*a, *b)
            .map(Value::Integer)
            .ok_or_else(|| ScriptError::RuntimeError("integer overflow".into())),
        _ => {
            if let (Some(a), Some(b)) = (left.as_number(), right.as_number()) {
                Ok(Value::Number(float_op(a, b)))
            } else {
                Err(ScriptError::TypeError("arithmetic on non-numbers".into()))
            }
        }
    }
}

/// Flatten `t`, `t.x`, `t[i]`, `t.a[i].b` … into a root name plus path
/// segments. Returns None for targets that cannot be assigned to.
fn flatten_target(expr: &Expr) -> Option<(String, Vec<PathSeg>)> {
    match expr {
        Expr::Ident(name) => Some((name.clone(), Vec::new())),
        Expr::Field { table, name } => {
            let (root, mut segs) = flatten_target(table)?;
            segs.push(PathSeg::Field(name.clone()));
            Some((root, segs))
        }
        Expr::Index { table, key } => {
            let (root, mut segs) = flatten_target(table)?;
            segs.push(PathSeg::Index((**key).clone()));
            Some((root, segs))
        }
        _ => None,
    }
}

/// Recursive upsert: descend `slot` through `keys`, writing `val` at the end.
/// Intermediate tables are auto-created (Lua semantics).
fn set_value_path(slot: &mut Value, keys: &[Value], val: Value) -> Result<(), ScriptError> {
    let (key, rest) = keys.split_first().ok_or_else(|| {
        ScriptError::RuntimeError("invalid assignment target".into())
    })?;
    match slot {
        Value::Table(entries) => {
            match entries.iter().position(|(k, _)| values_equal(k, key)) {
                Some(pos) => {
                    if rest.is_empty() {
                        entries[pos].1 = val;
                        Ok(())
                    } else {
                        set_value_path(&mut entries[pos].1, rest, val)
                    }
                }
                None => {
                    if rest.is_empty() {
                        entries.push((key.clone(), val));
                        Ok(())
                    } else {
                        entries.push((key.clone(), Value::Table(Vec::new())));
                        let last = entries.len() - 1;
                        set_value_path(&mut entries[last].1, rest, val)
                    }
                }
            }
        }
        other => Err(ScriptError::TypeError(format!(
            "attempt to index a {} value",
            other.type_name()
        ))),
    }
}

fn value_mem(v: &Value) -> usize {
    match v {
        Value::Str(s) => s.len(),
        Value::Table(t) => t.len() * std::mem::size_of::<(Value, Value)>(),
        _ => 0,
    }
}

fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Nil, Value::Nil) => true,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Integer(a), Value::Integer(b)) => a == b,
        (Value::Number(a), Value::Number(b)) => a == b,
        (Value::Integer(a), Value::Number(b)) => (*a as f64) == *b,
        (Value::Number(a), Value::Integer(b)) => *a == (*b as f64),
        (Value::Str(a), Value::Str(b)) => a == b,
        _ => false,
    }
}

/// Ordered comparison. `Ok(None)` means unordered (NaN involved): every
/// ordering comparison must then be false, never fall back to Equal.
fn compare_values(a: &Value, b: &Value) -> Result<Option<core::cmp::Ordering>, ScriptError> {
    match (a, b) {
        (Value::Integer(a), Value::Integer(b)) => Ok(Some(a.cmp(b))),
        (Value::Number(a), Value::Number(b)) => Ok(a.partial_cmp(b)),
        (Value::Str(a), Value::Str(b)) => Ok(Some(a.cmp(b))),
        _ => Err(ScriptError::TypeError("comparison of incompatible types".into())),
    }
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::Str(s) => s.clone(),
        other => format!("{}", other),
    }
}

fn is_windows_device_name(name: &str) -> bool {
    const DEVICES: [&str; 4] = ["CON", "PRN", "AUX", "NUL"];
    if DEVICES.contains(&name) {
        return true;
    }
    (0..=9).any(|i| name == format!("COM{}", i) || name == format!("LPT{}", i))
}

fn strip_verbatim_prefix(p: std::path::PathBuf) -> std::path::PathBuf {
    let s = p.to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(rest) => std::path::PathBuf::from(rest),
        None => p,
    }
}

fn resolve_script_path(path: &str) -> Result<std::path::PathBuf, ScriptError> {
    if path.trim().is_empty() {
        return Err(ScriptError::RuntimeError("empty path".into()));
    }
    let raw = std::path::Path::new(path);
    for component in raw.components() {
        let text = component.as_os_str().to_string_lossy().to_uppercase();
        let stem = std::path::Path::new(&text)
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or(text.clone());
        if is_windows_device_name(&stem) {
            return Err(ScriptError::CapabilityDenied(format!(
                "reserved device path '{}'",
                stem
            )));
        }
    }

    let cwd = strip_verbatim_prefix(
        std::env::current_dir()
            .map_err(|e| ScriptError::RuntimeError(format!("cwd unavailable: {}", e)))?,
    );

    let absolute = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        cwd.join(raw)
    };

    let file_name = absolute
        .file_name()
        .ok_or_else(|| ScriptError::RuntimeError("invalid path".into()))?;

    let parent = absolute
        .parent()
        .ok_or_else(|| ScriptError::RuntimeError("invalid path".into()))?;
    let canonical_parent =
        strip_verbatim_prefix(parent.canonicalize().map_err(|e| {
            ScriptError::RuntimeError(format!("path resolution failed: {}", e))
        })?);

    if !canonical_parent.starts_with(&cwd) {
        return Err(ScriptError::CapabilityDenied(
            "path escapes working directory".into(),
        ));
    }

    Ok(canonical_parent.join(file_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{run, sandbox::SandboxConfig};

    #[test]
    fn test_basic_arithmetic() {
        let result = run("local x = 2 + 3\nreturn x", &SandboxConfig::default(), &Capabilities::default()).unwrap();
        assert_eq!(result.as_integer(), Some(5));
    }

    #[test]
    fn test_instruction_limit() {
        let config = SandboxConfig { max_instructions: 10, ..Default::default() };
        let result = run("while true do end", &config, &Capabilities::default());
        assert!(matches!(result, Err(ScriptError::InstructionLimit)));
    }

    #[test]
    fn test_capability_denied() {
        let result = run("os.execute('rm -rf /')", &SandboxConfig::default(), &Capabilities::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_for_loop() {
        let result = run("local sum = 0\nfor i = 1, 5 do\n  sum = sum + i\nend\nreturn sum",
            &SandboxConfig::default(), &Capabilities::default()).unwrap();
        assert_eq!(result.as_integer(), Some(15));
    }

    fn file_io_caps() -> Capabilities {
        Capabilities { allow_file_io: true, ..Default::default() }
    }

    #[test]
    fn test_file_io_denied_by_default() {
        let result = run("return read_bytes('whatever.txt')", &SandboxConfig::default(), &Capabilities::default());
        assert!(matches!(result, Err(ScriptError::CapabilityDenied(name)) if name == "read_bytes"));

        let result = run("return write_bytes('a.txt', 'x')", &SandboxConfig::default(), &Capabilities::default());
        assert!(matches!(result, Err(ScriptError::CapabilityDenied(name)) if name == "write_bytes"));
    }

    #[test]
    fn test_write_read_roundtrip() {
        let path = "frs_test_io.tmp";
        let script = format!(
            "write_bytes('{}', 'hello sandbox')\nreturn read_bytes('{}')",
            path, path
        );
        let result = run(&script, &SandboxConfig::default(), &file_io_caps()).unwrap();
        assert!(matches!(result, Value::Str(ref s) if s == "hello sandbox"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_path_escape_denied() {
        let result = run(
            "return read_bytes('../../secrets.txt')",
            &SandboxConfig::default(),
            &file_io_caps(),
        );
        assert!(matches!(result, Err(ScriptError::CapabilityDenied(_))));
    }

    #[test]
    fn test_windows_device_name_denied() {
        for name in ["CON", "nul.txt", "COM1"] {
            let script = format!("return write_bytes('{}', 'x')", name);
            let result = run(&script, &SandboxConfig::default(), &file_io_caps());
            assert!(matches!(result, Err(ScriptError::CapabilityDenied(_))), "path: {}", name);
        }
    }

    #[test]
    fn test_index_respects_capabilities() {
        // User-defined tables are freely readable — the whitelist gates host
        // module namespaces, not script data.
        let result = run(
            "local t = {find_functions = 7}\nreturn t['find_functions']",
            &SandboxConfig::default(),
            &Capabilities::default(),
        )
        .unwrap();
        assert_eq!(result.as_integer(), Some(7));
    }

    #[test]
    fn test_host_module_field_denied() {
        // Unresolved root = host namespace → whitelisted names only.
        // `db.find_functions` is whitelisted, but db is undefined at runtime.
        let result = run(
            "return db.find_functions({})",
            &SandboxConfig::default(),
            &Capabilities::default(),
        );
        assert!(result.is_err());

        // Non-whitelisted namespace access is a capability denial.
        let mut caps = Capabilities::default();
        caps.allowed_fields.clear();
        let result = run("return foo.bar", &SandboxConfig::default(), &caps);
        assert!(matches!(result, Err(ScriptError::CapabilityDenied(ref m)) if m == "foo.bar"));
    }

    #[test]
    fn test_numeric_index_still_works() {
        let result = run(
            "local t = {10, 20, 30}\nreturn t[2]",
            &SandboxConfig::default(),
            &Capabilities::default(),
        )
        .unwrap();
        assert_eq!(result.as_integer(), Some(20));
    }

    // ── Regression tests for audit findings ───────────────────────

    #[test]
    fn test_user_function_call() {
        // Audit #1: user-defined calls must not hit CapabilityDenied.
        let result = run(
            "function double(x) return x * 2 end\nreturn double(21)",
            &SandboxConfig::default(),
            &Capabilities::default(),
        )
        .unwrap();
        assert_eq!(result.as_integer(), Some(42));
    }

    #[test]
    fn test_recursion_and_persistent_globals() {
        // Audit #2: top-level FuncDef/assignments must persist; fact must
        // resolve itself recursively.
        let result = run(
            "acc = 0\nfunction fact(n)\n  if n <= 1 then return 1 end\n  return n * fact(n - 1)\nend\nacc = fact(5)\nreturn acc",
            &SandboxConfig::default(),
            &Capabilities::default(),
        )
        .unwrap();
        assert_eq!(result.as_integer(), Some(120));
    }

    #[test]
    fn test_user_fn_shadows_builtin_name() {
        let result = run(
            "local saved = {}\nfunction print(x) return x end\nreturn print('hi')",
            &SandboxConfig::default(),
            &Capabilities::default(),
        );
        assert!(matches!(result, Ok(Value::Str(ref s)) if s == "hi"));
    }

    #[test]
    fn test_builtin_still_callable_and_gated() {
        // type is a whitelisted builtin.
        let result = run(
            "return type(42)",
            &SandboxConfig::default(),
            &Capabilities::default(),
        )
        .unwrap();
        assert!(matches!(result, Value::Str(ref s) if s == "integer"));

        // An empty whitelist denies host builtins but not user functions.
        let mut caps = Capabilities::default();
        caps.allowed_functions.clear();
        assert!(run("print(1)", &SandboxConfig::default(), &caps).is_err());
        assert!(run(
            "function f() return 9 end\nreturn f()",
            &SandboxConfig::default(),
            &caps
        )
        .unwrap()
        .as_integer()
            == Some(9));
    }

    #[test]
    fn test_table_named_keys() {
        // Audit #3: {name = value} keys are literal strings.
        let result = run(
            "local t = {name = 'freak', version = 2, 99}\nreturn t.name .. '/' .. t['version'] .. '/' .. t[1]",
            &SandboxConfig::default(),
            &Capabilities::default(),
        )
        .unwrap();
        assert!(matches!(result, Value::Str(ref s) if s == "freak/2/99"));
    }

    #[test]
    fn test_pow_operator() {
        // Audit #4: ^ parsed with Lua precedence: right-assoc, above unary -.
        let r = |src: &str| run(src, &SandboxConfig::default(), &Capabilities::default()).unwrap();
        assert_eq!(r("return 2 ^ 10").as_number(), Some(1024.0));
        assert_eq!(r("return -2 ^ 2").as_number(), Some(-4.0)); // -(2^2)
        assert_eq!(r("return 2 ^ 3 ^ 2").as_number(), Some(512.0)); // 2^(3^2)
        assert_eq!(r("return 2 * 3 ^ 2").as_number(), Some(18.0));
    }

    #[test]
    fn test_block_local_scoping() {
        // Audit #5: locals inside loop/if bodies do not leak.
        let result = run(
            "local j = 100\nfor i = 1, 3 do\n  local j = i\n  j = j + 1\nend\nif true then local j = 5 end\nreturn j",
            &SandboxConfig::default(),
            &Capabilities::default(),
        )
        .unwrap();
        assert_eq!(result.as_integer(), Some(100));
    }

    #[test]
    fn test_assignment_through_scopes() {
        // Assignment still reaches outer bindings through child scopes.
        let result = run(
            "local total = 0\nfor i = 1, 4 do\n  total = total + i\nend\nreturn total",
            &SandboxConfig::default(),
            &Capabilities::default(),
        )
        .unwrap();
        assert_eq!(result.as_integer(), Some(10));
    }

    #[test]
    fn test_non_ascii_strings() {
        // Audit #6: strings decode UTF-8 instead of byte-as-char mojibake.
        let result = run(
            "return 'привет' .. ' ' .. 'мир'",
            &SandboxConfig::default(),
            &Capabilities::default(),
        )
        .unwrap();
        assert!(matches!(result, Value::Str(ref s) if s == "привет мир"));
    }

    #[test]
    fn test_field_and_index_assignment() {
        // Audit #8: t.x = v / t[i] = v / nested paths work.
        let result = run(
            "local t = {}\nt.x = 5\nt['y'] = 6\nt.list = {}\nt.list[1] = 'a'\nt.deep.nested.v = 42\nreturn t.x + t.y + #t.list + t.deep.nested.v",
            &SandboxConfig::default(),
            &Capabilities::default(),
        )
        .unwrap();
        assert_eq!(result.as_integer(), Some(54));
    }

    #[test]
    fn test_assign_to_undefined_table_field_rejected() {
        let result = run("nope.x = 1", &SandboxConfig::default(), &Capabilities::default());
        assert!(matches!(result, Err(ScriptError::RuntimeError(ref m)) if m.contains("undefined")));
    }

    #[test]
    fn test_nan_comparisons_are_false() {
        // Audit #9: NaN never compares true in ordered comparisons.
        let nan = Value::Number(f64::NAN);
        for op in [BinOp::Lt, BinOp::Gt, BinOp::Lte, BinOp::Gte] {
            let res = Interpreter::new(SandboxConfig::default(), Capabilities::default())
                .eval_binop(&nan, op, &nan)
                .unwrap();
            assert!(matches!(res, Value::Bool(false)), "{:?} on NaN must be false", op);
        }
        // != remains meaningful: NaN ~= NaN is true.
        let mut interp = Interpreter::new(SandboxConfig::default(), Capabilities::default());
        let res = interp.eval_expr(&Expr::BinOp {
            left: Box::new(Expr::Number(f64::NAN)),
            op: BinOp::Neq,
            right: Box::new(Expr::Number(f64::NAN)),
        });
        assert!(matches!(res, Ok(Value::Bool(true))));
    }

    #[test]
    fn test_break_in_function_is_parse_error() {
        // Audit #10: break cannot cross function boundaries.
        let result = run(
            "function f() break end\nwhile true do f() end",
            &SandboxConfig::default(),
            &Capabilities::default(),
        );
        assert!(matches!(result, Err(ScriptError::RuntimeError(ref m)) if m.contains("break outside loop")));
    }

    #[test]
    fn test_break_inside_loop_works() {
        let result = run(
            "local i = 0\nwhile true do\n  i = i + 1\n  if i > 3 then break end\nend\nreturn i",
            &SandboxConfig::default(),
            &Capabilities::default(),
        )
        .unwrap();
        assert_eq!(result.as_integer(), Some(4));

        let result = run(
            "local n = 0\nfor i = 1, 10 do\n  if i == 5 then break end\n  n = n + i\nend\nreturn n",
            &SandboxConfig::default(),
            &Capabilities::default(),
        )
        .unwrap();
        assert_eq!(result.as_integer(), Some(10));
    }

    #[test]
    fn test_print_does_not_panic() {
        // Audit #11: print routes through writeln!(stderr), errors ignored.
        let result = run(
            "print('hello', 42)\nreturn 1",
            &SandboxConfig::default(),
            &Capabilities::default(),
        )
        .unwrap();
        assert_eq!(result.as_integer(), Some(1));
    }

    #[test]
    fn test_call_depth_limit_intact() {
        let config = SandboxConfig { max_call_depth: 8, ..Default::default() };
        let result = run(
            "function f(n) return 1 + f(n) end\nreturn f(0)",
            &config,
            &Capabilities::default(),
        );
        assert!(matches!(result, Err(ScriptError::CallDepthLimit)));
    }
}
