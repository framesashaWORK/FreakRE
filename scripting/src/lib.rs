#![allow(dead_code, unused_assignments)]
//! # Scripting Engine
//!
//! Embedded scripting for FreakRE using Rhai.
//! Allows users to automate analysis tasks, create custom plugins,
//! and extend the tool's functionality.
//!
//! ## Example
//!
//! ```rust
//! use scripting::ScriptEngine;
//!
//! let mut engine = ScriptEngine::new();
//! let result = engine.eval(r#"
//!     let funcs = db.list_functions();
//!     for func in funcs {
//!         if func.name.contains("main") {
//!             print("Found main at " + func.address.to_hex());
//!         }
//!     }
//! "#).unwrap();
//! ```

use rhai::{Engine, Scope, AST, Dynamic};
use project_db::ProjectDatabase;
use thiserror::Error;
use std::sync::{Arc, Mutex};

#[derive(Error, Debug)]
pub enum ScriptError {
    #[error("Script error: {0}")]
    Rhai(#[from] rhai::EvalAltResult),
    #[error("Script error: {0}")]
    RhaiBoxed(#[from] Box<rhai::EvalAltResult>),
    #[error("Parse error: {0}")]
    Parse(#[from] rhai::ParseError),
    #[error("Database error: {0}")]
    Database(#[from] project_db::DbError),
    #[error("Script not found: {0}")]
    NotFound(String),
    #[error("Invalid argument: {0}")]
    InvalidArg(String),
}

pub type Result<T> = std::result::Result<T, ScriptError>;

/// Script execution context
pub struct ScriptContext {
    db: Arc<Mutex<ProjectDatabase>>,
    output: Arc<Mutex<Vec<String>>>,
}

impl ScriptContext {
    pub fn new(db: Arc<Mutex<ProjectDatabase>>) -> Self {
        Self {
            db,
            output: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn get_output(&self) -> Vec<String> {
        self.output.lock().unwrap().clone()
    }

    pub fn clear_output(&self) {
        self.output.lock().unwrap().clear();
    }
}

/// Script engine with Rhai integration
pub struct ScriptEngine {
    engine: Engine,
    context: Option<ScriptContext>,
}

impl ScriptEngine {
    pub fn new() -> Self {
        let mut engine = Engine::new();

        // Security limits to prevent DoS/hang from malicious or buggy scripts
        engine.set_max_operations(50_000);
        engine.set_max_expr_depths(64, 64);
        engine.set_max_array_size(10_000);
        engine.set_max_map_size(10_000);
        engine.set_max_string_size(1_000_000);

        Self::register_api(&mut engine);
        Self {
            engine,
            context: None,
        }
    }

    pub fn with_context(mut self, db: Arc<Mutex<ProjectDatabase>>) -> Self {
        self.context = Some(ScriptContext::new(db));
        self
    }

    fn register_api(engine: &mut Engine) {
        // Register database methods
        // NOTE: Rhai native functions with NativeCallContext require the context
        // to be passed via engine state or scope. We use a simpler approach:
        // register pure utility functions here; DB access goes through eval_with_db.

        // Output functions (no context needed — use global output buffer)
        engine.register_fn("to_hex", |n: i64| -> String {
            format!("0x{:X}", n)
        });

        engine.register_fn("format_address", |n: i64| -> String {
            format!("0x{:016X}", n)
        });

    }

    /// Evaluate a script string
    pub fn eval(&mut self, script: &str) -> Result<Dynamic> {
        let ast = self.engine.compile(script)?;
        if let Some(ref context) = self.context {
            let mut scope = Scope::new();
            // Expose DB operations via scope variables that scripts can call
            // Scripts should use eval_with_db for full DB access
            let _ = context; // context available for future use
            let result = self.engine.eval_ast_with_scope::<Dynamic>(&mut scope, &ast)?;
            Ok(result)
        } else {
            let result = self.engine.eval_ast::<Dynamic>(&ast)?;
            Ok(result)
        }
    }

    /// Evaluate a script with access to the database
    pub fn eval_with_db(&mut self, script: &str) -> Result<Dynamic> {
        if self.context.is_none() {
            return Err(ScriptError::InvalidArg("No database context".to_string()));
        }

        let mut scope = Scope::new();
        if let Some(ref context) = self.context {
            scope.push("db", context.db.clone());
        }

        let ast = self.engine.compile(script)?;
        let result = self.engine.eval_ast_with_scope::<Dynamic>(&mut scope, &ast)?;
        Ok(result)
    }

    /// Compile a script for repeated execution
    pub fn compile(&self, script: &str) -> Result<AST> {
        Ok(self.engine.compile(script)?)
    }

    /// Execute a compiled AST
    pub fn run(&mut self, ast: &AST) -> Result<Dynamic> {
        if let Some(ref context) = self.context {
            let mut scope = Scope::new();
            scope.push("db", context.db.clone());
            Ok(self.engine.eval_ast_with_scope::<Dynamic>(&mut scope, ast)?)
        } else {
            Ok(self.engine.eval_ast::<Dynamic>(ast)?)
        }
    }

    /// Get script output
    pub fn get_output(&self) -> Vec<String> {
        self.context.as_ref().map(|c| c.get_output()).unwrap_or_default()
    }

    /// Clear script output
    pub fn clear_output(&mut self) {
        if let Some(ref context) = self.context {
            context.clear_output();
        }
    }
}

impl Default for ScriptEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Built-in script templates
pub struct ScriptTemplates;

impl ScriptTemplates {
    pub fn find_strings() -> &'static str {
        r#"
// Find all ASCII strings in the binary
let strings = [];
let current = "";

for i in 0..binary.len() {
    let byte = binary[i];
    if byte >= 32 && byte <= 126 {
        current += char(byte);
    } else {
        if current.len() >= 4 {
            strings.push(current);
        }
        current = "";
    }
}

for s in strings {
    println("String: " + s);
}
"#
    }

    pub fn find_crypto_constants() -> &'static str {
        r#"
// Find common cryptographic constants
let crypto_consts = #{
    0x67452301: "MD5_INIT_A",
    0xefcdab89: "MD5_INIT_B",
    0x98badcfe: "MD5_INIT_C",
    0x10325476: "MD5_INIT_D",
    0x6a09e667: "SHA256_H0",
    0xbb67ae85: "SHA256_H1",
    0x3c6ef372: "SHA256_H2",
    0xa54ff53a: "SHA256_H3",
};

let funcs = db.list_functions();
for func in funcs {
    println("Analyzing: " + func.name);
}
"#
    }

    pub fn rename_functions() -> &'static str {
        r#"
// Rename functions based on patterns
let funcs = db.list_functions();
let counter = 0;

for func in funcs {
    if func.name.starts_with("sub_") {
        let new_name = "func_" + counter.to_string();
        db.set_label(func.address, new_name);
        counter += 1;
    }
}

println("Renamed " + counter.to_string() + " functions");
"#
    }

    pub fn find_call_chains() -> &'static str {
        r#"
// Find all call chains from main to a specific function
let target = 0x401000; // Replace with target address
let main = 0x401000;   // Replace with main address

let callers = db.callers(target);
for caller in callers {
    let func = db.get_function(caller);
    println("Called by: " + func.name + " at " + caller.to_hex());
}
"#
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_eval() {
        let mut engine = ScriptEngine::new();
        let result = engine.eval("2 + 2").unwrap();
        assert_eq!(result.as_int().unwrap(), 4);
    }

    #[test]
    fn test_string_operations() {
        let mut engine = ScriptEngine::new();
        let result = engine.eval(r#""hello" + " world""#).unwrap();
        assert_eq!(result.into_string().unwrap(), "hello world");
    }

    #[test]
    fn test_to_hex() {
        let mut engine = ScriptEngine::new();
        let result = engine.eval("to_hex(255)").unwrap();
        assert_eq!(result.into_string().unwrap(), "0xFF");
    }
}


