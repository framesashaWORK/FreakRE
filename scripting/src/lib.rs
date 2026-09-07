#![allow(dead_code, unused_assignments)]
//! # Scripting Engine
//!
//! Embedded scripting for FreakRE using Rhai.
//! Allows users to automate analysis tasks, create custom plugins,
//! and extend the tool's functionality.
//!
//! ## Example
//!
//! ```rust,no_run
//! use scripting::ScriptEngine;
//!
//! let mut engine = ScriptEngine::new();
//! let result = engine.eval(r#"
//!     let funcs = db.list_functions();
//!     for func in funcs {
//!         if func.name.contains("main") {
//!             print("Found main at " + func.address);
//!         }
//!     }
//! "#).unwrap();
//! ```

use project_db::ProjectDatabase;
use rhai::{Array, Dynamic, Engine, Map, Scope, AST};
use std::sync::{Arc, Mutex};
use thiserror::Error;

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

/// Maximum number of print-output lines retained; older lines are discarded
/// (ring-buffer semantics over the backing `Vec`, oldest first).
const MAX_OUTPUT_LINES: usize = 1000;

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
        self.output
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub fn clear_output(&self) {
        self.output
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }
}

/// Script engine with Rhai integration
pub struct ScriptEngine {
    engine: Engine,
    context: Option<ScriptContext>,
    output: Arc<Mutex<Vec<String>>>,
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

        let output: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = output.clone();
        engine.on_print(move |msg: &str| {
            let mut buf = sink.lock().unwrap_or_else(|p| p.into_inner());
            buf.push(msg.to_string());
            if buf.len() > MAX_OUTPUT_LINES {
                let excess = buf.len() - MAX_OUTPUT_LINES;
                buf.drain(..excess);
            }
        });

        Self::register_api(&mut engine);
        Self {
            engine,
            context: None,
            output,
        }
    }

    pub fn with_context(mut self, db: Arc<Mutex<ProjectDatabase>>) -> Self {
        self.context = Some(ScriptContext::new(db.clone()));
        self.engine.register_fn(
            "list_functions",
            move |db: Arc<Mutex<ProjectDatabase>>| -> Array {
                let db = db.lock().unwrap_or_else(|p| p.into_inner());
                match db.list_functions() {
                    Ok(funcs) => funcs
                        .into_iter()
                        .map(|f| {
                            let mut m = Map::new();
                            m.insert("address".into(), Dynamic::from(f.address));
                            m.insert("name".into(), Dynamic::from(f.name));
                            Dynamic::from(m)
                        })
                        .collect(),
                    Err(_) => Array::new(),
                }
            },
        );
        self.engine.register_fn(
            "count_functions",
            move |db: Arc<Mutex<ProjectDatabase>>| -> i64 {
                let db = db.lock().unwrap_or_else(|p| p.into_inner());
                let n = db.list_functions().map(|f| f.len()).unwrap_or(0);
                n as i64
            },
        );
        self
    }

    fn register_api(engine: &mut Engine) {
        // Safe utility functions (no side effects, no system access)
        engine.register_fn("to_hex", |n: i64| -> String { format!("0x{:X}", n) });
        engine.register_fn("to_hex", |n: u64| -> String { format!("0x{:X}", n) });

        engine.register_fn("format_address", |n: i64| -> String {
            format!("0x{:016X}", n)
        });
        engine.register_fn("format_address", |n: u64| -> String {
            format!("0x{:016X}", n)
        });

        // Explicitly disable dangerous modules that Rhai might expose
        engine.set_max_modules(0); // Disable module loading
    }

    /// Evaluate a script string
    pub fn eval(&mut self, script: &str) -> Result<Dynamic> {
        let ast = self.engine.compile(script)?;
        if let Some(ref context) = self.context {
            let mut scope = Scope::new();
            scope.push("db", context.db.clone());
            let result = self
                .engine
                .eval_ast_with_scope::<Dynamic>(&mut scope, &ast)?;
            Ok(result)
        } else {
            let result = self.engine.eval_ast::<Dynamic>(&ast)?;
            Ok(result)
        }
    }

    /// Evaluate a script with access to the database.
    /// FIXED: The `db` object is wrapped in Arc<Mutex<>> and only exposes
    /// methods registered on ProjectDatabase. Scripts cannot escape the
    /// sandbox because:
    /// - No file/network/system APIs are registered
    /// - Module loading is disabled (set_max_modules(0))
    /// - Operation limits prevent infinite loops
    /// - Array/map/string size limits prevent memory exhaustion
    pub fn eval_with_db(&mut self, script: &str) -> Result<Dynamic> {
        if self.context.is_none() {
            return Err(ScriptError::InvalidArg("No database context".to_string()));
        }

        let mut scope = Scope::new();
        if let Some(ref context) = self.context {
            scope.push("db", context.db.clone());
        }

        let ast = self.engine.compile(script)?;
        let result = self
            .engine
            .eval_ast_with_scope::<Dynamic>(&mut scope, &ast)?;
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
            Ok(self
                .engine
                .eval_ast_with_scope::<Dynamic>(&mut scope, ast)?)
        } else {
            Ok(self.engine.eval_ast::<Dynamic>(ast)?)
        }
    }

    /// Get script output (capped to the most recent `MAX_OUTPUT_LINES` lines)
    pub fn get_output(&self) -> Vec<String> {
        self.output
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Clear script output
    pub fn clear_output(&mut self) {
        self.output
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
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
// List all known functions with their addresses
let funcs = db.list_functions();
print("Total functions: " + funcs.len().to_string());
for func in funcs {
    print(func.name + " at " + to_hex(func.address));
}
"#
    }

    pub fn find_crypto_constants() -> &'static str {
        r#"
// Find functions whose names look crypto-related
let keywords = ["md5", "sha", "aes", "rc4", "crypt", "xor"];
for func in db.list_functions() {
    for kw in keywords {
        if func.name.to_lower().contains(kw) {
            print("Crypto candidate: " + func.name + " at " + to_hex(func.address));
        }
    }
}
"#
    }

    pub fn rename_functions() -> &'static str {
        r#"
// Report unnamed sub_* functions
let count = 0;
for func in db.list_functions() {
    if func.name.starts_with("sub_") {
        count += 1;
        print("Unnamed function: " + func.name + " at " + format_address(func.address));
    }
}
print("Candidates to rename: " + count.to_string());
count
"#
    }

    pub fn find_call_chains() -> &'static str {
        r#"
// Show entry point candidates and function coverage
print("Functions in project: " + db.count_functions().to_string());
let entry = 0x401000;
print("Entry reference address: " + format_address(entry));
for func in db.list_functions() {
    print(func.name + " -> " + format_address(func.address));
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

    fn make_test_db(tag: &str) -> Arc<Mutex<ProjectDatabase>> {
        let dir = std::env::temp_dir().join(format!("scripting-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = ProjectDatabase::create(
            dir.join("test.bdb"),
            std::path::PathBuf::from("binary.exe"),
            "hash".to_string(),
            "x86".to_string(),
            "PE".to_string(),
        )
        .unwrap();
        Arc::new(Mutex::new(db))
    }

    #[test]
    fn test_eval_with_db() {
        let db = make_test_db("evaldb");
        let mut engine = ScriptEngine::new().with_context(db);
        let result = engine.eval_with_db("db.count_functions()").unwrap();
        assert_eq!(result.as_int().unwrap(), 0);
        let result = engine
            .eval_with_db("let f = db.list_functions(); f.len()")
            .unwrap();
        assert_eq!(result.as_int().unwrap(), 0);
    }

    #[test]
    fn test_print_output_capture() {
        let mut engine = ScriptEngine::new();
        let _ = engine.eval(r#"print("hello from script")"#).unwrap();
        assert_eq!(engine.get_output(), vec!["hello from script".to_string()]);
    }

    #[test]
    fn test_templates_run() {
        let db = make_test_db("templates");
        let mut engine = ScriptEngine::new().with_context(db);
        let _ = engine
            .eval_with_db(ScriptTemplates::find_strings())
            .unwrap();
        let _ = engine
            .eval_with_db(ScriptTemplates::find_crypto_constants())
            .unwrap();
        let _ = engine
            .eval_with_db(ScriptTemplates::rename_functions())
            .unwrap();
        let _ = engine
            .eval_with_db(ScriptTemplates::find_call_chains())
            .unwrap();
    }

    fn poison<T>(m: &Arc<Mutex<T>>) {
        let inner = m.clone();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _guard = inner.lock().unwrap();
            panic!("intentional poison for tests");
        }));
        assert!(m.is_poisoned());
    }

    #[test]
    fn test_registered_fns_survive_poisoned_db() {
        let db = make_test_db("poisondb");
        poison(&db);
        let mut engine = ScriptEngine::new().with_context(db);
        let n = engine.eval_with_db("db.count_functions()").unwrap();
        assert_eq!(n.as_int().unwrap(), 0);
        let funcs = engine.eval_with_db("db.list_functions()").unwrap();
        assert_eq!(funcs.into_array().map(|a| a.len()), Ok(0));
    }

    #[test]
    fn test_output_accessors_survive_poisoned_output() {
        let mut engine = ScriptEngine::new();
        poison(&engine.output);
        let _ = engine.eval(r#"print("after poison")"#).unwrap();
        assert_eq!(engine.get_output(), vec!["after poison".to_string()]);
        engine.clear_output();
        assert!(engine.get_output().is_empty());
    }

    #[test]
    fn test_context_output_accessors_survive_poisoned_output() {
        let db = make_test_db("poisonctx");
        let ctx = ScriptContext::new(db);
        poison(&ctx.output);
        assert!(ctx.get_output().is_empty());
        ctx.output
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push("kept".to_string());
        assert_eq!(ctx.get_output(), vec!["kept".to_string()]);
        ctx.clear_output();
        assert!(ctx.get_output().is_empty());
    }

    #[test]
    fn test_print_buffer_capped() {
        let mut engine = ScriptEngine::new();
        let _ = engine
            .eval(r#"for i in 0..1200 { print("line " + i); }"#)
            .unwrap();
        let out = engine.get_output();
        assert_eq!(out.len(), MAX_OUTPUT_LINES);
        assert_eq!(out.last().unwrap(), "line 1199");
        assert!(!out.first().unwrap().is_empty());
        engine.clear_output();
        assert!(engine.get_output().is_empty());
    }
}
