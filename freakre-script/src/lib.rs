//! freakre-script: Sandboxed Lua-like DSL interpreter.
//! - Capability-based security (whitelist API)
//! - Instruction counter + memory quota
//! - Deterministic (no RNG, no time, no env)
//! - No eval, no dynamic dispatch, no closures

pub mod lexer;
pub mod ast;
pub mod parser;
pub mod interpreter;
pub mod sandbox;

pub use interpreter::{Interpreter, ScriptError};
pub use sandbox::{Capabilities, SandboxConfig};
pub use ast::Stmt;

/// Run a script with the given config and capabilities.
pub fn run(
    source: &str,
    config: &SandboxConfig,
    caps: &Capabilities,
) -> Result<interpreter::Value, ScriptError> {
    let tokens = lexer::tokenize(source)?;
    let stmts = parser::parse(&tokens)?;
    let mut interp = Interpreter::new(config.clone(), caps.clone());
    interp.execute(&stmts)
}
