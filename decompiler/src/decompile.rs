//! Main decompiler API.

use crate::ast_to_c::ast_to_c;
use crate::ir_to_ast::ir_to_ast;
use freakre_ir::{IrFunction, IrProgram};
use thiserror::Error;

/// Decompiler configuration
#[derive(Debug, Clone)]
pub struct DecompilerConfig {
    /// Whether to include variable declarations
    pub include_declarations: bool,
    
    /// Whether to simplify expressions
    pub simplify_expressions: bool,
    
    /// Whether to add comments for addresses
    pub annotate_addresses: bool,
    
    /// Indentation string (default: 4 spaces)
    pub indent: String,

    /// Whether to run SSA construction / trivial-phi removal / out-of-SSA lowering
    /// before structuring. Enabled by default; falls back silently if SSA fails.
    pub use_ssa: bool,

    /// Whether to run interprocedural analysis (calling convention, param count)
    /// and auto-populate call names from the program's own function map.
    /// Enabled by default for `decompile_program`.
    pub auto_interproc: bool,
    pub auto_call_names: bool,
}

impl Default for DecompilerConfig {
    fn default() -> Self {
        DecompilerConfig {
            include_declarations: true,
            simplify_expressions: true,
            annotate_addresses: false,
            indent: "    ".to_string(),
            use_ssa: true,
            auto_interproc: true,
            auto_call_names: true,
        }
    }
}

/// Decompiler errors
#[derive(Debug, Error)]
pub enum DecompileError {
    #[error("Failed to convert IR to AST: {0}")]
    IrToAstError(String),
    
    #[error("Failed to generate C code: {0}")]
    CodeGenError(String),
    
    #[error("Function not found: {0}")]
    FunctionNotFound(String),
}

/// Decompile a single IR function to C pseudocode
pub fn decompile_function(func: &IrFunction) -> Result<String, DecompileError> {
    decompile_function_with_config(func, &DecompilerConfig::default())
}

/// Decompile a function through an explicit SSA round-trip.
///
/// When `use_ssa` is enabled (now default with stack-aware fallback), the
/// function is converted `to_ssa -> remove_trivial_phis -> from_ssa` before
/// structuring. Stack-heavy functions where `rsp` would be lost (SSA lowers
/// `Register("rsp")` to fresh `Var`s) are detected and SSA is skipped for
/// that function so `recover_stack_vars` keeps working.
pub fn decompile_function_ssa(func: &IrFunction) -> Result<String, DecompileError> {
    let mut cfg = DecompilerConfig::default();
    cfg.use_ssa = true;
    decompile_function_with_config(func, &cfg)
}

/// Decompile a single IR function with custom configuration
pub fn decompile_function_with_config(
    func: &IrFunction,
    config: &DecompilerConfig,
) -> Result<String, DecompileError> {
    decompile_function_inner(
        func,
        config,
        &crate::call_naming::SignatureMap::default(),
        &crate::call_naming::AddrNameMap::default(),
    )
}

fn decompile_function_inner(
    func: &IrFunction,
    config: &DecompilerConfig,
    signatures: &crate::call_naming::SignatureMap,
    addr_names: &crate::call_naming::AddrNameMap,
) -> Result<String, DecompileError> {
    // Phase 0: IR cleanups (flag folding, temp propagation, dead flags)
    let mut ir = func.clone();
    crate::fold_flags::fold_flag_comparisons(&mut ir);
    crate::fold_flags::propagate_block_temps(&mut ir);
    crate::fold_flags::fuse_load_copies(&mut ir);
    crate::fold_flags::fold_adc_carries(&mut ir);

    // Phase 0.6: SSA round-trip (optional, enabled by default).
    // Must run before stack-var recovery so that recovered Var ids correspond
    // to the final lowered IR (from_ssa allocates fresh Vars). However SSA
    // lowers `Register("rsp")` to `Var`s, which blinds `recover_stack_vars`
    // (it keys on `Register("rsp")`). For functions that actually use `rsp`
    // for stack slots, we detect the loss and fall back to the pre-SSA IR.
    if config.use_ssa {
        let has_stack_access = ir.blocks.iter().any(|b| {
            b.insts.iter().any(|i| {
                i.sources().iter().any(|v| matches!(v, freakre_ir::Value::Register { name, .. } if name == "rsp"))
                    || i.dst().map_or(false, |d| matches!(d, freakre_ir::Value::Register { name, .. } if name == "rsp"))
            })
        });
        let mut ssa_candidate = ir.clone();
        if let Ok(mut ssa) = freakre_ir::ssa::to_ssa(&mut ssa_candidate) {
            freakre_ir::ssa::remove_trivial_phis(&mut ssa);
            let lowered = freakre_ir::ssa::from_ssa(&ssa);
            let lowered_has_rsp = lowered.blocks.iter().any(|b| {
                b.insts.iter().any(|i| {
                    i.sources().iter().any(|v| matches!(v, freakre_ir::Value::Register { name, .. } if name == "rsp"))
                        || i.dst().map_or(false, |d| matches!(d, freakre_ir::Value::Register { name, .. } if name == "rsp"))
                })
            });
            if !(has_stack_access && !lowered_has_rsp) {
                ir = lowered;
                crate::fold_flags::eliminate_dead_flag_defs(&mut ir);
            }
            // else: SSA would hide `rsp`; keep original `ir` for stack recovery.
        }
    }

    // Phase 0.5: stack-variable recovery (rsp-relative Load/Store → locals).
    // Runs after SSA so that the recovered mapping matches the final IR's Var ids,
    // and before final dead-flag elimination so recovered copies stay alive.
    // If SSA was skipped due to rsp loss, `ir` is still the pre-SSA form.
    let stack_var_names = crate::stack_vars::recover_stack_vars(&mut ir);
    crate::fold_flags::eliminate_dead_flag_defs(&mut ir);

    // Phase 1: Convert IR to structured AST
    let mut ast = ir_to_ast(&ir);

    // Recovered slots are declared as v{id}; give them local_xx names.
    crate::stack_vars::apply_recovered_names(&mut ast, &stack_var_names);

    // Phase 2: Type reconstruction (infer types from usage)
    crate::types::reconstruct_types(&mut ast);

    // Phase 3: Expression simplification
    if config.simplify_expressions {
        crate::simplify::simplify_function(&mut ast);
    }

    // Phase 4: Compiler pattern recognition
    crate::patterns::recognize_patterns(&mut ast);

    // Phase 5: Second simplification pass after pattern transforms
    if config.simplify_expressions {
        crate::simplify::simplify_function(&mut ast);
    }

    crate::call_naming::apply_call_naming_with(&mut ast, signatures, addr_names, Some(ir.entry_address));

    // Phase 6: Convert AST to C pseudocode
    let c_code = ast_to_c(&ast);

    Ok(c_code)
}

/// Decompile all functions in an IR program
pub fn decompile_program(program: &IrProgram) -> Result<Vec<(String, String)>, DecompileError> {
    decompile_program_with_config(program, &DecompilerConfig::default())
}

/// Decompile all functions in an IR program with custom configuration
pub fn decompile_program_with_config(
    program: &IrProgram,
    config: &DecompilerConfig,
) -> Result<Vec<(String, String)>, DecompileError> {
    // Interprocedural analysis (calling conventions) and auto call-name maps
    let analysis = if config.auto_interproc {
        Some(crate::interproc::analyze_program(program))
    } else {
        None
    };
    let addr_names = if config.auto_call_names {
        crate::call_naming::addr_names_from_program(program)
    } else {
        crate::call_naming::AddrNameMap::default()
    };
    let signatures = crate::call_naming::SignatureMap::default();

    let mut results = Vec::new();
    for func in &program.functions {
        // Enrich metadata from interproc analysis if available
        let mut enriched = func.clone();
        if let Some(ref an) = analysis {
            if let Some(summary) = an.get_summary(&func.name) {
                if enriched.metadata.calling_convention.is_none() {
                    enriched.metadata.calling_convention = Some(summary.calling_convention.to_string());
                }
                if enriched.metadata.return_type.is_none() {
                    if let Some(ref rt) = summary.return_type {
                        if *rt != freakre_ir::Ty::Unknown {
                            enriched.metadata.return_type = Some(rt.clone());
                        }
                    }
                }
            }
        }
        let c_code = decompile_function_inner(&enriched, config, &signatures, &addr_names)?;
        results.push((func.name.clone(), c_code));
    }
    Ok(results)
}

/// Decompile a specific function by name
pub fn decompile_function_by_name(
    program: &IrProgram,
    name: &str,
) -> Result<String, DecompileError> {
    let func = program
        .function_by_name(name)
        .ok_or_else(|| DecompileError::FunctionNotFound(name.to_string()))?;
    
    decompile_function(func)
}

/// Decompile a specific function by address
pub fn decompile_function_at(
    program: &IrProgram,
    address: u64,
) -> Result<String, DecompileError> {
    let func = program
        .function_at(address)
        .ok_or_else(|| DecompileError::FunctionNotFound(format!("0x{:X}", address)))?;
    
    decompile_function(func)
}

/// High-level decompiler API
pub struct Decompiler {
    config: DecompilerConfig,
}

impl Decompiler {
    /// Create a new decompiler with default configuration
    pub fn new() -> Self {
        Decompiler {
            config: DecompilerConfig::default(),
        }
    }
    
    /// Create a new decompiler with custom configuration
    pub fn with_config(config: DecompilerConfig) -> Self {
        Decompiler { config }
    }
    
    /// Decompile a single function
    pub fn decompile(&self, func: &IrFunction) -> Result<String, DecompileError> {
        decompile_function_with_config(func, &self.config)
    }
    
    /// Decompile all functions in a program
    pub fn decompile_all(&self, program: &IrProgram) -> Result<Vec<(String, String)>, DecompileError> {
        decompile_program_with_config(program, &self.config)
    }
    
    /// Decompile a function by name
    pub fn decompile_by_name(
        &self,
        program: &IrProgram,
        name: &str,
    ) -> Result<String, DecompileError> {
        decompile_function_by_name(program, name)
    }
    
    /// Decompile a function by address
    pub fn decompile_at(
        &self,
        program: &IrProgram,
        address: u64,
    ) -> Result<String, DecompileError> {
        decompile_function_at(program, address)
    }
}

impl Default for Decompiler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use freakre_ir::{IrInst, OpCode, Ty};
    
    #[test]
    fn test_decompile_simple() {
        let mut func = IrFunction::new("test_func", 0x1000);
        let v0 = func.alloc_var(Ty::i32());
        let v1 = func.alloc_var(Ty::i32());
        let v2 = func.alloc_var(Ty::i32());
        
        func.push_inst(func.entry_block, IrInst::Binary {
            dst: v2.clone(),
            op: OpCode::Add,
            lhs: v0.clone(),
            rhs: v1.clone(),
        });
        func.push_inst(func.entry_block, IrInst::Return {
            value: Some(v2.clone()),
        });
        
        let result = decompile_function(&func);
        assert!(result.is_ok());
        
        let c_code = result.unwrap();
        assert!(c_code.contains("test_func"));
        assert!(c_code.contains("return"));
    }
    
    #[test]
    fn test_decompile_program() {
        let mut program = IrProgram::new();
        
        let mut func1 = IrFunction::new("func1", 0x1000);
        func1.push_inst(func1.entry_block, IrInst::Return { value: None });
        
        let mut func2 = IrFunction::new("func2", 0x2000);
        func2.push_inst(func2.entry_block, IrInst::Return { value: None });
        
        program.add_function(func1);
        program.add_function(func2);
        
        let result = decompile_program(&program);
        assert!(result.is_ok());
        
        let decompiled = result.unwrap();
        assert_eq!(decompiled.len(), 2);
    }
    
    #[test]
    fn test_decompiler_api() {
        let mut func = IrFunction::new("test", 0x1000);
        func.push_inst(func.entry_block, IrInst::Return { value: None });
        
        let decompiler = Decompiler::new();
        let result = decompiler.decompile(&func);
        
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_decompile_function_ssa_diamond() {
        use freakre_ir::{OpCode, Value};
        
        let mut func = IrFunction::new("ssa_diamond", 0x1000);
        let cond = func.alloc_var(Ty::Bool);
        let then_b = func.add_block("then");
        let else_b = func.add_block("else");
        let merge = func.add_block("merge");
        let x = Value::var(10, Ty::i32());
        
        func.push_inst(func.entry_block, IrInst::CBranch {
            cond,
            target_true: then_b,
            target_false: else_b,
        });
        func.push_inst(then_b, IrInst::Unary {
            dst: x.clone(),
            op: OpCode::Copy,
            src: Value::int(1),
        });
        func.push_inst(then_b, IrInst::Branch { target: merge });
        func.push_inst(else_b, IrInst::Unary {
            dst: x.clone(),
            op: OpCode::Copy,
            src: Value::int(2),
        });
        func.push_inst(else_b, IrInst::Branch { target: merge });
        func.push_inst(merge, IrInst::Return { value: Some(x) });
        
        let result = decompile_function_ssa(&func).unwrap();
        assert!(result.contains("ssa_diamond"));
        assert!(result.contains("return"));
        
        assert_eq!(
            decompile_function(&func).unwrap(),
            decompile_function(&func.clone()).unwrap()
        );
    }
}
