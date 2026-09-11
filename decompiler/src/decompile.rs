//! Main decompiler API.

use crate::ast_to_c::ast_to_c_with_config;
use crate::ir_to_ast::ir_to_ast;
use freakre_ir::{IrFunction, IrProgram};
use thiserror::Error;

/// Hard safety cap for one export-decompilation request.
pub const MAX_DECOMPILED_EXPORTS: usize = 256;
/// Hard safety cap for CFG size accepted by the decompiler.
pub const MAX_FUNCTION_BLOCKS: usize = 4096;
/// Hard safety cap for IR instructions accepted by the decompiler.
pub const MAX_FUNCTION_INSTRUCTIONS: usize = 262_144;
/// Hard safety cap for generated pseudocode returned for one function.
pub const MAX_PSEUDOCODE_BYTES: usize = 8 * 1024 * 1024;

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

    /// Recover struct fields from `*(T*)(base + off)` accesses and render
    /// them as `base->field_0xNN` (offset → field name in comments).
    /// Enabled by default; requires at least 2 distinct offsets per base.
    pub recover_struct_fields: bool,
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
            recover_struct_fields: true,
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

    #[error("Decompiler limit exceeded for {resource}: {actual} > {limit}")]
    LimitExceeded {
        resource: &'static str,
        actual: usize,
        limit: usize,
    },
}

/// Decompile a single IR function to C pseudocode
pub fn decompile_function(func: &IrFunction) -> Result<String, DecompileError> {
    decompile_function_with_config(func, &DecompilerConfig::default())
}

/// Decompile a single IR function, rendering address constants that point at
/// known image strings as C string literals (`f(0x14001000)` → `f("...")`).
///
/// The caller (scanner) owns the image layout and builds the table; this
/// entry point is the image-aware variant of [`decompile_function`].
pub fn decompile_function_with_strings(
    func: &IrFunction,
    strings: &crate::strings::StringTable,
) -> Result<String, DecompileError> {
    decompile_function_inner(
        func,
        &DecompilerConfig::default(),
        &crate::call_naming::SignatureMap::default(),
        &crate::call_naming::AddrNameMap::default(),
        Some(strings),
        None,
    )
}

/// Decompile a function through an explicit SSA round-trip.
///
/// When `use_ssa` is enabled (now default with stack-aware fallback), the
/// function is converted `to_ssa -> remove_trivial_phis -> from_ssa` before
/// structuring. Stack-heavy functions where `rsp` would be lost (SSA lowers
/// `Register("rsp")` to fresh `Var`s) are detected and SSA is skipped for
/// that function so `recover_stack_vars` keeps working.
pub fn decompile_function_ssa(func: &IrFunction) -> Result<String, DecompileError> {
    let cfg = DecompilerConfig {
        use_ssa: true,
        ..Default::default()
    };
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
        None,
        None,
    )
}

fn decompile_function_inner(
    func: &IrFunction,
    config: &DecompilerConfig,
    signatures: &crate::call_naming::SignatureMap,
    addr_names: &crate::call_naming::AddrNameMap,
    strings: Option<&crate::strings::StringTable>,
    callees: Option<&crate::types::CalleeTypes>,
) -> Result<String, DecompileError> {
    validate_function_size(func)?;

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
                i.sources()
                    .iter()
                    .any(|v| matches!(v, freakre_ir::Value::Register { name, .. } if name == "rsp"))
                    || i.dst().is_some_and(
                        |d| matches!(d, freakre_ir::Value::Register { name, .. } if name == "rsp"),
                    )
            })
        });
        let mut ssa_candidate = ir.clone();
        if let Ok(mut ssa) = freakre_ir::ssa::to_ssa(&mut ssa_candidate) {
            freakre_ir::ssa::remove_trivial_phis(&mut ssa);
            // SCCP: constant propagation over the SSA lattice. Kills dead
            // branches (constant flag compares), folds conditional branches
            // and collapses single-value phis before structuring.
            let _sccp_stats = freakre_ir::sccp::sccp(&mut ssa);
            // Second trivial-phi sweep: SCCP can make additional phis
            // trivial (identical / single surviving input), and the fold
            // now also covers single-input phis.
            freakre_ir::ssa::remove_trivial_phis(&mut ssa);
            // GVN: eliminate dominated pure recomputations (CSE with
            // commutative unification) before they materialize as
            // duplicated expressions in the AST.
            let _gvn_stats = freakre_ir::ssa::ssa_gvn(&mut ssa);
            // GVN can unify phi inputs, creating new trivial phis.
            freakre_ir::ssa::remove_trivial_phis(&mut ssa);
            // SSA-DCE: drop pure definitions left dead by SCCP folding,
            // before they materialize as copies/expressions in lowered IR.
            let _dce_stats = freakre_ir::ssa::ssa_dce(&mut ssa);
            // from_ssa can only fail on malformed SSA (never on to_ssa output);
            // on failure keep the pre-SSA IR exactly like the to_ssa-error path.
            if let Ok(lowered) = freakre_ir::ssa::from_ssa(&ssa) {
                let lowered_has_rsp = lowered.blocks.iter().any(|b| {
                    b.insts.iter().any(|i| {
                        i.sources().iter().any(
                            |v| matches!(v, freakre_ir::Value::Register { name, .. } if name == "rsp"),
                        ) || i.dst().is_some_and(
                            |d| matches!(d, freakre_ir::Value::Register { name, .. } if name == "rsp"),
                        )
                    })
                });
                if !(has_stack_access && !lowered_has_rsp) {
                    ir = lowered;
                    crate::fold_flags::eliminate_dead_flag_defs(&mut ir);
                }
                // else: SSA would hide `rsp`; keep original `ir` for stack recovery.
            }
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
    crate::types::reconstruct_types_with_callees(&mut ast, callees);
    crate::simplify::ensure_declared_temps(&mut ast);

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

    crate::call_naming::apply_call_naming_with(
        &mut ast,
        signatures,
        addr_names,
        Some(ir.entry_address),
    );

    // Phase 5.6: string-literal annotation — image addresses that point at
    // known strings become C literals. Runs after call naming so signature
    // matching still sees the original integer arguments.
    if let Some(table) = strings {
        crate::strings::annotate_function(&mut ast, table);
    }

    // Phase 5.7: struct-field recovery — repeated `*(T*)(base + off)` shapes
    // become `base->field_0xNN` once the same (base, offset, width) is seen
    // at least twice (threshold keeps one-off casts untouched).
    if config.recover_struct_fields {
        crate::struct_fields::recover_struct_fields(&mut ast, 2);
    }

    // Phase 6: Convert AST to C pseudocode
    let c_code = ast_to_c_with_config(&ast, config);

    if c_code.len() > MAX_PSEUDOCODE_BYTES {
        return Err(DecompileError::LimitExceeded {
            resource: "pseudocode bytes",
            actual: c_code.len(),
            limit: MAX_PSEUDOCODE_BYTES,
        });
    }

    Ok(c_code)
}

fn validate_function_size(func: &IrFunction) -> Result<(), DecompileError> {
    if func.blocks.len() > MAX_FUNCTION_BLOCKS {
        return Err(DecompileError::LimitExceeded {
            resource: "function blocks",
            actual: func.blocks.len(),
            limit: MAX_FUNCTION_BLOCKS,
        });
    }

    let instruction_count = func
        .blocks
        .iter()
        .try_fold(0usize, |count, block| count.checked_add(block.insts.len()))
        .unwrap_or(usize::MAX);
    if instruction_count > MAX_FUNCTION_INSTRUCTIONS {
        return Err(DecompileError::LimitExceeded {
            resource: "function instructions",
            actual: instruction_count,
            limit: MAX_FUNCTION_INSTRUCTIONS,
        });
    }

    Ok(())
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
    let signatures = crate::call_naming::SignatureMap::from_common_runtime();
    let callees = analysis
        .as_ref()
        .map(crate::types::callee_types_from_program);

    let mut results = Vec::new();
    for func in &program.functions {
        // Enrich metadata from interproc analysis if available
        let mut enriched = func.clone();
        if let Some(ref an) = analysis {
            if let Some(summary) = an.get_summary(&func.name) {
                if enriched.metadata.calling_convention.is_none() {
                    enriched.metadata.calling_convention =
                        Some(summary.calling_convention.to_string());
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
        let c_code = decompile_function_inner(
            &enriched,
            config,
            &signatures,
            &addr_names,
            None,
            callees.as_ref(),
        )?;
        results.push((func.name.clone(), c_code));
    }
    Ok(results)
}

/// Best-effort decompile up to `count` exported functions in an IR program.
///
/// At most [`MAX_DECOMPILED_EXPORTS`] export entries are inspected. Exports
/// are processed in address order. Missing functions and individual
/// decompilation failures are skipped without consuming the successful-result
/// quota, so a missing entry does not hide a later valid export.
pub fn decompile_exports(
    program: &IrProgram,
    count: usize,
) -> Vec<(String, String)> {
    decompile_exports_with_diagnostics(program, count, &DecompilerConfig::default())
        .0
}

/// Best-effort decompile up to `count` exported functions with custom config.
pub fn decompile_exports_with_config(
    program: &IrProgram,
    count: usize,
    config: &DecompilerConfig,
) -> Vec<(String, String)> {
    decompile_exports_with_diagnostics(program, count, config).0
}

/// Why an export was not decompiled (best-effort path).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DecompileDiagnosticKind {
    /// No function is registered at the export address.
    FunctionMissing,
    /// The function exists but decompilation failed (limits, IR/AST errors).
    DecompileFailed,
}

/// A skipped export, reported by `decompile_exports_with_diagnostics`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DecompileDiagnostic {
    pub export_name: String,
    pub address: u64,
    pub kind: DecompileDiagnosticKind,
    /// Human-readable detail (the underlying error, when present).
    pub detail: String,
}

/// Best-effort decompile that also reports every skipped export.
///
/// Returns `(decompiled, diagnostics)`; the decompiled list is identical to
/// [`decompile_exports_with_config`].
pub fn decompile_exports_with_diagnostics(
    program: &IrProgram,
    count: usize,
    config: &DecompilerConfig,
) -> (Vec<(String, String)>, Vec<DecompileDiagnostic>) {
    let mut diagnostics = Vec::new();
    if count == 0 {
        return (Vec::new(), diagnostics);
    }

    let result_count = count.min(MAX_DECOMPILED_EXPORTS);
    let addr_names = if config.auto_call_names {
        crate::call_naming::addr_names_from_program(program)
    } else {
        crate::call_naming::AddrNameMap::default()
    };
    let signatures = crate::call_naming::SignatureMap::from_common_runtime();
    let callees = if config.auto_interproc {
        Some(crate::types::callee_types_from_program(
            &crate::interproc::analyze_program(program),
        ))
    } else {
        None
    };

    let mut exports: Vec<_> = program.exports.iter().collect();
    exports.sort_by_key(|(address, _)| **address);

    let mut results = Vec::new();
    for (address, export_name) in exports.into_iter().take(MAX_DECOMPILED_EXPORTS) {
        if results.len() >= result_count {
            break;
        }
        let Some(func) = program.function_at(*address) else {
            diagnostics.push(DecompileDiagnostic {
                export_name: export_name.clone(),
                address: *address,
                kind: DecompileDiagnosticKind::FunctionMissing,
                detail: "no function registered at export address".to_string(),
            });
            continue;
        };
        let mut enriched = func.clone();
        if config.auto_interproc {
            let summary = crate::interproc::analyze_function(func);
            if enriched.metadata.calling_convention.is_none() {
                enriched.metadata.calling_convention =
                    Some(summary.calling_convention.to_string());
            }
            if enriched.metadata.return_type.is_none() {
                if let Some(ref return_type) = summary.return_type {
                    if *return_type != freakre_ir::Ty::Unknown {
                        enriched.metadata.return_type = Some(return_type.clone());
                    }
                }
            }
        }
        match decompile_function_inner(
            &enriched,
            config,
            &signatures,
            &addr_names,
            None,
            callees.as_ref(),
        ) {
            Ok(code) => results.push((export_name.clone(), code)),
            Err(e) => diagnostics.push(DecompileDiagnostic {
                export_name: export_name.clone(),
                address: *address,
                kind: DecompileDiagnosticKind::DecompileFailed,
                detail: e.to_string(),
            }),
        }
    }
    (results, diagnostics)
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
pub fn decompile_function_at(program: &IrProgram, address: u64) -> Result<String, DecompileError> {
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
    pub fn decompile_all(
        &self,
        program: &IrProgram,
    ) -> Result<Vec<(String, String)>, DecompileError> {
        decompile_program_with_config(program, &self.config)
    }

    /// Best-effort decompile up to `count` exported functions.
    pub fn decompile_exports(&self, program: &IrProgram, count: usize) -> Vec<(String, String)> {
        decompile_exports_with_config(program, count, &self.config)
    }

    /// Decompile a function by name
    pub fn decompile_by_name(
        &self,
        program: &IrProgram,
        name: &str,
    ) -> Result<String, DecompileError> {
        let func = program
            .function_by_name(name)
            .ok_or_else(|| DecompileError::FunctionNotFound(name.to_string()))?;

        decompile_function_with_config(func, &self.config)
    }

    /// Decompile a function by address
    pub fn decompile_at(
        &self,
        program: &IrProgram,
        address: u64,
    ) -> Result<String, DecompileError> {
        let func = program
            .function_at(address)
            .ok_or_else(|| DecompileError::FunctionNotFound(format!("0x{:X}", address)))?;

        decompile_function_with_config(func, &self.config)
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

        func.push_inst(
            func.entry_block,
            IrInst::Binary {
                dst: v2.clone(),
                op: OpCode::Add,
                lhs: v0.clone(),
                rhs: v1.clone(),
            },
        );
        func.push_inst(
            func.entry_block,
            IrInst::Return {
                value: Some(v2.clone()),
            },
        );

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
    fn test_decompile_exports_is_limited_and_best_effort() {
        let mut program = IrProgram::new();
        let mut first = IrFunction::new("first", 0x2000);
        first.push_inst(first.entry_block, IrInst::Return { value: None });
        let mut second = IrFunction::new("second", 0x1000);
        second.push_inst(second.entry_block, IrInst::Return { value: None });
        program.add_function(first);
        program.add_function(second);
        program.exports.insert(0x2000, "ExportFirst".to_string());
        program.exports.insert(0x1000, "ExportSecond".to_string());
        program.exports.insert(0x3000, "Missing".to_string());

        let result = decompile_exports(&program, 1);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "ExportSecond");
    }

    #[test]
    fn test_decompile_exports_preserves_custom_config() {
        let mut program = IrProgram::new();
        let mut func = IrFunction::new("configured_export", 0x1000);
        func.push_inst(func.entry_block, IrInst::Return { value: None });
        program.add_function(func);
        program.exports.insert(0x1000, "Configured".to_string());
        let config = DecompilerConfig {
            simplify_expressions: false,
            ..Default::default()
        };

        let result = decompile_exports_with_config(&program, 1, &config);

        assert_eq!(result.len(), 1);
        assert!(result[0].1.contains("configured_export"));
    }

    #[test]
    fn test_decompile_exports_skips_missing_entries_without_consuming_quota() {
        let mut program = IrProgram::new();
        let mut func = IrFunction::new("later", 0x2000);
        func.push_inst(func.entry_block, IrInst::Return { value: None });
        program.add_function(func);
        program.exports.insert(0x1000, "Missing".to_string());
        program.exports.insert(0x2000, "Later".to_string());

        let result = decompile_exports(&program, 1);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "Later");
    }

    #[test]
    fn test_decompile_rejects_oversized_cfg_before_cloning() {
        let mut func = IrFunction::new("oversized", 0x1000);
        for i in 0..MAX_FUNCTION_BLOCKS {
            func.add_block(&format!("block_{i}"));
        }

        assert!(matches!(
            decompile_function(&func),
            Err(DecompileError::LimitExceeded {
                resource: "function blocks",
                ..
            })
        ));
    }

    #[test]
    fn test_decompiler_api() {
        let mut func = IrFunction::new("test", 0x1000);
        func.push_inst(func.entry_block, IrInst::Return { value: None });

        let decompiler = Decompiler::new();
        let result = decompiler.decompile(&func);

        assert!(result.is_ok());
    }

    fn config_sensitive_program() -> IrProgram {
        let mut program = IrProgram::new();
        let mut func = IrFunction::new("config_sensitive", 0x1000);
        func.push_inst(func.entry_block, IrInst::Return { value: None });
        program.add_function(func);
        program
    }

    #[test]
    fn test_decompile_exports_diagnostics_report_skips() {
        let mut program = IrProgram::new();
        let mut func = IrFunction::new("later", 0x2000);
        func.push_inst(func.entry_block, IrInst::Return { value: None });
        program.add_function(func);
        program.exports.insert(0x1000, "Missing".to_string());
        program.exports.insert(0x2000, "Later".to_string());

        let (results, diagnostics) = decompile_exports_with_diagnostics(
            &program,
            1,
            &DecompilerConfig::default(),
        );
        // Same successful result as the plain API...
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "Later");
        // ...plus a diagnostic explaining the skipped export.
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].export_name, "Missing");
        assert_eq!(diagnostics[0].address, 0x1000);
        assert_eq!(diagnostics[0].kind, DecompileDiagnosticKind::FunctionMissing);
        assert!(!diagnostics[0].detail.is_empty());

        // Zero count short-circuits with no diagnostics.
        let (results, diagnostics) =
            decompile_exports_with_diagnostics(&program, 0, &DecompilerConfig::default());
        assert!(results.is_empty());
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn test_decompile_by_name_uses_instance_config() {
        let program = config_sensitive_program();
        let config = DecompilerConfig {
            annotate_addresses: true,
            ..Default::default()
        };
        let result = Decompiler::with_config(config)
            .decompile_by_name(&program, "config_sensitive")
            .unwrap();

        assert!(result.contains("config_sensitive"));
    }

    #[test]
    fn test_decompile_at_uses_instance_config() {
        let program = config_sensitive_program();
        let config = DecompilerConfig {
            annotate_addresses: true,
            ..Default::default()
        };
        let result = Decompiler::with_config(config)
            .decompile_at(&program, 0x1000)
            .unwrap();

        assert!(result.contains("config_sensitive"));
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

        func.push_inst(
            func.entry_block,
            IrInst::CBranch {
                cond,
                target_true: then_b,
                target_false: else_b,
            },
        );
        func.push_inst(
            then_b,
            IrInst::Unary {
                dst: x.clone(),
                op: OpCode::Copy,
                src: Value::int(1),
            },
        );
        func.push_inst(then_b, IrInst::Branch { target: merge });
        func.push_inst(
            else_b,
            IrInst::Unary {
                dst: x.clone(),
                op: OpCode::Copy,
                src: Value::int(2),
            },
        );
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
