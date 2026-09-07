//! Public decompilation API for the server (`/api/decompile`).
//!
//! Lifts and decompiles a real function from a PE image in memory. This is
//! the same pipeline the scanner's experimental decompiler finding uses
//! (func-finder boundaries → x86 lifter → decompiler), exposed as a
//! standalone entry point so the HTTP server does not need to re-implement
//! or dump findings.

use crate::report::Finding;
use crate::Severity;

/// One decompiled function, ready for JSON serialization.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DecompiledFunction {
    /// Virtual address the function was found at.
    pub address: u64,
    /// Synthetic name (`sub_<hex address>`).
    pub name: String,
    /// Function size in bytes, as detected by func-finder.
    pub size: u64,
    /// C pseudocode.
    pub c_code: String,
}

/// Decompile the function containing `address` from a PE image.
///
/// With `None`, the largest detected function in `.text` is used (the same
/// heuristic as the scanner finding). Returns `Err` with a human-readable
/// reason for every failure mode: not a PE, no executable section, no
/// function detected, lift or decompile errors.
pub fn decompile_pe_function(data: &[u8], address: Option<u64>) -> Result<DecompiledFunction, String> {
    let pe = pe_parser::PeFile::parse(data)
        .map_err(|e| format!("not a parseable PE image: {e}"))?;

    let text_section = pe.sections.iter().find(|s| {
        let name = s.name_string();
        name == ".text" || name == "CODE"
    });
    let Some(sec) = text_section else {
        return Err("no .text/CODE section found".to_string());
    };
    let code_region = sec.raw_data(data);
    if code_region.is_empty() {
        return Err(".text section has no raw data".to_string());
    }

    use func_finder::{Architecture, FunctionFinder};
    use freakre_ir::x86_lifter::X86Lifter;
    use freakre_ir::Lifter;

    let arch = if pe.is_64bit {
        Architecture::X86_64
    } else {
        Architecture::X86
    };
    let finder = FunctionFinder::new(arch).with_code_base(sec.virtual_address as u64);
    let entry_va = pe.image_base + pe.entry_point as u64;
    let detected = finder
        .find_all(code_region, &[entry_va])
        .map_err(|e| format!("function detection failed: {e}"))?;
    if detected.is_empty() {
        return Err("no functions detected in .text".to_string());
    }

    // Prefer the function containing the requested address; fall back to the
    // largest detected function.
    let chosen = address.and_then(|a| {
        detected
            .iter()
            .find(|f| f.start <= a && a < f.start + f.size as u64)
            .or_else(|| detected.iter().filter(|f| f.start <= a).max_by_key(|f| f.start))
    });
    let func = chosen.unwrap_or_else(|| {
        detected
            .iter()
            .max_by_key(|f| f.size)
            .or_else(|| detected.first())
            .expect("detected is non-empty")
    });

    let func_slice = crate::scanner::carve_func_slice(
        code_region,
        sec.virtual_address as u64,
        func.start,
        func.size,
    )
    .ok_or_else(|| "detected function lies outside .text bounds".to_string())?;

    let lifter = X86Lifter::new(pe.is_64bit);
    let func_name = format!("sub_{:X}", func.start);
    let ir_func = lifter
        .lift_function(func_slice, func.start, &func_name)
        .map_err(|e| format!("IR lift failed: {e}"))?;

    let c_code = decompiler::decompile_function(&ir_func)
        .map_err(|e| format!("decompilation failed: {e}"))?;

    Ok(DecompiledFunction {
        address: func.start,
        name: func_name,
        size: func.size as u64,
        c_code,
    })
}

/// Decompile and wrap failures as a `DECOMPILE_FAILED`-style finding list.
///
/// Convenience for callers that want the same finding shape as the scanner.
pub fn decompile_pe_function_findings(
    data: &[u8],
    address: Option<u64>,
) -> Vec<Finding> {
    match decompile_pe_function(data, address) {
        Ok(f) => vec![Finding {
            severity: Severity::Info,
            module: "decompiler".into(),
            rule_id: "DECOMPILED_CODE".into(),
            description: format!(
                "Decompiled function {} at 0x{:X} ({} bytes)",
                f.name, f.address, f.size
            ),
            details: Some(f.c_code.lines().take(20).collect::<Vec<_>>().join("\n")),
        }],
        Err(e) => vec![Finding {
            severity: Severity::Low,
            module: "decompiler".into(),
            rule_id: "DECOMPILE_FAILED".into(),
            description: e,
            details: None,
        }],
    }
}
