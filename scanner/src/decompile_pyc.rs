//! Python bytecode decompilation API.

use pyc_parser::{PycReport, analyze_python};

/// Result type for Python bytecode decompilation.
pub struct DecompiledPyC {
    /// High-level analysis of the bytecode.
    pub report: PycReport,
    /// Decomiled pseudocode.
    pub pseudocode: String,
    /// Extracted strings.
    pub strings: Vec<String>,
}

/// Decompile a Python bytecode file.
pub fn decompile_pyc(data: &[u8]) -> Result<DecompiledPyC, String> {
    let report = analyze_python(data).ok_or("not a valid .pyc file")?;
    
    // For now, just return the analysis without full decompilation
    // A full decompiler would need to parse and reconstruct control flow
    let strings = report.suspicious_strings.clone();
    let pseudocode = String::new(); // Placeholder

    Ok(DecompiledPyC {
        report,
        pseudocode,
        strings,
    })
}

