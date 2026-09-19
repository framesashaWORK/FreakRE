//! # PYC Parser
//!
//! Reads Python bytecode files (`.pyc` / `.pyo`) and detects PyInstaller
//! bundles. The goal is not a full bytecode disassembler (which is huge
//! per-version) but to surface the metadata that matters for malware
//! triage:
//!
//! * magic number → Python version
//! * embedded source file path (often leaks the malware family name)
//! * PyInstaller `MEI` / `MAGIC` / `MEIPASS` markers → bundled EXE
//! * archive entries (top of `struct` table) → internal modules
//! * import-table scan: high-risk modules (`os`, `subprocess`, `socket`,
//!   `ctypes`, `requests`, `base64`, `marshal`, ...)
//! * hardcoded strings, URLs, IPs
//! * bytecode disassembly (simple pseudocode reconstruction)
//!
//! For PyInstaller we recognize the `MAGIC` archive header and walk the
//! archive to list entries without unpacking executables.

use serde::{Deserialize, Serialize};

/// Python bytecode opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Opcode {
    // ─── Stack operations ─────────────────────────────────────────
    StopCode,
    PopTop,
    RotTwo,
    RotThree,
    DupTop,
    DupTopTwo,
    // ─── Imports ─────────────────────────────────────────────────
    ImportName,
    ImportFrom,
    ImportAll,
    // ─── Exceptions ──────────────────────────────────────────────
    PopExcept,
    PopBlock,
    // ─── Unpacking ───────────────────────────────────────────────
    UnpackSequence,
    UnpackEx,
    // ─── Comparisons ─────────────────────────────────────────────
    CompareOp,
    // ─── Jumps ───────────────────────────────────────────────────
    JumpIfTrueOrPop,
    JumpIfFalseOrPop,
    JumpForward,
    // ─── Names ───────────────────────────────────────────────────
    LoadName,
    StoreName,
    DeleteName,
    // ─── Attribute access ────────────────────────────────────────
    LoadAttr,
    StoreAttr,
    DeleteAttr,
    // ─── Stack ───────────────────────────────────────────────────
    LoadConst,
    // ─── Subscripts ──────────────────────────────────────────────
    LoadMap,
    StoreSubst,
    // ─── Call ────────────────────────────────────────────────────
    CallFunction,
    // ─── Control flow ────────────────────────────────────────────
    ForIter,
    IterNext,
    // ─── Special ─────────────────────────────────────────────────
    MakeFunction,
    CallFunctionEx,
    // ─── Binary operations ───────────────────────────────────────
    BinarySubtract,
    BinaryAdd,
    BinaryMultiply,
    BinaryModulo,
    BinaryAnd,
    BinaryOr,
    BinaryXor,
    BinaryFloorDivide,
    // ─── Augmented assignment ────────────────────────────────────
    InplaceAdd,
    InplaceSubtract,
    InplaceMultiply,
    InplaceModulo,
    InplacePower,
    InplaceAnd,
    InplaceOr,
    InplaceXor,
    InplaceFloorDivide,
}

impl Opcode {
    fn from_u8(code: u8, version: PythonVersion) -> Option<Opcode> {
        // Python 3.11+ has different opcode layout; we only support 3.6-3.10 for now.
        if matches!(version, PythonVersion::Py3_0 | PythonVersion::Py3_1) {
            return None;
        }

        let code = code as usize;
        // ─── Imports ─────────────────────────────────────────────────
        if code >= 0x5C && code <= 0x5E {
            return match code {
                0x5C => Some(Opcode::ImportName),
                0x5D => Some(Opcode::ImportFrom),
                0x5E => Some(Opcode::ImportAll),
                _ => unreachable!(),
            };
        }

        // ─── Comparisons ─────────────────────────────────────────────
        if code == 0x57 {
            return Some(Opcode::CompareOp);
        }

        // ─── Jumps ───────────────────────────────────────────────────
        if (code == 0x53)
            || (code == 0x68)
            || (code == 0x69)
            || (code == 0x72)
        {
            return match code {
                0x53 => Some(Opcode::JumpIfTrueOrPop),
                0x68 => Some(Opcode::JumpIfFalseOrPop),
                0x69 => Some(Opcode::JumpForward),
                0x72 => Some(Opcode::JumpForward), // JUMP_FORWARD
                _ => unreachable!(),
            };
        }

        // ─── Names ───────────────────────────────────────────────────
        if (code == 0x54)
            || (code == 0x55)
            || (code == 0x56)
        {
            return match code {
                0x54 => Some(Opcode::LoadName),
                0x55 => Some(Opcode::StoreName),
                0x56 => Some(Opcode::DeleteName),
                _ => unreachable!(),
            };
        }

        // ─── Attribute access ────────────────────────────────────────
        if (code == 0x1F)
            || (code == 0x63)
            || (code == 0x64)
        {
            return match code {
                0x1F => Some(Opcode::LoadAttr),
                0x63 => Some(Opcode::StoreAttr),
                0x64 => Some(Opcode::DeleteAttr),
                _ => unreachable!(),
            };
        }

        // ─── Stack ───────────────────────────────────────────────────
        if code == 0x64 {
            return Some(Opcode::LoadConst);
        }

        // ─── Call ────────────────────────────────────────────────────
        if code == 0x8D {
            return Some(Opcode::CallFunction);
        }

        // ─── Special ─────────────────────────────────────────────────
        if code == 0x6D {
            return Some(Opcode::MakeFunction);
        }

        // ─── Binary operations ───────────────────────────────────────
        if (code == 0x13)
            || (code == 0x14)
            || (code == 0x15)
            || (code == 0x16)
            || (code == 0x17)
            || (code == 0x18)
            || (code == 0x19)
            || (code == 0x1A)
        {
            return match code {
                0x13 => Some(Opcode::BinarySubtract),
                0x14 => Some(Opcode::BinaryAdd),
                0x15 => Some(Opcode::BinaryMultiply),
                0x16 => Some(Opcode::BinaryModulo),
                0x17 => Some(Opcode::BinaryAnd),
                0x18 => Some(Opcode::BinaryOr),
                0x19 => Some(Opcode::BinaryXor),
                0x1A => Some(Opcode::BinaryFloorDivide),
                _ => unreachable!(),
            };
        }

        // ─── Augmented assignment ────────────────────────────────────
        if (code >= 0x55 && code <= 0x5A)
            || (code == 0x1B)
            || (code == 0x1C)
        {
            return match code {
                0x55 => Some(Opcode::InplaceAdd),
                0x56 => Some(Opcode::InplaceSubtract),
                0x57 => Some(Opcode::InplaceMultiply),
                0x58 => Some(Opcode::InplaceModulo),
                0x59 => Some(Opcode::InplacePower),
                0x5A => Some(Opcode::InplaceFloorDivide),
                0x1B => Some(Opcode::InplaceAnd),
                0x1C => Some(Opcode::InplaceOr),
                _ => None,
            };
        }

        // ─── Control flow ────────────────────────────────────────────
        if code == 0x61 || code == 0x16 {
            return Some(Opcode::ForIter);
        }

        // ─── Unpacking ───────────────────────────────────────────────
        if code == 0x58 {
            return Some(Opcode::UnpackSequence);
        }

        // ─── Stack ───────────────────────────────────────────────────
        match code {
            0x01 => Some(Opcode::PopTop),
            0x02 => Some(Opcode::RotTwo),
            0x03 => Some(Opcode::RotThree),
            0x50 => Some(Opcode::PopTop),
            _ => None,
        }
    }

    fn to_c(&self) -> &'static str {
        match self {
            Opcode::StopCode => "STOP_CODE",
            Opcode::PopTop => "POP_TOP",
            Opcode::RotTwo => "ROT_TWO",
            Opcode::RotThree => "ROT_THREE",
            Opcode::ImportName => "IMPORT_NAME",
            Opcode::ImportFrom => "IMPORT_FROM",
            Opcode::CompareOp => "COMPARE_OP",
            Opcode::JumpForward => "JUMP_FORWARD",
            Opcode::LoadName => "LOAD_NAME",
            Opcode::StoreName => "STORE_NAME",
            Opcode::DeleteName => "DELETE_NAME",
            Opcode::LoadAttr => "LOAD_ATTR",
            Opcode::StoreAttr => "STORE_ATTR",
            Opcode::DeleteAttr => "DELETE_ATTR",
            Opcode::LoadConst => "LOAD_CONST",
            Opcode::CallFunction => "CALL_FUNCTION",
            Opcode::MakeFunction => "MAKE_FUNCTION",
            Opcode::BinaryAdd => "BINARY_ADD",
            Opcode::BinarySubtract => "BINARY_SUBTRACT",
            Opcode::BinaryMultiply => "BINARY_MULTIPLY",
            Opcode::BinaryModulo => "BINARY_MODULO",
            Opcode::BinaryAnd => "BINARY_AND",
            Opcode::BinaryOr => "BINARY_OR",
            Opcode::BinaryXor => "BINARY_XOR",
            Opcode::InplaceAdd => "INPLACE_ADD",
            Opcode::InplaceSubtract => "INPLACE_SUBTRACT",
            Opcode::InplaceMultiply => "INPLACE_MULTIPLY",
            Opcode::ForIter => "FOR_ITER",
            Opcode::UnpackSequence => "UNPACK_SEQUENCE",
            _ => "OP",
        }
    }
}

/// One bytecode instruction.
#[derive(Debug, Clone)]
pub struct Instruction {
    pub offset: usize,
    pub opcode: Opcode,
    pub arg: Option<u32>,
    pub arg_repr: Option<String>,
}

/// Disassembled code object.
#[derive(Debug, Clone)]
pub struct CodeObject {
    pub arg_count: u32,
    pub constants: Vec<String>,
    pub names: Vec<String>,
    pub instructions: Vec<Instruction>,
    pub source_path: Option<String>,
    pub co_code: Vec<u8>,
}

/// Python version inferred from the magic number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PythonVersion {
    Py2,
    Py3_0,
    Py3_1,
    Py3_2,
    Py3_3,
    Py3_4,
    Py3_5,
    Py3_6,
    Py3_7,
    Py3_8,
    Py3_9,
    Py3_10,
    Py3_11,
    Py3_12,
    Py3_13,
    Unknown(u32),
}

impl std::fmt::Display for PythonVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Py2 => write!(f, "Python 2.x"),
            Self::Py3_0 => write!(f, "Python 3.0"),
            Self::Py3_1 => write!(f, "Python 3.1"),
            Self::Py3_2 => write!(f, "Python 3.2"),
            Self::Py3_3 => write!(f, "Python 3.3"),
            Self::Py3_4 => write!(f, "Python 3.4"),
            Self::Py3_5 => write!(f, "Python 3.5"),
            Self::Py3_6 => write!(f, "Python 3.6"),
            Self::Py3_7 => write!(f, "Python 3.7"),
            Self::Py3_8 => write!(f, "Python 3.8"),
            Self::Py3_9 => write!(f, "Python 3.9"),
            Self::Py3_10 => write!(f, "Python 3.10"),
            Self::Py3_11 => write!(f, "Python 3.11"),
            Self::Py3_12 => write!(f, "Python 3.12"),
            Self::Py3_13 => write!(f, "Python 3.13"),
            Self::Unknown(m) => write!(f, "Unknown (0x{:08X})", m),
        }
    }
}

/// One entry inside a PyInstaller `MAGIC` archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveEntry {
    pub name: String,
    pub size: usize,
}

/// Outcome of analyzing a Python file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PycReport {
    pub kind: PycKind,
    pub python_version: Option<PythonVersion>,
    /// Embedded source path (UTF-8 string from .pyc header).
    pub source_path: Option<String>,
    /// True if this is a PyInstaller bundle (instead of plain .pyc).
    pub is_pyinstaller: bool,
    /// Size of the marshalled code object (best-effort).
    pub code_size: Option<usize>,
    /// Strings found in the body that look like imports.
    pub imports: Vec<String>,
    /// High-risk modules observed.
    pub high_risk_imports: Vec<String>,
    /// URLs / IPs from the string table.
    pub urls: Vec<String>,
    /// Sample of suspicious strings.
    pub suspicious_strings: Vec<String>,
    /// Number of archive entries (PyInstaller).
    pub archive_entry_count: usize,
    /// First 32 archive entries.
    pub archive_entries: Vec<ArchiveEntry>,
    /// Severity-tagged findings.
    pub findings: Vec<PycFinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PycKind {
    Bytecode,
    PyInstaller,
    OptimizedBytecode,
    /// Looks like a Python source script (text); included for completeness.
    Script,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PycFinding {
    pub severity: PycSeverity,
    pub rule_id: String,
    pub description: String,
    pub offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PycSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Top-level entry point. Returns `Some` for both `.pyc` and PyInstaller
/// bundles; `None` for anything else.
pub fn analyze_python(data: &[u8]) -> Option<PycReport> {
    if data.len() < 16 {
        return None;
    }

    // PyInstaller bundle: starts with "MEI\x0C\x0B\x0A\x0B\x0E" (MAGIC).
    // NOTE: no octal-duplicate check here on purpose — Rust has no octal
    // escapes, so `b"MEI\014..."` would mean NUL+"14" and never match.
    if data.starts_with(b"MEI\x0C\x0B\x0A\x0B\x0E") {
        return Some(analyze_pyinstaller(data));
    }
    // Python source — only treat as such when nothing else matched.
    if std::str::from_utf8(data).is_ok()
        && (data.starts_with(b"#!/")
            || data.starts_with(b"# -*-")
            || data.starts_with(b"import ")
            || data.starts_with(b"from "))
    {
        return Some(analyze_script(data));
    }

    // .pyc header: 4 bytes magic + 4 bytes (timestamp|hash) + (optional size) + code
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let python_version = python_version_from_magic(magic);
    if !is_pyc_magic(magic) {
        return None;
    }

    // Determine code offset based on Python version.
    // PEP 552 (Python 3.7+) added hash-based validation.
    let code_offset = match python_version {
        Some(PythonVersion::Py2)
        | Some(PythonVersion::Py3_0)
        | Some(PythonVersion::Py3_1)
        | Some(PythonVersion::Py3_2)
        | Some(PythonVersion::Py3_3)
        | Some(PythonVersion::Py3_4)
        | Some(PythonVersion::Py3_5)
        | Some(PythonVersion::Py3_6) => 8,
        _ => 16, // 3.7+ uses 8-byte header: magic(4) + flags(4) + payload
    };
    if data.len() < code_offset {
        return None;
    }

    // Try to read embedded source path (after header in 3.2-)
    let source_path = read_source_path(&data[code_offset..]);
    let body = &data[code_offset..];

    // Try to extract code object from bytecode body and parse constants
    let (instructions, constants) = {
        let (insts, consts) = parse_code_object(body);
        if insts.is_empty() {
            // Fallback to simple disassembly
            (
                if body.len() >= 2 {
                    disassemble(body, python_version)
                } else {
                    vec![]
                },
                consts,
            )
        } else {
            (insts, consts)
        }
    };

    // Scan for printable ASCII strings in bytecode body
    let mut suspicious_strings = Vec::new();
    let mut i = 0;
    while i < body.len() {
        if body[i].is_ascii_graphic() {
            let start = i;
            while i < body.len() && (body[i].is_ascii_graphic() || body[i] == b' ') {
                i += 1;
            }
            let len = i - start;
            if len >= 4 {
                if let Ok(s) = std::str::from_utf8(&body[start..i]) {
                    // Filter out PyInstaller/cPython internal strings
                    if !s.starts_with("<")
                        && !s.contains("Py")
                        && !s.contains("Python")
                        && !s.contains("import")
                    {
                        suspicious_strings.push(s.to_string());
                    }
                }
            }
        } else {
            i += 1;
        }
    }

    Some(build_report(
        PycKind::Bytecode,
        Some(python_version.unwrap_or(PythonVersion::Unknown(magic))),
        source_path,
        false,
        Some(body.len()),
        body,
        &suspicious_strings,
    ))
}

fn analyze_script(data: &[u8]) -> PycReport {
    let text = String::from_utf8_lossy(data);
    let imports = collect_imports(&text);
    let high_risk = filter_high_risk(&imports);
    let urls = collect_urls(&text);
    let mut findings: Vec<PycFinding> = Vec::new();
    if !high_risk.is_empty() {
        findings.push(PycFinding {
            severity: PycSeverity::Medium,
            rule_id: "PY_HIGH_RISK_IMPORT".to_string(),
            description: format!("High-risk Python imports: {}", high_risk.join(", ")),
            offset: 0,
        });
    }
    if urls
        .iter()
        .any(|u| u.ends_with(".exe") || u.contains("download"))
    {
        findings.push(PycFinding {
            severity: PycSeverity::High,
            rule_id: "PY_DOWNLOAD_URL".to_string(),
            description: "Script references a downloadable executable".into(),
            offset: 0,
        });
    }
    PycReport {
        kind: PycKind::Script,
        python_version: None,
        source_path: None,
        is_pyinstaller: false,
        code_size: Some(data.len()),
        imports,
        high_risk_imports: high_risk,
        urls,
        suspicious_strings: Vec::new(),
        archive_entry_count: 0,
        archive_entries: Vec::new(),
        findings,
    }
}

fn analyze_pyinstaller(data: &[u8]) -> PycReport {
    let mut findings: Vec<PycFinding> = Vec::new();
    let mut entries: Vec<ArchiveEntry> = Vec::new();
    let mut imports: Vec<String> = Vec::new();
    let mut urls: Vec<String> = Vec::new();
    let mut suspicious_strings: Vec<String> = Vec::new();

    // PyInstaller archive cookie: "MAGIC" then metadata: python lib name length,
    // then 40 bytes of dependency stuff, then pkg length, then pkg name, then
    // a struct describing entries.
    if let Some(magic_pos) = find_in(data, b"MAGIC") {
        if let Some(arch) = parse_pyinstaller_archive(&data[magic_pos..]) {
            entries = arch.entries;
            imports = arch.imports;
            urls = arch.urls;
            suspicious_strings = arch.suspicious_strings;
        }
    }

    findings.push(PycFinding {
        severity: PycSeverity::Info,
        rule_id: "PY_PYINSTALLER".to_string(),
        description: "PyInstaller bundle detected".into(),
        offset: 0,
    });

    let high_risk = filter_high_risk(&imports);
    if !high_risk.is_empty() {
        findings.push(PycFinding {
            severity: PycSeverity::High,
            rule_id: "PY_HIGH_RISK_IMPORT".to_string(),
            description: format!(
                "High-risk imports in PyInstaller bundle: {}",
                high_risk.join(", ")
            ),
            offset: 0,
        });
    }
    // PyInstaller bundles a `Crypto`, `Cryptodome`, `pyaes`, `socket`, `requests`
    // strongly suggest stealers.
    if imports
        .iter()
        .any(|i| i == "Crypto" || i == "Cryptodome" || i == "pyaes")
    {
        findings.push(PycFinding {
            severity: PycSeverity::Medium,
            rule_id: "PY_CRYPTO".to_string(),
            description: "Crypto library bundled — often used for credential encryption".into(),
            offset: 0,
        });
    }

    PycReport {
        kind: PycKind::PyInstaller,
        python_version: None,
        source_path: None,
        is_pyinstaller: true,
        code_size: Some(data.len()),
        imports,
        high_risk_imports: high_risk,
        urls,
        suspicious_strings,
        archive_entry_count: entries.len(),
        archive_entries: entries.into_iter().take(32).collect(),
        findings,
    }
}

#[derive(Default)]
struct PyInstScratch {
    entries: Vec<ArchiveEntry>,
    imports: Vec<String>,
    urls: Vec<String>,
    suspicious_strings: Vec<String>,
}

fn parse_pyinstaller_archive(data: &[u8]) -> Option<PyInstScratch> {

    // Walk the archive's "struct" entries. Each entry begins with a
    // null-terminated name. We only need first-pass metadata.
    let mut out = PyInstScratch::default();
    let mut i = 0;
    while i < data.len() {
        // Look for printable ASCII runs of >=4 chars that end in null
        if data[i].is_ascii_graphic() || data[i] == b' ' {
            let start = i;
            while i < data.len() && data[i] != 0 {
                i += 1;
            }
            let len = i - start;
            if (4..256).contains(&len) {
                if let Ok(s) = std::str::from_utf8(&data[start..start + len]) {
                    if s.contains('/') && !s.contains("..") {
                        out.entries.push(ArchiveEntry {
                            name: s.to_string(),
                            size: 0,
                        });
                    } else if s.contains('.') && !s.contains(' ') {
                        // plausible module or filename
                        if looks_like_module(s) {
                            out.imports.push(s.to_string());
                        }
                        if s.starts_with("http://") || s.starts_with("https://") {
                            out.urls.push(s.to_string());
                        }
                        if s.contains("password")
                            || s.contains("exfil")
                            || s.contains("wallet")
                            || s.contains("miner")
                        {
                            out.suspicious_strings.push(s.to_string());
                        }
                    }
                }
            }
        }
        i += 1;
    }
    Some(out)
}

/// Simple bytecode disassembler (Python 3.6+).
fn disassemble(body: &[u8], version: Option<PythonVersion>) -> Vec<Instruction> {
    let mut insts = Vec::new();
    let mut i = 0;

    while i < body.len() {
        let opcode_byte = body[i];
        let op = Opcode::from_u8(opcode_byte, version.unwrap_or(PythonVersion::Py3_6));
        let arg = if i + 1 < body.len() && op.is_some() {
            // Arguments follow opcode
            Some(u32::from_le_bytes([body[i + 1], body.get(i + 2).copied().unwrap_or(0), 0, 0]))
        } else {
            None
        };

        if let Some(op) = op {
            insts.push(Instruction {
                offset: i,
                opcode: op,
                arg,
                arg_repr: None,
            });
            i += if arg.is_some() && i + 1 < body.len() { 3 } else { 1 };
        } else {
            i += 1;
        }
    }

    insts
}

/// Parse a Python code object from marshalled bytecode to extract constants.
/// Returns (instructions, constants) where constants are marshal-parsed string values.
pub fn parse_code_object(body: &[u8]) -> (Vec<Instruction>, Vec<String>) {
    let mut constants = Vec::new();

    // Scan for marshal string constants: 'c' (STRING type) + 4-byte len + data
    for i in 0..body.len().saturating_sub(5) {
        if body[i] == b'c' {
            let len = u32::from_le_bytes([
                body[i + 1],
                body[i + 2],
                body[i + 3],
                body[i + 4],
            ]) as usize;
            if i + 5 + len <= body.len() && len >= 3 && len < 4096 {
                if let Ok(s) = std::str::from_utf8(&body[i + 5..i + 5 + len]) {
                    if !s.is_empty()
                        && s.chars().all(|c| c.is_ascii_alphanumeric() || c.is_ascii_punctuation() || c.is_ascii_whitespace())
                        && !s.contains("Py")
                        && !s.contains("Python")
                        && !s.contains("<")
                        && !s.contains(")")
                    {
                        constants.push(s.to_string());
                    }
                }
            }
        }
    }

    let instructions = disassemble(body, None);

    (instructions, constants)
}

fn build_report(
    kind: PycKind,
    version: Option<PythonVersion>,
    source_path: Option<String>,
    pyinstaller: bool,
    code_size: Option<usize>,
    body: &[u8],
    extra_strings: &[String],
) -> PycReport {
    let text = String::from_utf8_lossy(body);
    let imports = collect_imports(&text);
    let high_risk = filter_high_risk(&imports);
    let urls = collect_urls(&text);
    let mut findings: Vec<PycFinding> = Vec::new();

    if !high_risk.is_empty() {
        findings.push(PycFinding {
            severity: PycSeverity::High,
            rule_id: "PY_HIGH_RISK_IMPORT".to_string(),
            description: format!("High-risk imports: {}", high_risk.join(", ")),
            offset: 0,
        });
    }
    if urls.iter().any(|u| u.ends_with(".exe")) {
        findings.push(PycFinding {
            severity: PycSeverity::High,
            rule_id: "PY_EXE_URL".to_string(),
            description: "Reference to a remote .exe".into(),
            offset: 0,
        });
    }
    if let Some(ref p) = source_path {
        if p.contains("AppData") || p.contains("Temp") {
            findings.push(PycFinding {
                severity: PycSeverity::Medium,
                rule_id: "PY_USER_DIR".to_string(),
                description: format!("Source path is in a user-writable dir: {}", p),
                offset: 0,
            });
        }
    }

    PycReport {
        kind,
        python_version: version,
        source_path,
        is_pyinstaller: pyinstaller,
        code_size,
        imports,
        high_risk_imports: high_risk,
        urls,
        suspicious_strings: extra_strings.to_vec(),
        archive_entry_count: 0,
        archive_entries: Vec::new(),
        findings,
    }
}

fn read_source_path(body: &[u8]) -> Option<String> {
    // In Python 3.2+ the source file name lives right after the marshalled
    // code object; a null-terminated UTF-8 string. We scan the first 1 KiB.
    for i in 0..body.len().min(2048) {
        if body[i] == 0 && i > 0 {
            if let Ok(s) = std::str::from_utf8(&body[..i]) {
                if s.ends_with(".py") || s.contains('/') || s.contains('\\') {
                    return Some(s.to_string());
                }
            }
        }
    }
    None
}

fn collect_imports(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("import ") {
            for tok in rest.split(',') {
                let tok = tok.split_whitespace().next().unwrap_or("");
                if !tok.is_empty() {
                    out.push(tok.to_string());
                }
            }
        } else if let Some(rest) = t.strip_prefix("from ") {
            if let Some(m) = rest.split_whitespace().next() {
                if m != "import" {
                    out.push(m.to_string());
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn filter_high_risk(imports: &[String]) -> Vec<String> {
    const HIGH_RISK: &[&str] = &[
        "os",
        "subprocess",
        "sys",
        "socket",
        "ctypes",
        "struct",
        "win32api",
        "win32com",
        "winreg",
        "_winreg",
        "requests",
        "urllib",
        "urllib2",
        "http",
        "httplib",
        "base64",
        "marshal",
        "pickle",
        "shelve",
        "shutil",
        "tempfile",
        "smtplib",
        "ftplib",
        "telnetlib",
        "ssl",
        "hashlib",
        "hmac",
        "pycryptodome",
        "Crypto",
        "Cryptodome",
        "pyaes",
        "rsa",
        "pynput",
        "keyboard",
        "pyautogui",
        "mss",
        "PIL",
        "cv2",
        "browser_cookie3",
        "sqlite3",
        "pyperclip",
        "pyarmor",
        "psutil",
    ];
    imports
        .iter()
        .filter(|m| {
            HIGH_RISK
                .iter()
                .any(|h| m == h || m.starts_with(&format!("{}.", h)))
        })
        .cloned()
        .collect()
}

fn collect_urls(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lower = text.to_ascii_lowercase();
    for proto in ["http://", "https://", "ftp://", "tftp://"] {
        let mut start = 0;
        while let Some(rel) = lower[start..].find(proto) {
            let s = start + rel;
            let end = lower[s..]
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ')')
                .unwrap_or(lower.len() - s);
            out.push(text[s..s + end].to_string());
            start = s + end;
        }
    }
    out.sort();
    out.dedup();
    out
}

fn python_version_from_magic(magic: u32) -> Option<PythonVersion> {
    // Reference: Lib/importlib/_bootstrap_external.py in CPython
    match magic {
        0x0A0D0C00 | 0x0A0D0C0A => Some(PythonVersion::Py2),
        0x0A0D0D0A => Some(PythonVersion::Py3_0),
        0x0A0DEB0A => Some(PythonVersion::Py3_1),
        0x0A0DF20A => Some(PythonVersion::Py3_2),
        0x0A0DF50A => Some(PythonVersion::Py3_3),
        0x0A0DF70A => Some(PythonVersion::Py3_4),
        0x0A0DF80A => Some(PythonVersion::Py3_5),
        0x0A0DF90A => Some(PythonVersion::Py3_6),
        0x0A0DFA0A => Some(PythonVersion::Py3_7),
        0x0A0DFB0A => Some(PythonVersion::Py3_8),
        0x0A0DFC0A => Some(PythonVersion::Py3_9),
        0x0A0DFD0A => Some(PythonVersion::Py3_10),
        0x0A0DFE0A => Some(PythonVersion::Py3_11),
        0x0A0DFF0A => Some(PythonVersion::Py3_12),
        0x0A0D000B => Some(PythonVersion::Py3_13),
        _ if (magic & 0xFFFF_0000) == 0x0A0D_0000 => Some(PythonVersion::Unknown(magic)),
        _ => None,
    }
}

fn is_pyc_magic(magic: u32) -> bool {
    // All Python magic numbers start with bytes 0x0D 0x0A (i.e. \r\n) at
    // positions 0 and 1; in LE that means the low byte is 0x0D and the next
    // is 0x0A.
    magic & 0xFFFF_0000 == 0x0A0D_0000
}

fn looks_like_module(s: &str) -> bool {
    let mut parts = s.split('.');
    let head = parts.next().unwrap_or("");
    if head.is_empty() || !head.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return false;
    }
    for p in parts {
        if p.is_empty() {
            return false;
        }
    }
    true
}

fn find_in(data: &[u8], needle: &[u8]) -> Option<usize> {
    data.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_py37() {
        let m: u32 = 0x0A0DFA0A;
        assert!(is_pyc_magic(m));
        assert_eq!(python_version_from_magic(m), Some(PythonVersion::Py3_7));
    }

    #[test]
    fn test_magic_unknown() {
        let m: u32 = 0x12345678;
        assert!(!is_pyc_magic(m));
        assert_eq!(python_version_from_magic(m), None);
    }

    #[test]
    fn test_collect_imports() {
        let text = "import os, sys\nfrom requests import get\nimport base64\n";
        let im = collect_imports(text);
        assert!(im.contains(&"os".to_string()));
        assert!(im.contains(&"sys".to_string()));
        assert!(im.contains(&"requests".to_string()));
        assert!(im.contains(&"base64".to_string()));
    }

    #[test]
    fn test_filter_high_risk() {
        let im = vec![
            "os".to_string(),
            "json".to_string(),
            "subprocess".to_string(),
        ];
        let hr = filter_high_risk(&im);
        assert!(hr.contains(&"os".to_string()));
        assert!(hr.contains(&"subprocess".to_string()));
        assert!(!hr.contains(&"json".to_string()));
    }

    #[test]
    fn test_pyinstaller_detect() {
        // PyInstaller cookie
        let mut data = b"MEI\x0C\x0B\x0A\x0B\x0E".to_vec();
        data.extend_from_slice(b"PYZ-00.pyz\x00");
        data.extend_from_slice(b"struct os path subprocess\n\x00");
        let r = analyze_python(&data).unwrap();
        assert!(r.is_pyinstaller);
        assert!(r.findings.iter().any(|f| f.rule_id == "PY_PYINSTALLER"));
    }
}

