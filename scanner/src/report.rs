use serde::Serialize;
use std::path::PathBuf;

/// Severity level for findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A single finding from any analysis module
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub module: String,
    pub rule_id: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Information about a detected function
#[derive(Debug, Clone, Serialize)]
pub struct FunctionInfo {
    pub address: u64,
    pub name: String,
    pub size: usize,
    pub func_type: FunctionType,
}

/// Type of detected function
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FunctionType {
    User,
    Library,
    Imported,
    Thunk,
}

/// Complete scan report for a single file
#[derive(Debug, Clone, Serialize)]
pub struct FileReport {
    pub path: PathBuf,
    pub size: u64,
    pub sha256: String,
    pub md5: String,
    pub file_type: String,
    pub suspicion_score: f64,
    pub verdict: Verdict,
    pub findings: Vec<Finding>,
    pub strings_found: usize,
    pub sections_entropy: Vec<SectionEntropy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pe_info: Option<PeInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elf_info: Option<ElfInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub macho_info: Option<MachoInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wasm_info: Option<WasmInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dex_info: Option<DexInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coff_info: Option<CoffInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flat_binary_info: Option<FlatBinaryInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backdoor_report: Option<BackdoorSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shellcode_report: Option<ShellcodeSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xref_summary: Option<XrefSummaryInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg_summary: Option<CfgSummaryInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_summary: Option<SignatureSummaryInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ml_classification: Option<MlClassificationInfo>,
    pub scan_duration_ms: u128,
    /// Detected functions (populated by func-sigs analysis)
    pub functions: Vec<FunctionInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SectionEntropy {
    pub name: String,
    pub entropy: f64,
    pub classification: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeInfo {
    pub machine: String,
    pub num_sections: u16,
    pub timestamp: u32,
    pub characteristics: Vec<String>,
    /// Entry point as hex string (e.g., "0x1000")
    pub entry_point: Option<String>,
    /// Image base address
    pub image_base: Option<String>,
    /// DllCharacteristics flags: ASLR, DEP/NX, CFG
    pub dll_characteristics: Vec<String>,
    /// TLS callbacks detected (anti-debug technique)
    pub tls_callbacks: Vec<String>,
    /// .NET CLR assembly detected
    pub is_dotnet: bool,
    /// Overlay data present (appended after last section)
    pub has_overlay: bool,
    pub overlay_size: usize,
    /// Rich header compiler signatures
    pub rich_header: Vec<String>,
    /// Resources found (RT_RCDATA etc.)
    pub num_resources: usize,
    pub suspicious_resources: usize,
    /// Delay imports detected
    pub has_delay_imports: bool,
    pub delay_import_dlls: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ElfInfo {
    pub class: String,
    pub endian: String,
    pub machine: String,
    pub elf_type: String,
    pub entry_point: String,
    pub num_sections: usize,
    pub num_segments: usize,
    pub is_statically_linked: bool,
    pub is_stripped: bool,
    pub rwx_sections: Vec<String>,
    pub imported_functions: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MachoInfo {
    pub cpu_type: String,
    pub cpu_subtype: u32,
    pub file_type: String,
    pub is_64bit: bool,
    pub flags: u32,
    pub is_pie: bool,
    pub is_restricted: bool,
    pub is_encrypted: bool,
    pub has_code_signature: bool,
    pub num_segments: usize,
    pub num_sections: usize,
    pub imported_dylibs: Vec<String>,
    pub rwx_segments: Vec<String>,
    pub entry_point: Option<String>,
    pub warnings: Vec<String>,
}

/// Information about a WASM (WebAssembly) module
#[derive(Debug, Clone, Serialize)]
pub struct WasmInfo {
    pub version: u32,
    pub num_types: usize,
    pub num_functions: usize,
    pub num_imports: usize,
    pub num_exports: usize,
    pub num_tables: usize,
    pub num_memories: usize,
    pub num_globals: usize,
    pub num_data_segments: usize,
    pub imported_functions: Vec<String>,
    pub exported_functions: Vec<String>,
    pub custom_sections: Vec<String>,
    pub total_code_size: usize,
}

/// Information about a DEX (Dalvik Executable) file
#[derive(Debug, Clone, Serialize)]
pub struct DexInfo {
    pub version: String,
    pub num_classes: usize,
    pub num_methods: usize,
    pub num_fields: usize,
    pub num_strings: usize,
    pub num_types: usize,
    pub class_names: Vec<String>,
    pub method_names: Vec<String>,
}

/// Information about a COFF file
#[derive(Debug, Clone, Serialize)]
pub struct CoffInfo {
    pub machine: String,
    pub num_sections: usize,
    pub num_symbols: usize,
    pub timestamp: u32,
    pub characteristics: Vec<String>,
    pub section_names: Vec<String>,
    pub functions: Vec<String>,
    pub externals: Vec<String>,
}

/// Information about a flat binary file
#[derive(Debug, Clone, Serialize)]
pub struct FlatBinaryInfo {
    pub size: usize,
    pub entropy: f64,
    pub looks_like_shellcode: bool,
    pub shellcode_type: Option<String>,
    pub is_intel_hex: bool,
    pub is_srecord: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackdoorSummary {
    pub risk_score: f64,
    pub verdict: String,
    pub num_findings: usize,
    pub categories: Vec<String>,
    pub mitre_techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShellcodeSummary {
    pub verdict: String,
    pub num_findings: usize,
    pub api_hashes_resolved: Vec<String>,
    pub patterns_detected: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct XrefSummaryInfo {
    pub total_xrefs: usize,
    pub unique_targets: usize,
    pub string_xrefs: usize,
    pub import_xrefs: usize,
    pub correlated_pairs: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct CfgSummaryInfo {
    pub num_blocks: usize,
    pub num_edges: usize,
    pub total_instructions: usize,
    pub num_anomalies: usize,
    pub anomalies: Vec<String>,
    /// Real edges as (src_block_id, dst_block_id) pairs
    pub edges: Vec<(u32, u32)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignatureSummaryInfo {
    pub num_matches: usize,
    pub libraries_found: Vec<String>,
    pub compiler: Option<String>,
}

/// ML-based classification result
#[derive(Debug, Clone, Serialize)]
pub struct MlClassificationInfo {
    /// Predicted class (Clean, Suspicious, Malicious, Packed, PUA)
    pub classification: String,
    /// Confidence score [0.0, 1.0]
    pub confidence: f64,
    /// Human-readable explanation
    pub explanation: String,
    /// Top 5 most important features
    pub top_features: Vec<(String, f32)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
    Error,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Clean => write!(f, "CLEAN"),
            Verdict::Suspicious => write!(f, "SUSPICIOUS"),
            Verdict::Malicious => write!(f, "MALICIOUS"),
            Verdict::Error => write!(f, "ERROR"),
        }
    }
}

/// Aggregated scan summary
#[derive(Debug, Clone, Serialize)]
pub struct ScanSummary {
    pub total_files: usize,
    pub scanned_files: usize,
    pub clean: usize,
    pub suspicious: usize,
    pub malicious: usize,
    pub errors: usize,
    pub total_findings: usize,
    pub critical_findings: usize,
    pub scan_duration_ms: u128,
}
