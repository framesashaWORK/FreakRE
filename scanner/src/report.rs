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
    pub confidence: f64,
    pub api_references: Vec<String>,
    pub xref_offsets: Vec<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reachable_from_entry: Option<bool>,
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
    pub script_info: Option<ScriptInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdf_info: Option<PdfInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dotnet_info: Option<DotnetInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pyc_info: Option<PycInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firmware_info: Option<FirmwareInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memdump_info: Option<MemdumpInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dll_info: Option<DllInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architecture_info: Option<ArchitectureInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backdoor_report: Option<BackdoorSummary>,
    /// Full backdoor findings with evidence and confidence. The summary above
    /// remains for compact/legacy consumers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backdoor_analysis: Option<backdoor_analyzer::BackdoorReport>,
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
    pub analysis_profile: String,
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

/// Architecture detected from a binary (raw shellcode, embedded PE, or scan
/// of a binary blob). Used to report ARM/AArch64 support and to pick the
/// right instruction decoder for downstream analysis.
#[derive(Debug, Clone, Serialize)]
pub struct ArchitectureInfo {
    pub arch: String,            // "x86" / "x86_64" / "ARM" / "AArch64" / "unknown"
    pub endian: String,          // "little" / "big" / "mixed"
    pub bitness: u8,             // 32 / 64
    pub confidence: f32,         // 0.0 - 1.0
    pub indicators: Vec<String>, // reasons
}

/// Summary of a script-language analysis (PowerShell / AutoIt / AHK / BAT / VBS).
#[derive(Debug, Clone, Serialize)]
pub struct ScriptInfo {
    pub kind: String,
    pub line_count: usize,
    pub comment_count: usize,
    pub avg_line_length: f32,
    pub obfuscation_score: f32,
    pub finding_count: usize,
    pub highest_severity: String,
    pub suspicious_calls: Vec<String>,
    pub iocs: Vec<ScriptIoc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScriptIoc {
    pub kind: String,
    pub value: String,
}

/// Summary of a PDF analysis.
#[derive(Debug, Clone, Serialize)]
pub struct PdfInfo {
    pub version: String,
    pub is_encrypted: bool,
    pub is_linearized: bool,
    pub has_xfa: bool,
    pub has_javascript: bool,
    pub has_open_action: bool,
    pub has_launch_action: bool,
    pub has_embedded_files: bool,
    pub has_acroform: bool,
    pub object_count: usize,
    pub page_count: usize,
    pub uri_count: usize,
    pub suspicious_uris: Vec<String>,
    pub embedded_magic: Vec<String>,
    pub finding_count: usize,
    pub highest_severity: String,
}

/// Summary of a .NET / CLR analysis.
#[derive(Debug, Clone, Serialize)]
pub struct DotnetInfo {
    pub metadata_version: Option<String>,
    pub runtime_version: Option<String>,
    pub entry_point_token: Option<String>,
    pub flags: Vec<String>,
    pub strong_name_signed: bool,
    pub module_name: Option<String>,
    pub assembly_ref_count: usize,
    pub type_ref_count: usize,
    pub method_def_count: usize,
    pub member_ref_count: usize,
    pub user_string_count: usize,
    pub assembly_refs: Vec<String>,
    pub suspicious_strings: Vec<String>,
    pub finding_count: usize,
    pub highest_severity: String,
}

/// Summary of a Python .pyc / PyInstaller analysis.
#[derive(Debug, Clone, Serialize)]
pub struct PycInfo {
    pub kind: String,
    pub python_version: Option<String>,
    pub source_path: Option<String>,
    pub is_pyinstaller: bool,
    pub code_size: Option<usize>,
    pub imports: Vec<String>,
    pub high_risk_imports: Vec<String>,
    pub urls: Vec<String>,
    pub archive_entry_count: usize,
    pub archive_entries_sample: Vec<String>,
    pub finding_count: usize,
    pub highest_severity: String,
}

/// Summary of a UEFI/BIOS firmware analysis.
#[derive(Debug, Clone, Serialize)]
pub struct FirmwareInfo {
    pub kind: String,
    pub volume_count: usize,
    pub gpt_partition_count: usize,
    pub mbr_partition_count: usize,
    pub embedded_pe_count: usize,
    pub findings: Vec<String>,
}

/// Summary of a memory-dump analysis.
#[derive(Debug, Clone, Serialize)]
pub struct MemdumpInfo {
    pub kind: String,
    pub stream_count: usize,
    pub embedded_pe_count: usize,
    pub raw_mz_hits: usize,
    pub embedded_pe: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DllInfo {
    pub dll_type: String,
    pub architecture: String,
    pub is_dotnet: bool,
    pub is_resource_only: bool,
    pub is_com: bool,
    pub is_wdm_driver: bool,
    pub is_injectable: bool,
    pub calling_conventions: Vec<String>,
    pub exports: Vec<String>,
    pub dll_name: Option<String>,
    pub export_count: usize,
    pub import_count: usize,
    pub characteristics: Vec<String>,
    pub suspicion_score: f64,
    pub findings: Vec<DllFindingInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DllFindingInfo {
    pub severity: String,
    pub rule_id: String,
    pub description: String,
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
    pub semantic_roles: Vec<String>,
    pub semantic_sources: Vec<String>,
    pub semantic_sinks: Vec<String>,
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
