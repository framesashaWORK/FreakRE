/// Re-exports of the pipeline modules split out of this file, kept here so
/// existing `freakre_scanner::scanner::*` paths (benches, downstream crates)
/// keep working.
pub use crate::filetype::{contains_any, detect_file_type, hex_md5, hex_sha256, strip_utf8_bom};
pub use crate::packers::{detect_packers, pe_is_library, section_index_for_offset};
pub use crate::report::*;
pub use crate::scoring::{
    calculate_suspicion_score, calculate_suspicion_score_with_config, determine_verdict,
    is_executable_section, is_weak_shellcode_finding, is_yara_budget_notice, ScoringConfig,
};
use backdoor_analyzer::analyze_backdoors;
use cfg_builder::{build_cfg, CfgConfig};
use elf_parser::ElfFile;
use entropy_rs::calculate_entropy;
use func_sigs::{scan_signatures, SigScanConfig};
use import_analyzer::ImportAnalyzer;
use ml_detection;
use pe_parser::PeFile;
use shellcode_analyzer::{detect_architecture, detect_shellcode, Arch, ShellcodeConfig};
use std::path::Path;
use std::time::Instant;
use str_extract::{extract_strings, ExtractConfig};
use xrefs::{build_string_xrefs, build_import_xrefs, XrefDatabase};

use script_analyzer::{analyze_script, detect_kind as script_detect_kind};
use pdf_analyzer::analyze_pdf;
use dotnet_analyzer::analyze_dotnet;
use pyc_parser::analyze_python;
use firmware_analyzer::analyze_firmware;
use memdump_analyzer::analyze_dump;

/// Core scanner that orchestrates all analysis modules
pub struct Scanner {
    yara_scanner: Option<yara_lite::Scanner>,
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner {
    pub fn new() -> Self {
        Self { yara_scanner: None }
    }

    pub fn with_yara_rules(mut self, rules_path: &Path) -> Result<Self, String> {
        let source = std::fs::read_to_string(rules_path)
            .map_err(|e| format!("Failed to read YARA rules: {}", e))?;
        let parsed = yara_lite::parse_rules(&source)
            .map_err(|e| format!("Failed to parse YARA rules: {:?}", e))?;
        let compiled: Vec<_> = parsed
            .iter()
            .map(yara_lite::compile_rule)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to compile YARA rules: {}", e))?;
        self.yara_scanner = Some(
            yara_lite::Scanner::new(compiled)
                .map_err(|e| format!("Failed to initialize YARA scanner: {}", e))?,
        );
        Ok(self)
    }

    /// Scan a single file and produce a complete report
    pub fn scan_file(&self, path: &Path) -> FileReport {
        let start = Instant::now();
        let mut findings = Vec::new();

        // Read file
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                return FileReport {
                    path: path.to_path_buf(),
                    size: 0,
                    sha256: String::new(),
                    md5: String::new(),
                    file_type: "unknown".into(),
                    suspicion_score: 0.0,
                    verdict: Verdict::Error,
                    findings: vec![Finding {
                        severity: Severity::High,
                        module: "io".into(),
                        rule_id: "FILE_READ_ERROR".into(),
                        description: format!("Cannot read file: {}", e),
                        details: None,
                    }],
                    strings_found: 0,
                    sections_entropy: Vec::new(),
                    pe_info: None,
                    elf_info: None,
                    macho_info: None,
                    wasm_info: None,
                    dex_info: None,
                    coff_info: None,
                    flat_binary_info: None,
                    script_info: None,
                    pdf_info: None,
                    dotnet_info: None,
                    pyc_info: None,
                    firmware_info: None,
                    memdump_info: None,
                    dll_info: None,
                    architecture_info: None,
                    backdoor_report: None,
                    shellcode_report: None,
                    xref_summary: None,
                    cfg_summary: None,
                    signature_summary: None,
                    ml_classification: None,
                    scan_duration_ms: start.elapsed().as_millis(),
                    functions: Vec::new(),
                };
            }
        };

        let size = data.len() as u64;

        // Hashes
        let sha256 = hex_sha256(&data);
        let md5 = hex_md5(&data);

        // Detect file type
        let file_type = detect_file_type(&data);

        // String extraction
        let config = ExtractConfig::windows_pe(4);
        let strings = extract_strings(&data, &config);
        let strings_found = strings.len();

        // Collect string values for backdoor/shellcode analysis
        let string_values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();

        // в”Ђв”Ђв”Ђ PE Analysis в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        let mut pe_info = None;
        let mut sections_entropy = Vec::new();
        let mut import_score = 0.0;
        let mut is_library = false;
        let mut dll_info: Option<DllInfo> = None;

        // Store PE parse result for reuse (avoid double parsing)
        let pe_parse_result: Option<Result<PeFile<'_>, pe_parser::PeError>> =
            if file_type == "PE32" || file_type == "PE32+" {
                Some(PeFile::parse(&data))
            } else {
                None
            };

        // Cached import names from PE (reused by backdoor analyzer)
        let mut cached_import_names: Vec<String> = Vec::new();
        // Cached DLL module names (for ML feature extraction)
        let mut cached_dll_names: Vec<String> = Vec::new();

        // Unify PE parse result into a single match to avoid repeated `if let` patterns
        let pe: Option<&PeFile<'_>> = match &pe_parse_result {
            Some(Ok(pe_ref)) => Some(pe_ref),
            Some(Err(e)) => {
                findings.push(Finding {
                    severity: Severity::Medium,
                    module: "pe-parser".into(),
                    rule_id: "PE_PARSE_ERROR".into(),
                    description: format!("Failed to parse PE: {}", e),
                    details: None,
                });
                None
            }
            None => None,
        };

        if let Some(pe) = pe {
            is_library = pe_is_library(&data);

            // PE warnings в†’ findings
            for warning in &pe.warnings {
                let sev = match warning.kind {
                    pe_parser::WarningKind::RwxSection => Severity::High,
                    pe_parser::WarningKind::AnomalousELfanew => Severity::Medium,
                    pe_parser::WarningKind::ZeroSections => Severity::Critical,
                    pe_parser::WarningKind::DebugSymbolsInRelease => Severity::Low,
                    pe_parser::WarningKind::OverlappingSections => Severity::High,
                    pe_parser::WarningKind::ExecutableWithoutCodeFlag => Severity::Medium,
                    pe_parser::WarningKind::EmptyRawWithVirtualSize => Severity::High,
                    _ => Severity::Info,
                };
                findings.push(Finding {
                    severity: sev,
                    module: "pe-parser".into(),
                    rule_id: format!("PE_{:?}", warning.kind),
                    description: warning.message.clone(),
                    details: None,
                });
            }

            // Section entropy
            for section in &pe.sections {
                let raw = section.raw_data(&data);
                let ent_result = calculate_entropy(raw);
                let ent = ent_result.entropy;
                let class = ent_result.classify_section(&section.name_string());
                sections_entropy.push(SectionEntropy {
                    name: section.name_string(),
                    entropy: ent,
                    classification: class.to_string(),
                });

                if ent > 7.0 {
                    findings.push(Finding {
                        severity: Severity::High,
                        module: "entropy".into(),
                        rule_id: "HIGH_ENTROPY_SECTION".into(),
                        description: format!(
                            "Section '{}' has high entropy ({:.2}) - possible packing/encryption",
                            section.name_string(),
                            ent
                        ),
                        details: None,
                    });
                }
            }

            // Packer / protector identification (specific, low-false-positive)
            findings.extend(detect_packers(pe, &data));

            // Import analysis (single parse, cached result)
            let analyzer = ImportAnalyzer::new(&data, pe);
            let import_report = analyzer.analyze();
            // Capability-based import detection is unreliable for *libraries*
            // (DLLs legitimately export/use these APIs), so it is skipped for
            // them вЂ” a malicious library is still caught by the code-level
            // analyzers (shellcode / CFG / YARA).
            import_score = if is_library {
                0.0
            } else {
                import_report.suspicion_score
            };

            // Cache import names for backdoor analyzer.
            // Reuse existing String allocations where possible to reduce clone overhead.
            cached_import_names = import_report
                .modules
                .iter()
                .flat_map(|m| m.functions.iter().filter_map(|f| f.name.as_ref().cloned()))
                .collect();

            // Cache DLL module names for ML feature extraction
            cached_dll_names = import_report
                .modules
                .iter()
                .map(|m| m.name.clone())
                .collect();

            if !is_library {
                for rule_match in &import_report.rule_matches {
                    let sev = match rule_match.level {
                        import_analyzer::SuspicionLevel::Critical => Severity::Critical,
                        import_analyzer::SuspicionLevel::High => Severity::High,
                        import_analyzer::SuspicionLevel::Medium => Severity::Medium,
                        import_analyzer::SuspicionLevel::Low => Severity::Low,
                    };
                    findings.push(Finding {
                        severity: sev,
                        module: "import-analyzer".into(),
                        rule_id: rule_match.rule_id.to_string(),
                        description: rule_match.description.clone(),
                        details: Some(format!(
                            "Triggered by: {} (confidence: {:.2})",
                            rule_match.triggered_by.join(", "),
                            rule_match.confidence
                        )),
                    });
                }
            }

            pe_info = Some(PeInfo {
                machine: format!("{}", pe.nt_headers.file_header.machine),
                num_sections: pe.nt_headers.file_header.number_of_sections,
                timestamp: pe.nt_headers.file_header.time_date_stamp,
                characteristics: Vec::new(),
                entry_point: Some(format!("0x{:X}", pe.entry_point)),
                image_base: Some(format!("0x{:X}", pe.image_base)),
                dll_characteristics: pe.dll_characteristics_flags(),
                tls_callbacks: pe.tls_callbacks().iter().map(|cb| format!("0x{:X}", cb)).collect(),
                is_dotnet: pe.is_dotnet(),
                has_overlay: pe.overlay_size() > 0,
                overlay_size: pe.overlay_size(),
                rich_header: pe.rich_header(),
                num_resources: pe.resource_info().0,
                suspicious_resources: pe.resource_info().1,
                has_delay_imports: !pe.delay_imports().is_empty(),
                delay_import_dlls: pe.delay_imports(),
                warnings: pe.warnings.iter().map(|w| w.message.clone()).collect(),
            });

            // DLL Analysis — classify DLL type, calling convention, exports
            let export_names = pe.export_names();
            let (dll_name, _exports_raw) = pe.exports();
            let dll_raw = dll_analyzer::analyze_dll(
                &data,
                is_library,
                pe.is_dotnet(),
                pe.nt_headers.file_header.machine.to_raw(),
                pe.dll_characteristics,
                &export_names,
                dll_name,
                cached_import_names.len(),
            );
            dll_info = Some(DllInfo {
                dll_type: dll_raw.dll_type.to_string(),
                architecture: dll_raw.architecture,
                is_dotnet: dll_raw.is_dotnet,
                is_resource_only: dll_raw.is_resource_only,
                is_com: dll_raw.is_com,
                is_wdm_driver: dll_raw.is_wdm_driver,
                is_injectable: dll_raw.is_injectable,
                calling_conventions: dll_raw.calling_conventions.iter().map(|c| format!("{:?}", c)).collect(),
                exports: dll_raw.exports,
                dll_name: dll_raw.dll_name,
                export_count: dll_raw.export_count,
                import_count: dll_raw.import_count,
                characteristics: dll_raw.characteristics,
                suspicion_score: dll_raw.suspicion_score,
                findings: dll_raw.findings.into_iter().map(|f| DllFindingInfo {
                    severity: f.severity,
                    rule_id: f.rule_id,
                    description: f.description,
                }).collect(),
            });

            // в”Ђв”Ђв”Ђ PE Security Findings в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
            let dll_flags = pe.dll_characteristics_flags();
            if !dll_flags.iter().any(|f| f.contains("ASLR")) {
                findings.push(Finding {
                    severity: Severity::High,
                    module: "pe-parser".into(),
                    rule_id: "PE_NO_ASLR".into(),
                    description: "PE lacks ASLR (DYNAMIC_BASE) вЂ” easier to exploit".into(),
                    details: None,
                });
            }
            if !dll_flags.iter().any(|f| f.contains("DEP")) {
                findings.push(Finding {
                    severity: Severity::Medium,
                    module: "pe-parser".into(),
                    rule_id: "PE_NO_DEP".into(),
                    description: "PE lacks DEP/NX compatibility".into(),
                    details: None,
                });
            }
            if !dll_flags.iter().any(|f| f.contains("CFG")) {
                findings.push(Finding {
                    severity: Severity::Low,
                    module: "pe-parser".into(),
                    rule_id: "PE_NO_CFG".into(),
                    description: "PE lacks Control Flow Guard".into(),
                    details: None,
                });
            }

            // TLS callbacks вЂ” execute before entry point
            let tls_cbs = pe.tls_callbacks();
            if !tls_cbs.is_empty() {
                let sev = if tls_cbs.len() > 3 { Severity::High } else { Severity::Medium };
                findings.push(Finding {
                    severity: sev,
                    module: "pe-parser".into(),
                    rule_id: "PE_TLS_CALLBACKS".into(),
                    description: format!(
                        "{} TLS callback(s) detected вЂ” code runs before entry point (anti-debug/unpacker)",
                        tls_cbs.len()
                    ),
                    details: Some(format!("Callbacks: {}", tls_cbs.iter().map(|c| format!("0x{:X}", c)).collect::<Vec<_>>().join(", "))),
                });
            }

            // .NET CLR detection
            if pe.is_dotnet() {
                findings.push(Finding {
                    severity: Severity::Info,
                    module: "pe-parser".into(),
                    rule_id: "PE_DOTNET".into(),
                    description: ".NET CLR assembly detected вЂ” static x86/x64 analysis limited".into(),
                    details: Some("Use IL disassembler (ILSpy/dnSpy) for full analysis".into()),
                });
            }

            // Overlay detection
            let overlay_size = pe.overlay_size();
            if overlay_size > 0 {
                // Overlays are normal (digital signatures, debug info,
                // installer payloads). Keep as weak context only.
                let sev = Severity::Low;
                findings.push(Finding {
                    severity: sev,
                    module: "pe-parser".into(),
                    rule_id: "PE_OVERLAY".into(),
                    description: format!(
                        "Overlay data detected: {} bytes appended after last section",
                        overlay_size
                    ),
                    details: Some("Common technique to hide encrypted payloads or appended droppers".into()),
                });
            }

            // Suspicious resources
            let (num_res, susp_res) = pe.resource_info();
            if susp_res > 0 {
                findings.push(Finding {
                    severity: Severity::Medium,
                    module: "pe-parser".into(),
                    rule_id: "PE_SUSPICIOUS_RESOURCES".into(),
                    description: format!(
                        "{} suspicious resource(s) of {} total (high entropy in .rsrc вЂ” possible packed payload)",
                        susp_res, num_res
                    ),
                    details: None,
                });
            }

            // NOTE: `PE_DELAY_IMPORTS` and `PE_NO_RICH_HEADER` were intentionally
            // removed вЂ” both are benign/common on legitimate binaries (MinGW, Go,
            // Rust, linkers without rich headers) and produced only noise without
            // contributing to detection.
        }

        // в”Ђв”Ђв”Ђ ELF Analysis в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        let mut elf_info = None;

        if file_type == "ELF" {
            match ElfFile::parse(&data) {
                Ok(result) => {
                    for warning in &result.warnings {
                        let sev = match warning.kind {
                            elf_parser::ElfWarningKind::RwxSection => Severity::High,
                            elf_parser::ElfWarningKind::ExecutableStack => Severity::Critical,
                            elf_parser::ElfWarningKind::MissingProtection => Severity::High,
                            elf_parser::ElfWarningKind::StaticallyLinked => Severity::Medium,
                            elf_parser::ElfWarningKind::StrippedBinary => Severity::Low,
                            elf_parser::ElfWarningKind::SuspiciousInterpreter => Severity::High,
                            elf_parser::ElfWarningKind::OverlappingRegions => Severity::High,
                            elf_parser::ElfWarningKind::SuspiciousSection => Severity::Medium,
                            elf_parser::ElfWarningKind::EntryPointOutOfBounds => Severity::High,
                            elf_parser::ElfWarningKind::UnusualArchitecture => Severity::Medium,
                            elf_parser::ElfWarningKind::ExecutableWithoutFile => Severity::High,
                            elf_parser::ElfWarningKind::DynamicAnomaly => Severity::Medium,
                        };
                        findings.push(Finding {
                            severity: sev,
                            module: "elf-parser".into(),
                            rule_id: format!("ELF_{:?}", warning.kind),
                            description: warning.message.clone(),
                            details: None,
                        });
                    }

                    for section in &result.section_headers {
                        let raw: &[u8] = section.data;
                        let ent_result = calculate_entropy(raw);
                        let ent = ent_result.entropy;
                        let class = ent_result.classify_section(&section.name);
                        sections_entropy.push(SectionEntropy {
                            name: section.name.to_string(),
                            entropy: ent,
                            classification: class.to_string(),
                        });

                        if ent > 7.0 {
                            findings.push(Finding {
                                severity: Severity::High,
                                module: "entropy".into(),
                                rule_id: "HIGH_ENTROPY_ELF_SECTION".into(),
                                description: format!(
                                    "ELF section '{}' has high entropy ({:.2})",
                                    section.name, ent
                                ),
                                details: None,
                            });
                        }
                    }

                    let rwx_names: Vec<String> = result
                        .rwx_sections()
                        .iter()
                        .map(|s| s.name.to_string())
                        .collect();
                    let imports: Vec<String> = result
                        .imported_functions()
                        .iter()
                        .map(|s| s.to_string())
                        .collect();

                    // Cache ELF imports for backdoor analyzer
                    if cached_import_names.is_empty() {
                        cached_import_names = imports.clone();
                    }
                    // For ELF, shared library names come from NEEDED entries
                    // Use imported function names as a rough proxy for DLL names
                    if cached_dll_names.is_empty() {
                        cached_dll_names = imports.clone();
                    }

                    elf_info = Some(ElfInfo {
                        class: format!("{:?}", result.ident.class),
                        endian: format!("{:?}", result.ident.endian),
                        machine: format!("{:?}", result.machine),
                        elf_type: format!("{:?}", result.elf_type),
                        entry_point: format!("0x{:X}", result.entry_point),
                        num_sections: result.section_headers.len(),
                        num_segments: result.program_headers.len(),
                        is_statically_linked: result.is_statically_linked(),
                        is_stripped: result.is_stripped(),
                        rwx_sections: rwx_names,
                        imported_functions: imports,
                        warnings: result.warnings.iter().map(|w| w.message.clone()).collect(),
                    });
                }
                Err(e) => {
                    findings.push(Finding {
                        severity: Severity::Medium,
                        module: "elf-parser".into(),
                        rule_id: "ELF_PARSE_ERROR".into(),
                        description: format!("Failed to parse ELF: {}", e),
                        details: None,
                    });
                }
            }
        }

        // в”Ђв”Ђв”Ђ Mach-O Analysis в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        let mut macho_info = None;

        if file_type.starts_with("Mach-O") {
            // For fat/universal binaries, extract the preferred architecture slice
            let macho_data: &[u8] = match macho_parser::parse_any(&data) {
                Ok(macho_parser::MachoObject::Fat(archs)) if !archs.is_empty() => {
                    // Prefer 64-bit ARM or x86_64, fall back to first arch
                    let preferred = archs.iter().find(|a| a.cpu_type.is_64bit())
                        .unwrap_or(&archs[0]);
                    let start = preferred.offset as usize;
                    let end = (start + preferred.size as usize).min(data.len());
                    if start < data.len() {
                        &data[start..end]
                    } else {
                        &data
                    }
                }
                _ => &data,
            };

            match macho_parser::MachoFile::parse(macho_data) {
                Ok(macho) => {
                    for warning in &macho.warnings {
                        let sev = match warning.kind {
                            macho_parser::WarningKind::RwxSection => Severity::High,
                            macho_parser::WarningKind::NoCodeSignature => Severity::Medium,
                            macho_parser::WarningKind::EncryptedBinary => Severity::High,
                            macho_parser::WarningKind::StaticallyLinked => Severity::Medium,
                            macho_parser::WarningKind::StrippedBinary => Severity::Low,
                            macho_parser::WarningKind::PieDisabled => Severity::High,
                            macho_parser::WarningKind::RestrictOption => Severity::Low,
                            macho_parser::WarningKind::LazyBinding => Severity::Low,
                            macho_parser::WarningKind::OverlappingSegments => Severity::High,
                            macho_parser::WarningKind::EntitlementsAnomaly => Severity::Medium,
                            macho_parser::WarningKind::UnusualLoadCommand => Severity::Medium,
                            macho_parser::WarningKind::Other => Severity::Info,
                        };
                        findings.push(Finding {
                            severity: sev,
                            module: "macho-parser".into(),
                            rule_id: format!("MACHO_{:?}", warning.kind),
                            description: warning.message.clone(),
                            details: None,
                        });
                    }

                    // Section entropy for Mach-O
                    for section in macho.all_sections() {
                        let raw = section.raw_data(macho_data);
                        if !raw.is_empty() {
                            let ent_result = calculate_entropy(raw);
                            let ent = ent_result.entropy;
                            let class = ent_result.classify_section(&section.name);
                            sections_entropy.push(SectionEntropy {
                                name: format!("{},{}", section.segment_name, section.name),
                                entropy: ent,
                                classification: class.to_string(),
                            });

                            if ent > 7.0 {
                                findings.push(Finding {
                                    severity: Severity::High,
                                    module: "entropy".into(),
                                    rule_id: "HIGH_ENTROPY_MACHO_SECTION".into(),
                                    description: format!(
                                        "Mach-O section '{},{}' has high entropy ({:.2})",
                                        section.segment_name, section.name, ent
                                    ),
                                    details: None,
                                });
                            }
                        }
                    }

                    let rwx_segs: Vec<String> = macho.segments()
                        .iter()
                        .filter(|s| s.is_rwx())
                        .map(|s| s.name.clone())
                        .collect();

                    let dylibs: Vec<String> = macho.imported_dylibs()
                        .iter()
                        .map(|s| s.to_string())
                        .collect();

                    // Cache dylib names for backdoor analysis (as a rough proxy)
                    if cached_import_names.is_empty() {
                        cached_import_names = dylibs.clone();
                    }
                    // Cache dylib names for ML feature extraction
                    if cached_dll_names.is_empty() {
                        cached_dll_names = dylibs.clone();
                    }

                    let entry_point = macho.entry_point().map(|ep| format!("0x{:X}", ep));
                    let num_sections = macho.all_sections().len();

                    macho_info = Some(MachoInfo {
                        cpu_type: format!("{}", macho.cpu_type),
                        cpu_subtype: macho.cpu_subtype,
                        file_type: format!("{}", macho.file_type),
                        is_64bit: macho.is_64bit,
                        flags: macho.flags,
                        is_pie: macho.is_pie(),
                        is_restricted: macho.is_restricted(),
                        is_encrypted: macho.is_encrypted(),
                        has_code_signature: macho.has_code_signature(),
                        num_segments: macho.segments().len(),
                        num_sections,
                        imported_dylibs: dylibs,
                        rwx_segments: rwx_segs,
                        entry_point,
                        warnings: macho.warnings.iter().map(|w| w.message.clone()).collect(),
                    });
                }
                Err(e) => {
                    findings.push(Finding {
                        severity: Severity::Medium,
                        module: "macho-parser".into(),
                        rule_id: "MACHO_PARSE_ERROR".into(),
                        description: format!("Failed to parse Mach-O: {}", e),
                        details: None,
                    });
                }
            }
        }

        // в”Ђв”Ђв”Ђ WebAssembly Analysis в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        let mut wasm_info = None;

        if file_type == "WebAssembly" {
            match wasm_parser::parse_wasm(&data) {
                Ok(wasm) => {
                    let imported_funcs = wasm.imported_function_names();
                    let exported_funcs = wasm.exported_function_names();

                    // Cache WASM imports for backdoor analysis
                    if cached_import_names.is_empty() {
                        cached_import_names = imported_funcs.clone();
                    }

                    // Check for suspicious imports
                    for func in &imported_funcs {
                        let lower = func.to_lowercase();
                        if lower.contains("eval") || lower.contains("exec") || lower.contains("spawn") {
                            findings.push(Finding {
                                severity: Severity::Medium,
                                module: "wasm-parser".into(),
                                rule_id: "WASM_SUSPICIOUS_IMPORT".into(),
                                description: format!("WASM imports suspicious function: {}", func),
                                details: None,
                            });
                        }
                    }

                    // High code size might indicate obfuscation
                    let code_size = wasm.total_code_size();
                    if code_size > 1024 * 1024 {
                        findings.push(Finding {
                            severity: Severity::Low,
                            module: "wasm-parser".into(),
                            rule_id: "WASM_LARGE_CODE".into(),
                            description: format!("WASM module has large code section: {} bytes", code_size),
                            details: None,
                        });
                    }

                    wasm_info = Some(WasmInfo {
                        version: wasm.version,
                        num_types: wasm.types.len(),
                        num_functions: wasm.functions.len(),
                        num_imports: wasm.imports.len(),
                        num_exports: wasm.exports.len(),
                        num_tables: wasm.tables.len(),
                        num_memories: wasm.memories.len(),
                        num_globals: wasm.globals.len(),
                        num_data_segments: wasm.data.len(),
                        imported_functions: imported_funcs,
                        exported_functions: exported_funcs,
                        custom_sections: wasm.custom_sections.iter().map(|c| c.name.clone()).collect(),
                        total_code_size: code_size,
                    });
                }
                Err(e) => {
                    findings.push(Finding {
                        severity: Severity::Medium,
                        module: "wasm-parser".into(),
                        rule_id: "WASM_PARSE_ERROR".into(),
                        description: format!("Failed to parse WASM: {}", e),
                        details: None,
                    });
                }
            }
        }

        // в”Ђв”Ђв”Ђ DEX Analysis в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        let mut dex_info = None;

        if file_type == "DEX" {
            match dex_parser::parse_dex(&data) {
                Ok(dex) => {
                    let class_names: Vec<String> = dex.class_defs.iter()
                        .filter_map(|cd| dex.get_class_name(cd))
                        .collect();
                    let method_names = dex.all_method_names();

                    // Check for suspicious method names
                    for method in &method_names {
                        let lower = method.to_lowercase();
                        if lower.contains("runtime") || lower.contains("exec") || lower.contains("loadclass") {
                            findings.push(Finding {
                                severity: Severity::Medium,
                                module: "dex-parser".into(),
                                rule_id: "DEX_SUSPICIOUS_METHOD".into(),
                                description: format!("DEX contains suspicious method: {}", method),
                                details: None,
                            });
                        }
                    }

                    // Cache DEX method names for backdoor analysis
                    if cached_import_names.is_empty() {
                        cached_import_names = method_names.clone();
                    }

                    dex_info = Some(DexInfo {
                        version: dex.header.version(),
                        num_classes: dex.class_count(),
                        num_methods: dex.method_count(),
                        num_fields: dex.field_ids.len(),
                        num_strings: dex.strings.len(),
                        num_types: dex.type_ids.len(),
                        class_names,
                        method_names,
                    });
                }
                Err(e) => {
                    findings.push(Finding {
                        severity: Severity::Medium,
                        module: "dex-parser".into(),
                        rule_id: "DEX_PARSE_ERROR".into(),
                        description: format!("Failed to parse DEX: {}", e),
                        details: None,
                    });
                }
            }
        }

        // в”Ђв”Ђв”Ђ COFF Analysis в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        let mut coff_info = None;

        if file_type == "COFF" {
            match coff_parser::parse_coff(&data) {
                Ok(coff) => {
                    let section_names: Vec<String> = coff.sections.iter()
                        .map(|s| s.name.clone())
                        .collect();
                    let functions: Vec<String> = coff.functions().iter()
                        .map(|s| s.name.clone())
                        .collect();
                    let externals: Vec<String> = coff.externals().iter()
                        .map(|s| s.name.clone())
                        .collect();

                    // Cache COFF symbols for backdoor analysis
                    if cached_import_names.is_empty() {
                        cached_import_names = externals.clone();
                    }

                    // Check for RWX sections
                    for section in &coff.sections {
                        if section.is_readable() && section.is_writable() && section.is_executable() {
                            findings.push(Finding {
                                severity: Severity::High,
                                module: "coff-parser".into(),
                                rule_id: "COFF_RWX_SECTION".into(),
                                description: format!("COFF has RWX section: {}", section.name),
                                details: None,
                            });
                        }
                    }

                    coff_info = Some(CoffInfo {
                        machine: coff.machine_name().to_string(),
                        num_sections: coff.sections.len(),
                        num_symbols: coff.symbols.len(),
                        timestamp: coff.header.time_date_stamp,
                        characteristics: Vec::new(),
                        section_names,
                        functions,
                        externals,
                    });
                }
                Err(e) => {
                    findings.push(Finding {
                        severity: Severity::Medium,
                        module: "coff-parser".into(),
                        rule_id: "COFF_PARSE_ERROR".into(),
                        description: format!("Failed to parse COFF: {}", e),
                        details: None,
                    });
                }
            }
        }

        // в”Ђв”Ђв”Ђ Flat Binary Analysis в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        let mut flat_binary_info = None;

        if file_type == "unknown" || file_type.starts_with("Script/") || file_type == "DOS" {
            // Try to parse as Intel HEX
            if let Ok(text) = std::str::from_utf8(&data) {
                if flat_binary::IntelHex::parse(text).is_ok() {
                    let ihex = flat_binary::IntelHex::parse(text).unwrap();
                    let bin = ihex.to_flat_binary(0);
                    let entropy = bin.entropy();
                    let looks_like_shellcode = bin.looks_like_shellcode();
                    let shellcode_type = bin.detect_shellcode_type().map(|s| s.to_string());

                    flat_binary_info = Some(FlatBinaryInfo {
                        size: bin.size(),
                        entropy,
                        looks_like_shellcode,
                        shellcode_type,
                        is_intel_hex: true,
                        is_srecord: false,
                    });
                } else if flat_binary::SRecord::parse(text).is_ok() {
                    let srec = flat_binary::SRecord::parse(text).unwrap();
                    let bin = srec.to_flat_binary(0);
                    let entropy = bin.entropy();
                    let looks_like_shellcode = bin.looks_like_shellcode();
                    let shellcode_type = bin.detect_shellcode_type().map(|s| s.to_string());

                    flat_binary_info = Some(FlatBinaryInfo {
                        size: bin.size(),
                        entropy,
                        looks_like_shellcode,
                        shellcode_type,
                        is_intel_hex: false,
                        is_srecord: true,
                    });
                } else {
                    // Raw binary вЂ” use from_slice to avoid cloning entire data
                    let bin = flat_binary::FlatBinary::from_slice(&data, 0);
                    let entropy = bin.entropy();
                    let looks_like_shellcode = bin.looks_like_shellcode();
                    let shellcode_type = bin.detect_shellcode_type().map(|s| s.to_string());

                    flat_binary_info = Some(FlatBinaryInfo {
                        size: bin.size(),
                        entropy,
                        looks_like_shellcode,
                        shellcode_type,
                        is_intel_hex: false,
                        is_srecord: false,
                    });
                }
            } else {
                // Binary data вЂ” use from_slice to avoid cloning entire data
                let bin = flat_binary::FlatBinary::from_slice(&data, 0);
                let entropy = bin.entropy();
                let looks_like_shellcode = bin.looks_like_shellcode();
                let shellcode_type = bin.detect_shellcode_type().map(|s| s.to_string());

                flat_binary_info = Some(FlatBinaryInfo {
                    size: bin.size(),
                    entropy,
                    looks_like_shellcode,
                    shellcode_type,
                    is_intel_hex: false,
                    is_srecord: false,
                });
            }
        }

        // [NEW FORMATS] Script / PDF / .NET / Python / Firmware / Dump / Arch
        let mut script_info: Option<ScriptInfo> = None;
        let mut pdf_info: Option<PdfInfo> = None;
        let mut dotnet_info: Option<DotnetInfo> = None;
        let mut pyc_info: Option<PycInfo> = None;
        let mut firmware_info: Option<FirmwareInfo> = None;
        let mut memdump_info: Option<MemdumpInfo> = None;
        let mut architecture_info: Option<ArchitectureInfo> = None;

        // --- Script Analysis (PowerShell / AutoIt / AHK / BAT / VBS) ---
        if file_type.starts_with("Script/")
            || (file_type == "unknown"
                && std::str::from_utf8(&data).is_ok()
                && script_detect_kind(&data).is_some())
        {
            if let Some(kind) = script_detect_kind(&data)
                .or(match file_type.as_str() {
                    "Script/PowerShell" => Some(script_analyzer::ScriptKind::PowerShell),
                    "Script/AutoIt" => Some(script_analyzer::ScriptKind::AutoIt),
                    "Script/AutoHotkey" => Some(script_analyzer::ScriptKind::AutoHotkey),
                    "Script/Batch" => Some(script_analyzer::ScriptKind::Batch),
                    "Script/VBScript" => Some(script_analyzer::ScriptKind::VBScript),
                    _ => None,
                })
            {
                let report = analyze_script(kind, &data);
                let highest_severity = report.findings.iter()
                    .map(|f| f.severity)
                    .max()
                    .map(|s| match s {
                        script_analyzer::ScriptSeverity::Critical => "Critical",
                        script_analyzer::ScriptSeverity::High => "High",
                        script_analyzer::ScriptSeverity::Medium => "Medium",
                        script_analyzer::ScriptSeverity::Low => "Low",
                        script_analyzer::ScriptSeverity::Info => "Info",
                    }.to_string())
                    .unwrap_or_else(|| "Info".into());
                for f in &report.findings {
                    let sev = match f.severity {
                        script_analyzer::ScriptSeverity::Critical => Severity::Critical,
                        script_analyzer::ScriptSeverity::High => Severity::High,
                        script_analyzer::ScriptSeverity::Medium => Severity::Medium,
                        script_analyzer::ScriptSeverity::Low => Severity::Low,
                        script_analyzer::ScriptSeverity::Info => Severity::Info,
                    };
                    findings.push(Finding {
                        severity: sev,
                        module: "script-analyzer".into(),
                        rule_id: f.rule_id.clone(),
                        description: f.description.clone(),
                        details: Some(format!("offset 0x{:X}", f.offset)),
                    });
                }
                if report.obfuscation_score >= 0.3 {
                    findings.push(Finding {
                        severity: Severity::Medium,
                        module: "script-analyzer".into(),
                        rule_id: "SCRIPT_OBFUSCATION".into(),
                        description: format!(
                            "Script obfuscation score {:.0}% — likely obfuscated/encoded",
                            report.obfuscation_score * 100.0
                        ),
                        details: Some(format!("kind: {:?}", report.kind)),
                    });
                }
                script_info = Some(ScriptInfo {
                    kind: format!("{:?}", report.kind),
                    line_count: report.line_count,
                    comment_count: report.comment_count,
                    avg_line_length: report.avg_line_length,
                    obfuscation_score: report.obfuscation_score,
                    finding_count: report.findings.len(),
                    highest_severity,
                    suspicious_calls: report.suspicious_calls,
                    iocs: report.iocs.into_iter().map(|i| ScriptIoc {
                        kind: format!("{:?}", i.kind),
                        value: i.value,
                    }).collect(),
                });
            }
        }

        // --- PDF Analysis ---
        if file_type == "PDF" {
            if let Some(report) = analyze_pdf(&data) {
                let highest = report.findings.iter()
                    .map(|f| f.severity).max()
                    .map(|s| match s {
                        pdf_analyzer::PdfSeverity::Critical => "Critical",
                        pdf_analyzer::PdfSeverity::High => "High",
                        pdf_analyzer::PdfSeverity::Medium => "Medium",
                        pdf_analyzer::PdfSeverity::Low => "Low",
                        pdf_analyzer::PdfSeverity::Info => "Info",
                    }.to_string())
                    .unwrap_or_else(|| "Info".into());
                for f in &report.findings {
                    let sev = match f.severity {
                        pdf_analyzer::PdfSeverity::Critical => Severity::Critical,
                        pdf_analyzer::PdfSeverity::High => Severity::High,
                        pdf_analyzer::PdfSeverity::Medium => Severity::Medium,
                        pdf_analyzer::PdfSeverity::Low => Severity::Low,
                        pdf_analyzer::PdfSeverity::Info => Severity::Info,
                    };
                    findings.push(Finding {
                        severity: sev,
                        module: "pdf-analyzer".into(),
                        rule_id: f.rule_id.clone(),
                        description: f.description.clone(),
                        details: Some(format!("offset 0x{:X}", f.offset)),
                    });
                }
                pdf_info = Some(PdfInfo {
                    version: report.version,
                    is_encrypted: report.is_encrypted,
                    is_linearized: report.is_linearized,
                    has_xfa: report.has_xfa,
                    has_javascript: report.has_javascript,
                    has_open_action: report.has_open_action,
                    has_launch_action: report.has_launch_action,
                    has_embedded_files: report.has_embedded_files,
                    has_acroform: report.has_acroform,
                    object_count: report.object_count,
                    page_count: report.page_count,
                    uri_count: report.uri_count,
                    suspicious_uris: report.suspicious_uris,
                    embedded_magic: report.embedded_magic,
                    finding_count: report.findings.len(),
                    highest_severity: highest,
                });
            }
        }

        // --- .NET / C# Analysis (only when PE flagged as .NET) ---
        if let Some(ref pei) = pe_info {
            if pei.is_dotnet {
                if let Some(report) = analyze_dotnet(&data) {
                    let highest = report.findings.iter()
                        .map(|f| f.severity).max()
                        .map(|s| match s {
                            dotnet_analyzer::DotnetSeverity::Critical => "Critical",
                            dotnet_analyzer::DotnetSeverity::High => "High",
                            dotnet_analyzer::DotnetSeverity::Medium => "Medium",
                            dotnet_analyzer::DotnetSeverity::Low => "Low",
                            dotnet_analyzer::DotnetSeverity::Info => "Info",
                        }.to_string())
                        .unwrap_or_else(|| "Info".into());
                    for f in &report.findings {
                        let sev = match f.severity {
                            dotnet_analyzer::DotnetSeverity::Critical => Severity::Critical,
                            dotnet_analyzer::DotnetSeverity::High => Severity::High,
                            dotnet_analyzer::DotnetSeverity::Medium => Severity::Medium,
                            dotnet_analyzer::DotnetSeverity::Low => Severity::Low,
                            dotnet_analyzer::DotnetSeverity::Info => Severity::Info,
                        };
                        findings.push(Finding {
                            severity: sev,
                            module: "dotnet-analyzer".into(),
                            rule_id: f.rule_id.clone(),
                            description: f.description.clone(),
                            details: Some(format!("offset 0x{:X}", f.offset)),
                        });
                    }
                    dotnet_info = Some(DotnetInfo {
                        metadata_version: report.metadata_version,
                        runtime_version: report.runtime_version,
                        entry_point_token: report.entry_point_token,
                        flags: report.flags,
                        strong_name_signed: report.strong_name_signed,
                        module_name: report.module_name,
                        assembly_ref_count: report.assembly_ref_count,
                        type_ref_count: report.type_ref_count,
                        method_def_count: report.method_def_count,
                        member_ref_count: report.member_ref_count,
                        user_string_count: report.user_string_count,
                        assembly_refs: report.assembly_refs,
                        suspicious_strings: report.suspicious_strings,
                        finding_count: report.findings.len(),
                        highest_severity: highest,
                    });
                }
            }
        }

        // --- Python / .pyc / PyInstaller ---
        if file_type == "Python/Compiled" {
            if let Some(report) = analyze_python(&data) {
                let highest = report.findings.iter()
                    .map(|f| f.severity).max()
                    .map(|s| match s {
                        pyc_parser::PycSeverity::Critical => "Critical",
                        pyc_parser::PycSeverity::High => "High",
                        pyc_parser::PycSeverity::Medium => "Medium",
                        pyc_parser::PycSeverity::Low => "Low",
                        pyc_parser::PycSeverity::Info => "Info",
                    }.to_string())
                    .unwrap_or_else(|| "Info".into());
                for f in &report.findings {
                    let sev = match f.severity {
                        pyc_parser::PycSeverity::Critical => Severity::Critical,
                        pyc_parser::PycSeverity::High => Severity::High,
                        pyc_parser::PycSeverity::Medium => Severity::Medium,
                        pyc_parser::PycSeverity::Low => Severity::Low,
                        pyc_parser::PycSeverity::Info => Severity::Info,
                    };
                    findings.push(Finding {
                        severity: sev,
                        module: "pyc-parser".into(),
                        rule_id: f.rule_id.clone(),
                        description: f.description.clone(),
                        details: Some(format!("offset 0x{:X}", f.offset)),
                    });
                }
                pyc_info = Some(PycInfo {
                    kind: format!("{:?}", report.kind),
                    python_version: report.python_version.map(|v| v.to_string()),
                    source_path: report.source_path,
                    is_pyinstaller: report.is_pyinstaller,
                    code_size: report.code_size,
                    imports: report.imports,
                    high_risk_imports: report.high_risk_imports,
                    urls: report.urls,
                    archive_entry_count: report.archive_entry_count,
                    archive_entries_sample: report.archive_entries.into_iter()
                        .map(|e| e.name).collect(),
                    finding_count: report.findings.len(),
                    highest_severity: highest,
                });
            }
        }

        // --- Firmware (UEFI / BIOS) ---
        if matches!(file_type.as_str(),
            "UEFI/FirmwareVolume" | "UEFI/FFS" | "UEFI/GPT-Disk" | "BIOS/MBR")
        {
            if let Some(report) = analyze_firmware(&data) {
                let finding_strs: Vec<String> = report.findings.iter()
                    .map(|f| format!("[{:?}] {}: {}", f.severity, f.rule_id, f.description))
                    .collect();
                for f in &report.findings {
                    let sev = match f.severity {
                        firmware_analyzer::FirmwareSeverity::Critical => Severity::Critical,
                        firmware_analyzer::FirmwareSeverity::High => Severity::High,
                        firmware_analyzer::FirmwareSeverity::Medium => Severity::Medium,
                        firmware_analyzer::FirmwareSeverity::Low => Severity::Low,
                        firmware_analyzer::FirmwareSeverity::Info => Severity::Info,
                    };
                    findings.push(Finding {
                        severity: sev,
                        module: "firmware-analyzer".into(),
                        rule_id: f.rule_id.clone(),
                        description: f.description.clone(),
                        details: Some(format!("offset 0x{:X}", f.offset)),
                    });
                }
                firmware_info = Some(FirmwareInfo {
                    kind: format!("{:?}", report.kind),
                    volume_count: report.volumes.len(),
                    gpt_partition_count: report.gpt_partitions.len(),
                    mbr_partition_count: report.mbr_partitions.len(),
                    embedded_pe_count: report.embedded_pe.len(),
                    findings: finding_strs,
                });
            }
        }

        // --- Memory Dump ---
        if matches!(file_type.as_str(),
            "Minidump" | "ELF Core" | "Mach-O Core")
            || (file_type == "unknown" && analyze_dump(&data).is_some())
        {
            if let Some(report) = analyze_dump(&data) {
                for f in &report.findings {
                    let sev = match f.severity {
                        memdump_analyzer::DumpSeverity::Critical => Severity::Critical,
                        memdump_analyzer::DumpSeverity::High => Severity::High,
                        memdump_analyzer::DumpSeverity::Medium => Severity::Medium,
                        memdump_analyzer::DumpSeverity::Low => Severity::Low,
                        memdump_analyzer::DumpSeverity::Info => Severity::Info,
                    };
                    findings.push(Finding {
                        severity: sev,
                        module: "memdump-analyzer".into(),
                        rule_id: f.rule_id.clone(),
                        description: f.description.clone(),
                        details: Some(format!("offset 0x{:X}", f.offset)),
                    });
                }
                memdump_info = Some(MemdumpInfo {
                    kind: format!("{:?}", report.kind),
                    stream_count: report.streams.len(),
                    embedded_pe_count: report.embedded_pe.len(),
                    raw_mz_hits: report.raw_mz_hits,
                    embedded_pe: report.embedded_pe.iter()
                        .map(|p| format!("{} {}-bit @ 0x{:X}",
                            p.machine, if p.is_64bit { 64 } else { 32 }, p.offset))
                        .collect(),
                });
            }
        }

        // --- Architecture auto-detection (ARM / AArch64 / x86_64 / x86) ---
        if file_type == "unknown" || file_type.starts_with("Mach-O")
            || flat_binary_info.is_some()
        {
            let arch_from_pe = if let Some(ref pi) = pe_info {
                match pi.machine.as_str() {
                    "Machine(0x14C)" => Some(("x86".to_string(), "little".to_string(), 32u8)),
                    "Machine(0x8664)" => Some(("x86_64".to_string(), "little".to_string(), 64u8)),
                    "Machine(0x1C0)" => Some(("ARM".to_string(), "little".to_string(), 32u8)),
                    "Machine(0xAA64)" => Some(("AArch64".to_string(), "little".to_string(), 64u8)),
                    "Machine(0x1C4)" => Some(("ARMNT".to_string(), "little".to_string(), 32u8)),
                    _ => None,
                }
            } else { None };
            if let Some((a, e, b)) = arch_from_pe {
                architecture_info = Some(ArchitectureInfo {
                    arch: a,
                    endian: e,
                    bitness: b,
                    confidence: 1.0,
                    indicators: vec!["PE machine code".into()],
                });
            } else if let Some(ref ei) = elf_info {
                let (a, e, b) = match ei.machine.as_str() {
                    "Machine(3)" => ("x86", "little", 32),
                    "Machine(62)" => ("x86_64", "little", 64),
                    "Machine(40)" => ("ARM", "little", 32),
                    "Machine(183)" => ("AArch64", "little", 64),
                    "Machine(20)" => ("PowerPC", "big", 32),
                    "Machine(21)" => ("PowerPC64", "big", 64),
                    _ => ("unknown", "unknown", 0),
                };
                architecture_info = Some(ArchitectureInfo {
                    arch: a.into(),
                    endian: e.into(),
                    bitness: b,
                    confidence: 1.0,
                    indicators: vec!["ELF e_machine".into()],
                });
            } else if (file_type == "unknown" || file_type.starts_with("BIOS") || file_type.starts_with("UEFI")) && pe_info.is_none() && elf_info.is_none() && !data.is_empty() {
                // Only run arch detection on raw binaries — skip text-like files
                let printable_count = data.iter().take(256).filter(|&&b| (0x20..=0x7E).contains(&b) || b == 0x09 || b == 0x0A || b == 0x0D).count();
                let total = data.len().min(256);
                let is_text = total > 0 && (printable_count as f64 / total as f64) > 0.85;
                if !is_text {
                    let d = detect_architecture(&data);
                let bitness = d.arch.bitness();
                let endian = d.arch.is_little_endian()
                    .map(|b| if b { "little".to_string() } else { "big".to_string() })
                    .unwrap_or_else(|| "unknown".into());
                let arch_name = match d.arch {
                    Arch::X86 => "x86",
                    Arch::X86_64 => "x86_64",
                    Arch::ArmLe | Arch::ArmBe => "ARM",
                    Arch::AArch64Le | Arch::AArch64Be => "AArch64",
                    Arch::Unknown => "unknown",
                }.to_string();
                if d.arch != Arch::Unknown {
                    architecture_info = Some(ArchitectureInfo {
                        arch: arch_name,
                        endian,
                        bitness,
                        confidence: d.confidence as f64 as f32,
                        indicators: d.indicators,
                    });
                }
                } // if !is_text
            }
        }

        // [BACKDOOR]
        let mut backdoor_report = None;

        // Backdoor/behavioral *pattern* detection (C2 beacon loops, DLL
        // hijacking) is unreliable for libraries вЂ” skipped for DLLs.
        if !is_library {
            let bd_report = analyze_backdoors(&data, &cached_import_names, &string_values);
            if !bd_report.findings.is_empty() {
                for bd_finding in &bd_report.findings {
                    let sev = match bd_finding.severity {
                        backdoor_analyzer::BackdoorSeverity::Critical => Severity::Critical,
                        backdoor_analyzer::BackdoorSeverity::High => Severity::High,
                        backdoor_analyzer::BackdoorSeverity::Medium => Severity::Medium,
                    };
                    findings.push(Finding {
                        severity: sev,
                        module: "backdoor-analyzer".into(),
                        rule_id: format!("{:?}", bd_finding.rule_id),
                        description: bd_finding.description.clone(),
                        details: Some(format!(
                            "MITRE: {} | Evidence: {}",
                            bd_finding.mitre_ids.join(", "),
                            bd_finding.evidence.join(", ")
                        )),
                    });
                }

                let categories: Vec<String> = bd_report
                    .findings
                    .iter()
                    .map(|f| format!("{:?}", f.rule_id))
                    .collect();
                let mitre: Vec<String> = bd_report
                    .findings
                    .iter()
                    .flat_map(|f| f.mitre_ids.iter().cloned())
                    .collect();

                backdoor_report = Some(BackdoorSummary {
                    risk_score: bd_report.risk_score,
                    verdict: format!("{}", bd_report.verdict),
                    num_findings: bd_report.findings.len(),
                    categories,
                    mitre_techniques: mitre,
                });
            }
        }

        // в”Ђв”Ђв”Ђ Shellcode Analysis в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        let mut shellcode_report = None;

        // File-offset ranges of non-code sections (resources, data, relocs).
        // Genuinely high entropy there is normal (icons, compressed resources),
        // so the shellcode analyzer must ignore them to avoid false positives.
        let mut ignore_ranges: Vec<(usize, usize)> = Vec::new();
        if let Some(pe) = pe {
            for section in &pe.sections {
                if !section.is_executable() {
                    let start = section.raw_data_offset as usize;
                    let end = start.saturating_add(section.raw_data_size as usize);
                    if end > start {
                        ignore_ranges.push((start, end));
                    }
                }
            }
        }

        let mut sc_config = ShellcodeConfig { ignore_ranges, ..Default::default() };
        // The XOR-encoded-blob brute force (255 keys x every window) is very
        // expensive on large PE files and only produces coincidental hits in
        // normal code. For PEs, staged shellcode is already caught by the
        // entropy-gated XOR_DECODER / packer detection, so skip it here.
        if file_type.starts_with("PE") {
            sc_config.max_blob_size = 0;
        }
        let sc_report = detect_shellcode(&data, &sc_config);

        // For libraries, generic/coincidental shellcode idioms are expected and
        // unreliable (a DLL's code routinely contains GetPC-like patterns, NOP
        // sleds, or high-entropy runs). Only specific, high-signal patterns are
        // kept for DLLs.
        let mut pushed_shellcode = false;
        let mut sc_section_entropy: std::collections::HashMap<usize, Option<f64>> =
            std::collections::HashMap::new();
        for sc_finding in &sc_report.findings {
            if is_library && is_weak_shellcode_finding(&sc_finding.rule_id) {
                continue;
            }
            // For PE files, shellcode patterns inside *normal* (low-entropy)
            // code sections are almost always coincidental вЂ” compilers emit
            // `xor [reg], imm8` / loops constantly. Only flag them in
            // high-entropy (в‰Ґ7.0) / anomalous regions where real self-
            // decrypting or packed code lives. Flat binaries / shellcode
            // blobs are scanned whole and kept as-is.
            if file_type.starts_with("PE") {
                if let Some(pe_ref) = pe.as_ref() {
                    if let Some(sec_idx) =
                        section_index_for_offset(pe_ref, sc_finding.offset)
                    {
                        let ent = *sc_section_entropy
                            .entry(sec_idx)
                            .or_insert_with(|| {
                                let s = &pe_ref.sections[sec_idx];
                                let start = s.raw_data_offset as usize;
                                let end =
                                    (start + s.raw_data_size as usize).min(data.len());
                                if end <= start {
                                    Some(0.0)
                                } else {
                                    Some(calculate_entropy(&data[start..end]).entropy)
                                }
                            });
                        if ent.unwrap_or(0.0) < 7.0 {
                            continue;
                        }
                    }
                }
            }
            let severity = if sc_finding.confidence >= 0.7 {
                Severity::High
            } else if sc_finding.confidence >= 0.5 {
                Severity::Medium
            } else {
                Severity::Low
            };
            findings.push(Finding {
                severity,
                module: "shellcode-analyzer".into(),
                rule_id: sc_finding.rule_id.clone(),
                description: sc_finding.description.clone(),
                details: Some(format!(
                    "Offset: 0x{:X}, Confidence: {:.0}%",
                    sc_finding.offset, sc_finding.confidence * 100.0
                )),
            });
            pushed_shellcode = true;
        }

        if pushed_shellcode {
            let patterns: Vec<String> = sc_report
                .findings
                .iter()
                .filter(|f| !(is_library && is_weak_shellcode_finding(&f.rule_id)))
                .map(|f| f.description.clone())
                .collect();

            shellcode_report = Some(ShellcodeSummary {
                verdict: format!("{}", sc_report.verdict),
                num_findings: sc_report.findings.len(),
                api_hashes_resolved: Vec::new(),
                patterns_detected: patterns,
            });
        }

        // в”Ђв”Ђв”Ђ Cross-Reference Analysis в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        let mut xref_summary = None;
        {
            let __tx = std::time::Instant::now();
            let string_xrefs = build_string_xrefs(&data, &strings);
            let import_xrefs_list = build_import_xrefs(&data, &cached_import_names);

            let mut db = XrefDatabase::new();
            db.add_all(string_xrefs);
            db.add_all(import_xrefs_list);

            if !db.is_empty() {
            let summary = db.summary();

                let correlated_pairs = [
                    ("cmd.exe", "CreateProcessA"),
                    ("cmd.exe", "WinExec"),
                    ("/bin/sh", "execve"),
                    ("powershell", "CreateProcessW"),
                ]
                .iter()
                .filter(|(a, b)| {
                    !db.xrefs_to(a).is_empty() && !db.xrefs_to(b).is_empty()
                })
                .count();

                if correlated_pairs > 0 {
                    findings.push(Finding {
                        severity: Severity::High,
                        module: "xrefs".into(),
                        rule_id: "CORRELATED_XREF_PAIR".into(),
                        description: format!(
                            "{} correlated string+import xref pair(s) detected",
                            correlated_pairs
                        ),
                        details: Some("Code references both suspicious strings and dangerous APIs".into()),
                    });
                }

                xref_summary = Some(XrefSummaryInfo {
                    total_xrefs: summary.total_xrefs,
                    unique_targets: summary.unique_targets,
                    string_xrefs: summary.string_xrefs,
                    import_xrefs: summary.import_xrefs,
                    correlated_pairs,
                });
            }
        }

        // в”Ђв”Ђв”Ђ CFG Analysis в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        let mut cfg_summary_info = None;
        {
            // Only run CFG on actual executable code sections.
            // Falling back to the entire file when .text is missing produces
            // meaningless anomalies (PE headers, strings, imports treated as code).
            let code_tuple: Option<(&[u8], usize, bool)> = if let Some(pe) = pe {
                // Try .text or CODE first
                let text_section = pe.sections.iter().find(|s| {
                    let name = s.name_string();
                    name == ".text" || name == "CODE"
                });
                // Fall back to any section with EXECUTE + CODE flags
                let code_section = text_section.or_else(|| {
                    pe.sections.iter().find(|s| s.is_executable() && s.is_code())
                });
                code_section.map(|sec| {
                    let raw = sec.raw_data(&data);
                    (raw, sec.virtual_address as usize, pe.is_64bit)
                })
                // If no code section found вЂ” skip CFG entirely (don't use whole file)
            } else {
                None
            };

            if let Some((code_region, code_base, is_64bit)) = code_tuple {
            if !code_region.is_empty() {
                let cfg_config = CfgConfig {
                    is_64bit,
                    base_va: code_base as u64,
                    max_instructions: 50_000,
                    ..Default::default()
                };
                let __tc = std::time::Instant::now();
                let cfg = build_cfg(code_region, code_base, &cfg_config);

                if !cfg.anomalies.is_empty() {
                    for anomaly in &cfg.anomalies {
                        let sev = match anomaly.severity {
                            cfg_builder::AnomalySeverity::High => Severity::High,
                            cfg_builder::AnomalySeverity::Medium => Severity::Medium,
                            cfg_builder::AnomalySeverity::Low => Severity::Low,
                            cfg_builder::AnomalySeverity::Info => Severity::Info,
                        };
                        findings.push(Finding {
                            severity: sev,
                            module: "cfg-builder".into(),
                            rule_id: "CFG_ANOMALY".into(),
                            description: anomaly.description.clone(),
                            details: if anomaly.offsets.is_empty() {
                                None
                            } else {
                                Some(format!("Offsets: {:?}", anomaly.offsets))
                            },
                        });
                    }
                }

                cfg_summary_info = Some(CfgSummaryInfo {
                    num_blocks: cfg.num_blocks(),
                    num_edges: cfg.num_edges(),
                    total_instructions: cfg.total_instructions,
                    num_anomalies: cfg.anomalies.len(),
                    anomalies: cfg.anomalies.iter().map(|a| a.description.clone()).collect(),
                    // Collect real edges for graph visualization
                    edges: cfg.blocks.iter()
                        .flat_map(|b| b.successors.iter().map(move |succ| (b.id as u32, *succ as u32)))
                        .collect(),
                });
            }
            // else: no code section found, skip CFG analysis
            }
        }

        // в”Ђв”Ђв”Ђ Function Signature Matching в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        let mut signature_summary_info = None;
        {
            let sig_config = SigScanConfig::default();
            let sig_result = scan_signatures(&data, 0, &sig_config);

            // NOTE: `KNOWN_FUNCTION` and `COMPILER_DETECTED` were previously
            // emitted as Info-level findings, but they are benign context that
            // does not affect the verdict and only added noise to clean files.
            // The compiler/library summary is preserved below for the report.
            signature_summary_info = Some(SignatureSummaryInfo {
                num_matches: sig_result.matches.len(),
                libraries_found: sig_result.libraries_found,
                compiler: sig_result
                    .compiler_info
                    .as_ref()
                    .map(|c| c.compiler.clone()),
            });
        }

        // в”Ђв”Ђв”Ђ YARA Scanning в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        if let Some(ref yara) = self.yara_scanner {
            let result = yara.scan(&data);
            if result.truncated {
                findings.push(Finding {
                    severity: Severity::Low,
                    module: "yara-lite".into(),
                    rule_id: "YARA_MATCH_BUDGET".into(),
                    description: format!(
                        "YARA match collection hit the safety budget ({}); counts may be incomplete",
                        yara_lite::MAX_COLLECTED_MATCHES
                    ),
                    details: None,
                });
            }
            for m in &result.matches {
                findings.push(Finding {
                    severity: Severity::High,
                    module: "yara-lite".into(),
                    rule_id: m.rule_name.clone(),
                    description: format!("YARA rule '{}' matched at offset 0x{:X}", m.rule_name, m.offset),
                    details: Some(format!(
                        "String '{}' matched ({} bytes)",
                        m.string_id, m.length
                    )),
                });
            }
        }

        // в”Ђв”Ђв”Ђ ML Classification в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        let mut ml_classification = None;
        let mut ml_malicious_confidence: f64 = 0.0;
        {
            // Real RWX section counts reported by the format parsers (PE
            // section flags, ELF/Mach-O RWX lists) — not an entropy proxy.
            let rwx_section_count = pe.map(|p| p.sections.iter().filter(|s| s.is_rwx()).count())
                .unwrap_or(0)
                + elf_info.as_ref().map(|e| e.rwx_sections.len()).unwrap_or(0)
                + macho_info.as_ref().map(|m| m.rwx_segments.len()).unwrap_or(0);

            // Build BinaryInfo from all gathered data
            let mut binary_info = ml_detection::BinaryInfo {
                num_sections: sections_entropy.len(),
                section_entropies: sections_entropy.iter().map(|s| s.entropy as f32).collect(),
                rwx_section_count,
                string_patterns: ml_detection::StringPatterns::from_strings(
                    &string_values
                ),
                ..Default::default()
            };

            // Populate import stats from PE import modules (DLL names)
            let imp = &mut binary_info.imports;
            imp.total_imports = cached_import_names.len();
            // Use cached DLL module names (populated during PE/ELF/Mach-O analysis)
            let dll_names = &cached_dll_names;
            imp.unique_dlls = dll_names.len();
            for name in dll_names {
                let lower = name.to_lowercase();
                if lower.contains("kernel32") { imp.kernel32 += 1; }
                if lower.contains("user32") { imp.user32 += 1; }
                if lower.contains("advapi32") { imp.advapi32 += 1; }
                if lower.contains("ws2_32") { imp.ws2_32 += 1; }
                if lower.contains("wininet") { imp.wininet += 1; }
                if lower.contains("urlmon") { imp.urlmon += 1; }
                if lower.contains("shell32") { imp.shell32 += 1; }
                if lower.contains("ole32") { imp.ole32 += 1; }
                if lower.contains("crypt32") { imp.crypt32 += 1; }
                if lower.contains("ntdll") { imp.ntdll += 1; }
                if lower.contains("msvcrt") { imp.msvcrt += 1; }
                if lower.contains("wtsapi32") { imp.wtsapi32 += 1; }
            }
            // NOTE: We intentionally do NOT double-count function names here.
            // DLL module names already capture the import source (e.g., kernel32.dll).
            // Counting individual functions like VirtualAlloc under kernel32 again
            // would inflate ML features and produce false positives.

            // Populate structural features
            if let Some(ref pei) = pe_info {
                binary_info.has_overlay = pei.has_overlay;
                binary_info.overlay_size_ratio = if size > 0 {
                    pei.overlay_size as f32 / size as f32
                } else { 0.0 };
                binary_info.has_tls = !pei.tls_callbacks.is_empty();
                binary_info.has_resources = pei.num_resources > 0;
                binary_info.num_data_dirs = pe_parse_result.as_ref()
                    .and_then(|r| r.as_ref().ok())
                    .map(|p| p.data_directories.len())
                    .unwrap_or(0);
                binary_info.is_packed = sections_entropy.iter().any(|s| s.entropy > 7.5);
                binary_info.code_section_entropy = sections_entropy.iter()
                    .find(|s| is_executable_section(&s.name))
                    .map(|s| s.entropy as f32)
                    .unwrap_or(0.0);
            }
            if let Some(ref elfi) = elf_info {
                binary_info.num_segments = elfi.num_segments;
                binary_info.is_packed = binary_info.is_packed
                    || sections_entropy.iter().any(|s| s.entropy > 7.5);
            }

            // Behavioral signals
            binary_info.behavioral.backdoor_risk = backdoor_report.as_ref().map(|b| b.risk_score as f32).unwrap_or(0.0);
            binary_info.behavioral.shellcode_score = if shellcode_report.is_some() { 1.0 } else { 0.0 };
            binary_info.behavioral.cfg_anomaly_count = cfg_summary_info.as_ref().map(|c| c.num_anomalies).unwrap_or(0);
            binary_info.behavioral.xref_correlation = xref_summary.as_ref().map(|x| x.correlated_pairs).unwrap_or(0);
            binary_info.behavioral.yara_match_count = findings
                .iter()
                .filter(|f| f.module == "yara-lite" && !is_yara_budget_notice(f))
                .count();

            let features = ml_detection::extract_features(&data, &binary_info);
            let classifier = ml_detection::EnsembleClassifier::new();
            let result = classifier.classify(&features);

            ml_malicious_confidence = result.probabilities.malicious as f64;

            let top_features: Vec<(String, f32)> = result.important_features
                .iter()
                .take(5)
                .map(|fi| (fi.name.to_string(), fi.contribution))
                .collect();

            // Add ML finding if confident
            if result.class == ml_detection::MalwareClass::Malicious && result.confidence > 0.7 {
                findings.push(Finding {
                    severity: Severity::High,
                    module: "ml-detection".into(),
                    rule_id: "ML_MALICIOUS".into(),
                    description: format!(
                        "ML classifier: MALICIOUS ({:.0}% confidence)",
                        result.confidence * 100.0
                    ),
                    details: Some(result.explanation.clone()),
                });
            } else if result.class == ml_detection::MalwareClass::Suspicious && result.confidence > 0.6 {
                findings.push(Finding {
                    severity: Severity::Medium,
                    module: "ml-detection".into(),
                    rule_id: "ML_SUSPICIOUS".into(),
                    description: format!(
                        "ML classifier: SUSPICIOUS ({:.0}% confidence)",
                        result.confidence * 100.0
                    ),
                    details: Some(result.explanation.clone()),
                });
            } else if result.class == ml_detection::MalwareClass::Packed && result.confidence > 0.7 {
                findings.push(Finding {
                    severity: Severity::Medium,
                    module: "ml-detection".into(),
                    rule_id: "ML_PACKED".into(),
                    description: format!(
                        "ML classifier: PACKED ({:.0}% confidence)",
                        result.confidence * 100.0
                    ),
                    details: Some(result.explanation.clone()),
                });
            }

            ml_classification = Some(MlClassificationInfo {
                classification: format!("{:?}", result.class),
                confidence: result.confidence as f64,
                explanation: result.explanation,
                top_features,
            });
        }

        // вЂDecompiler Pipeline (experimental) вЂ
        // Lift and decompile the largest detected function from .text.
        // Uses func-finder to locate real function boundaries instead of
        // blindly lifting the first N bytes (which may be data/padding).
        // This is opt-in via `decompiler` feature; failures don't affect scan results.
        #[cfg(feature = "decompiler")]
        if let Some(pe) = pe {
            if let Some(ref _cfg_summary) = cfg_summary_info {
                use freakre_ir::x86_lifter::X86Lifter;
                use freakre_ir::Lifter;
                use func_finder::{Architecture, FunctionFinder};
                use decompiler::{decompile_function, DecompilerConfig};
                
                // Extract code region from .text section
                let text_section = pe.sections.iter().find(|s| {
                    let name = s.name_string();
                    name == ".text" || name == "CODE"
                });
                
                if let Some(sec) = text_section {
                    let code_region = sec.raw_data(&data);
                    if !code_region.is_empty() {
                        // Find actual function boundaries using prologue scanning
                        let arch = if pe.is_64bit {
                            Architecture::X86_64
                        } else {
                            Architecture::X86
                        };
                        let finder = FunctionFinder::new(arch)
                            .with_code_base(sec.virtual_address as u64);
                        // pe.entry_point and sec.virtual_address are both RVAs from image base.
                        // FunctionFinder needs the VA, so use image_base + entry_point_rva.
                        let entry_va = pe.image_base + pe.entry_point as u64;
                        let detected = finder.find_all(code_region, &[entry_va])
                            .unwrap_or_default();
                        
                        // Pick the largest function (most meaningful to decompile)
                        let best = detected.iter()
                            .max_by_key(|f| f.size)
                            .or_else(|| detected.first());
                        
                        if let Some(func) = best {
                            let func_offset = (func.start - sec.virtual_address as u64) as usize;
                            let func_size = func.size;
                            // Safety: clamp to bounds
                            let func_end = (func_offset + func_size).min(code_region.len());
                            let func_slice = &code_region[func_offset..func_end];
                            
                            // Lift to IR
                            let lifter = X86Lifter::new(pe.is_64bit);
                            let func_name = format!("sub_{:X}", func.start);
                            match lifter.lift_function(func_slice, func.start, &func_name) {
                                Ok(ir_func) => {
                                    // Decompile to C pseudocode
                                    let _config = DecompilerConfig::default();
                                    match decompile_function(&ir_func) {
                                        Ok(c_code) => {
                                            findings.push(Finding {
                                                severity: Severity::Info,
                                                module: "decompiler".into(),
                                                rule_id: "DECOMPILED_CODE".into(),
                                                description: format!(
                                                    "Decompiled function at 0x{:X} ({} bytes) to C pseudocode",
                                                    func.start, func_size
                                                ),
                                                details: Some(c_code.lines().take(20).collect::<Vec<_>>().join("\n")),
                                            });
                                        }
                                        Err(e) => {
                                            findings.push(Finding {
                                                severity: Severity::Low,
                                                module: "decompiler".into(),
                                                rule_id: "DECOMPILE_FAILED".into(),
                                                description: format!("Decompiler failed: {}", e),
                                                details: None,
                                            });
                                        }
                                    }
                                }
                                Err(e) => {
                                    findings.push(Finding {
                                        severity: Severity::Low,
                                        module: "decompiler".into(),
                                        rule_id: "LIFT_FAILED".into(),
                                        description: format!("IR lifter failed: {}", e),
                                        details: None,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        // в”Ђв”Ђв”Ђ Strong-signal gate (noise-free) в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        // Pattern / behavioral heuristics (backdoor strings, import
        // capability, entropy, structural PE quirks) are unreliable on large
        // legitimate binaries and must be corroborated by a concrete
        // code-level signal вЂ” shellcode execution, a CFG anomaly, or packer
        // detection вЂ” before they can drive a non-clean verdict. Without such
        // a signal only Low/Medium findings are discarded; Critical/High
        // findings always survive so real malware is never silenced here.
        let has_strong_signal = findings.iter().any(|f| {
            f.rule_id.starts_with("PE_PACKER_")
                || matches!(
                    f.rule_id.as_str(),
                    "SHELLCODE_XOR_DECODER"
                        | "SHELLCODE_FPU_GETPC"
                        | "SHELLCODE_EGG_HUNTER"
                        | "SHELLCODE_XOR_ENCODED"
                        | "SHELLCODE_CALL_POP_GETPC"
                )
                || ((f.module == "shellcode-analyzer" || f.module == "cfg-builder")
                    && matches!(f.severity, Severity::High | Severity::Critical))
        });

        // в”Ђв”Ђв”Ђ Final Scoring в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
        let (suspicion_score, verdict) = if has_strong_signal {
            let max_severity = findings.iter().map(|f| f.severity).max();
            let backdoor_score = backdoor_report.as_ref().map(|b| b.risk_score).unwrap_or(0.0);
            let suspicion_score = calculate_suspicion_score(
                &findings,
                import_score,
                backdoor_score,
                &sections_entropy,
                shellcode_report.is_some(),
                xref_summary.as_ref().map(|x| x.correlated_pairs).unwrap_or(0),
                ml_malicious_confidence,
            );

            let verdict =
                determine_verdict(suspicion_score, max_severity, backdoor_score, &findings);
            (suspicion_score, verdict)
        } else {
            findings.retain(|f| matches!(f.severity, Severity::High | Severity::Critical));
            if findings.is_empty() {
                (0.0, Verdict::Clean)
            } else {
                let max_severity = findings.iter().map(|f| f.severity).max();
                let backdoor_score = backdoor_report.as_ref().map(|b| b.risk_score).unwrap_or(0.0);
                let suspicion_score = calculate_suspicion_score(
                    &findings,
                    import_score,
                    backdoor_score,
                    &sections_entropy,
                    shellcode_report.is_some(),
                    xref_summary.as_ref().map(|x| x.correlated_pairs).unwrap_or(0),
                    ml_malicious_confidence,
                );
                let verdict =
                    determine_verdict(suspicion_score, max_severity, backdoor_score, &findings);
                (suspicion_score, verdict)
            }
        };

        FileReport {
            path: path.to_path_buf(),
            size,
            sha256,
            md5,
            file_type,
            suspicion_score,
            verdict,
            findings,
            strings_found,
            sections_entropy,
            pe_info,
            elf_info,
            macho_info,
            wasm_info,
            dex_info,
            coff_info,
            flat_binary_info,
            script_info,
            pdf_info,
            dotnet_info,
            pyc_info,
            firmware_info,
            memdump_info,
            dll_info,
            architecture_info,
            backdoor_report,
            shellcode_report,
            xref_summary,
            cfg_summary: cfg_summary_info,
            signature_summary: signature_summary_info,
            ml_classification,
            scan_duration_ms: start.elapsed().as_millis(),
            functions: Vec::new(),
        }
    }
}
