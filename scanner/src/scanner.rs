use crate::report::*;
use backdoor_analyzer::analyze_backdoors;
use cfg_builder::{build_cfg, CfgConfig};
use elf_parser::ElfFile;
use entropy_rs::calculate_entropy;
use func_sigs::{scan_signatures, SigScanConfig};
use import_analyzer::ImportAnalyzer;
use ml_detection;
use pe_parser::PeFile;
use md5::{Md5, Digest};
use sha2::Sha256;
use shellcode_analyzer::{detect_shellcode, ShellcodeConfig};
use std::path::Path;
use std::time::Instant;
use str_extract::{extract_strings, ExtractConfig};
use xrefs::{build_string_xrefs, build_import_xrefs, XrefDatabase};

/// Core scanner that orchestrates all analysis modules
pub struct Scanner {
    yara_scanner: Option<yara_lite::Scanner>,
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
            .map(|r| yara_lite::compile_rule(r))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to compile YARA rules: {}", e))?;
        self.yara_scanner = Some(yara_lite::Scanner::new(compiled));
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
                    backdoor_report: None,
                    shellcode_report: None,
                    xref_summary: None,
                    cfg_summary: None,
                    signature_summary: None,
                    ml_classification: None,
                    scan_duration_ms: start.elapsed().as_millis(),
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

        // ─── PE Analysis ──────────────────────────────────────────────
        let mut pe_info = None;
        let mut sections_entropy = Vec::new();
        let mut import_score = 0.0;

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
            // PE warnings → findings
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
                let class = ent_result.classify();
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

            // Import analysis (single parse, cached result)
            let analyzer = ImportAnalyzer::new(&data, pe);
            let import_report = analyzer.analyze();
            import_score = import_report.suspicion_score;

            // Cache import names for backdoor analyzer
            cached_import_names = import_report
                .modules
                .iter()
                .flat_map(|m| m.functions.iter().filter_map(|f| f.name.clone()))
                .collect();

            // Cache DLL module names for ML feature extraction
            cached_dll_names = import_report
                .modules
                .iter()
                .map(|m| m.name.clone())
                .collect();

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

            // ─── PE Security Findings ─────────────────────────────
            let dll_flags = pe.dll_characteristics_flags();
            if !dll_flags.iter().any(|f| f.contains("ASLR")) {
                findings.push(Finding {
                    severity: Severity::High,
                    module: "pe-parser".into(),
                    rule_id: "PE_NO_ASLR".into(),
                    description: "PE lacks ASLR (DYNAMIC_BASE) — easier to exploit".into(),
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

            // TLS callbacks — execute before entry point
            let tls_cbs = pe.tls_callbacks();
            if !tls_cbs.is_empty() {
                let sev = if tls_cbs.len() > 3 { Severity::High } else { Severity::Medium };
                findings.push(Finding {
                    severity: sev,
                    module: "pe-parser".into(),
                    rule_id: "PE_TLS_CALLBACKS".into(),
                    description: format!(
                        "{} TLS callback(s) detected — code runs before entry point (anti-debug/unpacker)",
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
                    description: ".NET CLR assembly detected — static x86/x64 analysis limited".into(),
                    details: Some("Use IL disassembler (ILSpy/dnSpy) for full analysis".into()),
                });
            }

            // Overlay detection
            let overlay_size = pe.overlay_size();
            if overlay_size > 0 {
                let sev = if overlay_size > 1024 * 1024 { Severity::High } else { Severity::Medium };
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
                        "{} suspicious resource(s) of {} total (high entropy in .rsrc — possible packed payload)",
                        susp_res, num_res
                    ),
                    details: None,
                });
            }

            // Delay imports
            let delay_dlls = pe.delay_imports();
            if !delay_dlls.is_empty() {
                findings.push(Finding {
                    severity: Severity::Info,
                    module: "pe-parser".into(),
                    rule_id: "PE_DELAY_IMPORTS".into(),
                    description: format!("{} delay-imported DLL(s) detected", delay_dlls.len()),
                    details: Some(delay_dlls.join(", ")),
                });
            }

            // Rich header
            let rich = pe.rich_header();
            if rich.is_empty() && !pe.is_dotnet() {
                // Absence of Rich header in non-.NET PE compiled with MSVC is suspicious
                findings.push(Finding {
                    severity: Severity::Low,
                    module: "pe-parser".into(),
                    rule_id: "PE_NO_RICH_HEADER".into(),
                    description: "No Rich header found — unusual for MSVC-compiled binary (possible packer stripped it)".into(),
                    details: None,
                });
            }
        }

        // ─── ELF Analysis ─────────────────────────────────────────────
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
                        let class = ent_result.classify();
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

        // ─── Mach-O Analysis ──────────────────────────────────────────
        let mut macho_info = None;

        if file_type.starts_with("Mach-O") {
            // For fat/universal binaries, extract the first architecture slice
            let macho_data: &[u8] = if file_type == "Mach-O Fat" {
                match macho_parser::parse_fat_header(&data) {
                    Ok(archs) if !archs.is_empty() => {
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
                }
            } else {
                &data
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
                            let class = ent_result.classify();
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

        // ─── Backdoor Analysis (uses cached imports — no re-parse) ────
        let mut backdoor_report = None;

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

        // ─── Shellcode Analysis ───────────────────────────────────────
        let mut shellcode_report = None;

        let sc_config = ShellcodeConfig::default();
        let sc_report = detect_shellcode(&data, &sc_config);
        if !sc_report.findings.is_empty() {
            for sc_finding in &sc_report.findings {
                findings.push(Finding {
                    severity: Severity::High,
                    module: "shellcode-analyzer".into(),
                    rule_id: "SHELLCODE_PATTERN".into(),
                    description: sc_finding.description.clone(),
                    details: Some(format!(
                        "Offset: 0x{:X}, Confidence: {:.0}%",
                        sc_finding.offset, sc_finding.confidence * 100.0
                    )),
                });
            }

            let patterns: Vec<String> = sc_report
                .findings
                .iter()
                .map(|f| f.description.clone())
                .collect();

            shellcode_report = Some(ShellcodeSummary {
                verdict: format!("{}", sc_report.verdict),
                num_findings: sc_report.findings.len(),
                api_hashes_resolved: Vec::new(),
                patterns_detected: patterns,
            });
        }

        // ─── Cross-Reference Analysis ────────────────────────────────
        let mut xref_summary = None;
        {
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

        // ─── CFG Analysis ─────────────────────────────────────────────
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
                // If no code section found — skip CFG entirely (don't use whole file)
            } else {
                None
            };

            if let Some((code_region, code_base, is_64bit)) = code_tuple {
            if !code_region.is_empty() {
                let cfg_config = CfgConfig {
                    is_64bit,
                    max_instructions: 50_000,
                    ..Default::default()
                };
                let cfg = build_cfg(&code_region, code_base, &cfg_config);

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

        // ─── Function Signature Matching ──────────────────────────────
        let mut signature_summary_info = None;
        {
            let sig_config = SigScanConfig::default();
            let sig_result = scan_signatures(&data, 0, &sig_config);

            if !sig_result.matches.is_empty() || sig_result.compiler_info.is_some() {
                for m in &sig_result.matches {
                    findings.push(Finding {
                        severity: Severity::Info,
                        module: "func-sigs".into(),
                        rule_id: "KNOWN_FUNCTION".into(),
                        description: format!("Known function: {}::{}", m.signature.library, m.signature.function_name),
                        details: Some(format!("Offset: 0x{:X}, confidence: {:.0}%", m.offset, m.confidence * 100.0)),
                    });
                }

                if let Some(ref ci) = sig_result.compiler_info {
                    findings.push(Finding {
                        severity: Severity::Info,
                        module: "func-sigs".into(),
                        rule_id: "COMPILER_DETECTED".into(),
                        description: format!("Compiler detected: {}", ci.compiler),
                        details: Some(format!("Evidence: {}", ci.evidence.join("; "))),
                    });
                }

                signature_summary_info = Some(SignatureSummaryInfo {
                    num_matches: sig_result.matches.len(),
                    libraries_found: sig_result.libraries_found,
                    compiler: sig_result.compiler_info.map(|c| c.compiler),
                });
            }
        }

        // ─── YARA Scanning ────────────────────────────────────────────
        if let Some(ref yara) = self.yara_scanner {
            let result = yara.scan(&data);
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

        // ─── ML Classification ────────────────────────────────────────
        let mut ml_classification = None;
        let mut ml_malicious_confidence: f64 = 0.0;
        {
            // Build BinaryInfo from all gathered data
            let mut binary_info = ml_detection::BinaryInfo::default();
            binary_info.num_sections = sections_entropy.len();
            binary_info.section_entropies = sections_entropy.iter().map(|s| s.entropy as f32).collect();
            binary_info.rwx_section_count = sections_entropy.iter().filter(|s| s.entropy > 7.0).count();
            binary_info.string_patterns = ml_detection::StringPatterns::from_strings(
                &string_values
            );

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
            // Also check function names for suspicious API patterns
            for name in &cached_import_names {
                let lower = name.to_lowercase();
                if lower.contains("virtualalloc") || lower.contains("virtualprotect") { imp.kernel32 += 1; }
                if lower.contains("socket") || lower.contains("connect") || lower.contains("send") { imp.ws2_32 += 1; }
                if lower.contains("internetopen") || lower.contains("httpopen") { imp.wininet += 1; }
                if lower.contains("urldownload") || lower.contains("obtainuseragent") { imp.urlmon += 1; }
                if lower.contains("shellexecute") || lower.contains("shell_notify") { imp.shell32 += 1; }
                if lower.contains("cryptencrypt") || lower.contains("crypthash") { imp.crypt32 += 1; }
                if lower.contains("regopenkey") || lower.contains("regsetvalue") { imp.advapi32 += 1; }
            }

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
            binary_info.behavioral.yara_match_count = findings.iter().filter(|f| f.module == "yara-lite").count();

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

        // ─── Decompiler Pipeline (experimental) ───────────────────────
        // Attempt to lift and decompile the first detected function.
        // This is opt-in via `decompiler` feature; failures don't affect scan results.
        #[cfg(feature = "decompiler")]
        if let Some(pe) = pe {
            if let Some(ref _cfg_summary) = cfg_summary_info {
                use bibleteks_ir::x86_lifter::X86Lifter;
                use bibleteks_decompiler::{decompile_function, DecompilerConfig};
                
                // Extract code region from .text section
                let text_section = pe.sections.iter().find(|s| {
                    let name = s.name_string();
                    name == ".text" || name == "CODE"
                });
                
                if let Some(sec) = text_section {
                    let code_region = sec.raw_data(&data);
                    if !code_region.is_empty() {
                        // Limit to first 4KB for performance
                        let code_limit = code_region.len().min(4096);
                        let code_slice = &code_region[..code_limit];
                        
                        // Lift to IR
                        let lifter = X86Lifter::new(pe.is_64bit);
                        match lifter.lift_function(code_slice, sec.virtual_address as u64) {
                            Ok(ir_func) => {
                                // Decompile to C pseudocode
                                let config = DecompilerConfig::default();
                                match decompile_function(&ir_func) {
                                    Ok(c_code) => {
                                        findings.push(Finding {
                                            severity: Severity::Info,
                                            module: "decompiler".into(),
                                            rule_id: "DECOMPILED_CODE".into(),
                                            description: format!("Decompiled {} bytes of .text section to C pseudocode", code_limit),
                                            details: Some(c_code.lines().take(20).collect::<Vec<_>>().join("\n")),
                                        });
                                    }
                                    Err(e) => {
                                        // Decompilation failed — not critical, just log
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
                                // Lifting failed — not critical, just log
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

        // ─── Final Scoring ────────────────────────────────────────────
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

        let verdict = determine_verdict(suspicion_score, max_severity, backdoor_score, &findings);

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
            backdoor_report,
            shellcode_report,
            xref_summary,
            cfg_summary: cfg_summary_info,
            signature_summary: signature_summary_info,
            ml_classification,
            scan_duration_ms: start.elapsed().as_millis(),
        }
    }
}

/// Configurable scoring weights for the suspicion score calculation.
/// All weights can be calibrated against known malware/benign samples.
#[derive(Debug, Clone)]
pub struct ScoringConfig {
    // ─── Module signal weights ────────────────────────────────
    pub import_weight: f64,
    pub backdoor_weight: f64,
    pub shellcode_signal: f64,
    /// Weight for ML-based malicious confidence (0.0-1.0 signal).
    pub ml_weight: f64,

    // ─── YARA weights ─────────────────────────────────────────
    pub yara_per_match: f64,
    pub yara_cap: f64,

    // ─── Critical findings (index = count, diminishing returns)
    pub critical_weights: [f64; 4], // [0, 1, 2, 3+]

    // ─── High findings (index = count, diminishing returns)
    pub high_weights: [f64; 6],     // [0, 1, 2, 3, 4, 5+]

    // ─── Medium/Low per-finding weights and caps
    pub medium_per_finding: f64,
    pub medium_cap: f64,
    pub low_per_finding: f64,
    pub low_cap: f64,

    // ─── Structural signals ───────────────────────────────────
    pub packed_executable_bonus: f64,
    pub xref_per_pair: f64,
    pub xref_cap: f64,

    // ─── Signal compounding ───────────────────────────────────
    pub compounding_3plus: f64,
    pub compounding_5plus: f64,

    // ─── Thresholds for active signal categories
    pub import_active_threshold: f64,
    pub backdoor_active_threshold: f64,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            import_weight: 0.25,
            backdoor_weight: 0.25,
            shellcode_signal: 0.25,
            ml_weight: 0.15,

            yara_per_match: 0.15,
            yara_cap: 0.45,

            critical_weights: [0.0, 0.20, 0.25, 0.30],
            high_weights: [0.0, 0.10, 0.15, 0.18, 0.20, 0.22],

            medium_per_finding: 0.04,
            medium_cap: 0.20,
            low_per_finding: 0.01,
            low_cap: 0.05,

            packed_executable_bonus: 0.08,
            xref_per_pair: 0.05,
            xref_cap: 0.15,

            compounding_3plus: 0.05,
            compounding_5plus: 0.05,

            import_active_threshold: 0.3,
            backdoor_active_threshold: 0.2,
        }
    }
}

/// Calculate suspicion score using weighted signal correlation.
///
/// The scoring considers:
/// - Module scores (import analyzer, backdoor analyzer) as base signals
/// - Finding severity with diminishing returns for repeated low-severity signals
/// - Content-based signals (shellcode, YARA matches) as strong indicators
/// - Structural anomalies (RWX sections, high entropy) as moderate indicators
/// - Cross-module correlations (xref pairs, cfg anomalies) as amplifiers
/// - ML classification as a strong indicator (if available)
///
/// All weights are configurable via `ScoringConfig` for calibration against
/// known malware/benign sample datasets.
///
/// Returns a value in [0.0, 1.0] where higher = more suspicious.
pub fn calculate_suspicion_score_with_config(
    cfg: &ScoringConfig,
    findings: &[Finding],
    import_score: f64,
    backdoor_score: f64,
    sections_entropy: &[SectionEntropy],
    has_shellcode: bool,
    correlated_xref_pairs: usize,
    ml_confidence_malicious: f64,
) -> f64 {
    let mut score: f64 = 0.0;

    // ─── Base module scores (already normalized 0.0-1.0) ───────────
    score += import_score * cfg.import_weight;
    score += backdoor_score * cfg.backdoor_weight;

    // ─── ML-based signal (strong indicator) ───────────────────────
    score += ml_confidence_malicious * cfg.ml_weight;

    // ─── Content-based signals (very strong) ───────────────────────
    if has_shellcode {
        score += cfg.shellcode_signal;
    }

    // ─── Finding-based scoring with diminishing returns ─────────────
    let mut critical_count = 0usize;
    let mut high_count = 0usize;
    let mut medium_count = 0usize;
    let mut low_count = 0usize;
    let mut yara_matches = 0usize;

    for f in findings {
        match f.severity {
            Severity::Critical => critical_count += 1,
            Severity::High => {
                if f.module == "yara-lite" {
                    yara_matches += 1;
                } else {
                    high_count += 1;
                }
            }
            Severity::Medium => medium_count += 1,
            Severity::Low => low_count += 1,
            Severity::Info => {}
        }
    }

    // YARA matches
    score += (yara_matches as f64 * cfg.yara_per_match).min(cfg.yara_cap);

    // Critical findings (diminishing returns, capped at index 3+)
    let crit_idx = critical_count.min(cfg.critical_weights.len() - 1);
    score += cfg.critical_weights[crit_idx];

    // High findings (diminishing returns, capped at index 5+)
    let high_idx = high_count.min(cfg.high_weights.len() - 1);
    score += cfg.high_weights[high_idx];

    // Medium findings
    score += (medium_count as f64 * cfg.medium_per_finding).min(cfg.medium_cap);

    // Low findings
    score += (low_count as f64 * cfg.low_per_finding).min(cfg.low_cap);

    // ─── Structural signals ────────────────────────────────────────
    let suspicious_high_entropy = sections_entropy
        .iter()
        .filter(|s| s.entropy > 7.0 && is_executable_section(&s.name))
        .count();
    if suspicious_high_entropy > 0 {
        score += cfg.packed_executable_bonus;
    }

    // ─── Cross-module correlation amplifier ─────────────────────────
    if correlated_xref_pairs > 0 {
        score += (correlated_xref_pairs as f64 * cfg.xref_per_pair).min(cfg.xref_cap);
    }

    // ─── Signal compounding bonus ──────────────────────────────────
    let signal_categories = [
        import_score > cfg.import_active_threshold,
        backdoor_score > cfg.backdoor_active_threshold,
        has_shellcode,
        high_count > 0,
        suspicious_high_entropy > 0,
        yara_matches > 0,
    ];
    let active_signals = signal_categories.iter().filter(|&&x| x).count();
    if active_signals >= 3 {
        score += cfg.compounding_3plus;
    }
    if active_signals >= 5 {
        score += cfg.compounding_5plus;
    }

    score.min(1.0)
}

/// Calculate suspicion score using default configuration.
pub fn calculate_suspicion_score(
    findings: &[Finding],
    import_score: f64,
    backdoor_score: f64,
    sections_entropy: &[SectionEntropy],
    has_shellcode: bool,
    correlated_xref_pairs: usize,
    ml_confidence_malicious: f64,
) -> f64 {
    let cfg = ScoringConfig::default();
    calculate_suspicion_score_with_config(
        &cfg,
        findings,
        import_score,
        backdoor_score,
        sections_entropy,
        has_shellcode,
        correlated_xref_pairs,
        ml_confidence_malicious,
    )
}

/// Determine the final verdict based on all signals.
fn determine_verdict(
    suspicion_score: f64,
    max_severity: Option<Severity>,
    backdoor_score: f64,
    findings: &[Finding],
) -> Verdict {
    if findings.is_empty() {
        return Verdict::Clean;
    }

    // Hard overrides: certain signals force Malicious regardless of score
    let has_critical = max_severity == Some(Severity::Critical);
    let has_shellcode_finding = findings
        .iter()
        .any(|f| f.module == "shellcode-analyzer");
    let has_yara_match = findings.iter().any(|f| f.module == "yara-lite");

    if has_critical || has_shellcode_finding {
        return Verdict::Malicious;
    }

    // Score-based classification
    if suspicion_score >= 0.65 || backdoor_score >= 0.7 || has_yara_match {
        Verdict::Malicious
    } else if suspicion_score >= 0.35
        || max_severity >= Some(Severity::High)
        || backdoor_score >= 0.4
    {
        Verdict::Suspicious
    } else if suspicion_score >= 0.15 || max_severity >= Some(Severity::Medium) {
        Verdict::Suspicious
    } else {
        Verdict::Clean
    }
}

/// Check if a section name corresponds to an executable section.
fn is_executable_section(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower == ".text"
        || lower == "code"
        || lower == ".code"
        || lower.contains("exec")
        || lower == ".init"
        || lower == ".fini"
}

fn detect_file_type(data: &[u8]) -> String {
    if data.len() < 4 {
        return "unknown".into();
    }

    // ─── PE / DOS ───────────────────────────────────────────────────
    if data.starts_with(b"MZ") {
        if data.len() > 60 {
            let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
            if pe_offset + 4 <= data.len() && &data[pe_offset..pe_offset + 4] == b"PE\0\0" {
                if pe_offset + 24 <= data.len() {
                    let magic = u16::from_le_bytes([data[pe_offset + 24], data[pe_offset + 25]]);
                    return if magic == 0x20B {
                        "PE32+".into()
                    } else {
                        "PE32".into()
                    };
                }
            }
        }
        return "DOS".into();
    }

    // ─── ELF ────────────────────────────────────────────────────────
    if data.starts_with(b"\x7FELF") {
        return "ELF".into();
    }

    // ─── Mach-O ────────────────────────────────────────────────────
    // Mach-O magic values:
    //   0xFEEDFACE = MH_MAGIC    (32-bit, native byte order)
    //   0xFEEDFACF = MH_MAGIC_64 (64-bit, native byte order)
    //   0xCEFAEDFE = MH_CIGAM    (32-bit, swapped byte order)
    //   0xCFFAEDFE = MH_CIGAM_64 (64-bit, swapped byte order)
    //   0xCAFEBABE = FAT_MAGIC   (Universal/Fat binary)
    //   0xBEBAFECA = FAT_CIGAM   (Universal/Fat binary, swapped)
    if data.len() >= 4 {
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        match magic {
            // Fat/Universal binary (contains multiple architectures)
            0xCAFEBABE | 0xBEBAFECA => return "Mach-O Fat".into(),
            _ => {}
        }
        let magic_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        match magic_le {
            0xFEEDFACE => return "Mach-O 32-bit".into(),
            0xFEEDFACF => return "Mach-O 64-bit".into(),
            _ => {}
        }
        // Check big-endian variants (MH_CIGAM / MH_CIGAM_64)
        let magic_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        match magic_be {
            0xFEEDFACE => return "Mach-O 32-bit (BE)".into(),
            0xFEEDFACF => return "Mach-O 64-bit (BE)".into(),
            0xCEFAEDFE => return "Mach-O 32-bit (swapped)".into(),
            0xCFFAEDFE => return "Mach-O 64-bit (swapped)".into(),
            _ => {}
        }
    }

    // ─── Script files (shebang detection) ───────────────────────────
    if data.starts_with(b"#!") {
        // Read first line to identify interpreter
        let first_line_end = data.iter().position(|&b| b == b'\n').unwrap_or(data.len().min(256));
        let first_line = String::from_utf8_lossy(&data[2..first_line_end]);
        let line = first_line.to_lowercase();

        if line.contains("python") || line.contains("python3") || line.contains("python2") {
            return "Script/Python".into();
        }
        if line.contains("bash") || line.contains("sh") || line.contains("zsh") || line.contains("ksh") {
            return "Script/Shell".into();
        }
        if line.contains("perl") {
            return "Script/Perl".into();
        }
        if line.contains("ruby") {
            return "Script/Ruby".into();
        }
        if line.contains("node") || line.contains("js") || line.contains("deno") {
            return "Script/JavaScript".into();
        }
        if line.contains("php") {
            return "Script/PHP".into();
        }
        if line.contains("lua") {
            return "Script/Lua".into();
        }
        if line.contains("awk") {
            return "Script/Awk".into();
        }
        return "Script/Unknown".into();
    }

    // ─── Batch / PowerShell scripts (no shebang) ───────────────────
    // Batch files often start with @echo off or @rem
    if data.starts_with(b"@echo") || data.starts_with(b"@ECHO") || data.starts_with(b"@rem") {
        return "Script/Batch".into();
    }

    // PowerShell scripts often start with UTF-8 BOM or specific patterns
    if data.len() >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
        // UTF-8 BOM — could be PS1, check further
        let body = &data[3..];
        let preview = String::from_utf8_lossy(&body[..body.len().min(128)]).to_lowercase();
        if preview.contains("param(") || preview.contains("function ") || preview.contains("invoke-") || preview.contains("get-") {
            return "Script/PowerShell".into();
        }
    }

    "unknown".into()
}

fn hex_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn hex_md5(data: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(severity: Severity, module: &str) -> Finding {
        Finding {
            severity,
            module: module.into(),
            rule_id: "TEST".into(),
            description: "test".into(),
            details: None,
        }
    }

    #[test]
    fn test_clean_file_score() {
        let findings: Vec<Finding> = vec![];
        let score = calculate_suspicion_score(
            &findings,
            0.0,
            0.0,
            &[],
            false,
            0,
            0.0, // no ML signal
        );
        assert_eq!(score, 0.0);
    }

    #[test]
    fn test_single_critical_finding() {
        let findings = vec![make_finding(Severity::Critical, "pe-parser")];
        let score = calculate_suspicion_score(
            &findings,
            0.0,
            0.0,
            &[],
            false,
            0,
            0.0,
        );
        assert!(score >= 0.20, "Critical finding should give at least 0.20, got {}", score);
    }

    #[test]
    fn test_yara_match_boosts_score() {
        let findings = vec![make_finding(Severity::High, "yara-lite")];
        let score = calculate_suspicion_score(
            &findings,
            0.0,
            0.0,
            &[],
            false,
            0,
            0.0,
        );
        assert!(score >= 0.15, "YARA match should give at least 0.15, got {}", score);
    }

    #[test]
    fn test_shellcode_gives_strong_signal() {
        let findings = vec![make_finding(Severity::High, "shellcode-analyzer")];
        let score = calculate_suspicion_score(
            &findings,
            0.0,
            0.0,
            &[],
            true, // has_shellcode
            0,
            0.0,
        );
        assert!(score >= 0.25, "Shellcode should give at least 0.25, got {}", score);
    }

    #[test]
    fn test_high_entropy_executable_section() {
        let sections = vec![SectionEntropy {
            name: ".text".into(),
            entropy: 7.5,
            classification: "high".into(),
        }];
        let findings = vec![];
        let score = calculate_suspicion_score(
            &findings,
            0.0,
            0.0,
            &sections,
            false,
            0,
            0.0,
        );
        assert!(score >= 0.08, "High entropy in .text should add 0.08, got {}", score);
    }

    #[test]
    fn test_correlated_xref_pairs() {
        let findings = vec![];
        let score = calculate_suspicion_score(
            &findings,
            0.0,
            0.0,
            &[],
            false,
            2, // 2 correlated pairs
            0.0,
        );
        assert!(score >= 0.10, "2 xref pairs should add ~0.10, got {}", score);
    }

    #[test]
    fn test_diminishing_returns_high_findings() {
        let one_high = vec![make_finding(Severity::High, "pe-parser")];
        let five_high = vec![
            make_finding(Severity::High, "pe-parser"),
            make_finding(Severity::High, "pe-parser"),
            make_finding(Severity::High, "pe-parser"),
            make_finding(Severity::High, "pe-parser"),
            make_finding(Severity::High, "pe-parser"),
        ];
        let score_one = calculate_suspicion_score(&one_high, 0.0, 0.0, &[], false, 0, 0.0);
        let score_five = calculate_suspicion_score(&five_high, 0.0, 0.0, &[], false, 0, 0.0);
        // 5 high findings should not be 5x the score of 1
        assert!(score_five < score_one * 3.0, "Diminishing returns not working");
    }

    #[test]
    fn test_compounding_bonus() {
        // Multiple signal categories active
        let findings = vec![
            make_finding(Severity::High, "pe-parser"),
            make_finding(Severity::High, "yara-lite"),
        ];
        let sections = vec![SectionEntropy {
            name: ".text".into(),
            entropy: 7.5,
            classification: "high".into(),
        }];
        let score = calculate_suspicion_score(
            &findings,
            0.5,   // import_score > 0.3
            0.3,   // backdoor_score > 0.2
            &sections,
            true,  // has_shellcode
            1,     // correlated pairs
            0.0,
        );
        // With 6 signal categories active, should get both compounding bonuses
        assert!(score >= 0.70, "Compounding should push score high, got {}", score);
    }

    #[test]
    fn test_ml_signal_boosts_score() {
        let findings = vec![];
        let score = calculate_suspicion_score(
            &findings,
            0.0,
            0.0,
            &[],
            false,
            0,
            0.9, // strong ML malicious signal
        );
        assert!(score >= 0.13, "ML signal (0.9 * 0.15) should add ~0.135, got {}", score);
    }

    #[test]
    fn test_verdict_clean() {
        let verdict = determine_verdict(0.0, None, 0.0, &[]);
        assert_eq!(verdict, Verdict::Clean);
    }

    #[test]
    fn test_verdict_malicious_from_critical() {
        let findings = vec![make_finding(Severity::Critical, "pe-parser")];
        let verdict = determine_verdict(0.5, Some(Severity::Critical), 0.0, &findings);
        assert_eq!(verdict, Verdict::Malicious);
    }

    #[test]
    fn test_verdict_malicious_from_shellcode() {
        let findings = vec![make_finding(Severity::High, "shellcode-analyzer")];
        let verdict = determine_verdict(0.4, Some(Severity::High), 0.0, &findings);
        assert_eq!(verdict, Verdict::Malicious);
    }

    #[test]
    fn test_verdict_malicious_from_yara() {
        let findings = vec![make_finding(Severity::High, "yara-lite")];
        let verdict = determine_verdict(0.3, Some(Severity::High), 0.0, &findings);
        assert_eq!(verdict, Verdict::Malicious);
    }

    #[test]
    fn test_verdict_suspicious() {
        let findings = vec![make_finding(Severity::Medium, "pe-parser")];
        let verdict = determine_verdict(0.25, Some(Severity::Medium), 0.0, &findings);
        assert_eq!(verdict, Verdict::Suspicious);
    }

    #[test]
    fn test_is_executable_section() {
        assert!(is_executable_section(".text"));
        assert!(is_executable_section("CODE"));
        assert!(is_executable_section(".code"));
        assert!(is_executable_section(".init"));
        assert!(!is_executable_section(".data"));
        assert!(!is_executable_section(".rdata"));
        assert!(!is_executable_section(".rsrc"));
    }

    #[test]
    fn test_detect_file_type() {
        assert_eq!(detect_file_type(b"MZ\x90\x00"), "DOS");
        assert_eq!(detect_file_type(b"\x7FELF"), "ELF");
        assert_eq!(detect_file_type(b"AAAA"), "unknown");
        assert_eq!(detect_file_type(b""), "unknown");

        // Mach-O 64-bit (little-endian)
        let mut macho64 = [0u8; 32];
        macho64[0] = 0xCF; macho64[1] = 0xFA; macho64[2] = 0xED; macho64[3] = 0xFE;
        assert_eq!(detect_file_type(&macho64), "Mach-O 64-bit");

        // Mach-O 32-bit (little-endian)
        let mut macho32 = [0u8; 32];
        macho32[0] = 0xCE; macho32[1] = 0xFA; macho32[2] = 0xED; macho32[3] = 0xFE;
        assert_eq!(detect_file_type(&macho32), "Mach-O 32-bit");

        // Mach-O Fat binary
        let mut fat = [0u8; 32];
        fat[0] = 0xCA; fat[1] = 0xFE; fat[2] = 0xBA; fat[3] = 0xBE;
        assert_eq!(detect_file_type(&fat), "Mach-O Fat");

        // Python script
        let py = b"#!/usr/bin/env python3\nprint('hello')";
        assert_eq!(detect_file_type(py), "Script/Python");

        // Shell script
        let sh = b"#!/bin/bash\necho hello";
        assert_eq!(detect_file_type(sh), "Script/Shell");

        // Batch file
        let bat = b"@echo off\necho hello";
        assert_eq!(detect_file_type(bat), "Script/Batch");
    }
}
