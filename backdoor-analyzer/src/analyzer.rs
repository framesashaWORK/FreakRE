//! Core backdoor analysis engine.
//! Combines import signatures, string signatures, and structural heuristics
//! to detect 12 categories of backdoor behavior.

use crate::report::{BackdoorFinding, BackdoorReport, BackdoorSeverity};
use crate::rules::{BackdoorRuleId, ImportSignature, IMPORT_SIGNATURES, STRING_SIGNATURES};

/// Analyze a binary for backdoor indicators.
///
/// # Arguments
/// * `data` - Raw file bytes (used for entropy/structural checks)
/// * `import_names` - List of imported function names (case-insensitive matching)
/// * `strings` - Extracted strings from the binary
pub fn analyze_backdoors(
    data: &[u8],
    import_names: &[String],
    strings: &[&str],
) -> BackdoorReport {
    let mut findings = Vec::new();

    // Normalize imports to lowercase for case-insensitive matching
    let imports_lower: Vec<String> = import_names.iter().map(|s| s.to_lowercase()).collect();

    // Check import-based signatures
    check_import_signatures(&imports_lower, &mut findings);

    // Check string-based signatures
    check_string_signatures(strings, &mut findings);

    // Structural heuristics on raw data
    check_structural_heuristics(data, &imports_lower, &mut findings);

    // Deduplicate by rule_id (keep highest severity)
    deduplicate_findings(&mut findings);

    BackdoorReport::from_findings(findings)
}

fn check_import_signatures(imports_lower: &[String], findings: &mut Vec<BackdoorFinding>) {
    for sig in IMPORT_SIGNATURES {
        if matches_import_signature(imports_lower, sig) {
            let evidence: Vec<String> = sig
                .required_apis
                .iter()
                .chain(sig.optional_apis.iter())
                .filter(|api| imports_lower.iter().any(|i| i.contains(&api.to_lowercase())))
                .map(|s| s.to_string())
                .collect();

            findings.push(BackdoorFinding {
                rule_id: sig.rule_id,
                severity: sig.rule_id.default_severity(),
                description: sig.rule_id.description().to_string(),
                evidence,
                mitre_ids: sig
                    .rule_id
                    .mitre_ids()
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            });
        }
    }
}

fn matches_import_signature(imports_lower: &[String], sig: &ImportSignature) -> bool {
    // All required APIs must be present
    let all_required = sig.required_apis.iter().all(|api| {
        let api_lower = api.to_lowercase();
        imports_lower.iter().any(|i| i.contains(&api_lower))
    });

    if !all_required {
        return false;
    }

    // Check optional APIs threshold
    if sig.min_optional > 0 {
        let optional_count = sig.optional_apis.iter().filter(|api| {
            let api_lower = api.to_lowercase();
            imports_lower.iter().any(|i| i.contains(&api_lower))
        }).count();

        if optional_count < sig.min_optional {
            return false;
        }
    }

    true
}

fn check_string_signatures(strings: &[&str], findings: &mut Vec<BackdoorFinding>) {
    for sig in STRING_SIGNATURES {
        let match_count = sig.patterns.iter().filter(|pattern| {
            let pattern_lower = pattern.to_lowercase();
            strings.iter().any(|s| s.to_lowercase().contains(&pattern_lower))
        }).count();

        if match_count >= sig.min_matches {
            let matched_patterns: Vec<String> = sig
                .patterns
                .iter()
                .filter(|p| {
                    let p_lower = p.to_lowercase();
                    strings.iter().any(|s| s.to_lowercase().contains(&p_lower))
                })
                .map(|s| s.to_string())
                .collect();

            findings.push(BackdoorFinding {
                rule_id: sig.rule_id,
                severity: sig.rule_id.default_severity(),
                description: sig.rule_id.description().to_string(),
                evidence: matched_patterns,
                mitre_ids: sig
                    .rule_id
                    .mitre_ids()
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            });
        }
    }
}

fn check_structural_heuristics(
    data: &[u8],
    imports_lower: &[String],
    findings: &mut Vec<BackdoorFinding>,
) {
    // Encrypted config detection: high entropy region near network imports
    let has_net_imports = imports_lower.iter().any(|i| {
        i.contains("wsastartup") || i.contains("connect") || i.contains("recv")
            || i.contains("send") || i.contains("internetopen") || i.contains("winhttp")
    });

    if has_net_imports && data.len() > 256 {
        // Check for high-entropy blocks (>7.0) that could be encrypted configs
        let window_size = 256;
        let step = 128;
        let mut high_entropy_regions = 0;

        for offset in (0..data.len().saturating_sub(window_size)).step_by(step) {
            let chunk = &data[offset..offset + window_size];
            let entropy = entropy_rs::calculate_entropy(chunk).entropy;
            if entropy > 7.0 {
                high_entropy_regions += 1;
            }
        }

        if high_entropy_regions >= 2 {
            findings.push(BackdoorFinding {
                rule_id: BackdoorRuleId::EncryptedConfig,
                severity: BackdoorSeverity::Medium,
                description: "High-entropy encrypted config block detected near network API imports".to_string(),
                evidence: vec![format!("{} high-entropy regions found", high_entropy_regions)],
                mitre_ids: BackdoorRuleId::EncryptedConfig
                    .mitre_ids()
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            });
        }
    }
}

fn deduplicate_findings(findings: &mut Vec<BackdoorFinding>) {
    use std::collections::HashMap;

    let mut best: HashMap<BackdoorRuleId, usize> = HashMap::new();

    for (idx, f) in findings.iter().enumerate() {
        best.entry(f.rule_id)
            .and_modify(|existing| {
                if f.severity > findings[*existing].severity {
                    *existing = idx;
                }
            })
            .or_insert(idx);
    }

    let keep_indices: Vec<usize> = best.into_values().collect();
    let mut deduped: Vec<BackdoorFinding> = Vec::with_capacity(keep_indices.len());
    for idx in keep_indices {
        deduped.push(findings[idx].clone());
    }

    // Sort by severity descending
    deduped.sort_by(|a, b| b.severity.cmp(&a.severity));

    *findings = deduped;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_binary() {
        let report = analyze_backdoors(&[0u8; 64], &[], &[]);
        assert_eq!(report.verdict, crate::report::BackdoorVerdict::Clean);
    }

    #[test]
    fn test_reverse_shell_detection() {
        let imports = vec![
            "WSAStartup".to_string(),
            "connect".to_string(),
            "CreateProcessA".to_string(),
        ];
        let strings = vec!["cmd.exe", "whoami"];
        let report = analyze_backdoors(&[0u8; 64], &imports, &strings);
        assert!(report.findings.iter().any(|f| f.rule_id == BackdoorRuleId::ReverseShell));
    }

    #[test]
    fn test_webshell_detection() {
        let strings = vec!["eval($_POST['cmd'])", "base64_decode($input)", "system('ls')"];
        let report = analyze_backdoors(&[0u8; 64], &[], &strings);
        assert!(report.findings.iter().any(|f| f.rule_id == BackdoorRuleId::WebShellIndicator));
    }

    #[test]
    fn test_deduplication() {
        let imports = vec![
            "WSAStartup".to_string(),
            "connect".to_string(),
            "CreateProcessA".to_string(),
            "WSAConnect".to_string(),
        ];
        let strings = vec!["cmd.exe", "/bin/sh"];
        let report = analyze_backdoors(&[0u8; 64], &imports, &strings);
        let rev_shell_count = report
            .findings
            .iter()
            .filter(|f| f.rule_id == BackdoorRuleId::ReverseShell)
            .count();
        assert_eq!(rev_shell_count, 1, "Should deduplicate to single finding per rule");
    }
}
