//! Core backdoor analysis engine.
//! Combines import signatures, string signatures, and structural heuristics
//! to detect 27 categories of backdoor behavior.

use crate::report::{BackdoorFinding, BackdoorReport, BackdoorSeverity};
use crate::rules::{BackdoorRuleId, ImportSignatureLowered};

use std::collections::HashSet;

/// Rules whose string-based evidence is only meaningful when corroborated by
/// the corresponding API imports. Bare strings describing shell commands,
/// network loops or IPC exist in virtually every large binary (docs, embedded
/// runtimes, frameworks), so an import-less hit is downgraded.
const CORROBORATION_REQUIRED: &[BackdoorRuleId] = &[
    BackdoorRuleId::ReverseShell,
    BackdoorRuleId::BindShell,
    BackdoorRuleId::C2Beacon,
    BackdoorRuleId::NamedPipeBackdoor,
    BackdoorRuleId::ServiceBackdoor,
    BackdoorRuleId::RegistryPersistence,
    // Ransomware/Cryptominer/UacBypass/LolbinAbuse markers are famous enough
    // to appear in security write-ups and tooling embedded in large binaries;
    // without matching API-level evidence they are discounted.
    BackdoorRuleId::Ransomware,
    BackdoorRuleId::Cryptominer,
    BackdoorRuleId::UacBypass,
    BackdoorRuleId::LolbinAbuse,
];

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

    // Normalize imports to lowercase for case-insensitive matching.
    // Use Cow to avoid allocating when the string is already lowercase.
    let imports_lower: Vec<String> = import_names.iter().map(|s| {
        if s.chars().all(|c| c.is_ascii_lowercase() || !c.is_ascii_alphabetic()) {
            s.clone()
        } else {
            s.to_lowercase()
        }
    }).collect();

    // Whole-name lookup set, built once: turns every per-signature API check
    // from an O(n) linear scan into O(1) hashing (with A/W suffix variants).
    let import_set: HashSet<&str> = imports_lower.iter().map(|s| s.as_str()).collect();

    // Check import-based signatures; remember which rules have real API-level
    // evidence so string-only hits can be discounted.
    let import_backed = check_import_signatures(&import_set, &mut findings);

    // Check string-based signatures
    check_string_signatures(strings, &mut findings);

    // Structural heuristics on raw data
    check_structural_heuristics(data, &import_set, &imports_lower, &mut findings);

    // Discount uncorroborated string-only findings
    downgrade_uncorroborated(&mut findings, &import_backed);

    // Deduplicate by rule_id (keep highest severity)
    deduplicate_findings(&mut findings);

    BackdoorReport::from_findings(findings)
}

fn downgrade_one(sev: BackdoorSeverity) -> BackdoorSeverity {
    match sev {
        BackdoorSeverity::Critical => BackdoorSeverity::High,
        _ => BackdoorSeverity::Medium,
    }
}

fn downgrade_uncorroborated(
    findings: &mut [BackdoorFinding],
    import_backed: &HashSet<BackdoorRuleId>,
) {
    for f in findings.iter_mut() {
        if CORROBORATION_REQUIRED.contains(&f.rule_id) && !import_backed.contains(&f.rule_id) {
            f.severity = downgrade_one(f.severity);
            f.confidence = (f.confidence * 0.5).min(0.5);
            f.evidence.push("strings-only heuristic (no corroborating imports)".to_string());
        }
    }
}

/// Whole-name import match with Windows A/W suffix tolerance.
///
/// Both arguments must already be lowercase. `import` matches `api` when the
/// names are equal, or when `import` extends `api` by exactly one ANSI (`a`)
/// or wide (`w`) suffix character. Substring hits are deliberately rejected:
/// `connect` must not match `InternetConnectW`, and `accept` must not match
/// `AcceptSecurityContext`.
///
/// Kept as the executable specification of [`set_has_api`]'s set semantics:
/// production matching uses the O(1) set lookup, while tests verify both
/// paths agree.
#[cfg(test)]
fn import_matches(import_lower: &str, api_lower: &str) -> bool {
    matches!(import_lower.strip_prefix(api_lower), Some("") | Some("a") | Some("w"))
}

/// O(1) set membership equivalent to scanning for any import that
/// [`import_matches`] the given (already lowercase) API name.
///
/// The exact match plus the two single-character suffix variants (`api`,
/// `api + "a"`, `api + "w"`) enumerate precisely the imports the linear scan
/// accepted, so results are identical — just without touching every import.
/// `scratch` is reused across calls to avoid repeated allocation.
#[inline]
fn set_has_api(
    import_set: &HashSet<&str>,
    api_lower: &str,
    scratch: &mut String,
) -> bool {
    if import_set.contains(api_lower) {
        return true;
    }
    scratch.clear();
    scratch.push_str(api_lower);
    scratch.push('a');
    if import_set.contains(scratch.as_str()) {
        return true;
    }
    scratch.pop();
    scratch.push('w');
    import_set.contains(scratch.as_str())
}

fn check_import_signatures(
    import_set: &HashSet<&str>,
    findings: &mut Vec<BackdoorFinding>,
) -> HashSet<BackdoorRuleId> {
    let mut scratch = String::new();
    let mut fired = HashSet::new();
    for sig in crate::rules::import_signatures_lowered() {
        if matches_import_signature(import_set, sig, &mut scratch) {
            fired.insert(sig.rule_id);
            let evidence: Vec<String> = sig
                .required_orig
                .iter()
                .chain(sig.optional_orig.iter())
                .copied()
                .zip(
                    sig.required_lower
                        .iter()
                        .chain(sig.optional_lower.iter())
                        .copied(),
                )
                .filter(|(_, api_lower)| set_has_api(import_set, api_lower, &mut scratch))
                .map(|(orig, _)| orig.to_string())
                .collect();

            findings.push(BackdoorFinding {
                rule_id: sig.rule_id,
                severity: sig.rule_id.default_severity(),
                confidence: sig.rule_id.default_confidence(),
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
    fired
}

fn matches_import_signature(
    import_set: &HashSet<&str>,
    sig: &ImportSignatureLowered,
    scratch: &mut String,
) -> bool {
    // All required APIs must be present
    let all_required = sig
        .required_lower
        .iter()
        .all(|api| set_has_api(import_set, api, scratch));

    if !all_required {
        return false;
    }

    // Check optional APIs threshold
    if sig.min_optional > 0 {
        let optional_count = sig
            .optional_lower
            .iter()
            .filter(|api| set_has_api(import_set, api, scratch))
            .count();

        if optional_count < sig.min_optional {
            return false;
        }
    }

    true
}

fn check_string_signatures(strings: &[&str], findings: &mut Vec<BackdoorFinding>) {
    // Lowercase every extracted string exactly once per analysis; pattern
    // needles are already lowercase (precomputed once per process from the
    // &'static rules), so matching is a pure scan with zero allocations.
    let lowered: Vec<String> = strings.iter().map(|s| s.to_lowercase()).collect();

    for sig in crate::rules::string_signatures_lowered() {
        let matched_required: Vec<String> = sig
            .patterns_orig
            .iter()
            .zip(sig.patterns_lower.iter())
            .filter(|(_, pattern_lower)| {
                lowered.iter().any(|s| s.contains(*pattern_lower))
            })
            .map(|(orig, _)| orig.to_string())
            .collect();
        let matched_optional: Vec<String> = sig
            .optional_patterns_orig
            .iter()
            .zip(sig.optional_patterns_lower.iter())
            .filter(|(_, pattern_lower)| {
                lowered.iter().any(|s| s.contains(*pattern_lower))
            })
            .map(|(orig, _)| orig.to_string())
            .collect();

        if matched_required.len() >= sig.min_matches
            && (sig.optional_patterns_orig.is_empty() || !matched_optional.is_empty())
        {
            let mut evidence = matched_required;
            evidence.extend(matched_optional);

            findings.push(BackdoorFinding {
                rule_id: sig.rule_id,
                severity: sig.rule_id.default_severity(),
                confidence: sig.rule_id.default_confidence(),
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

fn check_structural_heuristics(
    data: &[u8],
    import_set: &HashSet<&str>,
    imports_lower: &[String],
    findings: &mut Vec<BackdoorFinding>,
) {
    // Encrypted config detection: high entropy region near network imports.
    // Use precise matching: bare verbs (connect/recv/send/...) must match the
    // whole import name (so `SendMessageW` does NOT match `send`), and the
    // distinctive winsock/WinHTTP/Internet prefixes are safe substrings.
    let has_net_imports = imports_lower.iter().any(|i| {
        i == "connect" || i == "recv" || i == "send" || i == "sendto" || i == "recvfrom"
            || i.starts_with("wsa")
            || i.starts_with("winhttp")
            || i.starts_with("internet")
            || i.starts_with("http")
            || i.starts_with("socket")
            || i.starts_with("urlopen")
    });

    if has_net_imports && data.len() > 256 {
        // Check for high-entropy blocks (>7.0) that could be encrypted configs
        let window_size = 256;
        let step = 128;
        let mut high_entropy_regions = 0;

        for offset in (0..=data.len().saturating_sub(window_size)).step_by(step) {
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
                confidence: BackdoorRuleId::EncryptedConfig.default_confidence(),
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

    // DNS C2 anomaly: resolver APIs present while the binary carries no
    // HTTP/socket stack at all. Deliberately Medium/low-confidence — pure DNS
    // utilities (resolvers, ad blockers) share this exact shape.
    let resolver_apis = ["dnsquery", "dnsquery_a", "dnsquery_w", "dnsqueryex"];
    let matched_resolvers: Vec<&str> = resolver_apis
        .iter()
        .copied()
        .filter(|api| import_set.contains(api))
        .collect();
    if !matched_resolvers.is_empty() && !has_net_imports {
        findings.push(BackdoorFinding {
            rule_id: BackdoorRuleId::DnsC2Anomaly,
            severity: BackdoorRuleId::DnsC2Anomaly.default_severity(),
            confidence: BackdoorRuleId::DnsC2Anomaly.default_confidence(),
            description: BackdoorRuleId::DnsC2Anomaly.description().to_string(),
            evidence: vec![format!(
                "DNS resolver APIs ({}) without any HTTP/socket import",
                matched_resolvers.join(", ")
            )],
            mitre_ids: BackdoorRuleId::DnsC2Anomaly
                .mitre_ids()
                .iter()
                .map(|s| s.to_string())
                .collect(),
        });
    }

    // Direct syscall stubs (byte-level): repeated mov-eax/syscall/ret
    // sequences in executable-looking regions indicate ntdll-hook-evading
    // direct system calls. High-entropy regions look packed rather than
    // executable and are skipped by the scanner's entropy gate.
    let stub_count = count_direct_syscall_stubs(data);
    if stub_count >= MIN_DIRECT_SYSCALL_STUBS {
        findings.push(BackdoorFinding {
            rule_id: BackdoorRuleId::DirectSyscalls,
            severity: BackdoorRuleId::DirectSyscalls.default_severity(),
            confidence: BackdoorRuleId::DirectSyscalls.default_confidence(),
            description: BackdoorRuleId::DirectSyscalls.description().to_string(),
            evidence: vec![format!(
                "{} mov-eax/syscall/ret stub sequences found",
                stub_count
            )],
            mitre_ids: BackdoorRuleId::DirectSyscalls
                .mitre_ids()
                .iter()
                .map(|s| s.to_string())
                .collect(),
        });
    }
}

/// Minimum repeated syscall stub sequences required to fire DirectSyscalls.
/// A single stub can occur in ordinary low-level code; two or more distinct
/// numbered stubs is a hand-rolled syscall table.
const MIN_DIRECT_SYSCALL_STUBS: usize = 2;

/// Regions whose neighborhood entropy exceeds this look packed/encrypted
/// rather than executable code, so syscall-stub scanning skips them.
const CODE_ENTROPY_CEILING: f64 = 6.9;

/// Maximum bytes allowed between the `mov eax, imm32` opcode and the `syscall`
/// instruction (small register setups like `xor ecx, ecx` are common).
const MAX_MOV_SYSCALL_GAP: usize = 6;

/// Maximum bytes allowed between `syscall` and the closing `ret`.
const MAX_SYSCALL_RET_GAP: usize = 3;

/// Count direct-syscall stub shapes: `B8 xx xx xx xx` (`mov eax, imm32`)
/// followed within [`MAX_MOV_SYSCALL_GAP`] bytes by `0F 05` (`syscall`) and
/// then within [`MAX_SYSCALL_RET_GAP`] bytes by `C3` (`ret`). Only regions
/// whose neighborhood entropy looks like code (≤[`CODE_ENTROPY_CEILING`]) are
/// scanned, so packed/encrypted blobs cannot produce spurious matches.
fn count_direct_syscall_stubs(data: &[u8]) -> usize {
    let mut count = 0usize;
    let mut i = 0usize;
    // Outer bound guarantees room for the immediate operand plus one
    // potential `0F 05` pair right after the `mov`.
    while i + 7 < data.len() {
        if data[i] != 0xB8 {
            i += 1;
            continue;
        }

        // Entropy gate: only scan executable-looking neighborhoods.
        let ctx_start = i.saturating_sub(32);
        let ctx_end = (i + 96).min(data.len());
        if entropy_rs::calculate_entropy(&data[ctx_start..ctx_end]).entropy > CODE_ENTROPY_CEILING {
            i += 1;
            continue;
        }

        // Locate `0F 05` within the gap after the mov's immediate operand.
        let scan_end = (i + 5 + MAX_MOV_SYSCALL_GAP).min(data.len() - 2);
        let mut syscall_at = None;
        let mut j = i + 5;
        while j <= scan_end {
            if data[j] == 0x0F && data[j + 1] == 0x05 {
                syscall_at = Some(j);
                break;
            }
            j += 1;
        }
        let sys = match syscall_at {
            Some(s) => s,
            None => {
                i += 1;
                continue;
            }
        };

        // Locate the closing `ret` shortly after `syscall`.
        let ret_end = (sys + 2 + MAX_SYSCALL_RET_GAP).min(data.len() - 1);
        let mut ret_at = None;
        let mut k = sys + 2;
        while k <= ret_end {
            if data[k] == 0xC3 {
                ret_at = Some(k);
                break;
            }
            k += 1;
        }

        match ret_at {
            Some(r) => {
                count += 1;
                // Resume after this stub so overlapping candidates never
                // double-count a single sequence.
                i = r + 1;
            }
            None => i += 1,
        }
    }
    count
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

    // Sort by severity descending; ties broken by rule id so the output
    // order never depends on HashMap iteration order.
    deduped.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.rule_id.to_string().cmp(&b.rule_id.to_string()))
    });

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
        let strings = vec!["eval($_POST['cmd'])", "base64_decode($input)", "shell_exec('ls')"];
        let report = analyze_backdoors(&[0u8; 64], &[], &strings);
        assert!(report.findings.iter().any(|f| f.rule_id == BackdoorRuleId::WebShellIndicator));
    }

    // ── False-positive regressions (large legitimate binaries) ───────

    #[test]
    fn electron_style_js_strings_do_not_fire_webshell() {
        // eval(/exec(/system( are ubiquitous in embedded JS runtimes.
        let strings = vec![
            "eval(function(){})", "exec(cmd)", "system('pause')",
            "child_process.exec", "Function('return this')()",
        ];
        let report = analyze_backdoors(&[0u8; 64], &[], &strings);
        assert!(
            !report.findings.iter().any(|f| f.rule_id == BackdoorRuleId::WebShellIndicator),
            "generic JS/PHP tokens must not trigger WebShellIndicator"
        );
    }

    #[test]
    fn generic_shell_names_do_not_fire_reverse_shell() {
        let strings = vec!["cmd.exe", "powershell.exe", "whoami", "ipconfig"];
        let report = analyze_backdoors(&[0u8; 64], &[], &strings);
        assert!(
            !report.findings.iter().any(|f| f.rule_id == BackdoorRuleId::ReverseShell),
            "bare interpreter names must not trigger ReverseShell"
        );
    }

    #[test]
    fn strings_only_reverse_shell_is_downgraded() {
        // Distinctive shell patterns but no socket imports → downgraded.
        let strings = vec!["spawn /bin/sh", "bash -i >& /dev/tcp"];
        let report = analyze_backdoors(&[0u8; 64], &[], &strings);
        let f = report
            .findings
            .iter()
            .find(|f| f.rule_id == BackdoorRuleId::ReverseShell)
            .expect("distinctive shell strings should still fire");
        assert_ne!(f.severity, BackdoorSeverity::Critical, "strings-only hit must be downgraded");
        assert!(f.confidence <= 0.5);
    }

    #[test]
    fn sleep_recv_without_connect_is_not_a_beacon() {
        let imports = vec!["Sleep".to_string(), "recv".to_string(), "VirtualAlloc".to_string()];
        let report = analyze_backdoors(&[0u8; 64], &imports, &[]);
        assert!(
            !report.findings.iter().any(|f| f.rule_id == BackdoorRuleId::C2Beacon),
            "Sleep+recv without outbound connect is every networked app"
        );
    }

    #[test]
    fn named_pipe_with_universal_apis_does_not_fire() {
        let imports = vec![
            "CreateNamedPipeA".to_string(),
            "ReadFile".to_string(),
            "WriteFile".to_string(),
        ];
        let report = analyze_backdoors(&[0u8; 64], &imports, &[]);
        assert!(
            !report.findings.iter().any(|f| f.rule_id == BackdoorRuleId::NamedPipeBackdoor),
            "ReadFile/WriteFile carry no signal"
        );
    }

    #[test]
    fn loadlibrary_alone_does_not_fire_dll_hijacking() {
        let imports = vec!["LoadLibraryA".to_string(), "LoadLibraryExW".to_string()];
        let report = analyze_backdoors(&[0u8; 64], &imports, &[]);
        assert!(
            !report.findings.iter().any(|f| f.rule_id == BackdoorRuleId::DllHijacking),
            "LoadLibrary* is ubiquitous and must not trigger on its own"
        );
    }

    #[test]
    fn weak_findings_cannot_saturate_risk() {
        // Five medium findings with low confidence — linear sum would give 0.5.
        let findings: Vec<BackdoorFinding> = (0..5)
            .map(|_| BackdoorFinding {
                rule_id: BackdoorRuleId::EncryptedConfig,
                severity: BackdoorSeverity::Medium,
                confidence: 0.4,
                description: "test".into(),
                evidence: vec![],
                mitre_ids: vec![],
            })
            .collect();
        let r = crate::report::BackdoorReport::from_findings(findings);
        assert!(
            r.risk_score < 0.35,
            "weak evidence pile-up must not saturate risk, got {}",
            r.risk_score
        );
        assert_eq!(r.verdict, crate::report::BackdoorVerdict::Suspicious);
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

    // ── Whole-name import matching (A/W suffix tolerance) ─────────────

    #[test]
    fn import_matching_is_whole_name_with_aw_suffix_tolerance() {
        assert!(import_matches("connect", "connect"));
        assert!(import_matches("connecta", "connect"));
        assert!(import_matches("connectw", "connect"));
        assert!(!import_matches("internetconnectw", "connect"));
        assert!(!import_matches("acceptsecuritycontext", "accept"));
        assert!(!import_matches("connectex", "connect"));
        assert!(!import_matches("wsarecvfrom", "recvfrom"));
    }

    #[test]
    fn internet_connect_w_does_not_trigger_reverse_shell() {
        // Substring matching used to treat InternetConnectW as `connect`.
        let imports = vec![
            "InternetOpenW".to_string(),
            "InternetConnectW".to_string(),
            "HttpSendRequestW".to_string(),
        ];
        let report = analyze_backdoors(&[0u8; 64], &imports, &[]);
        assert!(
            !report.findings.iter().any(|f| f.rule_id == BackdoorRuleId::ReverseShell),
            "InternetConnectW is a plain wininet API and must not satisfy `connect`"
        );
    }

    #[test]
    fn accept_security_context_does_not_trigger_bind_shell() {
        let imports = vec![
            "bind".to_string(),
            "listen".to_string(),
            "AcceptSecurityContext".to_string(),
            "CreateProcessA".to_string(),
        ];
        let report = analyze_backdoors(&[0u8; 64], &imports, &[]);
        assert!(
            !report.findings.iter().any(|f| f.rule_id == BackdoorRuleId::BindShell),
            "AcceptSecurityContext must not satisfy `accept`"
        );
    }

    // ── Wide-char API variants ────────────────────────────────────────

    #[test]
    fn create_service_w_fires_service_backdoor() {
        let imports = vec![
            "CreateServiceW".to_string(),
            "StartServiceW".to_string(),
        ];
        let report = analyze_backdoors(&[0u8; 64], &imports, &[]);
        let f = report
            .findings
            .iter()
            .find(|f| f.rule_id == BackdoorRuleId::ServiceBackdoor)
            .expect("CreateServiceW variant must fire ServiceBackdoor");
        assert!(
            f.evidence.iter().any(|e| e.eq_ignore_ascii_case("CreateServiceW")),
            "evidence must cite the actually-imported API, got {:?}",
            f.evidence
        );
    }

    #[test]
    fn wide_char_pipe_and_logon_variants_fire() {
        let pipe_imports = vec![
            "CreateNamedPipeW".to_string(),
            "ConnectNamedPipe".to_string(),
            "ImpersonateNamedPipeClient".to_string(),
        ];
        let r1 = analyze_backdoors(&[0u8; 64], &pipe_imports, &[]);
        assert!(
            r1.findings.iter().any(|f| f.rule_id == BackdoorRuleId::NamedPipeBackdoor),
            "CreateNamedPipeW variant must fire NamedPipeBackdoor"
        );

        let logon_imports = vec!["LogonUserW".to_string(), "CredReadA".to_string()];
        let r2 = analyze_backdoors(&[0u8; 64], &logon_imports, &[]);
        assert!(
            r2.findings.iter().any(|f| f.rule_id == BackdoorRuleId::AuthBypass),
            "LogonUserW variant must fire AuthBypass"
        );
    }

    // ── Set-based lookup equivalence with the historical linear scan ──

    /// Deterministic xorshift64 generator so the test never flakes.
    fn xorshift64(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn set_lookup_equals_linear_scan_reference() {
        // Universe mixing exact names, A/W variants, near misses and noise.
        let universe: &[&str] = &[
            "WSAStartup", "connect", "connecta", "connectw", "connectex",
            "InternetConnectW", "accept", "AcceptSecurityContext", "bind",
            "listen", "CreateProcessA", "CreateProcessW", "WinExec",
            "ShellExecuteA", "Sleep", "recv", "recvfrom", "sendto",
            "CreateNamedPipeW", "ConnectNamedPipe", "ImpersonateNamedPipeClient",
            "CreateServiceA", "LogonUserW", "CredReadA", "NetUserAdd",
            "CryptDecrypt", "VirtualAlloc", "LoadLibraryExW", "TransactNamedPipe",
            "StartServiceW", "wsarecvfrom", "WSAConnect", "LsaLogonUser",
        ];

        // Reference implementation of the pre-HashSet semantics: O(n*m)
        // whole-name linear scan with A/W suffix tolerance.
        let linear_contains = |imports_lower: &[String], api: &str| -> bool {
            let api_lower = api.to_lowercase();
            imports_lower
                .iter()
                .any(|i| import_matches(i, &api_lower))
        };

        let mut state: u64 = 0xDEADBEEF_CAFEF00D;
        for _round in 0..256 {
            let imports: Vec<String> = universe
                .iter()
                .filter(|_| xorshift64(&mut state).is_multiple_of(4))
                .map(|s| s.to_string())
                .collect();

            // Reference path: replicate the original Vec + any() pipeline.
            let ref_report = {
                let imports_lower: Vec<String> = imports
                    .iter()
                    .map(|s| {
                        if s.chars().all(|c| c.is_ascii_lowercase() || !c.is_ascii_alphabetic()) {
                            s.clone()
                        } else {
                            s.to_lowercase()
                        }
                    })
                    .collect();
                let mut findings = Vec::new();
                let mut fired = HashSet::new();
                for sig in crate::rules::import_signatures_lowered() {
                    let all_required = sig
                        .required_lower
                        .iter()
                        .all(|api| linear_contains(&imports_lower, api));
                    let optional_count = sig
                        .optional_lower
                        .iter()
                        .filter(|api| linear_contains(&imports_lower, api))
                        .count();
                    if all_required && optional_count >= sig.min_optional {
                        fired.insert(sig.rule_id);
                        let evidence: Vec<String> = sig
                            .required_orig
                            .iter()
                            .chain(sig.optional_orig.iter())
                            .copied()
                            .filter(|api| linear_contains(&imports_lower, api))
                            .map(|s| s.to_string())
                            .collect();
                        findings.push(BackdoorFinding {
                            rule_id: sig.rule_id,
                            severity: sig.rule_id.default_severity(),
                            confidence: sig.rule_id.default_confidence(),
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
                downgrade_uncorroborated(&mut findings, &fired);
                deduplicate_findings(&mut findings);
                BackdoorReport::from_findings(findings)
            };

            let actual = analyze_backdoors(&[], &imports, &[]);
            assert_eq!(
                format!("{:?}", ref_report.findings),
                format!("{:?}", actual.findings),
                "set-based path diverged from linear-scan reference for {:?}",
                imports
            );
        }
    }

    #[test]
    fn lowered_rule_tables_match_originals_element_for_element() {
        for (sig_lo, sig) in crate::rules::import_signatures_lowered()
            .iter()
            .zip(crate::rules::IMPORT_SIGNATURES.iter())
        {
            assert_eq!(sig_lo.rule_id, sig.rule_id);
            assert_eq!(sig_lo.min_optional, sig.min_optional);
            assert_eq!(sig_lo.required_orig.len(), sig.required_apis.len());
            assert_eq!(sig_lo.optional_orig.len(), sig.optional_apis.len());
            for ((lo, orig), orig2) in sig_lo
                .required_lower
                .iter()
                .zip(sig_lo.required_orig.iter())
                .zip(sig.required_apis.iter())
            {
                assert_eq!(orig, orig2);
                assert_eq!(*lo, orig2.to_lowercase());
            }
        }
        for (sig_lo, sig) in crate::rules::string_signatures_lowered()
            .iter()
            .zip(crate::rules::STRING_SIGNATURES.iter())
        {
            assert_eq!(sig_lo.min_matches, sig.min_matches);
            assert_eq!(sig_lo.patterns_orig, sig.patterns);
            assert_eq!(sig_lo.optional_patterns_orig, sig.optional_patterns);
            for (lo, orig) in sig_lo
                .patterns_lower
                .iter()
                .zip(sig_lo.patterns_orig.iter())
            {
                assert_eq!(*lo, orig.to_lowercase());
            }
        }
    }

    // ── Determinism ───────────────────────────────────────────────────

    #[test]
    fn dedup_output_order_is_deterministic_for_equal_severity() {
        // Three distinct critical-severity rules fire at once; the report
        // order among them must not depend on HashMap iteration order.
        let imports = vec![
            "WSAStartup".to_string(),
            "connect".to_string(),
            "CreateProcessA".to_string(), // ReverseShell (critical)
            "LogonUserA".to_string(),
            "CredEnumerateA".to_string(), // AuthBypass (critical)
            "CreateServiceA".to_string(), // ServiceBackdoor (critical)
        ];
        let expected: Vec<String> = ["AUTH_BYPASS", "REVERSE_SHELL", "SERVICE_BACKDOOR"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        for _ in 0..8 {
            let report = analyze_backdoors(&[0u8; 64], &imports, &[]);
            let ids: Vec<String> =
                report.findings.iter().map(|f| f.rule_id.to_string()).collect();
            assert_eq!(ids, expected, "equal-severity findings must have stable order");
        }
    }

    // ── Common malware pack ──────────────────────────────────────────

    fn finding(report: &BackdoorReport, rule: BackdoorRuleId) -> &BackdoorFinding {
        report
            .findings
            .iter()
            .find(|f| f.rule_id == rule)
            .unwrap_or_else(|| panic!("expected {:?} to fire", rule))
    }

    #[test]
    fn keylogger_hook_with_network_fires() {
        let imports = vec![
            "SetWindowsHookExW".to_string(),
            "GetAsyncKeyState".to_string(),
            "send".to_string(),
        ];
        let report = analyze_backdoors(&[0u8; 64], &imports, &[]);
        let f = finding(&report, BackdoorRuleId::Keylogger);
        assert_eq!(f.severity, BackdoorSeverity::High);
        assert!(f.mitre_ids.iter().any(|m| m == "T1056.001"));
    }

    #[test]
    fn getasynkeystate_without_network_is_not_keylogger() {
        // Game input loop: raw key polling with zero network capability.
        let imports = vec![
            "GetAsyncKeyState".to_string(),
            "GetKeyState".to_string(),
            "GetKeyboardState".to_string(),
        ];
        let report = analyze_backdoors(&[0u8; 64], &imports, &[]);
        assert!(
            !report.findings.iter().any(|f| f.rule_id == BackdoorRuleId::Keylogger),
            "offline key polling is ordinary game/IME behavior"
        );
    }

    #[test]
    fn clipboard_hijack_chain_fires_but_read_only_does_not() {
        // Full read-modify-write chain + network outlet → clipper.
        let clipper = vec![
            "OpenClipboard".to_string(),
            "GetClipboardData".to_string(),
            "SetClipboardData".to_string(),
            "connect".to_string(),
        ];
        let r1 = analyze_backdoors(&[0u8; 64], &clipper, &[]);
        let f = finding(&r1, BackdoorRuleId::ClipboardHijack);
        assert_eq!(f.mitre_ids, vec!["T1115"]);

        // Read-only pair without SetClipboardData/network → clipboard manager.
        let reader = vec![
            "OpenClipboard".to_string(),
            "GetClipboardData".to_string(),
        ];
        let r2 = analyze_backdoors(&[0u8; 64], &reader, &[]);
        assert!(
            !r2.findings.iter().any(|f| f.rule_id == BackdoorRuleId::ClipboardHijack),
            "clipboard read without replacement/outlet is benign"
        );
    }

    #[test]
    fn screen_capture_requires_network_outlet() {
        // Capture primitives WITH network → surveillance-grade.
        let exfil = vec![
            "BitBlt".to_string(),
            "GetDC".to_string(),
            "WSAStartup".to_string(),
            "connect".to_string(),
        ];
        let r1 = analyze_backdoors(&[0u8; 64], &exfil, &[]);
        finding(&r1, BackdoorRuleId::ScreenCapture);

        // GDI+ encoder variant.
        let gdiplus = vec![
            "GdiplusStartup".to_string(),
            "GetDC".to_string(),
            "socket".to_string(),
        ];
        let r2 = analyze_backdoors(&[0u8; 64], &gdiplus, &[]);
        finding(&r2, BackdoorRuleId::ScreenCapture);

        // Local screenshot utility: identical GDI primitives, no outlet.
        let local = vec![
            "BitBlt".to_string(),
            "GetDC".to_string(),
            "CreateCompatibleBitmap".to_string(),
            "GetDIBits".to_string(),
        ];
        let r3 = analyze_backdoors(&[0u8; 64], &local, &[]);
        assert!(
            !r3.findings.iter().any(|f| f.rule_id == BackdoorRuleId::ScreenCapture),
            "screen capture without any network capability must not fire"
        );
    }

    #[test]
    fn cryptominer_strings_fire_and_are_downgraded_without_imports() {
        let strings = vec![
            "stratum+tcp://eu.mining.example:3333",
            "mining.subscribe",
            "xmrig 6.19",
        ];
        let report = analyze_backdoors(&[0u8; 64], &[], &strings);
        let f = finding(&report, BackdoorRuleId::Cryptominer);
        assert_eq!(f.severity, BackdoorSeverity::Medium);
        assert!(
            f.confidence <= 0.5,
            "strings-only miner hit must be corroborated-downgraded, got {}",
            f.confidence
        );
    }

    #[test]
    fn cryptominer_cryptoapi_bulk_scale_fires() {
        let imports = vec![
            "CryptAcquireContextW".to_string(),
            "CryptHashData".to_string(),
            "CryptDeriveKey".to_string(),
            "CryptCreateHash".to_string(),
            "CryptEncrypt".to_string(),
        ];
        let report = analyze_backdoors(&[0u8; 64], &imports, &[]);
        finding(&report, BackdoorRuleId::Cryptominer);

        // Single hash call is ordinary software — 1 of 4 bulk ops is not enough.
        let ordinary = vec![
            "CryptAcquireContextW".to_string(),
            "CryptHashData".to_string(),
        ];
        let r2 = analyze_backdoors(&[0u8; 64], &ordinary, &[]);
        assert!(
            !r2.findings.iter().any(|f| f.rule_id == BackdoorRuleId::Cryptominer),
            "single CryptoAPI use must not look like mining"
        );
    }

    #[test]
    fn ransomware_imports_fire_at_full_strength() {
        let imports = vec![
            "FindFirstFileW".to_string(),
            "BCryptEncrypt".to_string(),
            "FindNextFileW".to_string(),
            "BCryptOpenAlgorithmProvider".to_string(),
        ];
        let report = analyze_backdoors(&[0u8; 64], &imports, &[]);
        let f = finding(&report, BackdoorRuleId::Ransomware);
        assert_eq!(f.severity, BackdoorSeverity::Critical, "import-backed hit stays critical");
        assert!(f.mitre_ids.contains(&"T1486".to_string()));
    }

    #[test]
    fn ransomware_strings_only_is_downgraded() {
        let strings = vec![".locked", "vssadmin delete shadows"];
        let report = analyze_backdoors(&[0u8; 64], &[], &strings);
        let f = finding(&report, BackdoorRuleId::Ransomware);
        assert_ne!(
            f.severity, BackdoorSeverity::Critical,
            "strings-only ransomware evidence must be downgraded"
        );
        assert!(f.confidence <= 0.5);
    }

    // ── Rare TTP pack ────────────────────────────────────────────────

    #[test]
    fn process_hollowing_classic_path_fires() {
        let imports = vec![
            "WriteProcessMemory".to_string(),
            "SetThreadContext".to_string(),
            "ResumeThread".to_string(),
        ];
        let report = analyze_backdoors(&[0u8; 64], &imports, &[]);
        let f = finding(&report, BackdoorRuleId::ProcessHollowing);
        assert_eq!(f.mitre_ids, vec!["T1055.012"]);
    }

    #[test]
    fn process_hollowing_section_mapping_path_fires() {
        // Section mapping plus a thread-execution primitive (the signature
        // requires one so bare section plumbing never fires).
        let imports = vec![
            "NtCreateSection".to_string(),
            "NtMapViewOfSection".to_string(),
            "WriteProcessMemory".to_string(),
        ];
        let report = analyze_backdoors(&[0u8; 64], &imports, &[]);
        finding(&report, BackdoorRuleId::ProcessHollowing);
    }

    #[test]
    fn bare_section_apis_do_not_fire_hollowing() {
        let imports = vec![
            "NtCreateSection".to_string(),
            "NtMapViewOfSection".to_string(),
            "NtUnmapViewOfSection".to_string(),
        ];
        let report = analyze_backdoors(&[0u8; 64], &imports, &[]);
        assert!(
            !report.findings.iter().any(|f| f.rule_id == BackdoorRuleId::ProcessHollowing),
            "section manipulation without an execution primitive is not hollowing"
        );
    }

    #[test]
    fn writeprocessmemory_alone_does_not_fire_hollowing() {
        // Debuggers and legit installers patch remote memory too.
        let imports = vec![
            "WriteProcessMemory".to_string(),
            "ReadProcessMemory".to_string(),
        ];
        let report = analyze_backdoors(&[0u8; 64], &imports, &[]);
        assert!(
            !report.findings.iter().any(|f| f.rule_id == BackdoorRuleId::ProcessHollowing),
            "remote memory write alone is not hollowing"
        );
    }

    #[test]
    fn callback_injection_rwx_combo_fires_but_gui_pair_does_not() {
        let injected = vec![
            "VirtualAlloc".to_string(),
            "EnumWindows".to_string(),
            "SetTimer".to_string(),
            "VirtualProtect".to_string(),
        ];
        let r1 = analyze_backdoors(&[0u8; 64], &injected, &[]);
        finding(&r1, BackdoorRuleId::CallbackInjection);

        // Ordinary GUI code pairs VirtualAlloc with EnumWindows all the time.
        let gui = vec!["VirtualAlloc".to_string(), "EnumWindows".to_string()];
        let r2 = analyze_backdoors(&[0u8; 64], &gui, &[]);
        assert!(
            !r2.findings.iter().any(|f| f.rule_id == BackdoorRuleId::CallbackInjection),
            "bare VirtualAlloc+EnumWindows is every windowed app"
        );
    }

    #[test]
    fn uac_bypass_strings_fire_and_are_downgraded_without_imports() {
        let strings = vec![
            "{3AD05575-8857-4850-9277-11b85BDB8E09}", // ICMLuaUtil elevator GUID context
            "ICMLuaUtil",
            "fodhelper.exe",
        ];
        let report = analyze_backdoors(&[0u8; 64], &[], &strings);
        let f = finding(&report, BackdoorRuleId::UacBypass);
        assert!(f.mitre_ids.contains(&"T1548.002".to_string()));
        assert!(
            f.confidence <= 0.5 && f.severity != BackdoorSeverity::High,
            "strings-only UAC bypass must be downgraded"
        );

        // One handler token alone is documentation noise.
        let single = analyze_backdoors(&[0u8; 64], &[], &["eventvwr.exe"]);
        assert!(
            !single.findings.iter().any(|f| f.rule_id == BackdoorRuleId::UacBypass),
            "a single auto-elevate token must not fire"
        );
    }

    #[test]
    fn lolbin_command_lines_fire_downgraded() {
        let strings = vec![
            "certutil -urlcache -f http://x/y http://x/y",
            "bitsadmin /transfer job /download /priority high",
        ];
        let report = analyze_backdoors(&[0u8; 64], &[], &strings);
        let f = finding(&report, BackdoorRuleId::LolbinAbuse);
        assert!(
            f.confidence <= 0.5,
            "LOLBin strings without matching imports are downgraded"
        );

        let benign_docs = analyze_backdoors(&[0u8; 64], &[], &["regsvr32"]);
        assert!(
            !benign_docs.findings.iter().any(|f| f.rule_id == BackdoorRuleId::LolbinAbuse),
            "bare tool names are not abuse command lines"
        );
    }

    #[test]
    fn dns_c2_anomaly_fires_only_without_http_socket_stack() {
        let dns_only = vec!["DnsQueryEx".to_string(), "DnsQuery_W".to_string()];
        let r1 = analyze_backdoors(&[0u8; 64], &dns_only, &[]);
        let f = finding(&r1, BackdoorRuleId::DnsC2Anomaly);
        assert_eq!(f.severity, BackdoorSeverity::Medium);
        assert_eq!(f.confidence, 0.5);
        assert!(f.mitre_ids.contains(&"T1071.004".to_string()));

        // Same resolver plus a wininet stack → normal DNS-backed HTTP client.
        let with_net = vec![
            "DnsQueryEx".to_string(),
            "InternetOpenA".to_string(),
            "HttpSendRequestA".to_string(),
        ];
        let r2 = analyze_backdoors(&[0u8; 64], &with_net, &[]);
        assert!(
            !r2.findings.iter().any(|f| f.rule_id == BackdoorRuleId::DnsC2Anomaly),
            "resolver + HTTP stack is an ordinary networked app"
        );
    }

    // ── Anti-debug / anti-VM / sandbox-evasion pack ──────────────────

    #[test]
    fn anti_debug_combos_fire_singles_do_not() {
        // Canonical check + companion probe.
        let combo = vec![
            "IsDebuggerPresent".to_string(),
            "CheckRemoteDebuggerPresent".to_string(),
        ];
        let r1 = analyze_backdoors(&[0u8; 64], &combo, &[]);
        let f = finding(&r1, BackdoorRuleId::AntiDebug);
        assert_eq!(f.mitre_ids, vec!["T1622"]);

        // ProcessDebugPort proxy: NtQueryInformationProcess + OutputDebugString trick.
        let port_proxy = vec![
            "NtQueryInformationProcess".to_string(),
            "OutputDebugStringW".to_string(),
        ];
        let r2 = analyze_backdoors(&[0u8; 64], &port_proxy, &[]);
        finding(&r2, BackdoorRuleId::AntiDebug);

        // Cross-process debug probe alone is already tool-grade.
        let solo_remote = vec!["CheckRemoteDebuggerPresent".to_string()];
        let r3 = analyze_backdoors(&[0u8; 64], &solo_remote, &[]);
        finding(&r3, BackdoorRuleId::AntiDebug);

        // IsDebuggerPresent or NtQueryInformationProcess alone: CRT/telemetry noise.
        for solo in [
            vec!["IsDebuggerPresent".to_string()],
            vec!["NtQueryInformationProcess".to_string()],
        ] {
            let r = analyze_backdoors(&[0u8; 64], &solo, &[]);
            assert!(
                !r.findings.iter().any(|f| f.rule_id == BackdoorRuleId::AntiDebug),
                "single ambiguous debugger API must not fire ({:?})",
                solo
            );
        }
    }

    #[test]
    fn anti_vm_cross_family_probe_fires() {
        // VBox pipe probe + VMware marker: hunting two hypervisor families.
        let strings = vec!["\\\\.\\pipe\\VBoxMiniRdDN", "vmware"];
        let report = analyze_backdoors(&[0u8; 64], &[], &strings);
        let f = finding(&report, BackdoorRuleId::AntiVm);
        assert_eq!(f.severity, BackdoorSeverity::Medium);

        // Sandboxie DLL reference alongside a VirtualBox registry key.
        let sandbox_probe = vec![
            "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
            "SbieDll.dll",
        ];
        let r2 = analyze_backdoors(&[0u8; 64], &[], &sandbox_probe);
        finding(&r2, BackdoorRuleId::AntiVm);
    }

    #[test]
    fn vmware_installer_strings_without_net_do_not_fire_anti_vm() {
        // A vendor's own installer legitimately embeds every marker of its
        // OWN family — and carries no probe-style cross-family references.
        let strings = vec![
            "VMware Workstation Pro Setup",
            "vmtoolsd.exe",
            "C:\\Program Files\\VMware\\VMware Tools",
        ];
        let report = analyze_backdoors(&[0u8; 64], &[], &strings);
        assert!(
            !report.findings.iter().any(|f| f.rule_id == BackdoorRuleId::AntiVm),
            "same-family vendor markers must never trigger AntiVm"
        );
    }

    #[test]
    fn single_foreign_vm_marker_does_not_fire() {
        let report = analyze_backdoors(&[0u8; 64], &[], &["cuckoo"]);
        assert!(
            !report.findings.iter().any(|f| f.rule_id == BackdoorRuleId::AntiVm),
            "one foreign-family mention (e.g. security docs) is not a probe"
        );
    }

    #[test]
    fn sleep_evasion_fires_only_with_network_gate() {
        let netted = vec![
            "Sleep".to_string(),
            "GetTickCount".to_string(),
            "WSAStartup".to_string(),
            "connect".to_string(),
        ];
        let r1 = analyze_backdoors(&[0u8; 64], &netted, &[]);
        let f = finding(&r1, BackdoorRuleId::SleepEvasion);
        assert_eq!(f.severity, BackdoorSeverity::Medium);
        assert_eq!(f.confidence, 0.4, "deliberately weak static proxy");

        // High-resolution counter variant also fires under the gate.
        let qpc = vec![
            "Sleep".to_string(),
            "QueryPerformanceCounter".to_string(),
            "send".to_string(),
        ];
        let r2 = analyze_backdoors(&[0u8; 64], &qpc, &[]);
        finding(&r2, BackdoorRuleId::SleepEvasion);

        // Sleep+tick without any network import = every UI timer app.
        let offline_timer = vec!["Sleep".to_string(), "GetTickCount".to_string()];
        let r3 = analyze_backdoors(&[0u8; 64], &offline_timer, &[]);
        assert!(
            !r3.findings.iter().any(|f| f.rule_id == BackdoorRuleId::SleepEvasion),
            "timing APIs without network capability are ubiquitous"
        );
    }

    #[test]
    fn mouse_activity_check_is_low_confidence_medium() {
        let imports = vec!["GetCursorPos".to_string(), "GetAsyncKeyState".to_string()];
        let report = analyze_backdoors(&[0u8; 64], &imports, &[]);
        let f = finding(&report, BackdoorRuleId::MouseActivityCheck);
        assert_eq!(f.severity, BackdoorSeverity::Medium);
        assert_eq!(f.confidence, 0.4);
        assert!(f.mitre_ids.contains(&"T1497.001".to_string()));
    }

    // ── Byte-level pack: direct syscall stubs ────────────────────────

    /// `mov eax, 41 ; syscall ; ret` — NtAllocateVirtualNumber-shaped stub.
    const SYSCALL_STUB: [u8; 8] = [0xB8, 0x29, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3];

    #[test]
    fn repeated_direct_syscall_stubs_fire() {
        let mut data = vec![0x90u8; 16]; // nop padding
        data.extend_from_slice(&SYSCALL_STUB);
        data.extend_from_slice(&[0x90u8; 12]);
        data.extend_from_slice(&SYSCALL_STUB); // distinct second stub
        data.extend_from_slice(&[0x90u8; 32]);

        let report = analyze_backdoors(&data, &[], &[]);
        let f = finding(&report, BackdoorRuleId::DirectSyscalls);
        assert_eq!(f.mitre_ids, vec!["T1106"]);
        assert!(f.evidence[0].starts_with("2 "), "evidence should count stubs");
    }

    #[test]
    fn single_direct_syscall_stub_does_not_fire() {
        let mut data = vec![0x90u8; 32];
        data.extend_from_slice(&SYSCALL_STUB);
        data.extend_from_slice(&[0x90u8; 32]);

        let report = analyze_backdoors(&data, &[], &[]);
        assert!(
            !report.findings.iter().any(|f| f.rule_id == BackdoorRuleId::DirectSyscalls),
            "one stub can occur in ordinary low-level code"
        );
    }

    #[test]
    fn high_entropy_regions_are_skipped_by_syscall_scan() {
        // Uniform pseudo-random bytes look packed/encrypted; a stub buried
        // inside them must not be counted.
        let mut state: u64 = 0x243F_6A88_85A3_08D3;
        let mut data = Vec::with_capacity(256);
        for _ in 0..120 {
            xorshift64(&mut state);
            data.push((state >> 33) as u8);
        }
        data.extend_from_slice(&SYSCALL_STUB);
        for _ in 0..120 {
            xorshift64(&mut state);
            data.push((state >> 33) as u8);
        }

        let report = analyze_backdoors(&data, &[], &[]);
        assert!(
            !report.findings.iter().any(|f| f.rule_id == BackdoorRuleId::DirectSyscalls),
            "packed-looking regions must not produce syscall-stub matches"
        );
    }
}
