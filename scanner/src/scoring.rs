//! Weighted suspicion scoring + verdict (extracted from `scanner.rs`).
//!
//! Pure functions over [`crate::report`] types. No I/O, no parsing.

use crate::report::{Finding, SectionEntropy, Severity, Verdict};

/// Configurable scoring weights for the suspicion score calculation.
/// All weights can be calibrated against known malware/benign samples.
#[derive(Debug, Clone)]
pub struct ScoringConfig {
    pub import_weight: f64,
    pub backdoor_weight: f64,
    pub shellcode_signal: f64,
    /// Weight for ML-based malicious confidence (0.0-1.0 signal).
    pub ml_weight: f64,

    pub yara_per_match: f64,
    pub yara_cap: f64,

    /// Critical findings (index = count, diminishing returns)
    pub critical_weights: [f64; 4], // [0, 1, 2, 3+]

    /// High findings (index = count, diminishing returns)
    pub high_weights: [f64; 6], // [0, 1, 2, 3, 4, 5+]

    /// Medium/Low per-finding weights and caps
    pub medium_per_finding: f64,
    pub medium_cap: f64,
    pub low_per_finding: f64,
    pub low_cap: f64,

    pub packed_executable_bonus: f64,
    pub xref_per_pair: f64,
    pub xref_cap: f64,

    pub compounding_3plus: f64,
    pub compounding_5plus: f64,

    /// Thresholds for active signal categories
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
/// Returns a value in [0.0, 1.0] where higher = more suspicious.
#[allow(clippy::too_many_arguments)] // public scoring API; grouping into a struct would break callers
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

    // ─── Base module scores (already normalized 0.0-1.0) ───
    score += import_score * cfg.import_weight;
    score += backdoor_score * cfg.backdoor_weight;

    // ─── ML-based signal (strong indicator) ───
    score += ml_confidence_malicious * cfg.ml_weight;

    // ─── Content-based signals (very strong) ───
    if has_shellcode {
        score += cfg.shellcode_signal;
    }

    // ─── Finding-based scoring with diminishing returns ───
    // Findings produced by modules that already contribute an aggregated
    // score (import-analyzer -> import_score, backdoor-analyzer ->
    // backdoor_score) are NOT counted again here.
    let aggregate_scored = |m: &str| m == "import-analyzer" || m == "backdoor-analyzer";

    let mut critical_count = 0usize;
    let mut high_count = 0usize;
    let mut medium_count = 0usize;
    let mut low_count = 0usize;
    let mut yara_matches = 0usize;

    for f in findings {
        if f.module == "yara-lite" {
            if !is_yara_budget_notice(f) {
                yara_matches += 1;
            }
            continue;
        }
        if aggregate_scored(&f.module) {
            continue;
        }
        match f.severity {
            Severity::Critical => critical_count += 1,
            Severity::High => {
                high_count += 1;
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

    // ─── Structural signals ───
    let suspicious_high_entropy = sections_entropy
        .iter()
        .filter(|s| s.entropy > 7.0 && is_executable_section(&s.name))
        .count();
    if suspicious_high_entropy > 0 {
        score += cfg.packed_executable_bonus;
    }

    // ─── Cross-module correlation amplifier ───
    if correlated_xref_pairs > 0 {
        score += (correlated_xref_pairs as f64 * cfg.xref_per_pair).min(cfg.xref_cap);
    }

    // ─── Signal compounding bonus ───
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
#[must_use]
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
#[must_use]
pub fn determine_verdict(
    suspicion_score: f64,
    max_severity: Option<Severity>,
    backdoor_score: f64,
    findings: &[Finding],
) -> Verdict {
    if findings.is_empty() {
        return Verdict::Clean;
    }

    // Hard overrides: only signals backed by byte-level evidence (shellcode
    // detection, YARA) force Malicious regardless of score.
    let has_critical = max_severity == Some(Severity::Critical);
    // Only a *strong* (High-severity) shellcode signal forces Malicious.
    let has_shellcode_finding = findings
        .iter()
        .any(|f| f.module == "shellcode-analyzer" && f.severity == Severity::High);
    let has_yara_match = findings
        .iter()
        .any(|f| f.module == "yara-lite" && !is_yara_budget_notice(f));

    if (has_critical && suspicion_score >= 0.45) || has_shellcode_finding {
        return Verdict::Malicious;
    }

    // Score-based classification
    if suspicion_score >= 0.65 || backdoor_score >= 0.7 || has_yara_match {
        Verdict::Malicious
    } else if suspicion_score >= 0.35
        || max_severity >= Some(Severity::High)
        || backdoor_score >= 0.4
        || suspicion_score >= 0.15
        || max_severity >= Some(Severity::Medium)
    {
        Verdict::Suspicious
    } else {
        // Only Low/Info findings remain — must not condemn a file.
        Verdict::Clean
    }
}

/// Check if a section name corresponds to an executable section.
pub fn is_executable_section(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower == ".text"
        || lower == "code"
        || lower == ".code"
        || lower.contains("exec")
        || lower == ".init"
        || lower == ".fini"
}

/// Shellcode rule IDs that are generic/coincidental in large normal code
/// and therefore unreliable when scanning full binaries / DLLs.
pub fn is_weak_shellcode_finding(rule_id: &str) -> bool {
    matches!(
        rule_id,
        "SHELLCODE_GETPC"
            | "SHELLCODE_HIGH_ENTROPY"
            | "SHELLCODE_PIC_HIGH_ENTROPY"
            | "SHELLCODE_NOP_SLED"
    )
}

/// The yara-lite budget notice reports truncated match collection; it is
/// not itself a signature hit and must not feed YARA counting or verdict
/// logic.
pub fn is_yara_budget_notice(f: &Finding) -> bool {
    f.module == "yara-lite" && f.rule_id == "YARA_MATCH_BUDGET"
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
        let score = calculate_suspicion_score(&findings, 0.0, 0.0, &[], false, 0, 0.0);
        assert_eq!(score, 0.0);
    }

    #[test]
    fn test_single_critical_finding() {
        let findings = vec![make_finding(Severity::Critical, "pe-parser")];
        let score = calculate_suspicion_score(&findings, 0.0, 0.0, &[], false, 0, 0.0);
        assert!(
            score >= 0.20,
            "Critical finding should give at least 0.20, got {}",
            score
        );
    }

    #[test]
    fn test_yara_match_boosts_score() {
        let findings = vec![make_finding(Severity::High, "yara-lite")];
        let score = calculate_suspicion_score(&findings, 0.0, 0.0, &[], false, 0, 0.0);
        assert!(
            score >= 0.15,
            "YARA match should give at least 0.15, got {}",
            score
        );
    }

    #[test]
    fn test_shellcode_gives_strong_signal() {
        let findings = vec![make_finding(Severity::High, "shellcode-analyzer")];
        let score = calculate_suspicion_score(&findings, 0.0, 0.0, &[], true, 0, 0.0);
        assert!(
            score >= 0.25,
            "Shellcode should give at least 0.25, got {}",
            score
        );
    }

    #[test]
    fn test_high_entropy_executable_section() {
        let sections = vec![SectionEntropy {
            name: ".text".into(),
            entropy: 7.5,
            classification: "high".into(),
        }];
        let score = calculate_suspicion_score(&[], 0.0, 0.0, &sections, false, 0, 0.0);
        assert!(
            score >= 0.08,
            "High entropy in .text should add 0.08, got {}",
            score
        );
    }

    #[test]
    fn test_correlated_xref_pairs() {
        let score = calculate_suspicion_score(&[], 0.0, 0.0, &[], false, 2, 0.0);
        assert!(
            score >= 0.10,
            "2 xref pairs should add ~0.10, got {}",
            score
        );
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
        assert!(
            score_five < score_one * 3.0,
            "Diminishing returns not working"
        );
    }

    #[test]
    fn test_compounding_bonus() {
        let findings = vec![
            make_finding(Severity::High, "pe-parser"),
            make_finding(Severity::High, "yara-lite"),
        ];
        let sections = vec![SectionEntropy {
            name: ".text".into(),
            entropy: 7.5,
            classification: "high".into(),
        }];
        let score = calculate_suspicion_score(&findings, 0.5, 0.3, &sections, true, 1, 0.0);
        assert!(
            score >= 0.70,
            "Compounding should push score high, got {}",
            score
        );
    }

    #[test]
    fn test_ml_signal_boosts_score() {
        let score = calculate_suspicion_score(&[], 0.0, 0.0, &[], false, 0, 0.9);
        assert!(
            score >= 0.13,
            "ML signal (0.9 * 0.15) should add ~0.135, got {}",
            score
        );
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
    fn test_verdict_ignores_yara_budget_notice() {
        let mut notice = make_finding(Severity::Low, "yara-lite");
        notice.rule_id = "YARA_MATCH_BUDGET".into();
        let verdict = determine_verdict(0.0, Some(Severity::Low), 0.0, &[notice.clone()]);
        assert_eq!(verdict, Verdict::Clean);
        assert_eq!(
            calculate_suspicion_score(&[notice], 0.0, 0.0, &[], false, 0, 0.0),
            0.0
        );
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
}
