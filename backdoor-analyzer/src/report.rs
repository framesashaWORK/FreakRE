//! Backdoor analysis report types.

use crate::rules::BackdoorRuleId;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Severity level for a backdoor finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackdoorSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for BackdoorSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl BackdoorRuleId {
    /// Default severity for each rule.
    pub fn default_severity(&self) -> BackdoorSeverity {
        match self {
            Self::ReverseShell
            | Self::BindShell
            | Self::ServiceBackdoor
            | Self::WebShellIndicator
            | Self::AuthBypass
            | Self::FirmwareIndicator => BackdoorSeverity::Critical,

            Self::NamedPipeBackdoor
            | Self::RegistryPersistence
            | Self::HiddenAccount
            | Self::C2Beacon => BackdoorSeverity::High,

            // Side-loading evidence (DLL name + writable dir) is contextual,
            // not a standalone backdoor signal.
            Self::DllHijacking => BackdoorSeverity::Medium,

            Self::EncryptedConfig => BackdoorSeverity::Medium,

            // Injection/destruction primitives (hollowing, ransomware) are
            // critical when fully corroborated; weaker evidence is downgraded
            // downstream by the corroboration gate.
            Self::ProcessHollowing | Self::Ransomware => BackdoorSeverity::Critical,

            // Behavioral malware indicators from the common/rare TTP packs:
            // high by default, string-only evidence is downgraded downstream.
            Self::Keylogger
            | Self::ClipboardHijack
            | Self::ScreenCapture
            | Self::CallbackInjection
            | Self::UacBypass
            | Self::LolbinAbuse
            | Self::AntiDebug
            | Self::DirectSyscalls
            | Self::RemoteThreadInjection
            | Self::TokenImpersonation => BackdoorSeverity::High,

            // Minidump tooling is dual-use (crash reporters and debuggers),
            // so credential-dumping evidence remains contextual.
            Self::CredentialDumping => BackdoorSeverity::Medium,

            Self::ScheduledTaskPersistence | Self::WmiPersistence => BackdoorSeverity::Low,

            // Contextual/ambiguous indicators: mining infra, DNS-only shapes,
            // evasion proxies. Real, but never damning on their own.
            Self::Cryptominer
            | Self::DnsC2Anomaly
            | Self::AntiVm
            | Self::SleepEvasion
            | Self::MouseActivityCheck => BackdoorSeverity::Medium,
        }
    }

    /// Default confidence for a finding from this rule.
    pub fn default_confidence(&self) -> f64 {
        match self {
            // Ubiquitous APIs/paths — weak evidence even with the tightened gates.
            // EncryptedConfig is the weakest heuristic of all (entropy-only,
            // no semantic content), so it must not masquerade as high confidence.
            Self::DllHijacking | Self::EncryptedConfig => 0.4,
            // Deliberately weak static proxies (see descriptions).
            Self::SleepEvasion | Self::MouseActivityCheck => 0.4,
            // Genuinely ambiguous: DNS-only stacks include benign resolvers.
            Self::DnsC2Anomaly => 0.5,
            Self::RegistryPersistence => 0.6,
            // GUI code legitimately pairs VirtualAlloc with EnumWindows;
            // VM markers can appear in virtualization-adjacent software.
            Self::CallbackInjection | Self::AntiVm => 0.6,
            Self::C2Beacon | Self::NamedPipeBackdoor => 0.75,
            Self::Keylogger
            | Self::ScreenCapture
            | Self::AntiDebug
            | Self::DirectSyscalls
            | Self::RemoteThreadInjection
            | Self::TokenImpersonation => 0.75,
            Self::CredentialDumping => 0.5,
            Self::ScheduledTaskPersistence | Self::WmiPersistence => 0.35,
            Self::WebShellIndicator => 0.8,
            // Distinctive protocol/command tokens — but string-derived, so
            // subject to corroboration downgrade.
            Self::Cryptominer | Self::UacBypass | Self::LolbinAbuse => 0.8,
            _ => 0.9,
        }
    }
}

/// A single backdoor detection finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackdoorFinding {
    /// Which rule triggered this finding.
    pub rule_id: BackdoorRuleId,
    /// Severity of this finding.
    pub severity: BackdoorSeverity,
    /// Confidence of this finding [0.0 – 1.0].
    pub confidence: f64,
    /// Human-readable explanation.
    pub description: String,
    /// Evidence: matched API names or string patterns.
    pub evidence: Vec<String>,
    /// MITRE ATT&CK technique IDs.
    pub mitre_ids: Vec<String>,
}

/// Provenance category for evidence shown to an analyst or an automation tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    Import,
    String,
    BytePattern,
    Structural,
    Correlation,
}

/// Structured evidence that can be attached by callers which know a file
/// location. Existing string evidence remains compatible with older clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub source: EvidenceSource,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
}

/// Human-readable confidence bucket used by explain/SARIF consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
}

impl ConfidenceLevel {
    pub fn from_score(score: f64) -> Self {
        if score >= 0.75 {
            Self::High
        } else if score >= 0.5 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

impl fmt::Display for BackdoorFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} — {}",
            self.severity, self.rule_id, self.description
        )?;
        if !self.evidence.is_empty() {
            write!(f, " (evidence: {})", self.evidence.join(", "))?;
        }
        Ok(())
    }
}

/// Overall verdict after backdoor analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BackdoorVerdict {
    Clean,
    Suspicious,
    BackdoorDetected,
}

impl fmt::Display for BackdoorVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clean => write!(f, "CLEAN"),
            Self::Suspicious => write!(f, "SUSPICIOUS"),
            Self::BackdoorDetected => write!(f, "BACKDOOR_DETECTED"),
        }
    }
}

/// Complete backdoor analysis report for a single file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackdoorReport {
    /// All findings, sorted by severity (critical first).
    pub findings: Vec<BackdoorFinding>,
    /// Overall risk score [0.0 – 1.0].
    pub risk_score: f64,
    /// Overall verdict.
    pub verdict: BackdoorVerdict,
}

/// Stable, explain-oriented view of one finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingExplanation {
    pub rule_id: String,
    pub description: String,
    pub severity: BackdoorSeverity,
    pub confidence: f64,
    pub confidence_level: ConfidenceLevel,
    pub evidence: Vec<String>,
    pub mitre_ids: Vec<String>,
    pub remediation: String,
}

impl BackdoorReport {
    /// Return an explain view for a rule, suitable for CLI/API output.
    pub fn explain(&self, rule_id: BackdoorRuleId) -> Option<FindingExplanation> {
        self.findings
            .iter()
            .find(|finding| finding.rule_id == rule_id)
            .map(|finding| FindingExplanation {
                rule_id: finding.rule_id.to_string(),
                description: finding.description.clone(),
                severity: finding.severity,
                confidence: finding.confidence,
                confidence_level: ConfidenceLevel::from_score(finding.confidence),
                evidence: finding.evidence.clone(),
                mitre_ids: finding.mitre_ids.clone(),
                remediation: "Validate the evidence in code context before taking action; static findings are hypotheses, not proof.".into(),
            })
    }

    /// Remove findings explicitly accepted by the caller while preserving an
    /// auditable, deterministic report recomputation.
    pub fn without_rules(&self, suppressed: &[BackdoorRuleId]) -> Self {
        let findings = self
            .findings
            .iter()
            .filter(|finding| !suppressed.contains(&finding.rule_id))
            .cloned()
            .collect();
        Self::from_findings(findings)
    }

    /// Emit a minimal SARIF 2.1.0 document for CI/security tooling.
    pub fn to_sarif(&self, artifact: &str) -> serde_json::Value {
        let results: Vec<_> = self
            .findings
            .iter()
            .map(|finding| {
                serde_json::json!({
                    "ruleId": finding.rule_id.to_string(),
                    "level": match finding.severity {
                        BackdoorSeverity::Critical | BackdoorSeverity::High => "error",
                        BackdoorSeverity::Medium => "warning",
                        BackdoorSeverity::Low => "note",
                    },
                    "message": { "text": finding.description },
                    "locations": [{ "physicalLocation": {
                        "artifactLocation": { "uri": artifact }
                    }}],
                    "properties": {
                        "confidence": finding.confidence,
                        "evidence": finding.evidence,
                        "mitre": finding.mitre_ids
                    }
                })
            })
            .collect();
        serde_json::json!({
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": { "driver": { "name": "FreakRE backdoor-analyzer" } },
                "results": results
            }]
        })
    }
}

impl BackdoorReport {
    /// Create an empty clean report.
    pub fn clean() -> Self {
        Self {
            findings: Vec::new(),
            risk_score: 0.0,
            verdict: BackdoorVerdict::Clean,
        }
    }

    /// Build report from findings, computing score and verdict.
    pub fn from_findings(mut findings: Vec<BackdoorFinding>) -> Self {
        if findings.is_empty() {
            return Self::clean();
        }

        // Sort: critical first, then high, then medium
        findings.sort_by_key(|f| std::cmp::Reverse(f.severity));

        // Probabilistic (noisy-OR) aggregation: each finding independently
        // pushes toward risk=1, so piling up weak findings cannot saturate
        // the score the way a linear sum does.
        let mut no_risk = 1.0_f64;
        for f in &findings {
            // Findings are a public input to this constructor. Treat invalid
            // floating-point values as no confidence instead of allowing NaN
            // to poison the report score and verdict comparisons.
            let confidence = if f.confidence.is_finite() {
                f.confidence.clamp(0.0, 1.0)
            } else {
                0.0
            };
            let weight = confidence
                * match f.severity {
                    BackdoorSeverity::Low => 0.05,
                    BackdoorSeverity::Critical => 0.35,
                    BackdoorSeverity::High => 0.20,
                    BackdoorSeverity::Medium => 0.10,
                };
            no_risk *= 1.0 - weight.min(0.99);
        }
        let risk_score = 1.0 - no_risk;

        // A verdict of BackdoorDetected requires either a high-confidence
        // critical finding or an aggregated score that is hard to reach with
        // weak evidence alone.
        let strong_critical = findings
            .iter()
            .any(|f| f.severity == BackdoorSeverity::Critical && f.confidence >= 0.7);
        let verdict = if strong_critical || risk_score >= 0.5 {
            BackdoorVerdict::BackdoorDetected
        } else if risk_score >= 0.15 {
            BackdoorVerdict::Suspicious
        } else {
            BackdoorVerdict::Clean
        };

        Self {
            findings,
            risk_score,
            verdict,
        }
    }

    /// One-line summary for CLI output.
    pub fn summary(&self) -> String {
        if self.findings.is_empty() {
            return "No backdoor indicators found".to_string();
        }
        format!(
            "{} finding(s), risk={:.2}, verdict={}",
            self.findings.len(),
            self.risk_score,
            self.verdict
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::BackdoorRuleId;

    #[test]
    fn test_clean_report() {
        let r = BackdoorReport::clean();
        assert_eq!(r.verdict, BackdoorVerdict::Clean);
        assert_eq!(r.risk_score, 0.0);
        assert!(r.findings.is_empty());
    }

    #[test]
    fn test_critical_triggers_backdoor_detected() {
        let findings = vec![BackdoorFinding {
            rule_id: BackdoorRuleId::ReverseShell,
            severity: BackdoorSeverity::Critical,
            confidence: 0.9,
            description: "test".into(),
            evidence: vec!["connect".into()],
            mitre_ids: vec![],
        }];
        let r = BackdoorReport::from_findings(findings);
        assert_eq!(r.verdict, BackdoorVerdict::BackdoorDetected);
        assert!(r.risk_score >= 0.3);
    }

    #[test]
    fn test_medium_only_is_clean() {
        let findings = vec![BackdoorFinding {
            rule_id: BackdoorRuleId::EncryptedConfig,
            severity: BackdoorSeverity::Medium,
            confidence: 0.9,
            description: "test".into(),
            evidence: vec![],
            mitre_ids: vec![],
        }];
        let r = BackdoorReport::from_findings(findings);
        assert_eq!(r.verdict, BackdoorVerdict::Clean);
    }

    #[test]
    fn non_finite_confidence_does_not_poison_report() {
        let findings = vec![BackdoorFinding {
            rule_id: BackdoorRuleId::EncryptedConfig,
            severity: BackdoorSeverity::Medium,
            confidence: f64::NAN,
            description: "test".into(),
            evidence: vec![],
            mitre_ids: vec![],
        }];
        let report = BackdoorReport::from_findings(findings);
        assert!(report.risk_score.is_finite());
        assert_eq!(report.risk_score, 0.0);
        assert_eq!(report.verdict, BackdoorVerdict::Clean);
    }

    #[test]
    fn explain_and_sarif_preserve_finding_evidence() {
        let finding = BackdoorFinding {
            rule_id: BackdoorRuleId::ReverseShell,
            severity: BackdoorSeverity::Critical,
            confidence: 0.9,
            description: "socket plus shell".into(),
            evidence: vec!["connect".into(), "/bin/sh".into()],
            mitre_ids: vec!["T1059".into()],
        };
        let report = BackdoorReport::from_findings(vec![finding]);
        let explanation = report.explain(BackdoorRuleId::ReverseShell).unwrap();
        assert_eq!(explanation.confidence_level, ConfidenceLevel::High);
        assert_eq!(explanation.evidence.len(), 2);
        let sarif = report.to_sarif("sample.exe");
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["results"][0]["ruleId"], "REVERSE_SHELL");
    }

    #[test]
    fn suppression_recomputes_report() {
        let finding = BackdoorFinding {
            rule_id: BackdoorRuleId::ScheduledTaskPersistence,
            severity: BackdoorSeverity::Low,
            confidence: 0.35,
            description: "task".into(),
            evidence: vec!["schtasks /create".into()],
            mitre_ids: vec!["T1053.005".into()],
        };
        let report = BackdoorReport::from_findings(vec![finding]);
        let filtered = report.without_rules(&[BackdoorRuleId::ScheduledTaskPersistence]);
        assert!(filtered.findings.is_empty());
        assert_eq!(filtered.risk_score, 0.0);
    }
}
