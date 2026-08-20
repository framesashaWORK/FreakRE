//! Backdoor analysis report types.

use crate::rules::BackdoorRuleId;
use std::fmt;

/// Severity level for a backdoor finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BackdoorSeverity {
    Medium,
    High,
    Critical,
}

impl fmt::Display for BackdoorSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
            | Self::C2Beacon
            | Self::AuthBypass
            | Self::FirmwareIndicator => BackdoorSeverity::Critical,

            Self::NamedPipeBackdoor
            | Self::RegistryPersistence
            | Self::DllHijacking
            | Self::HiddenAccount => BackdoorSeverity::High,

            Self::EncryptedConfig => BackdoorSeverity::Medium,
        }
    }
}

/// A single backdoor detection finding.
#[derive(Debug, Clone)]
pub struct BackdoorFinding {
    /// Which rule triggered this finding.
    pub rule_id: BackdoorRuleId,
    /// Severity of this finding.
    pub severity: BackdoorSeverity,
    /// Human-readable explanation.
    pub description: String,
    /// Evidence: matched API names or string patterns.
    pub evidence: Vec<String>,
    /// MITRE ATT&CK technique IDs.
    pub mitre_ids: Vec<String>,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone)]
pub struct BackdoorReport {
    /// All findings, sorted by severity (critical first).
    pub findings: Vec<BackdoorFinding>,
    /// Overall risk score [0.0 – 1.0].
    pub risk_score: f64,
    /// Overall verdict.
    pub verdict: BackdoorVerdict,
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
        findings.sort_by(|a, b| b.severity.cmp(&a.severity));

        // Compute weighted risk score
        let mut score = 0.0_f64;
        for f in &findings {
            score += match f.severity {
                BackdoorSeverity::Critical => 0.35,
                BackdoorSeverity::High => 0.20,
                BackdoorSeverity::Medium => 0.10,
            };
        }
        let risk_score = score.min(1.0);

        // Determine verdict
        let has_critical = findings.iter().any(|f| f.severity == BackdoorSeverity::Critical);
        let verdict = if has_critical || risk_score >= 0.5 {
            BackdoorVerdict::BackdoorDetected
        } else if risk_score >= 0.2 {
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
            description: "test".into(),
            evidence: vec![],
            mitre_ids: vec![],
        }];
        let r = BackdoorReport::from_findings(findings);
        assert_eq!(r.verdict, BackdoorVerdict::Clean);
    }
}
