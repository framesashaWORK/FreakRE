//! Conservative function-level correlation helpers.
//!
//! Import presence is not function behavior. Callers can provide the APIs
//! actually reached by a function, and this module only emits a correlation
//! when a complete technique chain is present in that same function.

use crate::report::{BackdoorFinding, BackdoorSeverity};
use crate::rules::BackdoorRuleId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionEvidence {
    pub address: u64,
    pub name: String,
    pub apis: Vec<String>,
}

fn has_api(apis: &[String], needle: &str) -> bool {
    apis.iter().any(|api| api.eq_ignore_ascii_case(needle))
}

/// Correlate a high-signal injection chain within one function.
pub fn correlate_function_evidence(function: &FunctionEvidence) -> Vec<BackdoorFinding> {
    let has_memory_chain = has_api(&function.apis, "VirtualAllocEx")
        && has_api(&function.apis, "WriteProcessMemory");
    let execution_api = [
        "CreateRemoteThread",
        "NtCreateThreadEx",
        "RtlCreateUserThread",
        "QueueUserAPC",
    ]
    .iter()
    .find(|api| has_api(&function.apis, api));

    if !(has_memory_chain && execution_api.is_some()) {
        return Vec::new();
    }

    let mut evidence = vec![
        "VirtualAllocEx".to_string(),
        "WriteProcessMemory".to_string(),
        execution_api.unwrap().to_string(),
    ];
    evidence.push(format!("function 0x{:X} ({})", function.address, function.name));
    vec![BackdoorFinding {
        rule_id: BackdoorRuleId::RemoteThreadInjection,
        severity: BackdoorSeverity::High,
        confidence: 0.95,
        description: "Remote process allocation, write, and thread execution chain in one function".into(),
        evidence,
        mitre_ids: vec!["T1055".into()],
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn function(apis: &[&str]) -> FunctionEvidence {
        FunctionEvidence {
            address: 0x401000,
            name: "inject".into(),
            apis: apis.iter().map(|api| (*api).into()).collect(),
        }
    }

    #[test]
    fn complete_chain_in_one_function_fires() {
        let findings = correlate_function_evidence(&function(&[
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        ]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, 0.95);
    }

    #[test]
    fn incomplete_chain_does_not_fire() {
        assert!(correlate_function_evidence(&function(&[
            "VirtualAllocEx", "WriteProcessMemory",
        ])).is_empty());
    }
}
