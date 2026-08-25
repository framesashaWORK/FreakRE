//! Backdoor detection rule definitions.
//! Each rule targets a specific backdoor TTP (Tactics, Techniques, and Procedures).

use std::fmt;
use std::sync::OnceLock;

/// Unique identifier for each backdoor detection rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackdoorRuleId {
    /// Reverse shell: outbound connection + shell spawn
    ReverseShell,
    /// Bind shell: listen on port + accept + shell spawn
    BindShell,
    /// Named pipe backdoor: IPC-based local backdoor
    NamedPipeBackdoor,
    /// Registry persistence: Run keys with suspicious paths
    RegistryPersistence,
    /// Service backdoor: CreateService pointing to temp/appdata
    ServiceBackdoor,
    /// DLL hijacking: side-loading via relative LoadLibrary
    DllHijacking,
    /// Web shell indicators: eval/base64/cmd patterns in resources
    WebShellIndicator,
    /// C2 beacon: sleep+recv+decrypt+execute loop pattern
    C2Beacon,
    /// Auth bypass: credential hooking / SSP injection
    AuthBypass,
    /// Hidden account creation: NetUserAdd with suspicious params
    HiddenAccount,
    /// Encrypted config block near network API
    EncryptedConfig,
    /// Firmware/UEFI backdoor indicators
    FirmwareIndicator,
}

impl fmt::Display for BackdoorRuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReverseShell => write!(f, "REVERSE_SHELL"),
            Self::BindShell => write!(f, "BIND_SHELL"),
            Self::NamedPipeBackdoor => write!(f, "NAMED_PIPE_BACKDOOR"),
            Self::RegistryPersistence => write!(f, "REGISTRY_PERSISTENCE"),
            Self::ServiceBackdoor => write!(f, "SERVICE_BACKDOOR"),
            Self::DllHijacking => write!(f, "DLL_HIJACKING"),
            Self::WebShellIndicator => write!(f, "WEBSHELL_INDICATOR"),
            Self::C2Beacon => write!(f, "C2_BEACON"),
            Self::AuthBypass => write!(f, "AUTH_BYPASS"),
            Self::HiddenAccount => write!(f, "HIDDEN_ACCOUNT"),
            Self::EncryptedConfig => write!(f, "ENCRYPTED_CONFIG"),
            Self::FirmwareIndicator => write!(f, "FIRMWARE_INDICATOR"),
        }
    }
}

impl BackdoorRuleId {
    /// Human-readable description of what this rule detects.
    pub fn description(&self) -> &'static str {
        match self {
            Self::ReverseShell => "Outbound socket connection combined with shell/process spawn",
            Self::BindShell => "Listening socket with accept + shell spawn (bind shell)",
            Self::NamedPipeBackdoor => "Named pipe IPC used as local backdoor channel",
            Self::RegistryPersistence => "Autorun registry key pointing to suspicious location",
            Self::ServiceBackdoor => "Windows service created with binary in temp/appdata",
            Self::DllHijacking => "DLL side-loading via relative path or known hijack targets",
            Self::WebShellIndicator => "Web shell code patterns (eval, base64_decode, cmd exec)",
            Self::C2Beacon => "C2 beacon loop: periodic sleep + receive + decrypt + execute",
            Self::AuthBypass => "Authentication bypass via credential hooking or SSP injection",
            Self::HiddenAccount => "Hidden/suspicious user account creation via NetUserAdd",
            Self::EncryptedConfig => "High-entropy encrypted config block adjacent to network API",
            Self::FirmwareIndicator => "Firmware/UEFI backdoor indicators (DXE/SMM references)",
        }
    }

    /// MITRE ATT&CK technique ID(s) associated with this rule.
    pub fn mitre_ids(&self) -> &'static [&'static str] {
        match self {
            Self::ReverseShell => &["T1059", "T1071"],
            Self::BindShell => &["T1059", "T1571"],
            Self::NamedPipeBackdoor => &["T1559.001"],
            Self::RegistryPersistence => &["T1547.001"],
            Self::ServiceBackdoor => &["T1543.003"],
            Self::DllHijacking => &["T1574.001"],
            Self::WebShellIndicator => &["T1505.003"],
            Self::C2Beacon => &["T1071", "T1573"],
            Self::AuthBypass => &["T1556", "T1547.008"],
            Self::HiddenAccount => &["T1136.001"],
            Self::EncryptedConfig => &["T1573", "T1027"],
            Self::FirmwareIndicator => &["T1542.001", "T1542.003"],
        }
    }
}

/// Import-based signature: a set of API names that together indicate a backdoor pattern.
#[derive(Debug, Clone)]
pub struct ImportSignature {
    pub rule_id: BackdoorRuleId,
    /// All of these imports must be present (case-insensitive).
    pub required_apis: &'static [&'static str],
    /// At least one of these must also be present (optional enrichment).
    pub optional_apis: &'static [&'static str],
    /// Minimum number of optional APIs required (0 = none required).
    pub min_optional: usize,
}

/// String-based signature: patterns found in extracted strings.
#[derive(Debug, Clone)]
pub struct StringSignature {
    pub rule_id: BackdoorRuleId,
    /// Required substrings to search for (case-insensitive).
    /// At least `min_matches` of these must match.
    pub patterns: &'static [&'static str],
    /// Minimum number of required patterns that must match.
    pub min_matches: usize,
    /// Enrichment substrings: when non-empty, at least one of these must ALSO
    /// match for the signature to fire.
    pub optional_patterns: &'static [&'static str],
}

// ─── Import Signatures ────────────────────────────────────────────────

pub const IMPORT_SIGNATURES: &[ImportSignature] = &[
    // Reverse Shell: connect out + spawn shell
    ImportSignature {
        rule_id: BackdoorRuleId::ReverseShell,
        required_apis: &["WSAStartup", "connect"],
        optional_apis: &["CreateProcessA", "CreateProcessW",
                         "ShellExecuteA", "ShellExecuteW", "WinExec"],
        min_optional: 1,
    },
    // Reverse Shell variant: WSAConnect
    ImportSignature {
        rule_id: BackdoorRuleId::ReverseShell,
        required_apis: &["WSAConnect"],
        optional_apis: &["CreateProcessA", "CreateProcessW", "WinExec"],
        min_optional: 1,
    },
    // Bind Shell: listen + accept + shell
    ImportSignature {
        rule_id: BackdoorRuleId::BindShell,
        required_apis: &["bind", "listen", "accept"],
        optional_apis: &["CreateProcessA", "CreateProcessW", "WinExec"],
        min_optional: 1,
    },
    // Named Pipe Backdoor.
    // ReadFile/WriteFile are universal (any file or pipe I/O), so they carry
    // no signal; require pipe-specific and execution-related APIs instead.
    ImportSignature {
        rule_id: BackdoorRuleId::NamedPipeBackdoor,
        required_apis: &["CreateNamedPipeA"],
        optional_apis: &["ConnectNamedPipe", "ImpersonateNamedPipeClient",
                         "TransactNamedPipe", "CreateProcessA", "CreateProcessW"],
        min_optional: 2,
    },
    // Named Pipe Backdoor (wide-char API variant).
    ImportSignature {
        rule_id: BackdoorRuleId::NamedPipeBackdoor,
        required_apis: &["CreateNamedPipeW"],
        optional_apis: &["ConnectNamedPipe", "ImpersonateNamedPipeClient",
                         "TransactNamedPipe", "CreateProcessA", "CreateProcessW"],
        min_optional: 2,
    },
    // Service Backdoor
    ImportSignature {
        rule_id: BackdoorRuleId::ServiceBackdoor,
        required_apis: &["CreateServiceA"],
        optional_apis: &["StartServiceA", "ChangeServiceConfigA"],
        min_optional: 0,
    },
    // Service Backdoor (wide-char API variant).
    ImportSignature {
        rule_id: BackdoorRuleId::ServiceBackdoor,
        required_apis: &["CreateServiceW"],
        optional_apis: &["StartServiceW", "ChangeServiceConfigW"],
        min_optional: 0,
    },
    // Auth Bypass: credential hooking
    ImportSignature {
        rule_id: BackdoorRuleId::AuthBypass,
        required_apis: &["LogonUserA"],
        optional_apis: &["CredEnumerateA", "CredReadA", "LsaLogonUser",
                         "SspiPrepareForCredRead"],
        min_optional: 1,
    },
    // Auth Bypass: credential hooking (wide-char API variant).
    ImportSignature {
        rule_id: BackdoorRuleId::AuthBypass,
        required_apis: &["LogonUserW"],
        optional_apis: &["CredEnumerateA", "CredReadA", "LsaLogonUser",
                         "SspiPrepareForCredRead"],
        min_optional: 1,
    },
    // Auth Bypass: SSP injection
    ImportSignature {
        rule_id: BackdoorRuleId::AuthBypass,
        required_apis: &["AddSecurityPackageA"],
        optional_apis: &[],
        min_optional: 0,
    },
    // Hidden Account
    ImportSignature {
        rule_id: BackdoorRuleId::HiddenAccount,
        required_apis: &["NetUserAdd"],
        optional_apis: &["NetLocalGroupAddMembers", "NetGroupAddMembers"],
        min_optional: 0,
    },
    // C2 Beacon: sleep + recv + OUTBOUND connect + crypto/self-modification.
    // Sleep+recv alone describe every networked application; a beacon must
    // also dial out and prepare received payloads for execution.
    ImportSignature {
        rule_id: BackdoorRuleId::C2Beacon,
        required_apis: &["Sleep", "recv", "connect"],
        optional_apis: &["CryptDecrypt", "BCryptDecrypt", "VirtualProtect",
                         "VirtualAlloc", "NtUnmapViewOfSection"],
        min_optional: 1,
    },
];

// ─── String Signatures ────────────────────────────────────────────────

pub const STRING_SIGNATURES: &[StringSignature] = &[
    // Web Shell Indicators.
    // `eval(` and `exec(` are ubiquitous in embedded JS/PHP runtimes of
    // legitimate software (Electron bundles etc.), so only webshell-specific
    // tokens count as evidence and at least TWO distinct ones are required.
    StringSignature {
        rule_id: BackdoorRuleId::WebShellIndicator,
        patterns: &["base64_decode", "shell_exec(", "passthru(", "proc_open("],
        min_matches: 2,
        optional_patterns: &[],
    },
    // Registry Persistence: Run/RunOnce autorun keys are mandatory; suspicious
    // directories only enrich (a path alone is not persistence evidence).
    StringSignature {
        rule_id: BackdoorRuleId::RegistryPersistence,
        patterns: &[
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        ],
        min_matches: 1,
        optional_patterns: &["\\AppData\\", "\\Temp\\", "\\ProgramData\\"],
    },
    // Service Backdoor paths
    StringSignature {
        rule_id: BackdoorRuleId::ServiceBackdoor,
        patterns: &["\\AppData\\Local\\Temp\\", "\\AppData\\Roaming\\",
                     "\\ProgramData\\", "svchost", "rundll32"],
        min_matches: 3,
        optional_patterns: &[],
    },
    // Firmware/UEFI indicators.
    // Tokens must be UEFI-specific: generic security vocabulary like
    // "SECURITY_PROTOCOL" appears in every large Windows binary.
    StringSignature {
        rule_id: BackdoorRuleId::FirmwareIndicator,
        patterns: &["DXE_CORE", "SMM_HANDLER", "EFI_BOOT_SERVICES",
                     "FV_MAIN", "PEI_CORE", "EFI_SYSTEM_TABLE"],
        min_matches: 2,
        optional_patterns: &[],
    },
    // C2 Beacon strings
    StringSignature {
        rule_id: BackdoorRuleId::C2Beacon,
        patterns: &["beacon", "callback", "checkin", "heartbeat",
                     "stage", "postback", "sleeptime"],
        min_matches: 3,
        optional_patterns: &[],
    },
    // Reverse shell strings. Generic interpreter names (cmd.exe, powershell,
    // whoami) live in virtually every large binary; only distinctive
    // shell-invocation patterns count as evidence.
    StringSignature {
        rule_id: BackdoorRuleId::ReverseShell,
        patterns: &["/bin/sh", "/bin/bash", "bash -i", "nc -e ",
                     "powershell -enc", "cmd.exe /c", "cmd.exe /k"],
        min_matches: 2,
        optional_patterns: &[],
    },
    // DLL hijacking via side-loading paths. Requires BOTH a DLL reference and
    // a user-writable directory — LoadLibrary imports alone are meaningless.
    StringSignature {
        rule_id: BackdoorRuleId::DllHijacking,
        patterns: &[".dll"],
        min_matches: 1,
        optional_patterns: &["\\AppData\\", "\\Temp\\", "\\ProgramData\\"],
    },
];

// ─── Pre-lowered signature tables (process-wide, computed once) ───────
//
// The analyzer lowercases every API/pattern for case-insensitive matching.
// Rules are `&'static` data, so the lowered forms never change: they are
// computed lazily exactly once per process via `OnceLock` and leaked,
// removing all per-analysis lowering allocations from the hot path.
//
// Original-cased arrays are kept alongside so evidence strings still cite
// the canonical rule text (e.g. "CreateServiceW", not "createservicew").

#[derive(Debug)]
pub struct ImportSignatureLowered {
    pub rule_id: BackdoorRuleId,
    /// Original-cased required APIs — used verbatim in evidence output.
    pub required_orig: &'static [&'static str],
    /// Lowercased required APIs — used for matching only.
    pub required_lower: &'static [&'static str],
    pub optional_orig: &'static [&'static str],
    pub optional_lower: &'static [&'static str],
    pub min_optional: usize,
}

#[derive(Debug)]
pub struct StringSignatureLowered {
    pub rule_id: BackdoorRuleId,
    /// Original-cased patterns — used verbatim in evidence output.
    pub patterns_orig: &'static [&'static str],
    /// Lowercased patterns — used for matching only.
    pub patterns_lower: &'static [&'static str],
    pub min_matches: usize,
    pub optional_patterns_orig: &'static [&'static str],
    pub optional_patterns_lower: &'static [&'static str],
}

fn leak_lowered(apis: &'static [&'static str]) -> &'static [&'static str] {
    let lowered: Vec<String> = apis.iter().map(|api| api.to_lowercase()).collect();
    let refs: Vec<&'static str> = lowered
        .into_iter()
        .map(|s| Box::leak(s.into_boxed_str()) as &'static str)
        .collect();
    Vec::leak(refs)
}

/// All import signatures with API names pre-lowered once per process.
///
/// Order mirrors [`IMPORT_SIGNATURES`] element-for-element; the parallel
/// `_orig`/`_lower` slices share indices and lengths.
pub fn import_signatures_lowered() -> &'static [ImportSignatureLowered] {
    static LOWERED: OnceLock<Vec<ImportSignatureLowered>> = OnceLock::new();
    LOWERED.get_or_init(|| {
        IMPORT_SIGNATURES
            .iter()
            .map(|sig| ImportSignatureLowered {
                rule_id: sig.rule_id,
                required_orig: sig.required_apis,
                required_lower: leak_lowered(sig.required_apis),
                optional_orig: sig.optional_apis,
                optional_lower: leak_lowered(sig.optional_apis),
                min_optional: sig.min_optional,
            })
            .collect()
    })
}

/// All string signatures with patterns pre-lowered once per process.
///
/// Order mirrors [`STRING_SIGNATURES`] element-for-element; the parallel
/// `_orig`/`_lower` slices share indices and lengths.
pub fn string_signatures_lowered() -> &'static [StringSignatureLowered] {
    static LOWERED: OnceLock<Vec<StringSignatureLowered>> = OnceLock::new();
    LOWERED.get_or_init(|| {
        STRING_SIGNATURES
            .iter()
            .map(|sig| StringSignatureLowered {
                rule_id: sig.rule_id,
                patterns_orig: sig.patterns,
                patterns_lower: leak_lowered(sig.patterns),
                min_matches: sig.min_matches,
                optional_patterns_orig: sig.optional_patterns,
                optional_patterns_lower: leak_lowered(sig.optional_patterns),
            })
            .collect()
    })
}
