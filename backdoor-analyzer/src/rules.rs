//! Backdoor detection rule definitions.
//! Each rule targets a specific backdoor TTP (Tactics, Techniques, and Procedures).

use std::fmt;

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
    /// Substrings to search for (case-insensitive).
    pub patterns: &'static [&'static str],
    /// Minimum number of patterns that must match.
    pub min_matches: usize,
}

// ─── Import Signatures ────────────────────────────────────────────────

pub const IMPORT_SIGNATURES: &[ImportSignature] = &[
    // Reverse Shell: connect out + spawn shell
    ImportSignature {
        rule_id: BackdoorRuleId::ReverseShell,
        required_apis: &["WSAStartup", "connect"],
        optional_apis: &["CreateProcessA", "CreateProcessW", "cmd.exe", "powershell",
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
        optional_apis: &["CreateProcessA", "CreateProcessW", "cmd.exe", "WinExec"],
        min_optional: 1,
    },
    // Named Pipe Backdoor
    ImportSignature {
        rule_id: BackdoorRuleId::NamedPipeBackdoor,
        required_apis: &["CreateNamedPipeA"],
        optional_apis: &["ConnectNamedPipe", "ReadFile", "WriteFile",
                         "CreateProcessA", "CreateProcessW"],
        min_optional: 2,
    },
    // Service Backdoor
    ImportSignature {
        rule_id: BackdoorRuleId::ServiceBackdoor,
        required_apis: &["CreateServiceA"],
        optional_apis: &["StartServiceA", "ChangeServiceConfigA"],
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
    // C2 Beacon: sleep + recv + crypto
    ImportSignature {
        rule_id: BackdoorRuleId::C2Beacon,
        required_apis: &["Sleep", "recv"],
        optional_apis: &["CryptDecrypt", "BCryptDecrypt", "VirtualProtect",
                         "VirtualAlloc", "NtUnmapViewOfSection"],
        min_optional: 1,
    },
    // DLL Hijacking: known vulnerable DLL loads
    ImportSignature {
        rule_id: BackdoorRuleId::DllHijacking,
        required_apis: &["LoadLibraryA"],
        optional_apis: &["SetDllDirectoryA", "AddDllDirectory"],
        min_optional: 0,
    },
];

// ─── String Signatures ────────────────────────────────────────────────

pub const STRING_SIGNATURES: &[StringSignature] = &[
    // Web Shell Indicators
    StringSignature {
        rule_id: BackdoorRuleId::WebShellIndicator,
        patterns: &["eval(", "base64_decode", "system(", "exec(",
                     "passthru(", "shell_exec(", "popen(", "proc_open("],
        min_matches: 2,
    },
    // Registry Persistence paths
    StringSignature {
        rule_id: BackdoorRuleId::RegistryPersistence,
        patterns: &[
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "\\AppData\\", "\\Temp\\", "\\ProgramData\\",
        ],
        min_matches: 2,
    },
    // Service Backdoor paths
    StringSignature {
        rule_id: BackdoorRuleId::ServiceBackdoor,
        patterns: &["\\AppData\\Local\\Temp\\", "\\AppData\\Roaming\\",
                     "\\ProgramData\\", "svchost", "rundll32"],
        min_matches: 1,
    },
    // Firmware/UEFI indicators
    StringSignature {
        rule_id: BackdoorRuleId::FirmwareIndicator,
        patterns: &["DXE_CORE", "SMM_HANDLER", "EFI_BOOT_SERVICES",
                     "SECURITY_PROTOCOL", "FV_MAIN", "PEI_CORE"],
        min_matches: 2,
    },
    // C2 Beacon strings
    StringSignature {
        rule_id: BackdoorRuleId::C2Beacon,
        patterns: &["beacon", "callback", "checkin", "heartbeat",
                     "stage", "postback", "sleeptime"],
        min_matches: 2,
    },
    // Reverse shell common strings
    StringSignature {
        rule_id: BackdoorRuleId::ReverseShell,
        patterns: &["cmd.exe", "/bin/sh", "/bin/bash", "powershell.exe",
                     "whoami", "ipconfig", "ifconfig"],
        min_matches: 2,
    },
];
