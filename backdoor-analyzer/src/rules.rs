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

    // ─── Common malware pack ─────────────────────────────────────────
    /// Keylogger: keystroke hooking / async key-state polling + exfil
    Keylogger,
    /// Clipboard hijack: monitor + replace clipboard contents
    ClipboardHijack,
    /// Screen capture primitives combined with network capability
    ScreenCapture,
    /// Cryptocurrency miner indicators (pool protocol, bulk CryptoAPI)
    Cryptominer,
    /// Ransomware: mass file enumeration + encryption + ransom markers
    Ransomware,

    // ─── Rare TTP pack ───────────────────────────────────────────────
    /// Process hollowing / section-based code injection
    ProcessHollowing,
    /// Execution via callback-registration APIs paired with RWX memory
    CallbackInjection,
    /// UAC bypass via auto-elevate handler registry abuse
    UacBypass,
    /// Living-off-the-land binary abuse (certutil/mshta/regsvr32/bitsadmin)
    LolbinAbuse,
    /// DNS resolver APIs without any HTTP/socket stack (DNS-only C2 shape)
    DnsC2Anomaly,

    // ─── Anti-debug / anti-VM / sandbox-evasion pack ─────────────────
    /// Debugger detection APIs
    AntiDebug,
    /// VM / sandbox artifact probing via distinctive guest markers
    AntiVm,
    /// Timing-loop evasion proxy (tick counter + Sleep + network)
    SleepEvasion,
    /// Human interaction check (cursor position + key state polling)
    MouseActivityCheck,

    // ─── Byte-level pack ─────────────────────────────────────────────
    /// Direct syscall stubs (mov eax, SSN; syscall; ret)
    DirectSyscalls,
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

            Self::Keylogger => write!(f, "KEYLOGGER"),
            Self::ClipboardHijack => write!(f, "CLIPBOARD_HIJACK"),
            Self::ScreenCapture => write!(f, "SCREEN_CAPTURE"),
            Self::Cryptominer => write!(f, "CRYPTOMINER"),
            Self::Ransomware => write!(f, "RANSOMWARE"),

            Self::ProcessHollowing => write!(f, "PROCESS_HOLLOWING"),
            Self::CallbackInjection => write!(f, "CALLBACK_INJECTION"),
            Self::UacBypass => write!(f, "UAC_BYPASS"),
            Self::LolbinAbuse => write!(f, "LOLBIN_ABUSE"),
            Self::DnsC2Anomaly => write!(f, "DNS_C2_ANOMALY"),

            Self::AntiDebug => write!(f, "ANTI_DEBUG"),
            Self::AntiVm => write!(f, "ANTI_VM"),
            Self::SleepEvasion => write!(f, "SLEEP_EVASION"),
            Self::MouseActivityCheck => write!(f, "MOUSE_ACTIVITY_CHECK"),

            Self::DirectSyscalls => write!(f, "DIRECT_SYSCALLS"),
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

            Self::Keylogger => "Keystroke monitoring via hook installation or async key-state polling with exfiltration",
            Self::ClipboardHijack => "Clipboard read-modify-write chain combined with network capability (clipper)",
            Self::ScreenCapture => "Screen capture primitives (BitBlt/GetDC/GDI+) combined with network capability",
            Self::Cryptominer => "Cryptocurrency mining indicators: pool protocol strings and bulk CryptoAPI usage",
            Self::Ransomware => "Mass file enumeration + encryption + ransom markers (renamed extensions, shadow-copy deletion)",

            Self::ProcessHollowing => "Process hollowing/injection primitives: section manipulation with WriteProcessMemory and thread-context rewrite",
            Self::CallbackInjection => "RWX allocation paired with callback-registration APIs (EnumWindows/SetTimer-style)",
            Self::UacBypass => "UAC bypass via auto-elevate handler registry abuse (fodhelper/eventvwr/ICMLuaUtil)",
            Self::LolbinAbuse => "Living-off-the-land download/exec command lines (certutil -urlcache, mshta, regsvr32, bitsadmin)",
            Self::DnsC2Anomaly => "DNS resolver APIs present without any HTTP/socket stack — possible DNS-only C2 (also true of DNS utilities)",

            Self::AntiDebug => "Debugger detection APIs (IsDebuggerPresent, ProcessDebugPort queries, OutputDebugString tricks)",
            Self::AntiVm => "VM/sandbox artifact probes (VirtualBox/VMware/QEMU/Sandboxie/Cuckoo guest markers)",
            Self::SleepEvasion => "Weak static proxy: Sleep + tick-counter APIs co-resident with network imports (timing-loop evasion)",
            Self::MouseActivityCheck => "Human interaction check: cursor position + key state polling (low confidence; games use the same pair)",

            Self::DirectSyscalls => "Direct syscall stubs (mov eax, SSN; syscall; ret) bypassing ntdll API hooks",
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

            Self::Keylogger => &["T1056.001"],
            Self::ClipboardHijack => &["T1115"],
            Self::ScreenCapture => &["T1113"],
            Self::Cryptominer => &["T1496"],
            Self::Ransomware => &["T1486", "T1490"],

            Self::ProcessHollowing => &["T1055.012"],
            Self::CallbackInjection => &["T1055"],
            Self::UacBypass => &["T1548.002"],
            Self::LolbinAbuse => &["T1105", "T1218"],
            Self::DnsC2Anomaly => &["T1071.004"],

            Self::AntiDebug => &["T1622"],
            Self::AntiVm => &["T1497.001"],
            Self::SleepEvasion => &["T1497.003"],
            Self::MouseActivityCheck => &["T1497.001"],

            Self::DirectSyscalls => &["T1106"],
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
    // ─── Common malware pack ─────────────────────────────────────────
    // Keylogger: keyboard hook installation. SetWindowsHookEx alone is used
    // by IMEs/accessibility tools, so an outbound network outlet is mandatory
    // before a hook chain is treated as exfiltrating keystrokes. (The
    // WH_KEYBOARD / WH_KEYBOARD_LL hook ids are call-time constants invisible
    // to static import analysis; the hook-install API is the closest proxy.)
    ImportSignature {
        rule_id: BackdoorRuleId::Keylogger,
        required_apis: &["SetWindowsHookEx"],
        optional_apis: &["connect", "socket", "send", "WSAStartup",
                         "InternetOpenA", "HttpSendRequestA"],
        min_optional: 1,
    },
    // Keylogger variant: raw async key-state polling loops. Games poll
    // GetAsyncKeyState constantly, so network capability is mandatory
    // before this shape is treated as keystroke theft.
    ImportSignature {
        rule_id: BackdoorRuleId::Keylogger,
        required_apis: &["GetAsyncKeyState"],
        optional_apis: &["connect", "socket", "send", "WSAStartup",
                         "InternetOpenA", "HttpSendRequestA"],
        min_optional: 1,
    },
    // Clipboard hijack: full read-modify-write clipboard chain + network.
    // Any single clipboard API (or OpenClipboard+GetClipboardData for reads)
    // is ordinary clipboard-manager behavior; only the complete replacement
    // chain with a network outlet indicates a clipper.
    ImportSignature {
        rule_id: BackdoorRuleId::ClipboardHijack,
        required_apis: &["OpenClipboard", "GetClipboardData", "SetClipboardData"],
        optional_apis: &["connect", "socket", "send", "WSAStartup",
                         "InternetOpenA", "HttpSendRequestA"],
        min_optional: 1,
    },
    // Screen capture: blit from a screen DC. Every local screenshot utility
    // shares these GDI primitives, so a network outlet (exfil path) is
    // mandatory before the pair is treated as surveillance.
    ImportSignature {
        rule_id: BackdoorRuleId::ScreenCapture,
        required_apis: &["BitBlt", "GetDC"],
        optional_apis: &["connect", "socket", "send", "WSAStartup",
                         "InternetOpenA", "HttpSendRequestA"],
        min_optional: 1,
    },
    // Screen capture variant: GDI+ encoder fed from a screen DC, again
    // gated on network capability.
    ImportSignature {
        rule_id: BackdoorRuleId::ScreenCapture,
        required_apis: &["GdiplusStartup", "GetDC"],
        optional_apis: &["connect", "socket", "send", "WSAStartup"],
        min_optional: 1,
    },
    // Cryptominer: classic CryptoAPI exercised at bulk scale (4 of 5
    // operations). Single hash/encrypt calls are ordinary software; miners
    // derive keys and hash continuously while talking to pools.
    ImportSignature {
        rule_id: BackdoorRuleId::Cryptominer,
        required_apis: &["CryptAcquireContextA"],
        optional_apis: &["CryptHashData", "CryptDeriveKey", "CryptCreateHash",
                         "CryptEncrypt", "CryptDecrypt"],
        min_optional: 4,
    },
    // Cryptominer (wide-char CryptoAPI variant).
    ImportSignature {
        rule_id: BackdoorRuleId::Cryptominer,
        required_apis: &["CryptAcquireContextW"],
        optional_apis: &["CryptHashData", "CryptDeriveKey", "CryptCreateHash",
                         "CryptEncrypt", "CryptDecrypt"],
        min_optional: 4,
    },
    // Ransomware: file iteration + bulk encryption.
    ImportSignature {
        rule_id: BackdoorRuleId::Ransomware,
        required_apis: &["FindFirstFileA", "CryptEncrypt"],
        optional_apis: &["FindNextFileA", "CryptAcquireContextA",
                         "DeleteFileA", "WriteFile"],
        min_optional: 1,
    },
    // Ransomware (wide-char / CNG variant).
    ImportSignature {
        rule_id: BackdoorRuleId::Ransomware,
        required_apis: &["FindFirstFileW", "BCryptEncrypt"],
        optional_apis: &["FindNextFileW", "BCryptOpenAlgorithmProvider",
                         "DeleteFileW", "WriteFile"],
        min_optional: 1,
    },
    // ─── Rare TTP pack ───────────────────────────────────────────────
    // Process hollowing: write payload + redirect execution into a
    // sacrificial process.
    ImportSignature {
        rule_id: BackdoorRuleId::ProcessHollowing,
        required_apis: &["WriteProcessMemory", "SetThreadContext"],
        optional_apis: &["ResumeThread", "NtUnmapViewOfSection",
                         "ZwUnmapViewOfSection", "VirtualAllocEx",
                         "ReadProcessMemory", "CreateProcessA", "CreateProcessW"],
        min_optional: 1,
    },
    // Process hollowing variant: section-mapping injection path.
    ImportSignature {
        rule_id: BackdoorRuleId::ProcessHollowing,
        required_apis: &["NtCreateSection", "NtMapViewOfSection"],
        optional_apis: &["WriteProcessMemory", "SetThreadContext", "ResumeThread",
                         "NtCreateThreadEx", "RtlCreateUserThread"],
        min_optional: 1,
    },
    // Callback injection: RWX-capable allocation combined with execution via
    // callback-registration APIs. VirtualAlloc/EnumWindows alone describe
    // ordinary GUI code; two further callback/protect APIs are required.
    ImportSignature {
        rule_id: BackdoorRuleId::CallbackInjection,
        required_apis: &["VirtualAlloc", "EnumWindows"],
        optional_apis: &["SetTimer", "SetWindowsHookExA", "SetWindowsHookExW",
                         "EnumChildWindows", "CertDuplicateCertificateContext",
                         "CreateThread", "VirtualProtect"],
        min_optional: 2,
    },
    // ─── Anti-debug / anti-VM / sandbox-evasion pack ─────────────────
    // Debugger detection: canonical check plus at least one companion probe.
    ImportSignature {
        rule_id: BackdoorRuleId::AntiDebug,
        required_apis: &["IsDebuggerPresent"],
        optional_apis: &["CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
                         "OutputDebugStringA", "OutputDebugStringW"],
        min_optional: 1,
    },
    // Debugger detection: cross-process debug check on its own is already
    // tool-grade behavior in a client binary.
    ImportSignature {
        rule_id: BackdoorRuleId::AntiDebug,
        required_apis: &["CheckRemoteDebuggerPresent"],
        optional_apis: &[],
        min_optional: 0,
    },
    // ProcessDebugPort heuristic: the ProcessDebugPort argument (7) is not
    // visible statically; NtQueryInformationProcess combined with debugger-
    // probe companions is the closest import-level proxy.
    ImportSignature {
        rule_id: BackdoorRuleId::AntiDebug,
        required_apis: &["NtQueryInformationProcess"],
        optional_apis: &["OutputDebugStringA", "OutputDebugStringW",
                         "IsDebuggerPresent", "CheckRemoteDebuggerPresent"],
        min_optional: 1,
    },
    // Sleep-acceleration / timing-loop evasion: WEAK static proxy. Malware
    // in sandboxes detects sleep-skipping via GetTickCount deltas around
    // Sleep and switches to busy-wait loops; statically, however, the mere
    // co-residence of a tick counter and Sleep cannot prove that pattern —
    // every networked UI app with a timer shares it. The network-import gate
    // only removes the most obvious non-networked false positives, so this
    // rule is deliberately Medium severity / low confidence.
    ImportSignature {
        rule_id: BackdoorRuleId::SleepEvasion,
        required_apis: &["Sleep", "GetTickCount"],
        optional_apis: &["connect", "socket", "send", "WSAStartup",
                         "InternetOpenA", "HttpSendRequestA"],
        min_optional: 1,
    },
    // Sleep-acceleration variant: high-resolution counter instead of ticks.
    ImportSignature {
        rule_id: BackdoorRuleId::SleepEvasion,
        required_apis: &["Sleep", "QueryPerformanceCounter"],
        optional_apis: &["connect", "socket", "send", "WSAStartup",
                         "InternetOpenA", "HttpSendRequestA"],
        min_optional: 1,
    },
    // Human interaction check: cursor position + key state polling.
    // Deliberately low confidence — games and automation frameworks use the
    // identical API pair for entirely legitimate purposes.
    ImportSignature {
        rule_id: BackdoorRuleId::MouseActivityCheck,
        required_apis: &["GetCursorPos", "GetAsyncKeyState"],
        optional_apis: &[],
        min_optional: 0,
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
    // ─── Common malware pack ─────────────────────────────────────────
    // Cryptominer protocol/config markers. Pool hostnames alone ("pool.")
    // are too generic and would double-count inside "stratum+tcp://pool/..."
    // strings, so only protocol verbs and miner identities carry signal.
    // Patterns are pairwise non-substring so one token cannot satisfy two.
    StringSignature {
        rule_id: BackdoorRuleId::Cryptominer,
        patterns: &["stratum+", "mining.subscribe", "mining.authorize",
                    "xmrig", "cryptonight", "randomx"],
        min_matches: 2,
        optional_patterns: &[],
    },
    // Ransomware markers: renamed-file extensions and shadow-copy /
    // recovery destruction commands. Patterns chosen non-overlapping so a
    // single token cannot satisfy two at once.
    StringSignature {
        rule_id: BackdoorRuleId::Ransomware,
        patterns: &[".encrypted", ".locked",
                    "vssadmin delete shadows", "wbadmin delete catalog",
                    "bcdedit /set recoveryenabled",
                    "how_to_decrypt", "how to restore files"],
        min_matches: 2,
        optional_patterns: &[],
    },
    // ─── Rare TTP pack ───────────────────────────────────────────────
    // UAC bypass via auto-elevate handlers. Tokens are handler-specific;
    // generic HKCU registry paths appear in every installer and are excluded.
    StringSignature {
        rule_id: BackdoorRuleId::UacBypass,
        patterns: &["ICMLuaUtil", "fodhelper", "eventvwr.exe", "ms-settings:",
                    "Software\\Classes\\exefile\\shell\\open\\command"],
        min_matches: 2,
        optional_patterns: &[],
    },
    // LOLBin abuse: distinctive download/exec command lines. A single hit is
    // already specific; the corroboration downgrade covers documentation
    // strings in security tooling.
    StringSignature {
        rule_id: BackdoorRuleId::LolbinAbuse,
        patterns: &["certutil -urlcache", "mshta http", "mshta vbscript",
                    "regsvr32 /i:http", "bitsadmin /transfer", "bitsadmin /create"],
        min_matches: 1,
        optional_patterns: &[],
    },
    // ─── Anti-analysis pack ──────────────────────────────────────────
    // VM/sandbox artifact probes. A probe is only meaningful when a binary
    // goes hunting for FOREIGN hypervisor/sandbox families: virtualization
    // vendors' own software legitimately embeds every artifact of its OWN
    // family (a VMware installer strings "VMware"/"vmtoolsd" everywhere), so
    // same-family repeats must never count as evidence. Each signature below
    // therefore demands one marker from a HOME family plus at least one
    // marker from a DIFFERENT family. All patterns are pairwise
    // non-substring so a single token cannot satisfy two slots.
    //
    // "VBoxMiniRdDN" also matches the full guest pipe "\\.\pipe\VBoxMiniRdDN"
    // and "Oracle\\VirtualBox Guest Additions" matches the registry key under
    // SOFTWARE — both classic VirtualBox probe targets.
    StringSignature {
        rule_id: BackdoorRuleId::AntiVm,
        // Home family: VirtualBox guest artifacts.
        patterns: &["VBoxService", "VBoxTray", "VBoxMiniRdDN",
                    "Oracle\\VirtualBox Guest Additions"],
        min_matches: 1,
        // Foreign families: VMware / Sandboxie / Cuckoo / QEMU.
        optional_patterns: &["vmware", "vmtoolsd",
                             "SbieDll.dll", "Sandboxie", "cuckoo", "qemu"],
    },
    StringSignature {
        rule_id: BackdoorRuleId::AntiVm,
        // Home family: VMware / QEMU guest artifacts.
        patterns: &["vmware", "vmtoolsd", "qemu"],
        min_matches: 1,
        // Foreign families: VirtualBox / Sandboxie / Cuckoo.
        optional_patterns: &["VBoxService", "VBoxTray", "VBoxMiniRdDN",
                             "Oracle\\VirtualBox Guest Additions",
                             "SbieDll.dll", "Sandboxie", "cuckoo"],
    },
    StringSignature {
        rule_id: BackdoorRuleId::AntiVm,
        // Home family: Sandboxie / Cuckoo sandbox artifacts.
        patterns: &["SbieDll.dll", "Sandboxie", "cuckoo"],
        min_matches: 1,
        // Foreign families: VirtualBox / VMware / QEMU.
        optional_patterns: &["VBoxService", "VBoxTray", "VBoxMiniRdDN",
                             "Oracle\\VirtualBox Guest Additions",
                             "vmware", "vmtoolsd", "qemu"],
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
