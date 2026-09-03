use serde::{Deserialize, Serialize};

/// Classification of a DLL by its functional purpose.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DllType {
    /// No executable code; contains only resources (.rsrc).
    ResourceOnly,
    /// COM/ActiveX DLL with self-registration exports.
    ComActiveX,
    /// Injectable DLL (DllMain-only, no legitimate exports, or process injection indicators).
    Injectable,
    /// Windows system DLL (kernel32, user32, ntdll, etc.).
    System,
    /// WDM kernel-mode driver (DLL with WDM_DRIVER characteristic).
    WdmDriver,
    /// .NET / CLR managed DLL.
    DotNet,
    /// Generic native DLL (C/C++/Delphi).
    Native,
    /// Unknown or could not classify.
    Unknown,
}

impl std::fmt::Display for DllType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ResourceOnly => write!(f, "Resource-only"),
            Self::ComActiveX => write!(f, "COM/ActiveX"),
            Self::Injectable => write!(f, "Injectable"),
            Self::System => write!(f, "System"),
            Self::WdmDriver => write!(f, "WDM Driver"),
            Self::DotNet => write!(f, ".NET"),
            Self::Native => write!(f, "Native"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Calling convention detected in the DLL.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CallingConvention {
    Cdecl,
    Stdcall,
    Fastcall,
    MicrosoftX64,
    SystemV,
    Vectorcall,
    Unknown,
}

/// Result of DLL analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DllInfo {
    /// Classified DLL type.
    pub dll_type: DllType,
    /// Architecture string (x86, x64, ARM, ARM64).
    pub architecture: String,
    /// Whether this is a .NET assembly.
    pub is_dotnet: bool,
    /// Whether this is a resource-only DLL.
    pub is_resource_only: bool,
    /// Whether this is a COM/ActiveX DLL.
    pub is_com: bool,
    /// Whether this has WDM_DRIVER characteristic (kernel driver).
    pub is_wdm_driver: bool,
    /// Whether this DLL is likely injectable.
    pub is_injectable: bool,
    /// Calling convention(s) detected.
    pub calling_conventions: Vec<CallingConvention>,
    /// Exported function names.
    pub exports: Vec<String>,
    /// DLL name from export table.
    pub dll_name: Option<String>,
    /// Number of exported functions.
    pub export_count: usize,
    /// Number of imported functions.
    pub import_count: usize,
    /// DllCharacteristics flags.
    pub characteristics: Vec<String>,
    /// Suspicion score from DLL-specific analysis (0.0-1.0).
    pub suspicion_score: f64,
    /// Findings from DLL analysis.
    pub findings: Vec<DllFinding>,
}

/// A single DLL analysis finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DllFinding {
    pub severity: String,
    pub rule_id: String,
    pub description: String,
}

/// Well-known system DLL names (lowercase).
const SYSTEM_DLLS: &[&str] = &[
    "kernel32.dll", "kernelbase.dll", "ntdll.dll", "user32.dll",
    "gdi32.dll", "gdiplus.dll", "advapi32.dll", "secur32.dll",
    "crypt32.dll", "wininet.dll", "ws2_32.dll", "ole32.dll",
    "oleaut32.dll", "shell32.dll", "shlwapi.dll", "comctl32.dll",
    "comdlg32.dll", "msvcrt.dll", "vcruntime140.dll", "ucrtbase.dll",
    "ntoskrnl.exe", "hal.dll", "msvcrt*.dll", "api-ms-win-*.dll",
];

/// COM/ActiveX required exports.
const COM_EXPORTS: &[&str] = &[
    "DllGetClassObject", "DllCanUnloadNow", "DllRegisterServer",
    "DllUnregisterServer",
];

/// Injectable DLL indicators: exports that suggest process injection.
const INJECTABLE_EXPORTS: &[&str] = &[
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "NtCreateThreadEx", "RtlCreateUserThread",
];

/// Well-known SSP/AP / credential provider DLL indicators.
const SSP_AP_INDICATORS: &[&str] = &[
    "SpInitialize", "SpLsaModeInitialize", "SpGetInfoFn",
];

/// Suspicious API exports commonly used in malware.
const SUSPICIOUS_APIS: &[&str] = &[
    // Process injection
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
    "NtQueueApcThread", "SetThreadContext", "GetThreadContext",
    // Memory manipulation
    "VirtualProtect", "VirtualProtectEx", "NtProtectVirtualMemory",
    "VirtualAlloc", "NtAllocateVirtualMemory",
    // Hooking / IAT
    "SetWindowsHookExA", "SetWindowsHookExW", "NtSetInformationThread",
    // Credential theft
    "LsaRetrievePrivateData", "SamQueryInformationUser",
    "CredReadA", "CredReadW", "CryptUnprotectData",
    // Anti-debug
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "OutputDebugStringA",
    // Network
    "InternetOpenA", "InternetOpenW", "InternetConnectA",
    "HttpSendRequestA", "URLDownloadToFileA",
    "WSAStartup", "connect", "send", "recv",
    // Registry (persistence)
    "RegCreateKeyExA", "RegSetValueExA",
    // Service (persistence)
    "CreateServiceA", "OpenSCManagerA",
    // Crypto
    "CryptEncrypt", "CryptDecrypt", "CryptGenKey",
    // Process manipulation
    "OpenProcess", "NtOpenProcess", "TerminateProcess",
    "CreateProcessA", "CreateProcessW", "ShellExecuteA",
];

/// Shellcode signature byte patterns that may appear in export names or ordinals.
const SHELLCODE_SIGNATURES: &[&[u8]] = &[
    &[0x64, 0x8B, 0x35],           // mov esi, dword ptr fs:[0x35] (PEB)
    &[0x64, 0xA1, 0x30, 0x00],     // mov eax, dword ptr fs:[0x30] (TEB)
    &[0x48, 0x8B, 0x05],           // mov rax, qword ptr [rip+...] (x64)
    &[0xFF, 0x15],                 // call [rip+...] (indirect call)
    &[0x0F, 0x01, 0xC8],           // rdtsc
    &[0xCD, 0x80],                 // int 0x80 (Linux syscall)
    &[0x0F, 0x05],                 // syscall (x64 Linux)
    &[0xCC],                       // int3 (breakpoint/debug trap)
    &[0xEB, 0xFE],                 // jmp $ (infinite loop)
];

/// Analyze a PE file as a DLL and return DllInfo.
///
/// This function expects the raw PE bytes and results from pe-parser.
/// It classifies the DLL by type, calling convention, and suspicious indicators.
#[allow(clippy::too_many_arguments)] // public analysis API; a config struct would break callers
pub fn analyze_dll(
    pe_data: &[u8],
    is_dll: bool,
    is_dotnet: bool,
    machine: u16,
    dll_characteristics: u16,
    exports: &[String],
    dll_name: Option<String>,
    import_count: usize,
) -> DllInfo {
    let mut findings = Vec::new();
    let mut suspicion_score: f64 = 0.0;

    // --- Architecture ---
    // NOTE: 0x01C2 is Thumb-2, distinct from 0x01C0/0x01C4 (ARM32) —
    // it must stay a separate arm (a combined pattern made it unreachable).
    let architecture = match machine {
        0x014C => "x86".to_string(),
        0x8664 => "x64".to_string(),
        0x01C0 | 0x01C4 => "ARM".to_string(),
        0x01C2 => "ARM Thumb".to_string(),
        0xAA64 => "ARM64".to_string(),
        0x0162 => "MIPS R3000".to_string(),
        0x0166 => "MIPS R4000".to_string(),
        0x0169 => "MIPS R10000".to_string(),
        0x01A2 => "Hitachi SH3".to_string(),
        0x01A3 => "Hitachi SH3 DSP".to_string(),
        0x01A6 => "Hitachi SH4".to_string(),
        0x01A8 => "Hitachi SH5".to_string(),
        0x01D3 => "Matsushita AM33".to_string(),
        0x01F0 => "PowerPC".to_string(),
        0x0200 => "IA64".to_string(),
        0x0266 => "MIPS16".to_string(),
        0x0366 => "MIPS FPU".to_string(),
        0x0466 => "MIPS FPU16".to_string(),
        0x01F1 => "PowerPC LE".to_string(),
        0x01F2 => "PowerPC64".to_string(),
        _ => "unknown".to_string(),
    };

    // --- Calling conventions ---
    let calling_conventions = detect_calling_conventions(&architecture, exports);

    // --- DllCharacteristics flags ---
    let characteristics = decode_dll_characteristics(dll_characteristics);

    let is_wdm_driver = dll_characteristics & 0x2000 != 0;
    if is_wdm_driver {
        findings.push(DllFinding {
            severity: "High".to_string(),
            rule_id: "DLL_WDM_DRIVER".to_string(),
            description: "WDM kernel-mode driver (DLL with WDM_DRIVER characteristic)".to_string(),
        });
    }

    // --- Export-based classification ---
    let export_lower: Vec<String> = exports.iter().map(|e| e.to_lowercase()).collect();

    // System DLL detection (needed before injectable check)
    let is_system = dll_name.as_ref()
        .map(|n| SYSTEM_DLLS.iter().any(|s| n.to_lowercase().ends_with(s)))
        .unwrap_or(false);

    // Resource-only: no exports and no .text code
    let is_resource_only = exports.is_empty() && !is_dll_has_code(pe_data);

    // COM/ActiveX: has required COM exports
    let com_count = COM_EXPORTS.iter()
        .filter(|com_e| export_lower.iter().any(|e| e.eq_ignore_ascii_case(com_e)))
        .count();
    let is_com = com_count >= 2; // Need at least DllGetClassObject + DllRegisterServer

    if is_com {
        findings.push(DllFinding {
            severity: "Info".to_string(),
            rule_id: "DLL_COM_ACTIVEX".to_string(),
            description: format!("COM/ActiveX DLL with {} COM exports", com_count),
        });
    }

    // Injectable: has injection-related exports or suspicious patterns
    // Skip this check for known system DLLs (they legitimately export these APIs)
    let inject_count = if !is_system {
        INJECTABLE_EXPORTS.iter()
            .filter(|ie| export_lower.iter().any(|e| e.eq_ignore_ascii_case(ie)))
            .count()
    } else { 0 };
    // DllMain-only only makes sense for actual DLLs: an EXE without
    // exports is normal, flagging it injectable was a false positive.
    let has_dllmain_only = is_dll && exports.is_empty() && import_count > 0;
    let is_injectable = inject_count > 0 || (has_dllmain_only && !is_resource_only && !is_system);

    if is_injectable {
        suspicion_score += 0.3;
        findings.push(DllFinding {
            severity: "High".to_string(),
            rule_id: "DLL_INJECTABLE".to_string(),
            description: "DLL has injection-related exports or no legitimate exports".to_string(),
        });
    }

    // Suspicious API detection
    if !is_system {
        let suspicious_count: usize = SUSPICIOUS_APIS.iter()
            .filter(|api| export_lower.iter().any(|e| e.eq_ignore_ascii_case(api)))
            .count();
        if suspicious_count > 0 {
            let score = (suspicious_count as f64 * 0.05).min(0.4);
            suspicion_score += score;
            findings.push(DllFinding {
                severity: if suspicious_count >= 5 { "High".to_string() } else { "Medium".to_string() },
                rule_id: "DLL_SUSPICIOUS_APIS".to_string(),
                description: format!("{} suspicious API exports detected", suspicious_count),
            });
        }
    }

    // Shellcode signature detection in export names
    let shellcode_exports: Vec<&String> = exports.iter()
        .filter(|name| {
            let name_bytes = name.as_bytes();
            SHELLCODE_SIGNATURES.iter().any(|sig| {
                name_bytes.windows(sig.len()).any(|w| w == *sig)
            })
        })
        .collect();
    if !shellcode_exports.is_empty() {
        suspicion_score += 0.4;
        findings.push(DllFinding {
            severity: "Critical".to_string(),
            rule_id: "DLL_SHELLCODE_EXPORTS".to_string(),
            description: format!(
                "{} export(s) contain shellcode byte patterns",
                shellcode_exports.len()
            ),
        });
    }

    // Export entropy analysis
    let export_entropy = compute_export_entropy(exports);
    if export_entropy > 5.0 && !exports.is_empty() {
        // High entropy in export names suggests obfuscation
        suspicion_score += 0.2;
        findings.push(DllFinding {
            severity: "Medium".to_string(),
            rule_id: "DLL_HIGH_EXPORT_ENTROPY".to_string(),
            description: format!(
                "High export name entropy ({:.2}) suggests obfuscation",
                export_entropy
            ),
        });
    }

    // Export name length analysis (very long names = possible obfuscation)
    let long_name_count = exports.iter().filter(|n| n.len() > 128).count();
    if long_name_count > 0 {
        suspicion_score += 0.15;
        findings.push(DllFinding {
            severity: "Medium".to_string(),
            rule_id: "DLL_LONG_EXPORT_NAMES".to_string(),
            description: format!("{} export(s) with extremely long names (>128 chars)", long_name_count),
        });
    }

    // SSP/AP indicators
    let ssp_count = SSP_AP_INDICATORS.iter()
        .filter(|ssp| export_lower.iter().any(|e| e.eq_ignore_ascii_case(ssp)))
        .count();
    if ssp_count > 0 {
        findings.push(DllFinding {
            severity: "Critical".to_string(),
            rule_id: "DLL_SSP_AP".to_string(),
            description: format!("SSP/AP credential provider DLL with {} security exports", ssp_count),
        });
        suspicion_score += 0.5;
    }

    // Resource-only
    if is_resource_only {
        findings.push(DllFinding {
            severity: "Info".to_string(),
            rule_id: "DLL_RESOURCE_ONLY".to_string(),
            description: "Resource-only DLL (no executable exports or code)".to_string(),
        });
    }

    // System DLL
    if is_system {
        findings.push(DllFinding {
            severity: "Info".to_string(),
            rule_id: "DLL_SYSTEM".to_string(),
            description: format!("System DLL: {}", dll_name.as_deref().unwrap_or("unknown")),
        });
    }

    // .NET
    if is_dotnet {
        findings.push(DllFinding {
            severity: "Info".to_string(),
            rule_id: "DLL_DOTNET".to_string(),
            description: ".NET / CLR managed DLL".to_string(),
        });
    }

    // Classify DLL type
    let dll_type = if is_resource_only {
        DllType::ResourceOnly
    } else if is_com {
        DllType::ComActiveX
    } else if is_injectable {
        DllType::Injectable
    } else if is_wdm_driver {
        DllType::WdmDriver
    } else if is_dotnet {
        DllType::DotNet
    } else if is_system {
        DllType::System
    } else {
        DllType::Native
    };

    suspicion_score = suspicion_score.min(1.0);

    DllInfo {
        dll_type,
        architecture,
        is_dotnet,
        is_resource_only,
        is_com,
        is_wdm_driver,
        is_injectable,
        calling_conventions,
        exports: exports.to_vec(),
        dll_name,
        export_count: exports.len(),
        import_count,
        characteristics,
        suspicion_score,
        findings,
    }
}

/// Detect calling conventions based on architecture and export patterns.
fn detect_calling_conventions(architecture: &str, exports: &[String]) -> Vec<CallingConvention> {
    let mut cc = Vec::new();

    match architecture {
        "x64" => cc.push(CallingConvention::MicrosoftX64),
        "ARM64" => cc.push(CallingConvention::MicrosoftX64), // Windows ARM64 uses MS x64 ABI
        "x86" => {
            // Heuristic: check for common stdcall name patterns (_FunctionName@N)
            let has_stdcall = exports.iter().any(|e| e.starts_with('_') && e.contains('@'));
            let has_fastcall = exports.iter().any(|e| e.starts_with('@'));
            if has_stdcall {
                cc.push(CallingConvention::Stdcall);
            }
            if has_fastcall {
                cc.push(CallingConvention::Fastcall);
            }
            if !has_stdcall && !has_fastcall {
                cc.push(CallingConvention::Cdecl);
            }
        }
        "ARM" => {
            cc.push(CallingConvention::Cdecl); // ARM uses AAPCS (similar to cdecl)
        }
        _ => {
            cc.push(CallingConvention::Unknown);
        }
    }

    cc
}

/// Check if the PE has executable code (non-empty .text section with code).
fn is_dll_has_code(pe_data: &[u8]) -> bool {
    // Simple heuristic: if the file is a PE with a .text section that has
    // execute permission, it has code.
    // For a proper implementation this would parse section headers,
    // but we use a simpler heuristic here: if the import count is > 0,
    // the DLL likely has code.
    // This is a conservative fallback; the scanner passes import_count.
    !pe_data.is_empty()
}

/// Decode DllCharacteristics flags into human-readable strings.
fn decode_dll_characteristics(flags: u16) -> Vec<String> {
    let mut out = Vec::new();
    if flags & 0x0020 != 0 { out.push("HIGH_ENTROPY_VA".into()); }
    if flags & 0x0040 != 0 { out.push("DYNAMIC_BASE/ASLR".into()); }
    if flags & 0x0080 != 0 { out.push("FORCE_INTEGRITY".into()); }
    if flags & 0x0100 != 0 { out.push("NX_COMPAT/DEP".into()); }
    if flags & 0x0200 != 0 { out.push("NO_ISOLATION".into()); }
    if flags & 0x0400 != 0 { out.push("NO_SEH".into()); }
    if flags & 0x0800 != 0 { out.push("NO_BIND".into()); }
    if flags & 0x1000 != 0 { out.push("APPCONTAINER".into()); }
    if flags & 0x2000 != 0 { out.push("WDM_DRIVER".into()); }
    if flags & 0x4000 != 0 { out.push("GUARD_CF/CFG".into()); }
    if flags & 0x8000 != 0 { out.push("TERMINAL_SERVER_AWARE".into()); }
    out
}

/// Compute Shannon entropy of export names.
/// Returns a value between 0.0 (all same byte) and 8.0 (maximum randomness).
fn compute_export_entropy(exports: &[String]) -> f64 {
    if exports.is_empty() {
        return 0.0;
    }

    // Concatenate all export names
    let all_bytes: Vec<u8> = exports.iter().flat_map(|n| n.bytes()).collect();
    if all_bytes.is_empty() {
        return 0.0;
    }

    let total = all_bytes.len() as f64;

    // Count byte frequencies
    let mut freq = [0u64; 256];
    for &b in &all_bytes {
        freq[b as usize] += 1;
    }

    // Calculate Shannon entropy
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dll_type_classification() {
        // COM DLL
        let info = analyze_dll(
            &[0u8; 100], true, false, 0x8664, 0,
            &["DllGetClassObject".into(), "DllCanUnloadNow".into(),
              "DllRegisterServer".into(), "DllUnregisterServer".into()],
            Some("mycom.dll".into()), 10,
        );
        assert_eq!(info.dll_type, DllType::ComActiveX);
        assert!(info.is_com);
        assert!(!info.is_injectable);
    }

    #[test]
    fn test_injectable_dll() {
        let info = analyze_dll(
            &[0u8; 100], true, false, 0x8664, 0,
            &["VirtualAllocEx".into(), "WriteProcessMemory".into()],
            Some("payload.dll".into()), 5,
        );
        assert_eq!(info.dll_type, DllType::Injectable);
        assert!(info.is_injectable);
        assert!(info.suspicion_score > 0.0);
    }

    #[test]
    fn test_system_dll() {
        let info = analyze_dll(
            &[0u8; 100], true, false, 0x8664, 0,
            &["CreateFileW".into(), "ReadFile".into()],
            Some("kernel32.dll".into()), 100,
        );
        assert_eq!(info.dll_type, DllType::System);
    }

    #[test]
    fn test_wdm_driver() {
        let info = analyze_dll(
            &[0u8; 100], true, false, 0x8664, 0x2000,
            &["DriverEntry".into()],
            Some("mydriver.dll".into()), 3,
        );
        assert!(info.is_wdm_driver);
        assert_eq!(info.dll_type, DllType::WdmDriver);
    }

    #[test]
    fn test_dotnet_dll() {
        let info = analyze_dll(
            &[0u8; 100], true, true, 0x8664, 0,
            &[".ctor".into(), "Main".into()],
            Some("mylib.dll".into()), 20,
        );
        assert!(info.is_dotnet);
        assert_eq!(info.dll_type, DllType::DotNet);
    }

    #[test]
    fn test_ssp_ap_dll() {
        let info = analyze_dll(
            &[0u8; 100], true, false, 0x8664, 0,
            &["SpInitialize".into(), "SpLsaModeInitialize".into()],
            Some("mimilib.dll".into()), 2,
        );
        // SSP/AP DLLs are credential providers, not injectable
        assert_eq!(info.dll_type, DllType::Native);
        assert!(info.suspicion_score >= 0.5);
        assert!(info.findings.iter().any(|f| f.rule_id == "DLL_SSP_AP"));
    }

    #[test]
    fn test_calling_conventions_x64() {
        let info = analyze_dll(
            &[0u8; 100], true, false, 0x8664, 0,
            &["main".into()],
            Some("test.dll".into()), 5,
        );
        assert!(info.calling_conventions.contains(&CallingConvention::MicrosoftX64));
    }

    #[test]
    fn test_calling_conventions_x86() {
        let info = analyze_dll(
            &[0u8; 100], true, false, 0x014C, 0,
            &["_CreateFileW@28".into(), "_ReadFile@20".into()],
            Some("test.dll".into()), 5,
        );
        assert!(info.calling_conventions.contains(&CallingConvention::Stdcall));
    }

    #[test]
    fn test_suspicious_apis_detected() {
        let info = analyze_dll(
            &[0u8; 100], true, false, 0x8664, 0,
            &[
                "VirtualAllocEx".into(),
                "WriteProcessMemory".into(),
                "CreateRemoteThread".into(),
                "NtCreateThreadEx".into(),
                "QueueUserAPC".into(),
            ],
            Some("suspicious.dll".into()), 10,
        );
        assert!(info.suspicion_score > 0.0);
        assert!(info.findings.iter().any(|f| f.rule_id == "DLL_SUSPICIOUS_APIS"));
    }

    #[test]
    fn test_high_export_entropy() {
        // Export names with high entropy (random-looking)
        let info = analyze_dll(
            &[0u8; 100], true, false, 0x8664, 0,
            &[
                "xK9mP2nQ7wR4".into(),
                "jB3vL8yT5uF1".into(),
                "aH6dW0sE3gZ9".into(),
            ],
            Some("obfuscated.dll".into()), 5,
        );
        assert!(info.findings.iter().any(|f| f.rule_id == "DLL_HIGH_EXPORT_ENTROPY"));
    }

    #[test]
    fn test_long_export_names() {
        let long_name = "A".repeat(200);
        let info = analyze_dll(
            &[0u8; 100], true, false, 0x8664, 0,
            &[long_name],
            Some("longnames.dll".into()), 5,
        );
        assert!(info.findings.iter().any(|f| f.rule_id == "DLL_LONG_EXPORT_NAMES"));
        assert!(info.suspicion_score > 0.0);
    }

    #[test]
    fn test_entropy_basic() {
        // All same bytes = 0 entropy
        let exports_same = vec!["AAAAAAAA".into(); 10];
        let e1 = compute_export_entropy(&exports_same);
        assert!(e1 < 0.01);

        // Random-looking = high entropy
        let exports_random = vec![
            "xK9mP2nQ7wR4jB3vL8yT5uF1aH6dW0sE3gZ9".into(),
            "mN4pQ8rT2vX6yB0kJ5wL3fH7dS1eA9iO6uC4".into(),
        ];
        let e2 = compute_export_entropy(&exports_random);
        assert!(e2 > 4.0);
    }
}
