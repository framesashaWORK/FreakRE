use crate::types::ImportedModule;

/// Уровень подозрительности сработавшего правила
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuspicionLevel {
    /// Низкий — может встречаться в легитимном ПО
    Low,
    /// Средний — требует внимания
    Medium,
    /// Высокий — сильный индикатор малвари
    High,
    /// Критический — почти наверняка малварь
    Critical,
}

impl SuspicionLevel {
    /// Signal strength of a single rule hit [0.0 – 1.0].
    ///
    /// These are deliberately below 1.0 even for Critical: import patterns
    /// are contextual evidence (legitimate installers, debuggers and update
    /// frameworks use the same APIs), so a lone hit must not saturate the
    /// module score.
    pub fn weight(&self) -> f64 {
        match self {
            Self::Low => 0.10,
            Self::Medium => 0.25,
            Self::High => 0.45,
            Self::Critical => 0.70,
        }
    }
}

/// Результат срабатывания одного правила
#[derive(Debug, Clone)]
pub struct RuleMatch {
    /// Идентификатор правила
    pub rule_id: &'static str,
    /// Описание
    pub description: String,
    /// Уровень подозрительности
    pub level: SuspicionLevel,
    /// Confidence (0.0 - 1.0)
    pub confidence: f64,
    /// Какие функции/DLL триггернули правило
    pub triggered_by: Vec<String>,
}

/// Оценивает все правила против списка импортированных модулей
pub fn evaluate_rules(modules: &[ImportedModule]) -> Vec<RuleMatch> {
    let mut matches = Vec::new();

    // Преобразуем в Vec для совместимости с существующими функциями проверки
    let func_names_lower: Vec<(String, String)> = modules
        .iter()
        .flat_map(|m| {
            m.functions.iter().filter_map(|f| {
                f.name
                    .as_ref()
                    .map(|n| (m.name.to_lowercase(), n.to_lowercase()))
            })
        })
        .collect();

    check_process_injection(&func_names_lower, &mut matches);
    check_persistence(&func_names_lower, &mut matches);
    check_evasion_techniques(&func_names_lower, &mut matches);
    check_network_c2(&func_names_lower, &mut matches);
    check_crypto_ransomware(&func_names_lower, &mut matches);
    check_keylogging(&func_names_lower, &mut matches);
    check_dll_suspicious(modules, &mut matches);
    check_ordinal_only_imports(modules, &mut matches);

    matches
}

// =============================================================================
// Правила детекции
// =============================================================================

/// Process Injection: классические комбинации API для инъекции кода
fn check_process_injection(imports: &[(String, String)], matches: &mut Vec<RuleMatch>) {
    let has = |func: &str| imports.iter().any(|(_, f)| f == func);

    // Combo 1: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
    if has("virtualallocex") && has("writeprocessmemory") && has("createremotethread") {
        matches.push(RuleMatch {
            rule_id: "INJ_REMOTE_THREAD",
            description: "Classic process injection: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread".into(),
            level: SuspicionLevel::Critical,
            confidence: 0.95,
            triggered_by: vec![
                "VirtualAllocEx".into(),
                "WriteProcessMemory".into(),
                "CreateRemoteThread".into(),
            ],
        });
    }

    // Combo 2: NtUnmapViewOfSection + SetThreadContext (hollowing)
    if has("ntunmapviewofsection") && has("setthreadcontext") {
        matches.push(RuleMatch {
            rule_id: "INJ_PROCESS_HOLLOWING",
            description: "Process hollowing detected: NtUnmapViewOfSection + SetThreadContext".into(),
            level: SuspicionLevel::Critical,
            confidence: 0.90,
            triggered_by: vec!["NtUnmapViewOfSection".into(), "SetThreadContext".into()],
        });
    }

    // Combo 3: QueueUserAPC (APC injection)
    if has("queueuserapc") && has("writeprocessmemory") {
        matches.push(RuleMatch {
            rule_id: "INJ_APC_INJECTION",
            description: "APC injection: QueueUserAPC + WriteProcessMemory".into(),
            level: SuspicionLevel::High,
            confidence: 0.80,
            triggered_by: vec!["QueueUserAPC".into(), "WriteProcessMemory".into()],
        });
    }

    // Single suspicious API without combo — lower confidence
    if has("createremotethread") && !has("virtualallocex") {
        matches.push(RuleMatch {
            rule_id: "INJ_SINGLE_REMOTE_THREAD",
            description: "CreateRemoteThread without VirtualAllocEx (possible alternative injection)".into(),
            level: SuspicionLevel::Low,
            confidence: 0.40,
            triggered_by: vec!["CreateRemoteThread".into()],
        });
    }
}

/// Persistence mechanisms
fn check_persistence(imports: &[(String, String)], matches: &mut Vec<RuleMatch>) {
    let has = |func: &str| imports.iter().any(|(_, f)| f == func);

    // Registry persistence
    if has("regsetvalueexw") || has("regsetvalueexa") || has("regcreatekeyexw") {
        matches.push(RuleMatch {
            rule_id: "PERSIST_REGISTRY",
            description: "Registry modification API (possible persistence via Run/RunOnce keys)".into(),
            level: SuspicionLevel::Low,
            confidence: 0.35,
            triggered_by: vec!["RegSetValueEx/RegCreateKeyEx".into()],
        });
    }

    // Service creation
    if has("createservicew") || has("createservicea") {
        matches.push(RuleMatch {
            rule_id: "PERSIST_SERVICE",
            description: "Service creation API (possible persistence as Windows service)".into(),
            level: SuspicionLevel::Low,
            confidence: 0.60,
            triggered_by: vec!["CreateService".into()],
        });
    }

    // Scheduled Task
    if has("schtaskscreate") || has("itaskservice") {
        matches.push(RuleMatch {
            rule_id: "PERSIST_SCHEDULED_TASK",
            description: "Scheduled Task creation (persistence mechanism)".into(),
            level: SuspicionLevel::Low,
            confidence: 0.65,
            triggered_by: vec!["SchtasksCreate/ITaskService".into()],
        });
    }
}

/// Evasion / Anti-analysis techniques
fn check_evasion_techniques(imports: &[(String, String)], matches: &mut Vec<RuleMatch>) {
    let has = |func: &str| imports.iter().any(|(_, f)| f == func);

    // Anti-debugging.
    // Split into *genuine* anti-debug primitives (rare in legitimate software)
    // and *benign/common* timing APIs that are present in vast numbers of normal
    // applications (GetTickCount / QueryPerformanceCounter are used for profiling,
    // animation, etc.). A lone IsDebuggerPresent is also common (telemetry gating,
    // game DRM checks, etc.). We only flag when >= 2 genuine primitives co-occur.
    let genuine_anti_debug = [
        "isdebuggerpresent",
        "checkremotedebuggerpresent",
        "ntqueryinformationprocess",
        "outputdebugstringa",
        "ntsetinformationthread",
        "blockinput",
    ];
    let common_timing = ["gettickcount", "queryperformancecounter"];

    let genuine_count = genuine_anti_debug.iter().filter(|f| has(f)).count();
    let common_count = common_timing.iter().filter(|f| has(f)).count();

    // Require at least two *genuine* anti-debug primitives. A single
    // IsDebuggerPresent (used for telemetry gating, game DRM, etc.) combined with
    // ubiquitous timing APIs (GetTickCount/QueryPerformanceCounter) is not a
    // meaningful anti-analysis signal and would otherwise false-positive on most
    // legitimate software.
    if genuine_count >= 2 {
        let triggered: Vec<String> = genuine_anti_debug
            .iter()
            .chain(common_timing.iter())
            .filter(|f| has(f))
            .map(|s| s.to_string())
            .collect();
        matches.push(RuleMatch {
            rule_id: "EVASION_ANTIDEBUG",
            description: format!("Multiple anti-debug APIs detected ({} genuine, {} timing)", genuine_count, common_count),
            level: SuspicionLevel::Medium,
            confidence: 0.70 + (genuine_count as f64 * 0.05).min(0.25),
            triggered_by: triggered,
        });
    }

    // Dynamic API resolution (GetProcAddress + LoadLibrary)
    if has("getprocaddress") && (has("loadlibrarya") || has("loadlibraryw")) {
        matches.push(RuleMatch {
            rule_id: "EVASION_DYNAMIC_RESOLVE",
            description: "Dynamic API resolution via GetProcAddress + LoadLibrary (obfuscation/evasion)".into(),
            level: SuspicionLevel::Medium,
            confidence: 0.30,
            triggered_by: vec!["GetProcAddress".into(), "LoadLibrary".into()],
        });
    }

    // VirtualProtect on executable memory
    if has("virtualprotect") || has("virtualprotectex") {
        matches.push(RuleMatch {
            rule_id: "EVASION_VIRTUALPROTECT",
            description: "VirtualProtect/VirtualProtectEx present (possible runtime code modification/unpacking)".into(),
            level: SuspicionLevel::Medium,
            confidence: 0.20,
            triggered_by: vec!["VirtualProtect(VirtualProtectEx)".into()],
        });
    }
}

/// Network / C2 communication
fn check_network_c2(imports: &[(String, String)], matches: &mut Vec<RuleMatch>) {
    let has = |func: &str| imports.iter().any(|(_, f)| f == func);

    // WinHTTP / WinINet for C2
    let http_funcs = [
        "winhttpopen",
        "winhttpconnect",
        "winhttpopenrequest",
        "winhttpsendrequest",
        "internetopenurla",
        "internetopenurlw",
        "internetreadfile",
        "urldownloadtofilea",
        "urldownloadtofilew",
    ];
    let http_count = http_funcs.iter().filter(|f| has(f)).count();
    if http_count >= 2 {
        matches.push(RuleMatch {
            rule_id: "NET_HTTP_C2",
            description: format!("Multiple HTTP/Internet APIs detected ({}) — possible C2 communication", http_count),
            level: SuspicionLevel::Medium,
            confidence: 0.60 + (http_count as f64 * 0.05).min(0.30),
            triggered_by: http_funcs
                .iter()
                .filter(|f| has(f))
                .map(|s| s.to_string())
                .collect(),
        });
    }

    // Raw sockets
    if has("wsastartup") && (has("socket") || has("connect") || has("send")) {
        matches.push(RuleMatch {
            rule_id: "NET_RAW_SOCKET",
            description: "Raw socket usage via Winsock (possible custom C2 protocol)".into(),
            level: SuspicionLevel::Medium,
            confidence: 0.65,
            triggered_by: vec!["WSAStartup".into(), "socket/connect/send".into()],
        });
    }
}

/// Crypto / Ransomware indicators
fn check_crypto_ransomware(imports: &[(String, String)], matches: &mut Vec<RuleMatch>) {
    let has = |func: &str| imports.iter().any(|(_, f)| f == func);

    // Cryptographic API
    let crypto_funcs = [
        "cryptacquirecontexta",
        "cryptacquirecontextw",
        "cryptgenkey",
        "cryptencrypt",
        "cryptdecrypt",
        "crypthashdata",
        "bcryptencrypt",
        "bcryptgeneratekeypair",
    ];
    let crypto_count = crypto_funcs.iter().filter(|f| has(f)).count();

    // File enumeration + crypto = ransomware pattern
    let file_enum = has("findfirstfilea") || has("findfirstfilew") || has("findnextfilea");
    if crypto_count >= 2 && file_enum {
        matches.push(RuleMatch {
            rule_id: "CRYPTO_RANSOMWARE_PATTERN",
            description: "Cryptographic APIs + file enumeration — possible ransomware behavior".into(),
            level: SuspicionLevel::High,
            confidence: 0.85,
            triggered_by: crypto_funcs
                .iter()
                .filter(|f| has(f))
                .map(|s| s.to_string())
                .chain(std::iter::once("FindFirstFile/FindNextFile".into()))
                .collect(),
        });
    } else if crypto_count >= 3 {
        matches.push(RuleMatch {
            rule_id: "CRYPTO_HEAVY_USAGE",
            description: format!("Heavy cryptographic API usage ({} functions)", crypto_count),
            level: SuspicionLevel::Low,
            confidence: 0.45,
            triggered_by: crypto_funcs
                .iter()
                .filter(|f| has(f))
                .map(|s| s.to_string())
                .collect(),
        });
    }
}

/// Keylogging / credential theft
fn check_keylogging(imports: &[(String, String)], matches: &mut Vec<RuleMatch>) {
    let has = |func: &str| imports.iter().any(|(_, f)| f == func);

    // Keyboard hooks
    if has("setwindowshookexa") || has("setwindowshookexw") {
        let has_keyboard = has("getasynckeystate") || has("getkeystate") || has("getkeyboardstate");
        if has_keyboard {
            matches.push(RuleMatch {
                rule_id: "KEYLOG_HOOK",
                description: "Windows hook + keyboard state API — possible keylogger".into(),
                level: SuspicionLevel::High,
                confidence: 0.75,
                triggered_by: vec!["SetWindowsHookEx".into(), "GetAsyncKeyState/GetKeyState".into()],
            });
        }
    }

    // Credential APIs
    if has("credenumeratew") || has("credenumeratea") || has("lsalogonuser") {
        matches.push(RuleMatch {
            rule_id: "CRED_THEFT_API",
            description: "Credential enumeration/authentication API — possible credential theft".into(),
            level: SuspicionLevel::High,
            confidence: 0.70,
            triggered_by: vec!["CredEnumerate/LsaLogonUser".into()],
        });
    }
}

/// Подозрительные DLL сами по себе
fn check_dll_suspicious(modules: &[ImportedModule], matches: &mut Vec<RuleMatch>) {
    let suspicious_dlls = [
        ("amsi.dll", "AMSI bypass target"),
        ("dbgcore.dll", "Debug/core dump manipulation"),
        ("dbghelp.dll", "Debug helper — unusual in production malware context"),
        ("version.dll", "Common side-loading target"),
        ("uxtheme.dll", "Theme API abuse for injection"),
        ("dwmapi.dll", "Desktop Window Manager — screen capture/injection"),
    ];

    for module in modules {
        let dll_lower = module.name.to_lowercase();
        for &(dll, desc) in &suspicious_dlls {
            if dll_lower == dll {
                // Evidence carries a source marker so delay-load imports are
                // distinguishable from regular IDT imports.
                let evidence = if module.is_delay_load {
                    format!("{} [delay-load]", module.name)
                } else {
                    module.name.clone()
                };
                matches.push(RuleMatch {
                    rule_id: "DLL_SUSPICIOUS",
                    description: if module.is_delay_load {
                        format!(
                            "Suspicious DLL import: {} via delay-load table ({})",
                            module.name, desc
                        )
                    } else {
                        format!("Suspicious DLL import: {} ({})", module.name, desc)
                    },
                    level: SuspicionLevel::Low,
                    confidence: 0.40,
                    triggered_by: vec![evidence],
                });
            }
        }
    }
}

/// Импорт только по ординалам — признак обфускации
fn check_ordinal_only_imports(modules: &[ImportedModule], matches: &mut Vec<RuleMatch>) {
    for module in modules {
        let total = module.functions.len();
        if total == 0 {
            continue;
        }
        // Only entries with an actual ordinal AND no name count as
        // ordinal-only imports. Entries with neither name nor ordinal
        // (unreadable hint/name table) are a parsing artifact, not
        // obfuscation, and must not inflate this signal.
        let ordinal_count = module
            .functions
            .iter()
            .filter(|f| f.ordinal.is_some() && f.name.is_none())
            .count();
        let ratio = ordinal_count as f64 / total as f64;

        if ordinal_count >= 3 && ratio > 0.5 {
            matches.push(RuleMatch {
                rule_id: "IMPORT_ORDINAL_OBFUSCATION",
                description: format!(
                    "DLL '{}' imports {}/{} functions by ordinal only ({:.0}%) — possible obfuscation",
                    module.name, ordinal_count, total, ratio * 100.0
                ),
                level: SuspicionLevel::Low,
                confidence: 0.50 * ratio,
                triggered_by: vec![module.name.clone()],
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ImportedFunction, ImportedModule};

    fn make_module(name: &str, funcs: &[&str]) -> ImportedModule {
        ImportedModule {
            name: name.into(),
            name_rva: 0,
            functions: funcs
                .iter()
                .map(|f| ImportedFunction {
                    name: Some(f.to_string()),
                    ordinal: None,
                    hint: 0,
                    ilt_rva: 0,
                    is_forwarder: false,
                })
                .collect(),
            is_delay_load: false,
        }
    }

    #[test]
    fn test_process_injection_detection() {
        let modules = vec![make_module(
            "kernel32.dll",
            &["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        )];
        let matches = evaluate_rules(&modules);
        assert!(matches.iter().any(|m| m.rule_id == "INJ_REMOTE_THREAD"));
    }

    #[test]
    fn test_no_false_positive_normal_app() {
        let modules = vec![
            make_module("kernel32.dll", &["CreateFileW", "ReadFile", "WriteFile", "CloseHandle"]),
            make_module("user32.dll", &["MessageBoxW", "ShowWindow"]),
        ];
        let matches = evaluate_rules(&modules);
        // Normal app should not produce any high/critical detections
        let critical = matches.iter().filter(|m| m.level == SuspicionLevel::Critical).count();
        let high = matches.iter().filter(|m| m.level == SuspicionLevel::High).count();
        assert_eq!(critical, 0);
        assert_eq!(high, 0);
    }

    #[test]
    fn test_ransomware_pattern() {
        let modules = vec![
            make_module(
                "advapi32.dll",
                &["CryptAcquireContextW", "CryptGenKey", "CryptEncrypt"],
            ),
            make_module("kernel32.dll", &["FindFirstFileW", "FindNextFileW"]),
        ];
        let matches = evaluate_rules(&modules);
        assert!(matches
            .iter()
            .any(|m| m.rule_id == "CRYPTO_RANSOMWARE_PATTERN"));
    }

    #[test]
    fn test_ordinal_obfuscation() {
        let module = ImportedModule {
            name: "ntdll.dll".into(),
            name_rva: 0,
            functions: (0..10)
                .map(|i| ImportedFunction {
                    name: None,
                    ordinal: Some(i),
                    hint: 0,
                    ilt_rva: 0,
                    is_forwarder: false,
                })
                .collect(),
            is_delay_load: false,
        };
        let matches = evaluate_rules(&[module]);
        assert!(matches
            .iter()
            .any(|m| m.rule_id == "IMPORT_ORDINAL_OBFUSCATION"));
    }

    #[test]
    fn test_unreadable_imports_not_counted_as_ordinal_only() {
        // Entries with name=None AND ordinal=None are unreadable hint/name
        // table entries (parsing artifact), NOT ordinal imports. A module
        // consisting only of these must not trigger IMPORT_ORDINAL_OBFUSCATION.
        let module = ImportedModule {
            name: "weird.dll".into(),
            name_rva: 0,
            functions: (0..10)
                .map(|_| ImportedFunction {
                    name: None,
                    ordinal: None,
                    hint: 7,
                    ilt_rva: 0,
                    is_forwarder: false,
                })
                .collect(),
            is_delay_load: false,
        };
        let matches = evaluate_rules(&[module]);
        assert!(
            !matches.iter().any(|m| m.rule_id == "IMPORT_ORDINAL_OBFUSCATION"),
            "unreadable entries must not be miscounted as ordinal-only obfuscation"
        );
    }

    #[test]
    fn test_mixed_unreadable_and_named_no_ordinal_flag() {
        // Mostly-unreadable module with a couple of named imports: the
        // unreadable majority must not count toward the ordinal ratio.
        let mut functions: Vec<ImportedFunction> = (0..8)
            .map(|_| ImportedFunction {
                name: None,
                ordinal: None,
                hint: 1,
                ilt_rva: 0,
                is_forwarder: false,
            })
            .collect();
        functions.push(ImportedFunction {
            name: Some("CreateFileW".into()),
            ordinal: None,
            hint: 2,
            ilt_rva: 0,
            is_forwarder: false,
        });
        functions.push(ImportedFunction {
            name: Some("CloseHandle".into()),
            ordinal: None,
            hint: 3,
            ilt_rva: 0,
            is_forwarder: false,
        });
        let module = ImportedModule {
            name: "mixed.dll".into(),
            name_rva: 0,
            functions,
            is_delay_load: false,
        };
        let matches = evaluate_rules(&[module]);
        assert!(!matches.iter().any(|m| m.rule_id == "IMPORT_ORDINAL_OBFUSCATION"));
    }
}
