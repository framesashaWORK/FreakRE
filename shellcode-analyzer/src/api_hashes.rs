//! Windows API hash resolution.
//! Malware frequently uses hashed API names instead of direct imports
//! to evade static analysis. This module resolves known hashes back to API names.

use std::collections::HashMap;
use std::fmt;
use std::sync::OnceLock;

/// Type of hash algorithm used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiHashType {
    /// ROR13 hash (used by Metasploit, Cobalt Strike, etc.)
    Ror13,
    /// CRC32 hash
    Crc32,
    /// DJB2 hash
    Djb2,
    /// Custom/unknown hash
    Unknown(u32),
}

impl fmt::Display for ApiHashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ror13 => write!(f, "ROR13"),
            Self::Crc32 => write!(f, "CRC32"),
            Self::Djb2 => write!(f, "DJB2"),
            Self::Unknown(v) => write!(f, "UNKNOWN(0x{:08X})", v),
        }
    }
}

/// A resolved API hash → function name mapping.
#[derive(Debug, Clone)]
pub struct ResolvedApi {
    /// The original hash value.
    pub hash: u32,
    /// Hash algorithm used.
    pub hash_type: ApiHashType,
    /// Resolved DLL name (e.g., "kernel32.dll").
    pub dll_name: &'static str,
    /// Resolved function name (e.g., "VirtualAlloc").
    pub function_name: &'static str,
}

impl fmt::Display for ResolvedApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "0x{:08X} ({}) → {}!{}",
            self.hash, self.hash_type, self.dll_name, self.function_name
        )
    }
}

// ─── ROR13 hashing ───────────────────────────────────────────────────
// The classic "Stephen Fewer" style hash: rotate-right-by-13 each
// accumulated character. Malware uses many conventions for what string is
// hashed (function name only, "module.function", "module\0function\0", with or
// without a trailing NUL). We therefore compute every common variant of each
// known API and index them all, so resolution succeeds regardless of which
// convention a given sample used.

/// ROR13 over `s` (exact case preserved, no trailing NUL). This is the
/// convention used by a large class of shellcodes that hash the bare function name.
pub fn compute_ror13(s: &str) -> u32 {
    let mut hash: u32 = 0;
    for c in s.bytes() {
        hash = hash.rotate_right(13).wrapping_add(c as u32);
    }
    hash
}

/// ROR13 over `s` followed by a single NUL terminator.
fn compute_ror13_nul(s: &str) -> u32 {
    let mut hash = compute_ror13(s);
    hash = hash.rotate_right(13).wrapping_add(0u32);
    hash
}

/// ROR13 over `module\0function\0` (the literal Stephen Fewer layout), preserving
/// the case of the names as supplied.
fn compute_ror13_module_func(dll: &str, func: &str) -> u32 {
    let mut hash: u32 = 0;
    for c in dll.bytes() {
        hash = hash.rotate_right(13).wrapping_add(c as u32);
    }
    hash = hash.rotate_right(13).wrapping_add(0u32);
    for c in func.bytes() {
        hash = hash.rotate_right(13).wrapping_add(c as u32);
    }
    hash = hash.rotate_right(13).wrapping_add(0u32);
    hash
}

// ─── Known API Hash Database ─────────────────────────────────────────
// Curated list of commonly abused Windows APIs. Hashes are *computed* at
// runtime (never hardcoded), eliminating the stale/incorrect table that
// previously made this module a non-functional stub.

const API_LIST: &[(&str, &str)] = &[
    // kernel32.dll
    ("kernel32.dll", "CreateThread"),
    ("kernel32.dll", "CreateRemoteThread"),
    ("kernel32.dll", "VirtualAlloc"),
    ("kernel32.dll", "VirtualAllocEx"),
    ("kernel32.dll", "VirtualFree"),
    ("kernel32.dll", "VirtualProtect"),
    ("kernel32.dll", "LoadLibraryA"),
    ("kernel32.dll", "LoadLibraryW"),
    ("kernel32.dll", "GetProcAddress"),
    ("kernel32.dll", "GetModuleHandleA"),
    ("kernel32.dll", "GetModuleHandleW"),
    ("kernel32.dll", "GetModuleFileNameA"),
    ("kernel32.dll", "WriteProcessMemory"),
    ("kernel32.dll", "ReadProcessMemory"),
    ("kernel32.dll", "OpenProcess"),
    ("kernel32.dll", "CreateProcessA"),
    ("kernel32.dll", "CreateProcessW"),
    ("kernel32.dll", "WinExec"),
    ("kernel32.dll", "ShellExecuteA"),
    ("kernel32.dll", "ExitProcess"),
    ("kernel32.dll", "Sleep"),
    ("kernel32.dll", "WaitForSingleObject"),
    ("kernel32.dll", "CloseHandle"),
    ("kernel32.dll", "IsDebuggerPresent"),
    ("kernel32.dll", "CheckRemoteDebuggerPresent"),
    ("kernel32.dll", "GetTickCount"),
    ("kernel32.dll", "QueryPerformanceCounter"),
    ("kernel32.dll", "CreateFileA"),
    ("kernel32.dll", "CreateFileW"),
    ("kernel32.dll", "ReadFile"),
    ("kernel32.dll", "WriteFile"),
    ("kernel32.dll", "SetFilePointer"),
    ("kernel32.dll", "DeviceIoControl"),
    ("kernel32.dll", "GetSystemDirectoryA"),
    ("kernel32.dll", "GetWindowsDirectoryA"),
    ("kernel32.dll", "NtUnmapViewOfSection"),
    ("kernel32.dll", "CreateFileMappingA"),
    ("kernel32.dll", "MapViewOfFile"),
    ("kernel32.dll", "ResumeThread"),
    ("kernel32.dll", "TerminateProcess"),
    ("kernel32.dll", "GetCurrentProcess"),
    ("kernel32.dll", "GetCommandLineA"),
    ("kernel32.dll", "GetEnvironmentVariableA"),
    ("kernel32.dll", "SetEnvironmentVariableA"),
    ("kernel32.dll", "MoveFileA"),
    ("kernel32.dll", "DeleteFileA"),
    ("kernel32.dll", "GetTempPathA"),
    ("kernel32.dll", "CreateDirectoryA"),
    ("kernel32.dll", "RemoveDirectoryA"),

    // ntdll.dll
    ("ntdll.dll", "NtAllocateVirtualMemory"),
    ("ntdll.dll", "NtProtectVirtualMemory"),
    ("ntdll.dll", "NtWriteVirtualMemory"),
    ("ntdll.dll", "NtReadVirtualMemory"),
    ("ntdll.dll", "NtCreateThreadEx"),
    ("ntdll.dll", "NtQueryInformationProcess"),
    ("ntdll.dll", "NtSetInformationThread"),
    ("ntdll.dll", "NtQuerySystemInformation"),
    ("ntdll.dll", "NtCreateSection"),
    ("ntdll.dll", "NtMapViewOfSection"),
    ("ntdll.dll", "RtlDecompressBuffer"),
    ("ntdll.dll", "RtlMoveMemory"),
    ("ntdll.dll", "RtlCopyMemory"),
    ("ntdll.dll", "LdrLoadDll"),
    ("ntdll.dll", "LdrGetProcedureAddress"),
    ("ntdll.dll", "NtFlushInstructionCache"),

    // ws2_32.dll
    ("ws2_32.dll", "WSAStartup"),
    ("ws2_32.dll", "WSASocketA"),
    ("ws2_32.dll", "WSASocketW"),
    ("ws2_32.dll", "socket"),
    ("ws2_32.dll", "connect"),
    ("ws2_32.dll", "bind"),
    ("ws2_32.dll", "listen"),
    ("ws2_32.dll", "accept"),
    ("ws2_32.dll", "send"),
    ("ws2_32.dll", "recv"),
    ("ws2_32.dll", "sendto"),
    ("ws2_32.dll", "recvfrom"),
    ("ws2_32.dll", "closesocket"),
    ("ws2_32.dll", "gethostbyname"),
    ("ws2_32.dll", "getaddrinfo"),
    ("ws2_32.dll", "inet_addr"),
    ("ws2_32.dll", "htons"),
    ("ws2_32.dll", "WSAConnect"),

    // advapi32.dll
    ("advapi32.dll", "RegOpenKeyExA"),
    ("advapi32.dll", "RegSetValueExA"),
    ("advapi32.dll", "RegGetValueA"),
    ("advapi32.dll", "CryptAcquireContextA"),
    ("advapi32.dll", "CryptEncrypt"),
    ("advapi32.dll", "CryptDecrypt"),
    ("advapi32.dll", "CryptGenKey"),
    ("advapi32.dll", "CreateServiceA"),
    ("advapi32.dll", "OpenSCManagerA"),
    ("advapi32.dll", "LogonUserA"),
    ("advapi32.dll", "AdjustTokenPrivileges"),
    ("advapi32.dll", "OpenProcessToken"),

    // user32.dll
    ("user32.dll", "MessageBoxA"),
    ("user32.dll", "MessageBoxW"),
    ("user32.dll", "SetWindowsHookExA"),
    ("user32.dll", "GetAsyncKeyState"),
    ("user32.dll", "FindWindowA"),
    ("user32.dll", "SendMessageA"),
    ("user32.dll", "PostMessageA"),
    ("user32.dll", "GetForegroundWindow"),
    ("user32.dll", "SetWinEventHook"),

    // wininet.dll / winhttp.dll
    ("wininet.dll", "InternetOpenA"),
    ("wininet.dll", "InternetConnectA"),
    ("wininet.dll", "HttpOpenRequestA"),
    ("wininet.dll", "HttpSendRequestA"),
    ("wininet.dll", "InternetReadFile"),
    ("winhttp.dll", "WinHttpOpen"),
    ("winhttp.dll", "WinHttpConnect"),
    ("winhttp.dll", "WinHttpOpenRequest"),
    ("winhttp.dll", "WinHttpSendRequest"),

    // urlmon.dll / oleaut32 / others
    ("urlmon.dll", "URLDownloadToFileA"),
    ("urlmon.dll", "URLDownloadToCacheFileA"),
    ("ole32.dll", "CoInitializeEx"),
    ("ole32.dll", "CoCreateInstance"),
    ("shell32.dll", "ShellExecuteExA"),
    ("msvcrt.dll", "system"),
    ("msvcrt.dll", "strcmp"),
    ("msvcrt.dll", "strncmp"),

    // ws2_32.dll (networking, common in staged loaders)
    ("ws2_32.dll", "WSAStartup"),
    ("ws2_32.dll", "WSASocketA"),
    ("ws2_32.dll", "socket"),
    ("ws2_32.dll", "connect"),
    ("ws2_32.dll", "send"),
    ("ws2_32.dll", "recv"),
    ("ws2_32.dll", "bind"),
    ("ws2_32.dll", "listen"),
    ("ws2_32.dll", "accept"),
    ("ws2_32.dll", "inet_addr"),
    ("ws2_32.dll", "htons"),
    ("ws2_32.dll", "closesocket"),
    ("ws2_32.dll", "gethostbyname"),
    ("ws2_32.dll", "WSAConnect"),

    // ntdll.dll (native, common in manual maps / process injection)
    ("ntdll.dll", "NtAllocateVirtualMemory"),
    ("ntdll.dll", "NtWriteVirtualMemory"),
    ("ntdll.dll", "NtProtectVirtualMemory"),
    ("ntdll.dll", "NtCreateThreadEx"),
    ("ntdll.dll", "NtOpenProcess"),
    ("ntdll.dll", "NtQueryInformationProcess"),
    ("ntdll.dll", "NtReadVirtualMemory"),
    ("ntdll.dll", "NtUnmapViewOfSection"),
    ("ntdll.dll", "RtlMoveMemory"),
    ("ntdll.dll", "memcpy"),
    ("ntdll.dll", "NtFlushInstructionCache"),
    ("ntdll.dll", "NtSetContextThread"),
    ("ntdll.dll", "NtGetContextThread"),
    ("ntdll.dll", "NtResumeThread"),
    ("ntdll.dll", "NtSuspendThread"),
    ("ntdll.dll", "NtQueueApcThread"),

    // More kernel32
    ("kernel32.dll", "CreateRemoteThread"),
    ("kernel32.dll", "OpenProcess"),
    ("kernel32.dll", "VirtualAllocEx"),
    ("kernel32.dll", "WriteProcessMemory"),
    ("kernel32.dll", "ReadProcessMemory"),
    ("kernel32.dll", "GetProcAddress"),
    ("kernel32.dll", "LoadLibraryA"),
    ("kernel32.dll", "CreateProcessA"),
    ("kernel32.dll", "CreateProcessW"),
    ("kernel32.dll", "WinExec"),
    ("kernel32.dll", "ReadFile"),
    ("kernel32.dll", "WriteFile"),
    ("kernel32.dll", "DeviceIoControl"),
    ("kernel32.dll", "SetFilePointer"),
    ("kernel32.dll", "GetModuleHandleW"),
    ("kernel32.dll", "GetModuleFileNameA"),
    ("kernel32.dll", "Sleep"),
    ("kernel32.dll", "ExitProcess"),
    ("kernel32.dll", "GetCommandLineA"),
    ("kernel32.dll", "GetTempPathA"),
    ("kernel32.dll", "CreateFileMappingA"),
    ("kernel32.dll", "MapViewOfFile"),

    // iphlpapi / dnsapi
    ("iphlpapi.dll", "GetAdaptersInfo"),
    ("dnsapi.dll", "DnsQuery_A"),

    // advapi32 / wtsapi
    ("advapi32.dll", "RegOpenKeyExA"),
    ("advapi32.dll", "RegSetValueExA"),
    ("advapi32.dll", "RegQueryValueExA"),
    ("advapi32.dll", "CryptCreateHash"),
    ("advapi32.dll", "CryptHashData"),
    ("wtsapi32.dll", "WTSQueryUserToken"),

    // gdi32 / shlwapi
    ("gdi32.dll", "CreateCompatibleDC"),
    ("shlwapi.dll", "StrStrA"),
];

fn build_db() -> HashMap<u32, ResolvedApi> {
    let mut db: HashMap<u32, ResolvedApi> = HashMap::new();
    for &(dll, func) in API_LIST {
        let variants = [
            compute_ror13(func),
            compute_ror13_nul(func),
            compute_ror13(&func.to_ascii_uppercase()),
            compute_ror13_nul(&func.to_ascii_uppercase()),
            compute_ror13(&format!("{}.{}", dll, func)),
            compute_ror13(&format!("{}.{}", dll.to_ascii_uppercase(), func.to_ascii_uppercase())),
            compute_ror13_module_func(dll, func),
            compute_ror13_module_func(&dll.to_ascii_lowercase(), &func.to_ascii_lowercase()),
        ];
        for h in variants {
            db.entry(h).or_insert(ResolvedApi {
                hash: h,
                hash_type: ApiHashType::Ror13,
                dll_name: dll,
                function_name: func,
            });
        }
    }
    db
}

fn api_db() -> &'static HashMap<u32, ResolvedApi> {
    static DB: OnceLock<HashMap<u32, ResolvedApi>> = OnceLock::new();
    DB.get_or_init(build_db)
}

/// Attempt to resolve a 32-bit hash to a known Windows API.
pub fn resolve_api_hash(hash: u32) -> Option<ResolvedApi> {
    api_db().get(&hash).cloned()
}

/// Scan a buffer for potential API hash values and resolve them.
/// Looks for 4-byte (little-endian) DWORDs that match known hashes.
pub fn scan_for_api_hashes(data: &[u8]) -> Vec<(usize, ResolvedApi)> {
    let mut results = Vec::new();

    if data.len() < 4 {
        return results;
    }

    // Scan every byte offset: real hash arrays are rarely 4-byte aligned
    // relative to the buffer start (stacked push imm32 sequences, unaligned
    // tables, packed code), so aligned-only scanning misses most hits.
    let mut offset = 0;
    while offset + 4 <= data.len() {
        let hash = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);

        if let Some(resolved) = resolve_api_hash(hash) {
            results.push((offset, resolved));
        }

        offset += 1;
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_known_hash() {
        // The database is built from compute_ror13, so a freshly computed
        // VirtualAlloc hash must resolve back to VirtualAlloc.
        let h = compute_ror13("VirtualAlloc");
        let result = resolve_api_hash(h);
        assert!(result.is_some(), "computed VirtualAlloc hash 0x{:08X} not resolved", h);
        let api = result.unwrap();
        assert_eq!(api.function_name, "VirtualAlloc");
        assert_eq!(api.dll_name, "kernel32.dll");
        assert_eq!(api.hash_type, ApiHashType::Ror13);
    }

    #[test]
    fn test_unknown_hash_returns_none() {
        let result = resolve_api_hash(0xDEADBEEF);
        assert!(result.is_none());
    }

    #[test]
    fn test_scan_finds_hashes_in_buffer() {
        let mut buf = vec![0u8; 64];
        let h = compute_ror13("VirtualAlloc");
        buf[16..20].copy_from_slice(&h.to_le_bytes());

        let results = scan_for_api_hashes(&buf);
        assert!(!results.is_empty(), "VirtualAlloc hash not found in buffer");
        assert_eq!(results[0].0, 16);
        assert_eq!(results[0].1.function_name, "VirtualAlloc");
    }

    #[test]
    fn test_scan_finds_unaligned_hashes() {
        // Real hash arrays are rarely aligned to the buffer start.
        let mut buf = vec![0xFFu8; 16];
        let h = compute_ror13("GetProcAddress");
        assert_ne!(5 % 4, 0);
        buf[5..9].copy_from_slice(&h.to_le_bytes());

        let results = scan_for_api_hashes(&buf);
        assert!(
            results.iter().any(|(off, a)| *off == 5 && a.function_name == "GetProcAddress"),
            "unaligned hash DWORD at offset 5 not found"
        );
    }

    #[test]
    fn test_ror13_compute() {
        let hash = compute_ror13("VirtualAlloc");
        assert_ne!(hash, 0);
        // Different names must not collide to 0 / identical values.
        assert_ne!(hash, compute_ror13("CreateThread"));
    }

    #[test]
    fn test_db_is_populated() {
        // Sanity: the generated DB must be non-trivial in size.
        assert!(api_db().len() > API_LIST.len());
    }

    #[test]
    fn test_canonical_ror13_hashes() {
        // Canonical Metasploit-style ROR13 values (exact case, no NUL):
        let resolved = resolve_api_hash(0x7C0DFCAA)
            .expect("0x7C0DFCAA must resolve to GetProcAddress");
        assert_eq!(resolved.dll_name, "kernel32.dll");
        assert_eq!(resolved.function_name, "GetProcAddress");

        assert_eq!(compute_ror13("LoadLibraryA"), 0xEC0E4E8E);
        let ll = resolve_api_hash(0xEC0E4E8E)
            .expect("0xEC0E4E8E must resolve to LoadLibraryA");
        assert_eq!(ll.dll_name, "kernel32.dll");
        assert_eq!(ll.function_name, "LoadLibraryA");
    }
}
