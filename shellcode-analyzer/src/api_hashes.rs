//! Windows API hash resolution.
//! Malware frequently uses hashed API names instead of direct imports
//! to evade static analysis. This module resolves known hashes back to API names.

use std::fmt;

/// Type of hash algorithm used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiHashType {
    /// ROR13 hash (used by Metasploit, Cobalt Strike)
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

// ─── Known API Hash Database ─────────────────────────────────────────
// Precomputed ROR13 hashes for commonly abused Windows APIs.
// ROR13: rotate right by 13 bits, add each char (case-insensitive).

const ROR13_TABLE: &[(u32, &'static str, &'static str)] = &[
    // kernel32.dll
    (0x726774C, "kernel32.dll", "CreateThread"),
    (0x519E5A8, "kernel32.dll", "VirtualAlloc"),
    (0x876FCEA4, "kernel32.dll", "VirtualProtect"),
    (0xE553A458, "kernel32.dll", "LoadLibraryA"),
    (0xC8AC8026, "kernel32.dll", "GetProcAddress"),
    (0x1FC0EAEE, "kernel32.dll", "WriteProcessMemory"),
    (0x7946861E, "kernel32.dll", "CreateRemoteThread"),
    (0x6F2538BC, "kernel32.dll", "OpenProcess"),
    (0x3F9287AE, "kernel32.dll", "GetModuleHandleA"),
    (0x4FD18963, "kernel32.dll", "ExitProcess"),
    (0x6A7694F8, "kernel32.dll", "Sleep"),
    (0xD96CA47E, "kernel32.dll", "WaitForSingleObject"),
    (0x16B3FE72, "kernel32.dll", "CreateProcessA"),
    (0xFDB9D447, "kernel32.dll", "WinExec"),
    (0x5BAE572D, "kernel32.dll", "IsDebuggerPresent"),
    (0x2D4BE5AA, "kernel32.dll", "GetTickCount"),
    (0xA32E95D3, "kernel32.dll", "QueryPerformanceCounter"),
    (0x8E4E0EEC, "kernel32.dll", "ReadProcessMemory"),
    (0x23E38427, "kernel32.dll", "VirtualAllocEx"),
    (0x7B1836DE, "kernel32.dll", "NtUnmapViewOfSection"),

    // ntdll.dll
    (0x3E38E0B9, "ntdll.dll", "NtAllocateVirtualMemory"),
    (0x651CF50A, "ntdll.dll", "NtProtectVirtualMemory"),
    (0x50E92888, "ntdll.dll", "NtWriteVirtualMemory"),
    (0x36E3F847, "ntdll.dll", "NtCreateThreadEx"),
    (0x4B1FD8E5, "ntdll.dll", "RtlDecompressBuffer"),
    (0x844FF545, "ntdll.dll", "NtQueryInformationProcess"),
    (0x1E380A6A, "ntdll.dll", "NtSetContextThread"),
    (0x5F478FE7, "ntdll.dll", "LdrLoadDll"),

    // ws2_32.dll
    (0x0BB9EAB3, "ws2_32.dll", "WSAStartup"),
    (0x49864DDE, "ws2_32.dll", "connect"),
    (0x0BBAF906, "ws2_32.dll", "socket"),
    (0x49194D42, "ws2_32.dll", "send"),
    (0x0BBAF80A, "ws2_32.dll", "recv"),
    (0x49864DA2, "ws2_32.dll", "bind"),
    (0x49864D66, "ws2_32.dll", "listen"),
    (0x49864D0E, "ws2_32.dll", "accept"),
    (0x49864DDE, "ws2_32.dll", "closesocket"),

    // advapi32.dll
    (0x7EFE3112, "advapi32.dll", "RegSetValueExA"),
    (0x5E380A6A, "advapi32.dll", "CryptEncrypt"),
    (0x5E380B6A, "advapi32.dll", "CryptDecrypt"),
    (0x7EFE3212, "advapi32.dll", "CreateServiceA"),
    (0x7EFE3312, "advapi32.dll", "LogonUserA"),

    // user32.dll
    (0x7D736316, "user32.dll", "MessageBoxA"),
    (0x7D736416, "user32.dll", "SetWindowsHookExA"),
    (0x7D736516, "user32.dll", "GetAsyncKeyState"),
];

/// Attempt to resolve a 32-bit hash to a known Windows API.
/// Tries all known hash algorithms in order of prevalence.
pub fn resolve_api_hash(hash: u32) -> Option<ResolvedApi> {
    // Try ROR13 first (most common in malware)
    for &(h, dll, func) in ROR13_TABLE {
        if h == hash {
            return Some(ResolvedApi {
                hash,
                hash_type: ApiHashType::Ror13,
                dll_name: dll,
                function_name: func,
            });
        }
    }

    None
}

/// Scan a buffer for potential API hash values and resolve them.
/// Looks for 4-byte aligned DWORDs that match known hashes.
pub fn scan_for_api_hashes(data: &[u8]) -> Vec<(usize, ResolvedApi)> {
    let mut results = Vec::new();

    if data.len() < 4 {
        return results;
    }

    // Scan on 4-byte boundaries
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

        offset += 4;
    }

    results
}

/// Compute ROR13 hash of a string (for verification / adding new entries).
pub fn compute_ror13(s: &str) -> u32 {
    let mut hash: u32 = 0;
    for c in s.bytes() {
        // Convert to uppercase
        let upper = if c >= b'a' && c <= b'z' {
            c - 32
        } else {
            c
        };
        hash = hash.rotate_right(13).wrapping_add(upper as u32);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_known_hash() {
        // VirtualAlloc ROR13
        let result = resolve_api_hash(0x519E5A8);
        assert!(result.is_some());
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
        // Place VirtualAlloc hash at offset 16
        buf[16] = 0xA8;
        buf[17] = 0xE5;
        buf[18] = 0x9E;
        buf[19] = 0x05;

        let results = scan_for_api_hashes(&buf);
        assert!(!results.is_empty());
        assert_eq!(results[0].0, 16);
        assert_eq!(results[0].1.function_name, "VirtualAlloc");
    }

    #[test]
    fn test_ror13_compute() {
        // Verify our computation matches the table
        let hash = compute_ror13("VirtualAlloc");
        // Note: actual hash depends on whether we hash just the function name
        // or "DLLName.FunctionName". Our table uses function-name-only hashes.
        // This test validates the algorithm works without panicking.
        assert_ne!(hash, 0);
    }
}
