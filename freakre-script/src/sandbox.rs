//! Sandbox configuration and capability system.
//!
//! File I/O built-ins (`read_bytes`/`write_bytes`) are gated by
//! `Capabilities::allow_file_io`. No network or process APIs exist in this
//! DSL; the `allow_network`/`allow_process` flags are reserved for future use.

use std::collections::HashSet;

/// Resource limits for script execution.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Maximum number of interpreter instructions.
    pub max_instructions: u64,
    /// Maximum memory allocations (in bytes).
    pub max_memory: usize,
    /// Maximum call stack depth.
    pub max_call_depth: usize,
    /// Maximum string length.
    pub max_string_len: usize,
    /// Maximum table entries.
    pub max_table_entries: usize,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            max_instructions: 100_000,
            max_memory: 4 * 1024 * 1024, // 4 MB
            max_call_depth: 64,
            max_string_len: 65536,
            max_table_entries: 10000,
        }
    }
}

/// Capability whitelist: only listed APIs are accessible.
#[derive(Debug, Clone)]
pub struct Capabilities {
    /// Allowed top-level function names.
    pub allowed_functions: HashSet<String>,
    /// Allowed module.field accesses (e.g., "db.find_functions").
    pub allowed_fields: HashSet<String>,
    /// Whether file I/O is allowed (default: false).
    pub allow_file_io: bool,
    /// Whether network access is allowed (default: false).
    pub allow_network: bool,
    /// Whether process creation is allowed (default: false).
    pub allow_process: bool,
}

impl Default for Capabilities {
    fn default() -> Self {
        let mut allowed_functions = HashSet::new();
        // Safe built-ins
        for name in &[
            "print", "type", "tostring", "tonumber",
            "pairs", "ipairs", "next", "select",
            "unpack", "table", "string", "math",
            // stdlib: string utils
            "len", "sub", "find", "replace", "upper", "lower", "trim",
            "split", "join", "format_number",
            // stdlib: data helpers (pure byte computation, no I/O)
            "hex_encode", "hex_decode", "bytes_to_u32_le", "u32_to_bytes_le",
            "base64_encode", "base64_decode", "crc32", "xor_bytes",
            // stdlib: pattern helpers
            "contains_any", "count_occurrences", "extract_between",
            // stdlib: math/misc
            "min", "max", "abs", "floor", "ceil",
        ] {
            allowed_functions.insert(name.to_string());
        }

        let mut allowed_fields = HashSet::new();
        // RE-specific APIs
        for name in &[
            "db.find_functions", "db.get_function", "db.get_strings",
            "db.flag", "db.rename", "db.get_xrefs",
            "report.add_finding", "report.summary",
            "strings.contains", "strings.find_all",
            "binary.read_bytes", "binary.size",
        ] {
            allowed_fields.insert(name.to_string());
        }

        Self {
            allowed_functions,
            allowed_fields,
            allow_file_io: false,
            allow_network: false,
            allow_process: false,
        }
    }
}

impl Capabilities {
    /// Check if a function call is allowed.
    pub fn can_call(&self, name: &str) -> bool {
        if matches!(name, "read_bytes" | "write_bytes") {
            return self.allow_file_io;
        }
        self.allowed_functions.contains(name)
    }

    /// Check if a field access is allowed.
    pub fn can_access_field(&self, table: &str, field: &str) -> bool {
        let full = format!("{}.{}", table, field);
        self.allowed_fields.contains(&full)
    }
}
