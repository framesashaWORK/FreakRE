//! Feature extraction from binary files for heuristic classification.
//!
//! Extracts a fixed-size feature vector from PE/ELF/raw binaries that can
//! be fed to the ensemble classifier. Features are inspired by Ember/PEframe
//! and include: byte histograms, entropy statistics, string patterns,
//! section statistics, import counts, and structural anomalies.

use serde::{Deserialize, Serialize};

/// Number of features in the feature vector.
pub const NUM_FEATURES: usize = 96;

mod f32_array_serde {
    use serde::{self, Deserialize, Deserializer, Serializer};

    const LEN: usize = super::NUM_FEATURES;

    pub fn serialize<S>(arr: &[f32; LEN], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(arr.iter())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[f32; LEN], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: Vec<f32> = Deserialize::deserialize(deserializer)?;
        if vec.len() != LEN {
            return Err(serde::de::Error::custom(format!(
                "expected {} elements, got {}",
                LEN,
                vec.len()
            )));
        }
        let mut arr = [0.0f32; LEN];
        arr.copy_from_slice(&vec);
        Ok(arr)
    }
}

/// A fixed-size feature vector extracted from a binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureVector {
    /// The raw feature values.
    #[serde(with = "f32_array_serde")]
    pub features: [f32; NUM_FEATURES],
    /// Human-readable feature names for debugging.
    #[serde(skip)]
    pub names: Vec<&'static str>,
}

impl FeatureVector {
    /// Create a zeroed feature vector.
    pub fn zeros() -> Self {
        FeatureVector {
            features: [0.0; NUM_FEATURES],
            names: feature_names().to_vec(),
        }
    }
}

/// Feature names for debugging and interpretation.
pub(crate) fn feature_names() -> &'static [&'static str] {
    &[
        // 0-15: Byte histogram (16 bins, normalized)
        "byte_hist_0",
        "byte_hist_1",
        "byte_hist_2",
        "byte_hist_3",
        "byte_hist_4",
        "byte_hist_5",
        "byte_hist_6",
        "byte_hist_7",
        "byte_hist_8",
        "byte_hist_9",
        "byte_hist_a",
        "byte_hist_b",
        "byte_hist_c",
        "byte_hist_d",
        "byte_hist_e",
        "byte_hist_f",
        // 16-31: Byte-printable ratios + entropy stats
        "printable_ratio",
        "uppercase_ratio",
        "digit_ratio",
        "null_ratio",
        "high_byte_ratio",
        "global_entropy",
        "entropy_std",
        "entropy_max_section",
        "file_size_log",
        "num_sections",
        "avg_section_size_log",
        "rwx_section_count",
        "text_section_ratio",
        "data_section_ratio",
        "resource_section_ratio",
        "other_section_ratio",
        // 32-47: String patterns
        "string_url_count",
        "string_ip_count",
        "string_path_count",
        "string_registry_count",
        "string_crypto_count",
        "string_cmd_count",
        "string_powershell_count",
        "string_encoding_count",
        "string_error_count",
        "string_debug_count",
        "string_avg_length",
        "string_max_length",
        "string_total_count",
        "string_unique_ratio",
        "string_suspicious_ratio",
        "string_base64_count",
        // 48-63: Import/DLL features
        "import_kernel32",
        "import_user32",
        "import_advapi32",
        "import_ws2_32",
        "import_wininet",
        "import_urlmon",
        "import_shell32",
        "import_ole32",
        "import_crypt32",
        "import_ntdll",
        "import_msvcrt",
        "import_wtsapi32",
        "total_imports_log",
        "unique_dlls_log",
        "suspicious_import_ratio",
        "rare_dll_count",
        // 64-79: Structural features
        "has_debug_info",
        "is_packed_entropy",
        "num_exports_log",
        "timestamp_age_years",
        "checksum_valid",
        "has_overlay",
        "overlay_size_ratio",
        "num_data_dirs",
        "has_tls",
        "has_resources",
        "has_security_dir",
        "has_relocations",
        "code_section_entropy",
        "data_section_entropy",
        "entry_in_text",
        "num_segments_elf",
        // 80-95: Behavioral features
        "anti_debug_count",
        "anti_vm_count",
        "crypto_ops_count",
        "process_inject_count",
        "keylog_count",
        "persistence_count",
        "network_count",
        "file_ops_count",
        "shellcode_score",
        "obfuscation_score",
        "xref_correlation",
        "cfg_anomaly_count",
        "backdoor_risk",
        "yara_match_count",
        "suspicion_score",
        "composite_threat",
    ]
}

/// Extract features from a raw binary file.
///
/// Works with PE, ELF, or raw binaries. For PE/ELF, pass parsed metadata
/// via the `BinaryInfo` struct for richer features.
pub fn extract_features(data: &[u8], info: &BinaryInfo) -> FeatureVector {
    let mut fv = FeatureVector::zeros();

    // ─── Byte histogram (16 bins) ────────────────────────────────
    let mut hist = [0u32; 16];
    for &b in data {
        hist[(b >> 4) as usize] += 1;
    }
    let total = data.len() as f32;
    if total > 0.0 {
        for (i, &h) in hist.iter().enumerate() {
            fv.features[i] = h as f32 / total;
        }
    }

    // ─── Byte-printable ratios ───────────────────────────────────
    let mut printable = 0u32;
    let mut uppercase = 0u32;
    let mut digit = 0u32;
    let mut null = 0u32;
    let mut high = 0u32;
    for &b in data {
        if (0x20..0x7F).contains(&b) {
            printable += 1;
        }
        if b.is_ascii_uppercase() {
            uppercase += 1;
        }
        if b.is_ascii_digit() {
            digit += 1;
        }
        if b == 0 {
            null += 1;
        }
        if b > 0x7F {
            high += 1;
        }
    }
    if total > 0.0 {
        fv.features[16] = printable as f32 / total;
        fv.features[17] = uppercase as f32 / total;
        fv.features[18] = digit as f32 / total;
        fv.features[19] = null as f32 / total;
        fv.features[20] = high as f32 / total;
    }

    // ─── Global entropy ──────────────────────────────────────────
    fv.features[21] = calculate_entropy(data);

    // ─── Entropy statistics from sections ────────────────────────
    if !info.section_entropies.is_empty() {
        let entropies: Vec<f32> = info.section_entropies.to_vec();
        let mean = entropies.iter().sum::<f32>() / entropies.len() as f32;
        let variance =
            entropies.iter().map(|e| (e - mean).powi(2)).sum::<f32>() / entropies.len() as f32;
        fv.features[22] = variance.sqrt(); // std
        fv.features[23] = entropies.iter().cloned().fold(0.0f32, f32::max);
    }

    // ─── File size (log scale) ──────────────────────────────────
    fv.features[24] = (data.len() as f32 + 1.0).log2();

    // ─── Section statistics ─────────────────────────────────────
    fv.features[25] = info.num_sections as f32;
    if let Some(avg_size) = data.len().checked_div(info.num_sections) {
        fv.features[26] = (avg_size as f32 + 1.0).log2();
    }
    fv.features[27] = info.rwx_section_count as f32;

    // Section type ratios
    if info.num_sections > 0 {
        let n = info.num_sections as f32;
        fv.features[28] = info.code_sections as f32 / n;
        fv.features[29] = info.data_sections as f32 / n;
        fv.features[30] = info.resource_sections as f32 / n;
        fv.features[31] = info
            .num_sections
            .saturating_sub(info.code_sections)
            .saturating_sub(info.data_sections)
            .saturating_sub(info.resource_sections) as f32
            / n;
    }

    // ─── String patterns ────────────────────────────────────────
    let sp = &info.string_patterns;
    fv.features[32] = sp.url_count as f32;
    fv.features[33] = sp.ip_count as f32;
    fv.features[34] = sp.path_count as f32;
    fv.features[35] = sp.registry_count as f32;
    fv.features[36] = sp.crypto_count as f32;
    fv.features[37] = sp.cmd_count as f32;
    fv.features[38] = sp.powershell_count as f32;
    fv.features[39] = sp.encoding_count as f32;
    fv.features[40] = sp.error_count as f32;
    fv.features[41] = sp.debug_count as f32;
    fv.features[42] = sp.avg_length as f32;
    fv.features[43] = sp.max_length as f32;
    fv.features[44] = sp.total_count as f32;
    fv.features[45] = sp.unique_ratio;
    fv.features[46] = sp.suspicious_ratio;
    fv.features[47] = sp.base64_count as f32;

    // ─── Import/DLL features ────────────────────────────────────
    let imp = &info.imports;
    fv.features[48] = imp.kernel32 as f32;
    fv.features[49] = imp.user32 as f32;
    fv.features[50] = imp.advapi32 as f32;
    fv.features[51] = imp.ws2_32 as f32;
    fv.features[52] = imp.wininet as f32;
    fv.features[53] = imp.urlmon as f32;
    fv.features[54] = imp.shell32 as f32;
    fv.features[55] = imp.ole32 as f32;
    fv.features[56] = imp.crypt32 as f32;
    fv.features[57] = imp.ntdll as f32;
    fv.features[58] = imp.msvcrt as f32;
    fv.features[59] = imp.wtsapi32 as f32;
    fv.features[60] = (imp.total_imports as f32 + 1.0).log2();
    fv.features[61] = (imp.unique_dlls as f32 + 1.0).log2();
    fv.features[62] = imp.suspicious_ratio;
    fv.features[63] = imp.rare_dll_count as f32;

    // ─── Structural features ────────────────────────────────────
    fv.features[64] = if info.has_debug_info { 1.0 } else { 0.0 };
    fv.features[65] = if info.is_packed { 1.0 } else { 0.0 };
    fv.features[66] = (info.num_exports as f32 + 1.0).log2();
    fv.features[67] = info.timestamp_age_years;
    fv.features[68] = if info.checksum_valid { 1.0 } else { 0.0 };
    fv.features[69] = if info.has_overlay { 1.0 } else { 0.0 };
    fv.features[70] = info.overlay_size_ratio;
    fv.features[71] = info.num_data_dirs as f32;
    fv.features[72] = if info.has_tls { 1.0 } else { 0.0 };
    fv.features[73] = if info.has_resources { 1.0 } else { 0.0 };
    fv.features[74] = if info.has_security_dir { 1.0 } else { 0.0 };
    fv.features[75] = if info.has_relocations { 1.0 } else { 0.0 };
    fv.features[76] = info.code_section_entropy;
    fv.features[77] = info.data_section_entropy;
    fv.features[78] = if info.entry_in_text { 1.0 } else { 0.0 };
    fv.features[79] = info.num_segments as f32;

    // ─── Behavioral features ────────────────────────────────────
    let beh = &info.behavioral;
    fv.features[80] = beh.anti_debug_count as f32;
    fv.features[81] = beh.anti_vm_count as f32;
    fv.features[82] = beh.crypto_ops_count as f32;
    fv.features[83] = beh.process_inject_count as f32;
    fv.features[84] = beh.keylog_count as f32;
    fv.features[85] = beh.persistence_count as f32;
    fv.features[86] = beh.network_count as f32;
    fv.features[87] = beh.file_ops_count as f32;
    fv.features[88] = beh.shellcode_score;
    fv.features[89] = beh.obfuscation_score;
    fv.features[90] = beh.xref_correlation as f32;
    fv.features[91] = beh.cfg_anomaly_count as f32;
    fv.features[92] = beh.backdoor_risk;
    fv.features[93] = beh.yara_match_count as f32;
    fv.features[94] = beh.suspicion_score;
    fv.features[95] = beh.composite_threat;

    fv
}

/// Calculate Shannon entropy of a byte slice.
fn calculate_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let total = data.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / total;
            entropy -= p * p.log2();
        }
    }
    entropy as f32
}

/// Metadata about the binary to enrich feature extraction.
///
/// Populate this from PE/ELF parsing and other analysis modules.
#[derive(Debug, Clone, Default)]
pub struct BinaryInfo {
    pub num_sections: usize,
    pub rwx_section_count: usize,
    pub code_sections: usize,
    pub data_sections: usize,
    pub resource_sections: usize,
    pub section_entropies: Vec<f32>,

    pub string_patterns: StringPatterns,
    pub imports: ImportStats,

    pub has_debug_info: bool,
    pub is_packed: bool,
    pub num_exports: usize,
    pub timestamp_age_years: f32,
    pub checksum_valid: bool,
    pub has_overlay: bool,
    pub overlay_size_ratio: f32,
    pub num_data_dirs: usize,
    pub has_tls: bool,
    pub has_resources: bool,
    pub has_security_dir: bool,
    pub has_relocations: bool,
    pub code_section_entropy: f32,
    pub data_section_entropy: f32,
    pub entry_in_text: bool,
    pub num_segments: usize,

    pub behavioral: BehavioralStats,
}

/// String pattern counts extracted from the binary's strings.
#[derive(Debug, Clone, Default)]
pub struct StringPatterns {
    pub url_count: usize,
    pub ip_count: usize,
    pub path_count: usize,
    pub registry_count: usize,
    pub crypto_count: usize,
    pub cmd_count: usize,
    pub powershell_count: usize,
    pub encoding_count: usize,
    pub error_count: usize,
    pub debug_count: usize,
    pub avg_length: usize,
    pub max_length: usize,
    pub total_count: usize,
    pub unique_ratio: f32,
    pub suspicious_ratio: f32,
    pub base64_count: usize,
}

/// Import statistics from PE/ELF parsing.
#[derive(Debug, Clone, Default)]
pub struct ImportStats {
    pub kernel32: usize,
    pub user32: usize,
    pub advapi32: usize,
    pub ws2_32: usize,
    pub wininet: usize,
    pub urlmon: usize,
    pub shell32: usize,
    pub ole32: usize,
    pub crypt32: usize,
    pub ntdll: usize,
    pub msvcrt: usize,
    pub wtsapi32: usize,
    pub total_imports: usize,
    pub unique_dlls: usize,
    pub suspicious_ratio: f32,
    pub rare_dll_count: usize,
}

/// Behavioral statistics from backdoor/shellcode/cfg analysis.
#[derive(Debug, Clone, Default)]
pub struct BehavioralStats {
    pub anti_debug_count: usize,
    pub anti_vm_count: usize,
    pub crypto_ops_count: usize,
    pub process_inject_count: usize,
    pub keylog_count: usize,
    pub persistence_count: usize,
    pub network_count: usize,
    pub file_ops_count: usize,
    pub shellcode_score: f32,
    pub obfuscation_score: f32,
    pub xref_correlation: usize,
    pub cfg_anomaly_count: usize,
    pub backdoor_risk: f32,
    pub yara_match_count: usize,
    pub suspicion_score: f32,
    pub composite_threat: f32,
}

impl StringPatterns {
    /// Extract string patterns from a list of strings.
    pub fn from_strings(strings: &[&str]) -> Self {
        let mut sp = StringPatterns {
            total_count: strings.len(),
            ..Default::default()
        };

        let mut suspicious = 0usize;
        let mut total_len = 0usize;
        let mut unique: std::collections::HashSet<&str> = std::collections::HashSet::new();

        for s in strings {
            let lower = s.to_lowercase();
            total_len += s.len();
            unique.insert(s);
            sp.max_length = sp.max_length.max(s.len());

            if lower.starts_with("http://") || lower.starts_with("https://") {
                sp.url_count += 1;
                suspicious += 1;
            }
            // Note: url_count is already incremented above for http(s):// prefixes.
            // This line was a no-op bug (x.max(x)). Removed.

            // IP pattern: x.x.x.x
            if is_ip_like(&lower) {
                sp.ip_count += 1;
                suspicious += 1;
            }

            if lower.contains("\\") || lower.starts_with('/') {
                sp.path_count += 1;
            }
            if lower.contains("hklm") || lower.contains("hkcu") || lower.contains("software\\") {
                sp.registry_count += 1;
                suspicious += 1;
            }
            if lower.contains("aes")
                || lower.contains("rsa")
                || lower.contains("encrypt")
                || lower.contains("decrypt")
            {
                sp.crypto_count += 1;
                suspicious += 1;
            }
            if lower.contains("cmd.exe") || lower.contains("/c ") || lower.contains("command") {
                sp.cmd_count += 1;
                suspicious += 1;
            }
            if lower.contains("powershell") || lower.contains("pwsh") {
                sp.powershell_count += 1;
                suspicious += 1;
            }
            if lower.contains("base64") || lower.contains("utf-8") || lower.contains("ascii") {
                sp.encoding_count += 1;
            }
            if lower.contains("error") || lower.contains("fail") || lower.contains("exception") {
                sp.error_count += 1;
            }
            if lower.contains("debug") || lower.contains("isdebug") || lower.contains("breakpoint")
            {
                sp.debug_count += 1;
                suspicious += 1;
            }

            // Base64 pattern: long alphanumeric strings with padding
            if is_base64_like(s) {
                sp.base64_count += 1;
                suspicious += 1;
            }
        }

        if let Some(avg) = total_len.checked_div(sp.total_count) {
            sp.avg_length = avg;
        }
        if sp.total_count > 0 {
            sp.unique_ratio = unique.len() as f32 / sp.total_count as f32;
            sp.suspicious_ratio = (suspicious as f32 / sp.total_count as f32).min(1.0);
        }

        sp
    }
}

fn is_ip_like(s: &str) -> bool {
    // Accept an optional trailing ":port"; only the address part is parsed.
    let host = match s.split_once(':') {
        Some((host, _port)) => host,
        None => s,
    };
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| {
        // u8::from_str accepts a leading '+' as a sign; real dotted quads
        // never have one.
        !p.is_empty() && !p.starts_with('+') && p.parse::<u8>().is_ok()
    })
}

fn is_base64_like(s: &str) -> bool {
    if s.len() < 20 {
        return false;
    }
    let b64_chars = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
    let has_padding = s.ends_with('=') || s.ends_with("==");
    b64_chars && (has_padding || s.len() >= 40)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_features_empty() {
        let info = BinaryInfo::default();
        let fv = extract_features(&[], &info);
        assert_eq!(fv.features.len(), NUM_FEATURES);
    }

    #[test]
    fn test_extract_features_basic() {
        let data = b"Hello World! This is a test binary with some content.";
        let info = BinaryInfo::default();
        let fv = extract_features(data, &info);
        assert!(fv.features[21] > 0.0); // entropy should be > 0
        assert!(fv.features[24] > 0.0); // log(size) > 0
    }

    #[test]
    fn test_entropy() {
        // All zeros → entropy = 0
        let data = [0u8; 1000];
        assert_eq!(calculate_entropy(&data), 0.0);

        // Uniform distribution → entropy = 8.0
        let mut data = Vec::new();
        for i in 0..=255u8 {
            data.extend_from_slice(&[i; 4]); // 4 of each byte
        }
        let ent = calculate_entropy(&data);
        assert!((ent - 8.0).abs() < 0.01, "Expected ~8.0, got {}", ent);
    }

    #[test]
    fn test_string_patterns() {
        let strings = vec![
            "http://malware.com/c2",
            "cmd.exe /c whoami",
            "HKLM\\Software\\Run",
            "AES-256-CBC",
            "normal string here",
        ];
        let sp = StringPatterns::from_strings(&strings);
        assert!(sp.url_count >= 1);
        assert!(sp.cmd_count >= 1);
        assert!(sp.registry_count >= 1);
        assert!(sp.crypto_count >= 1);
        assert_eq!(sp.total_count, 5);
    }

    #[test]
    fn test_is_ip_like() {
        assert!(is_ip_like("192.168.1.1"));
        assert!(!is_ip_like("not.an.ip"));
        assert!(!is_ip_like("192.168.1"));
    }

    #[test]
    fn test_is_ip_like_edges() {
        // Leading '+' parses as a sign in u8::from_str — reject it.
        assert!(!is_ip_like("+1.+2.+3.+4"));
        assert!(!is_ip_like("+192.168.1.1"));
        assert!(!is_ip_like("192.168.+1.1"));
        // Optional trailing ":port" is accepted.
        assert!(is_ip_like("10.0.0.1:8080"));
        assert!(is_ip_like("10.0.0.1:"));
        // Garbage address with a port still fails.
        assert!(!is_ip_like("999.1.1.1:80"));
        assert!(!is_ip_like("1.2.3.4.5:80"));
    }

    #[test]
    fn test_is_base64_like() {
        assert!(is_base64_like("SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IQ=="));
        assert!(!is_base64_like("short"));
        assert!(!is_base64_like("hello world this has spaces"));
    }
}
