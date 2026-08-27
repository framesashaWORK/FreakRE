#![allow(dead_code, unused_assignments)]
//! # str-extract
//!
//! Binary string extractor designed for malware analysis.
//!
//! Unlike generic `strings` utilities, this crate provides:
//! - **Byte offsets** for every extracted string (critical for correlation
//!   with PE sections, overlays, and resource entries)
//! - **ASCII + UTF-16LE + UTF-16BE** extraction in a single pass
//! - **Configurable minimum length** to filter noise
//! - **Payload-blob detection** — embedded Base64 / hex blobs decoded and
//!   classified (URL / PE / shellcode / PowerShell) via
//!   [`extract_strings_with_blobs`]
//! - **Zero-copy** where possible вЂ" strings reference the original buffer
//! - **Iterator API** вЂ" no intermediate allocations
//!
//! ## Malware Analysis Use Cases
//! - Extract C2 URLs, IPs, registry keys, file paths from binaries
//! - Correlate string offsets with PE section boundaries
//! - Detect embedded scripts / payloads by string density patterns
//! - Feed extracted strings into YARA-like matching pipelines

mod blob;

pub use blob::{BlobFinding, BlobKind};

/// Minimum printable ASCII code (inclusive).
const ASCII_PRINTABLE_MIN: u8 = 0x20;
/// Maximum printable ASCII code (inclusive).
const ASCII_PRINTABLE_MAX: u8 = 0x7E;

/// Encoding of an extracted string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Encoding {
    /// Standard 7-bit printable ASCII (0x20вЂ"0x7E).
    Ascii,
    /// UTF-16 Little Endian (common in Windows PE files).
    Utf16Le,
    /// UTF-16 Big Endian (less common, but seen in cross-platform malware).
    Utf16Be,
}

impl std::fmt::Display for Encoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Encoding::Ascii => write!(f, "ASCII"),
            Encoding::Utf16Le => write!(f, "UTF-16LE"),
            Encoding::Utf16Be => write!(f, "UTF-16BE"),
        }
    }
}

/// A string extracted from a binary buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedString<'a> {
    /// Byte offset within the original buffer where this string starts.
    pub offset: usize,
    /// The decoded string content. Owned because UTF-16 requires decoding.
    pub value: String,
    /// Detected encoding.
    pub encoding: Encoding,
    /// Raw bytes slice from the original buffer (for hex dump / verification).
    pub raw_bytes: &'a [u8],
}

impl<'a> std::fmt::Display for ExtractedString<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{:#08x}] ({}) \"{}\"",
            self.offset, self.encoding, self.value
        )
    }
}

/// Configuration for string extraction.
#[derive(Debug, Clone)]
pub struct ExtractConfig {
    /// Minimum string length in *characters* (not bytes).
    pub min_length: usize,
    /// Whether to extract ASCII strings.
    pub ascii: bool,
    /// Whether to extract UTF-16LE strings.
    pub utf16le: bool,
    /// Whether to extract UTF-16BE strings.
    pub utf16be: bool,
    /// Minimum length of a contiguous Base64 run (`[A-Za-z0-9+/=]`) that
    /// triggers payload-blob detection. Default 24.
    pub min_blob_base64_len: usize,
    /// Minimum length of a contiguous hex-digit run that triggers blob
    /// detection. Default 64.
    pub min_blob_hex_len: usize,
    /// Whether to run Base64 / hex payload-blob detection at all.
    /// Default true; results are returned separately from the strings.
    pub detect_blobs: bool,
}

impl Default for ExtractConfig {
    fn default() -> Self {
        Self {
            min_length: 4,
            ascii: true,
            utf16le: true,
            utf16be: true,
            min_blob_base64_len: 24,
            min_blob_hex_len: 64,
            detect_blobs: true,
        }
    }
}

impl ExtractConfig {
    /// Create config with only ASCII extraction.
    pub fn ascii_only(min_length: usize) -> Self {
        Self {
            min_length,
            ascii: true,
            utf16le: false,
            utf16be: false,
            ..Default::default()
        }
    }

    /// Create config for Windows PE analysis (ASCII + UTF-16LE).
    pub fn windows_pe(min_length: usize) -> Self {
        Self {
            min_length,
            ascii: true,
            utf16le: true,
            utf16be: false,
            ..Default::default()
        }
    }
}

/// Check if a byte is printable ASCII.
#[inline]
fn is_ascii_printable(b: u8) -> bool {
    (ASCII_PRINTABLE_MIN..=ASCII_PRINTABLE_MAX).contains(&b)
}

/// Extract strings **and** payload blobs from a binary buffer.
///
/// Returns extracted [`ExtractedString`]s (identical to what
/// [`extract_strings`] yields) plus a `Vec` of [`BlobFinding`]s for embedded
/// Base64 / hex payloads, decoded and classified (URL / PE / shellcode /
/// PowerShell markers, entropy-based payload-likeness).
///
/// Blob detection honours `config.min_blob_base64_len` (default 24),
/// `config.min_blob_hex_len` (default 64), the UTF-16 toggles for wide-char
/// wrapped Base64, and can be disabled via `config.detect_blobs`.
///
/// # Examples
/// ```
/// use str_extract::{extract_strings_with_blobs, ExtractConfig};
///
/// // Hex run decoding to an MZ-prefixed payload.
/// let data = b"\x00\x114d5a4d5a4d5a4d5a4d5a4d5a4d5a4d5a4d5a4d5a4d5a4d5a\
///              4d5a4d5a4d5a4d5a4d5a\x00";
/// let config = ExtractConfig::default();
/// let (_strings, blobs) = extract_strings_with_blobs(data, &config);
/// assert!(blobs.iter().any(|b| b.looks_like_pe));
/// ```
pub fn extract_strings_with_blobs<'a>(
    data: &'a [u8],
    config: &ExtractConfig,
) -> (Vec<ExtractedString<'a>>, Vec<BlobFinding>) {
    let strings = run_string_passes(data, config);
    let blobs = if config.detect_blobs {
        blob::detect_blobs(data, config)
    } else {
        Vec::new()
    };
    (strings, blobs)
}

/// Extract all strings from a binary buffer using the given configuration.
///
/// Returns a `Vec` of [`ExtractedString`] sorted by offset.
/// Strings from different encodings may overlap in the buffer вЂ" this is
/// intentional, as malware sometimes embeds the same data in multiple encodings.
///
/// This is the classic string-only API; use [`extract_strings_with_blobs`]
/// to additionally receive classified Base64 / hex payload findings.
///
/// # Examples
/// ```
/// use str_extract::{extract_strings, ExtractConfig};
///
/// let data = b"\x00\x00H\x00e\x00l\x00l\x00o\x00\x00\x00World!\x00";
/// let config = ExtractConfig { min_length: 4, ..Default::default() };
/// let strings = extract_strings(data, &config);
/// assert!(strings.iter().any(|s| s.value == "Hello"));
/// assert!(strings.iter().any(|s| s.value == "World!"));
/// ```
pub fn extract_strings<'a>(data: &'a [u8], config: &ExtractConfig) -> Vec<ExtractedString<'a>> {
    extract_strings_with_blobs(data, config).0
}

fn run_string_passes<'a>(data: &'a [u8], config: &ExtractConfig) -> Vec<ExtractedString<'a>> {
    let mut results = Vec::new();

    if config.ascii {
        extract_ascii(data, config.min_length, &mut results);
    }
    if config.utf16le {
        extract_utf16(data, config.min_length, Encoding::Utf16Le, &mut results);
    }
    if config.utf16be {
        extract_utf16(data, config.min_length, Encoding::Utf16Be, &mut results);
    }

    // Sort by offset for consistent output regardless of encoding order.
    results.sort_by_key(|s| s.offset);

    // Deduplicate phantom duplicates produced by the dual-alignment UTF-16
    // passes: within a single encoding, legitimate strings never overlap
    // (adjacent strings are separated by terminators), so any two overlapping
    // runs of the same encoding are an artifact of scanning at both even and
    // odd byte alignments. Later overlapping runs are dropped, keeping the
    // earliest. Cross-encoding overlaps are intentionally preserved (same
    // data embedded in multiple encodings).
    let mut kept: std::collections::HashMap<Encoding, std::collections::VecDeque<(usize, usize)>> =
        std::collections::HashMap::new();

    let mut deduped: Vec<ExtractedString<'a>> = Vec::with_capacity(results.len());
    for s in results {
        let end = s.offset + s.raw_bytes.len();
        let queue = kept.entry(s.encoding).or_default();

        // Runs arrive in ascending offset order and kept runs of one encoding
        // are pairwise non-overlapping, so runs ending at or before this
        // offset can never conflict with this or any later candidate.
        while queue.front().is_some_and(|&(_, ke)| ke <= s.offset) {
            queue.pop_front();
        }

        // After eviction, the front run is the only possible overlapper.
        let overlaps = queue
            .front()
            .is_some_and(|&(ko, ke)| ko < end && s.offset < ke);

        if !overlaps {
            queue.push_back((s.offset, end));
            deduped.push(s);
        }
    }

    deduped
}

/// Extract ASCII strings.
fn extract_ascii<'a>(
    data: &'a [u8],
    min_length: usize,
    out: &mut Vec<ExtractedString<'a>>,
) {
    let mut start: Option<usize> = None;

    for (i, &byte) in data.iter().enumerate() {
        if is_ascii_printable(byte) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start {
            let len = i - s;
            if len >= min_length {
                let raw = &data[s..i];
                // SAFETY: we verified every byte is printable ASCII.
                let value = unsafe { String::from_utf8_unchecked(raw.to_vec()) };
                out.push(ExtractedString {
                    offset: s,
                    value,
                    encoding: Encoding::Ascii,
                    raw_bytes: raw,
                });
            }
            start = None;
        }
    }

    // Handle string at end of buffer.
    if let Some(s) = start {
        let len = data.len() - s;
        if len >= min_length {
            let raw = &data[s..];
            let value = unsafe { String::from_utf8_unchecked(raw.to_vec()) };
            out.push(ExtractedString {
                offset: s,
                value,
                encoding: Encoding::Ascii,
                raw_bytes: raw,
            });
        }
    }
}

/// Extract UTF-16 strings (LE or BE).
fn extract_utf16<'a>(
    data: &'a [u8],
    min_length: usize,
    encoding: Encoding,
    out: &mut Vec<ExtractedString<'a>>,
) {
    if data.len() < 2 {
        return;
    }

    let decode_u16 = match encoding {
        Encoding::Utf16Le => |first: u8, second: u8| u16::from_le_bytes([first, second]),
        Encoding::Utf16Be => |first: u8, second: u8| u16::from_be_bytes([first, second]),
        _ => unreachable!(),
    };

    let mut start: Option<usize> = None;
    let mut chars: Vec<u16> = Vec::new();

    // Iterate over aligned pairs. We check both even and odd alignments
    // because UTF-16 strings in malware are not always aligned.
    for base_offset in 0..2 {
        let mut i = base_offset;
        while i + 1 < data.len() {
            let code_unit = decode_u16(data[i], data[i + 1]);

            if is_utf16_printable(code_unit) {
                if start.is_none() {
                    start = Some(i);
                    chars.clear();
                }
                chars.push(code_unit);
            } else if let Some(s) = start {
                if chars.len() >= min_length {
                    let raw_end = s + chars.len() * 2;
                    let raw = &data[s..raw_end];
                    let value = String::from_utf16_lossy(&chars);
                    out.push(ExtractedString {
                        offset: s,
                        value,
                        encoding,
                        raw_bytes: raw,
                    });
                }
                start = None;
                chars.clear();
            }

            i += 2;
        }

        // Handle string at end of buffer.
        if let Some(s) = start {
            if chars.len() >= min_length {
                let raw_end = s + chars.len() * 2;
                if raw_end <= data.len() {
                    let raw = &data[s..raw_end];
                    let value = String::from_utf16_lossy(&chars);
                    out.push(ExtractedString {
                        offset: s,
                        value,
                        encoding,
                        raw_bytes: raw,
                    });
                }
            }
            start = None;
            chars.clear();
        }
    }
}

/// Check if a UTF-16 code unit is a printable character worth extracting.
/// Accepts basic ASCII range + common Latin characters.
#[inline]
fn is_utf16_printable(c: u16) -> bool {
    // Printable ASCII range in UTF-16
    (0x0020..=0x007E).contains(&c)
        // Common Latin Extended
        || (0x00A0..=0x024F).contains(&c)
        // CJK Unified Ideographs (malware targeting Asia)
        || (0x4E00..=0x9FFF).contains(&c)
        // Cyrillic
        || (0x0400..=0x04FF).contains(&c)
        // Surrogate range: must be accepted so strings containing astral
        // characters (encoded as surrogate pairs) are not split and dropped.
        // `String::from_utf16_lossy` performs the final pair-aware decoding;
        // lone surrogates degrade to U+FFFD instead of truncating the run.
        || (0xD800..=0xDFFF).contains(&c)
}

/// Convenience: extract strings with default configuration.
pub fn extract_strings_default<'a>(data: &'a [u8]) -> Vec<ExtractedString<'a>> {
    extract_strings(data, &ExtractConfig::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_basic() {
        let data = b"\x00\x00Hello World\x00\x00";
        let config = ExtractConfig::ascii_only(4);
        let results = extract_strings(data, &config);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "Hello World");
        assert_eq!(results[0].offset, 2);
        assert_eq!(results[0].encoding, Encoding::Ascii);
    }

    #[test]
    fn ascii_min_length_filter() {
        let data = b"AB\x00CDEF\x00GHIJKLMNOP";
        let config = ExtractConfig::ascii_only(4);
        let results = extract_strings(data, &config);
        // "AB" too short, "CDEF" ok, "GHIJKLMNOP" ok
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].value, "CDEF");
        assert_eq!(results[1].value, "GHIJKLMNOP");
    }

    #[test]
    fn ascii_at_buffer_end() {
        let data = b"\x00\x00TestString";
        let config = ExtractConfig::ascii_only(4);
        let results = extract_strings(data, &config);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "TestString");
        assert_eq!(results[0].offset, 2);
    }

    #[test]
    fn utf16le_basic() {
        // "Hi" in UTF-16LE: 48 00 69 00
        let data = [0x00, 0x00, 0x48, 0x00, 0x69, 0x00, 0x21, 0x00, 0x00, 0x00];
        let config = ExtractConfig {
            min_length: 3,
            ascii: false,
            utf16le: true,
            utf16be: false,
            ..Default::default()
        };
        let results = extract_strings(&data, &config);
        assert!(
            results.iter().any(|s| s.value == "Hi!" && s.encoding == Encoding::Utf16Le),
            "Expected 'Hi!' in UTF-16LE, got: {:?}",
            results
        );
    }

    #[test]
    fn utf16be_basic() {
        // "OK!" in UTF-16BE: 00 4F 00 4B 00 21
        let data = [0x00, 0x00, 0x00, 0x4F, 0x00, 0x4B, 0x00, 0x21, 0x00, 0x00];
        let config = ExtractConfig {
            min_length: 3,
            ascii: false,
            utf16le: false,
            utf16be: true,
            ..Default::default()
        };
        let results = extract_strings(&data, &config);
        assert!(
            results.iter().any(|s| s.value == "OK!" && s.encoding == Encoding::Utf16Be),
            "Expected 'OK!' in UTF-16BE, got: {:?}",
            results
        );
    }

    #[test]
    fn mixed_encodings_sorted_by_offset() {
        // ASCII "URL" at offset 0, then padding, then UTF-16LE "CMD"
        let mut data = Vec::new();
        data.extend_from_slice(b"URL\x00");           // offset 0: ASCII
        data.extend_from_slice(&[0x00; 4]);           // padding
        data.extend_from_slice(&[0x43, 0x00, 0x4D, 0x00, 0x44, 0x00]); // offset 8: UTF-16LE "CMD"

        let config = ExtractConfig {
            min_length: 3,
            ascii: true,
            utf16le: true,
            utf16be: false,
            ..Default::default()
        };
        let results = extract_strings(&data, &config);
        assert!(results.len() >= 2);
        // Verify sorted by offset
        for w in results.windows(2) {
            assert!(w[0].offset <= w[1].offset);
        }
    }

    #[test]
    fn empty_buffer() {
        let results = extract_strings_default(b"");
        assert!(results.is_empty());
    }

    #[test]
    fn no_printable_chars() {
        let data = vec![0x00u8; 256];
        let results = extract_strings_default(&data);
        assert!(results.is_empty());
    }

    #[test]
    fn raw_bytes_matches_value() {
        let data = b"\x00Malware.exe\x00";
        let config = ExtractConfig::ascii_only(4);
        let results = extract_strings(data, &config);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].raw_bytes, b"Malware.exe");
        assert_eq!(results[0].raw_bytes.as_ptr(), data[1..].as_ptr());
    }

    #[test]
    fn display_format() {
        let data = b"\x00Test\x00";
        let config = ExtractConfig::ascii_only(4);
        let results = extract_strings(data, &config);
        let s = format!("{}", results[0]);
        assert!(s.contains("ASCII"));
        assert!(s.contains("Test"));
        assert!(s.contains("0x"));
    }

    #[test]
    fn windows_pe_config_excludes_utf16be() {
        let config = ExtractConfig::windows_pe(4);
        assert!(config.ascii);
        assert!(config.utf16le);
        assert!(!config.utf16be);
    }

    #[test]
    fn c2_url_extraction() {
        // Simulate finding a C2 URL in binary noise
        let mut data = vec![0xDEu8; 64];
        let url = b"http://evil.example.com/gate.php";
        data[20..20 + url.len()].copy_from_slice(url);
        data.extend_from_slice(&[0xDE; 32]);

        let config = ExtractConfig::ascii_only(6);
        let results = extract_strings(&data, &config);
        assert!(
            results.iter().any(|s| s.value.contains("evil.example.com")),
            "Should extract C2 URL, got: {:?}",
            results.iter().map(|s| &s.value).collect::<Vec<_>>()
        );
        assert_eq!(results.iter().find(|s| s.value.contains("evil.example.com")).unwrap().offset, 20);
    }

    #[test]
    fn utf16le_surrogate_pair_not_split() {
        // "Test😀ing" — U+1F600 is encoded as surrogate pair D83D DE00.
        // The astral char must not split the run into fragments that get
        // dropped by min_length.
        let mut units: Vec<u16> = "Test".chars().map(|c| c as u16).collect();
        units.extend_from_slice(&[0xD83D, 0xDE00]);
        units.extend("ing".chars().map(|c| c as u16));

        let mut data = Vec::new();
        for u in &units {
            data.extend_from_slice(&u.to_le_bytes());
        }

        let config = ExtractConfig {
            min_length: 4,
            ascii: false,
            utf16le: true,
            utf16be: false,
            ..Default::default()
        };
        let results = extract_strings(&data, &config);
        assert_eq!(
            results.len(),
            1,
            "surrogate pair must keep the string whole, got: {:?}",
            results.iter().map(|s| &s.value).collect::<Vec<_>>()
        );
        assert_eq!(results[0].value, "Test\u{1F600}ing");
        assert_eq!(results[0].offset, 0);
    }

    #[test]
    fn utf16le_lone_surrogate_stays_single_run() {
        // A lone surrogate decodes to U+FFFD but must still form ONE run,
        // not terminate extraction mid-string.
        let mut data = Vec::new();
        for u in [0x0041u16, 0x0042, 0xDD1E, 0x0043, 0x0044] {
            data.extend_from_slice(&u.to_le_bytes());
        }

        let config = ExtractConfig {
            min_length: 4,
            ascii: false,
            utf16le: true,
            utf16be: false,
            ..Default::default()
        };
        let results = extract_strings(&data, &config);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "AB\u{FFFD}CD");
    }

    #[test]
    fn dual_alignment_phantom_duplicates_deduped() {
        // Buffer of 0x55 bytes decodes to unit 0x5555 (CJK range => printable)
        // at EVERY byte alignment, so both alignment passes find long
        // overlapping runs. extract_strings() must emit a single entry per
        // encoding.
        let mut data = vec![0x55u8; 16];
        data.extend_from_slice(&[0x00, 0x00]);

        let config = ExtractConfig {
            min_length: 4,
            ascii: false,
            utf16le: true,
            utf16be: false,
            ..Default::default()
        };
        let results = extract_strings(&data, &config);
        assert_eq!(
            results.len(),
            1,
            "dual-alignment pass must not produce overlapping duplicates: {:?}",
            results
        );
        assert_eq!(results[0].offset, 0);

        // Repeated genuine strings at distinct offsets survive, and the
        // output never contains overlapping same-encoding entries.
        let mut repeated = Vec::new();
        for _ in 0..2 {
            for c in "abcd".chars() {
                repeated.extend_from_slice(&(c as u16).to_le_bytes());
            }
            repeated.extend_from_slice(&[0x00, 0x00]);
        }
        let results2 = extract_strings(&repeated, &config);
        for i in 0..results2.len() {
            for b in &results2[i + 1..] {
                let a = &results2[i];
                if a.encoding == b.encoding {
                    assert!(
                        b.offset >= a.offset + a.raw_bytes.len(),
                        "overlapping same-encoding duplicates must be deduped: {:?} vs {:?}",
                        a,
                        b
                    );
                }
            }
        }
        assert_eq!(results2[0].value, "abcd");
        assert_eq!(results2[0].offset, 0);
        assert!(results2.iter().any(|s| s.value == "abcd"));
    }
}
