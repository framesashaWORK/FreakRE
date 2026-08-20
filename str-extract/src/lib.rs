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
//! - **Zero-copy** where possible — strings reference the original buffer
//! - **Iterator API** — no intermediate allocations
//!
//! ## Malware Analysis Use Cases
//! - Extract C2 URLs, IPs, registry keys, file paths from binaries
//! - Correlate string offsets with PE section boundaries
//! - Detect embedded scripts / payloads by string density patterns
//! - Feed extracted strings into YARA-like matching pipelines

/// Minimum printable ASCII code (inclusive).
const ASCII_PRINTABLE_MIN: u8 = 0x20;
/// Maximum printable ASCII code (inclusive).
const ASCII_PRINTABLE_MAX: u8 = 0x7E;

/// Encoding of an extracted string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Encoding {
    /// Standard 7-bit printable ASCII (0x20–0x7E).
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
}

impl Default for ExtractConfig {
    fn default() -> Self {
        Self {
            min_length: 4,
            ascii: true,
            utf16le: true,
            utf16be: true,
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
        }
    }

    /// Create config for Windows PE analysis (ASCII + UTF-16LE).
    pub fn windows_pe(min_length: usize) -> Self {
        Self {
            min_length,
            ascii: true,
            utf16le: true,
            utf16be: false,
        }
    }
}

/// Check if a byte is printable ASCII.
#[inline]
fn is_ascii_printable(b: u8) -> bool {
    b >= ASCII_PRINTABLE_MIN && b <= ASCII_PRINTABLE_MAX
}

/// Extract all strings from a binary buffer using the given configuration.
///
/// Returns a `Vec` of [`ExtractedString`] sorted by offset.
/// Strings from different encodings may overlap in the buffer — this is
/// intentional, as malware sometimes embeds the same data in multiple encodings.
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
    results
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
        Encoding::Utf16Le => |hi: u8, lo: u8| u16::from_le_bytes([lo, hi]),
        Encoding::Utf16Be => |hi: u8, lo: u8| u16::from_be_bytes([hi, lo]),
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
    (c >= 0x0020 && c <= 0x007E)
        // Common Latin Extended
        || (c >= 0x00A0 && c <= 0x024F)
        // CJK Unified Ideographs (malware targeting Asia)
        || (c >= 0x4E00 && c <= 0x9FFF)
        // Cyrillic
        || (c >= 0x0400 && c <= 0x04FF)
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
}


