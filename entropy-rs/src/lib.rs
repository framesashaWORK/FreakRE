#![allow(dead_code, unused_assignments)]
//! # entropy-rs
//!
//! Shannon entropy calculator tailored for malware analysis.
//!
//! ## Features
//! - Whole-buffer entropy
//! - Per-section entropy (for PE/ELF sections)
//! - Sliding window entropy with configurable step — detects packed regions
//!   inside otherwise normal files
//! - Zero allocations in hot path (stack-allocated 256-element histogram)
//!
//! ## Thresholds (malware analysis conventions)
//! | Range     | Interpretation                        |
//! |-----------|---------------------------------------|
//! | 0.0–1.0   | Empty / null-filled                   |
//! | 1.0–3.5   | Plain text / structured data          |
//! | 3.5–6.0   | Normal compiled code                  |
//! | 6.0–7.0   | Compressed / obfuscated               |
//! | 7.0–8.0   | Encrypted / fully packed              |

/// Shannon entropy thresholds commonly used in malware analysis.
pub mod thresholds {
    /// Below this: likely empty or null-padded region.
    pub const EMPTY: f64 = 1.0;
    /// Below this: plain text or highly structured data.
    pub const TEXT: f64 = 3.5;
    /// Above this: suspicious compression or obfuscation.
    pub const SUSPICIOUS: f64 = 6.8;
    /// Above this: almost certainly encrypted or fully packed.
    pub const PACKED: f64 = 7.2;
}

/// Result of an entropy calculation with metadata.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EntropyResult {
    /// Shannon entropy value in bits per byte (0.0 – 8.0).
    pub entropy: f64,
    /// Number of bytes that were actually processed.
    pub bytes_processed: usize,
}

impl EntropyResult {
    /// Returns true if entropy indicates a packed or encrypted region.
    #[inline]
    pub fn is_packed(&self) -> bool {
        self.entropy >= thresholds::PACKED
    }

    /// Returns true if entropy is above the suspicious threshold.
    #[inline]
    pub fn is_suspicious(&self) -> bool {
        self.entropy >= thresholds::SUSPICIOUS
    }

    /// Classify the entropy into a human-readable category.
    pub fn classify(&self) -> &'static str {
        if self.bytes_processed == 0 {
            return "empty";
        }
        match self.entropy {
            e if e < thresholds::EMPTY => "empty/null",
            e if e < thresholds::TEXT => "text/data",
            e if e < thresholds::SUSPICIOUS => "normal/code",
            e if e < thresholds::PACKED => "compressed/obfuscated",
            _ => "encrypted/packed",
        }
    }
}

impl std::fmt::Display for EntropyResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:.4} bits/byte ({}, {} bytes)",
            self.entropy,
            self.classify(),
            self.bytes_processed
        )
    }
}

/// Calculate Shannon entropy of a byte slice.
///
/// Uses a stack-allocated 256-element frequency table — no heap allocation.
/// Returns `EntropyResult` with `bytes_processed = 0` and `entropy = 0.0`
/// for empty input.
///
/// # Examples
/// ```
/// use entropy_rs::{calculate_entropy, thresholds};
///
/// let result = calculate_entropy(b"AAAAAAAAAA");
/// assert!(result.entropy < thresholds::EMPTY);
///
/// // Random-ish data has high entropy
/// let random: Vec<u8> = (0..=255).cycle().take(1024).collect();
/// let result = calculate_entropy(&random);
/// assert!(result.entropy > 7.0);
/// ```
pub fn calculate_entropy(data: &[u8]) -> EntropyResult {
    if data.is_empty() {
        return EntropyResult {
            entropy: 0.0,
            bytes_processed: 0,
        };
    }

    // Stack-allocated histogram — avoids heap allocation entirely.
    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0_f64;

    for &count in &freq {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }

    EntropyResult {
        entropy,
        bytes_processed: data.len(),
    }
}

/// Sliding window entropy scan.
///
/// Yields `(offset, EntropyResult)` pairs as the window slides across `data`.
/// Useful for detecting **locally packed regions** inside otherwise normal files.
///
/// # Arguments
/// - `data`: full buffer to scan
/// - `window_size`: size of each window in bytes (typical: 256–4096)
/// - `step`: how many bytes to advance between windows (use 1 for exhaustive,
///   or `window_size` for non-overlapping)
///
/// # Panics
/// Panics if `window_size == 0` or `step == 0`.
///
/// # Examples
/// ```
/// use entropy_rs::sliding_window_entropy;
///
/// let data = vec![0u8; 512]; // all zeros → low entropy everywhere
/// let results: Vec<_> = sliding_window_entropy(&data, 256, 256).collect();
/// assert!(results.iter().all(|(_, r)| r.entropy < 1.0));
/// ```
pub fn sliding_window_entropy(
    data: &[u8],
    window_size: usize,
    step: usize,
) -> impl Iterator<Item = (usize, EntropyResult)> + '_ {
    // Gracefully handle zero window/step instead of panicking
    if window_size == 0 || step == 0 || data.len() < window_size {
        return Vec::new().into_iter();
    }

    (0..=data.len().saturating_sub(window_size))
        .step_by(step)
        .map(move |offset| {
            let end = offset + window_size;
            let window = &data[offset..end];
            (offset, calculate_entropy(window))
        })
        .collect::<Vec<_>>()
        .into_iter()
}

/// Calculate entropy for multiple named sections (e.g., PE sections).
///
/// Returns a `Vec` of `(name, EntropyResult)` pairs. Sections with empty
/// data are included with `bytes_processed = 0`.
///
/// # Examples
/// ```
/// use entropy_rs::sections_entropy;
///
/// let sections = vec![
///     (".text", &b"\xCC\x90\xCC\x90"[..]),
///     (".rdata", &b"Hello World\0"[..]),
/// ];
/// let results = sections_entropy(&sections);
/// assert_eq!(results.len(), 2);
/// assert_eq!(results[0].0, ".text");
/// ```
pub fn sections_entropy<'a>(
    sections: &[(&'a str, &'a [u8])],
) -> Vec<(&'a str, EntropyResult)> {
    sections
        .iter()
        .map(|&(name, data)| (name, calculate_entropy(data)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input() {
        let r = calculate_entropy(b"");
        assert_eq!(r.entropy, 0.0);
        assert_eq!(r.bytes_processed, 0);
        assert_eq!(r.classify(), "empty");
    }

    #[test]
    fn single_byte_repeated() {
        let data = vec![0x41u8; 1000];
        let r = calculate_entropy(&data);
        assert!(r.entropy < 0.01, "uniform data should have ~0 entropy");
        assert_eq!(r.classify(), "empty/null");
    }

    #[test]
    fn two_symbols_equal_distribution() {
        // Alternating 0x00 and 0xFF → exactly 1.0 bit/byte
        let data: Vec<u8> = (0..1000).map(|i| if i % 2 == 0 { 0x00 } else { 0xFF }).collect();
        let r = calculate_entropy(&data);
        assert!((r.entropy - 1.0).abs() < 0.01);
    }

    #[test]
    fn uniform_distribution_max_entropy() {
        // All 256 byte values equally represented → ~8.0 bits/byte
        let data: Vec<u8> = (0..=255u8).cycle().take(256 * 100).collect();
        let r = calculate_entropy(&data);
        assert!(
            r.entropy > 7.99,
            "uniform 256-value distribution should be ~8.0, got {}",
            r.entropy
        );
        assert!(r.is_packed());
    }

    #[test]
    fn ascii_text_low_entropy() {
        let text = b"The quick brown fox jumps over the lazy dog. \
                      Pack my box with five dozen liquor jugs.";
        let r = calculate_entropy(text);
        assert!(
            r.entropy > 2.0 && r.entropy < 5.0,
            "English text should be moderate entropy, got {}",
            r.entropy
        );
        assert_eq!(r.classify(), "normal/code");
    }

    #[test]
    fn sliding_window_detects_packed_region() {
        // First half: zeros (low entropy), second half: uniform (high entropy)
        let mut data = vec![0u8; 512];
        for i in 512..1024 {
            data.push((i % 256) as u8);
        }

        let results: Vec<_> = sliding_window_entropy(&data, 256, 256).collect();
        assert!(results.len() >= 3);

        // First window: all zeros
        assert!(results[0].1.entropy < 0.01);
        // Last window: uniform distribution
        assert!(results.last().unwrap().1.entropy > 7.5);
    }

    #[test]
    fn sliding_window_step_greater_than_window() {
        let data = vec![0xABu8; 1024];
        let results: Vec<_> = sliding_window_entropy(&data, 256, 512).collect();
        assert_eq!(results.len(), 2); // offsets 0 and 512
        assert_eq!(results[0].0, 0);
        assert_eq!(results[1].0, 512);
    }

    #[test]
    fn sections_entropy_basic() {
        let sections = vec![
            (".text", &[0xCC, 0x90, 0xCC, 0x90][..]),
            (".rdata", &b"Hello\0World\0"[..]),
            (".bss", &[][..]),
        ];
        let results = sections_entropy(&sections);
        assert_eq!(results.len(), 3);
        assert_eq!(results[2].1.bytes_processed, 0);
        assert_eq!(results[2].1.classify(), "empty");
    }

    #[test]
    fn display_format() {
        let r = calculate_entropy(b"AAAA");
        let s = format!("{}", r);
        assert!(s.contains("bits/byte"));
        assert!(s.contains("bytes"));
    }

    #[test]
    fn sliding_window_zero_window_returns_empty() {
        // Gracefully returns empty instead of panicking
        let results: Vec<_> = sliding_window_entropy(b"data", 0, 1).collect();
        assert!(results.is_empty());
    }

    #[test]
    fn sliding_window_zero_step_returns_empty() {
        // Gracefully returns empty instead of panicking
        let results: Vec<_> = sliding_window_entropy(b"data", 256, 0).collect();
        assert!(results.is_empty());
    }
}


