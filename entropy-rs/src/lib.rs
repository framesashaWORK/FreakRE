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
//! | 3.5–6.8   | Normal compiled code                  |
//! | 6.8–7.2   | Compressed / obfuscated               |
//! | 7.2–8.0   | Encrypted / fully packed              |

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

    /// Classify entropy with awareness of the section's purpose.
    ///
    /// Exception/import/relocation tables are structurally dense (sorted
    /// runtime-function entries, packed RVA pairs) and routinely sit in the
    /// 6.5–7.2 range in fully legitimate binaries. Labeling them
    /// "compressed/obfuscated" is noise; they get a dedicated label instead.
    pub fn classify_section(&self, section_name: &str) -> &'static str {
        let n = section_name.trim_start_matches('.').trim_start_matches('_');
        let metadata = matches!(
            n,
            "pdata" | "xdata" | "idata" | "edata" | "reloc" | "gfids" | "rdata"
        ) || n.starts_with("debug");
        if metadata && self.entropy < thresholds::PACKED {
            "metadata/dense"
        } else {
            self.classify()
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
#[inline]
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

    EntropyResult {
        entropy: entropy_from_histogram(&freq, data.len()),
        bytes_processed: data.len(),
    }
}

/// Shannon entropy (bits/byte) from a prebuilt 256-bucket histogram.
///
/// Shared by [`calculate_entropy`] and the batched sliding-window path so
/// both perform the summation in exactly the same order and produce
/// bit-identical results for identical histograms.
#[inline]
fn entropy_from_histogram(freq: &[u64; 256], byte_len: usize) -> f64 {
    let len = byte_len as f64;
    let mut entropy = 0.0_f64;

    for &count in freq.iter() {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }

    entropy
}

/// Sliding window entropy scan.
///
/// Yields `(offset, EntropyResult)` pairs as the window slides across `data`.
/// Useful for detecting **locally packed regions** inside otherwise normal files.
///
/// The returned iterator is fully lazy: each window's entropy is computed
/// on `next()`, so no result vector is materialized up front and iteration
/// can be stopped early (e.g. via `take`) without scanning the whole buffer.
///
/// # Arguments
/// - `data`: full buffer to scan
/// - `window_size`: size of each window in bytes (typical: 256–4096)
/// - `step`: how many bytes to advance between windows (use 1 for exhaustive,
///   or `window_size` for non-overlapping)
///
/// If `window_size == 0`, `step == 0`, or `data` is shorter than one window,
/// the iterator is empty instead of panicking.
///
/// The final window is always anchored at the buffer end
/// (`offset = data.len() - window_size`): when the stride does not land
/// exactly on that offset, one extra tail window is emitted so every byte of
/// the buffer is covered by a full-size window, without duplicating any
/// stride-aligned window that already reaches the end.
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
    let valid = window_size > 0 && step > 0 && data.len() >= window_size;
    let last_start = if valid { data.len() - window_size } else { 0 };
    let stride = if step == 0 { 1 } else { step };

    // Stride-aligned start offsets: 0, stride, 2*stride, ... <= last_start.
    let aligned = (0..last_start + 1).step_by(stride);

    // When the stride skips over the final possible offset, append one extra
    // window anchored exactly at the buffer end. It is strictly greater than
    // the last aligned offset, so no window is duplicated.
    let needs_tail = valid && last_start % stride != 0;
    let offsets = aligned
        .chain(std::iter::once(last_start).filter(move |_| needs_tail))
        .filter(move |_| valid);

    // Entropy is computed lazily per yielded offset.
    offsets.map(move |offset| {
        let window_end = offset + window_size;
        (offset, calculate_entropy(&data[offset..window_end]))
    })
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

/// Batched sliding window entropy scan — computes **all** windows in a
/// single O(n) pass over `data` using a running histogram.
///
/// Equivalent to collecting [`sliding_window_entropy`], but instead of
/// re-counting every window's bytes (O(n · window_size)), each successive
/// window is derived from the previous one by removing the bytes that left
/// the window and adding the bytes that entered it. Because histograms stay
/// exact integer counts and entropy is summed through the same shared
/// routine in the same bucket order, every emitted [`EntropyResult`] is
/// bit-identical to the per-window recomputation.
///
/// Window offsets follow exactly the same layout as
/// [`sliding_window_entropy`] (stride-aligned starts plus an optional tail
/// window anchored at the buffer end), and invalid parameters (`window_size
/// == 0`, `step == 0`, buffer shorter than one window) yield an empty vector,
/// matching the lazy iterator's behavior.
///
/// # Examples
/// ```
/// use entropy_rs::{sliding_window_entropy, sliding_window_entropy_batched};
///
/// let data: Vec<u8> = (0..=255u8).cycle().take(2048).collect();
/// let lazy: Vec<_> = sliding_window_entropy(&data, 256, 128).collect();
/// let batched = sliding_window_entropy_batched(&data, 256, 128);
/// assert_eq!(lazy.len(), batched.len());
/// for ((lo, lr), (bo, br)) in lazy.into_iter().zip(batched) {
///     assert_eq!(lo, bo);
///     assert_eq!(lr.entropy.to_bits(), br.entropy.to_bits());
/// }
/// ```
pub fn sliding_window_entropy_batched(
    data: &[u8],
    window_size: usize,
    step: usize,
) -> Vec<(usize, EntropyResult)> {
    let valid = window_size > 0 && step > 0 && data.len() >= window_size;
    if !valid {
        return Vec::new();
    }

    let last_start = data.len() - window_size;
    let stride = step;

    // Same offset layout as the lazy iterator: stride-aligned starts plus a
    // single tail window anchored at the buffer end when the stride skips it.
    let mut offsets: Vec<usize> = (0..=last_start).step_by(stride).collect();
    if !last_start.is_multiple_of(stride) {
        offsets.push(last_start);
    }

    // Initial histogram for the first window [0, window_size).
    let mut freq = [0u64; 256];
    for &byte in &data[..window_size] {
        freq[byte as usize] += 1;
    }

    let mut results = Vec::with_capacity(offsets.len());
    let mut prev_start = 0usize;
    for &offset in &offsets {
        let delta = offset - prev_start;
        if delta > 0 {
            if delta < window_size {
                // Overlapping windows: slide the running histogram forward
                // by `delta` — evict the bytes leaving on the left, admit
                // the ones entering on the right.
                let out = &data[prev_start..offset];
                let inp = &data[prev_start + window_size..offset + window_size];
                for &byte in out {
                    freq[byte as usize] -= 1;
                }
                for &byte in inp {
                    freq[byte as usize] += 1;
                }
            } else {
                // Non-overlapping or disjoint windows (`step >= window`):
                // bytes between the old window's right edge and the new
                // window's left edge were never counted, so a pure slide is
                // impossible — recount from scratch. Counts stay exact, so
                // results remain identical to per-window recomputation.
                freq = [0u64; 256];
                for &byte in &data[offset..offset + window_size] {
                    freq[byte as usize] += 1;
                }
            }
            prev_start = offset;
        }
        results.push((
            offset,
            EntropyResult {
                entropy: entropy_from_histogram(&freq, window_size),
                bytes_processed: window_size,
            },
        ));
    }

    results
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
        // Aligned offsets 0 and 512, plus a tail window anchored at the
        // buffer end so bytes 768..1024 are covered too.
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].0, 0);
        assert_eq!(results[1].0, 512);
        assert_eq!(results.last().unwrap().0, 768); // data.len() - window_size
    }

    #[test]
    fn sliding_window_covers_buffer_tail_when_step_does_not_divide() {
        let mut data = vec![0u8; 744]; // low-entropy head
        data.extend(std::iter::repeat(0x5Au8).take(256)); // distinct constant tail
        let window = 256;
        let step = 300;

        let results: Vec<_> = sliding_window_entropy(&data, window, step).collect();
        let offsets: Vec<usize> = results.iter().map(|&(o, _)| o).collect();

        // Final window is anchored exactly at the buffer end.
        assert_eq!(*offsets.last().unwrap(), data.len() - window);

        // Strictly increasing ⇒ every window appears at most once.
        assert!(offsets.windows(2).all(|w| w[0] < w[1]));

        // The tail window actually processes a full window of bytes.
        assert_eq!(results.last().unwrap().1.bytes_processed, window);
    }

    #[test]
    fn sliding_window_tail_smaller_than_stride_still_covered() {
        // Buffer only slightly longer than one window: the aligned window at
        // offset 0 does not reach the end, so a second window must appear.
        let data = vec![0x41u8; 300];
        let results: Vec<_> = sliding_window_entropy(&data, 256, 500).collect();
        let offsets: Vec<usize> = results.iter().map(|&(o, _)| o).collect();
        assert_eq!(offsets, vec![0, 44]); // 44 = 300 - 256
    }

    #[test]
    fn sliding_window_exact_division_has_no_extra_tail_window() {
        let data = vec![0u8; 1024];
        let results: Vec<_> = sliding_window_entropy(&data, 256, 128).collect();
        let offsets: Vec<usize> = results.iter().map(|&(o, _)| o).collect();
        assert_eq!(offsets.len(), (1024 - 256) / 128 + 1);
        assert_eq!(*offsets.last().unwrap(), 1024 - 256);
        assert!(offsets.windows(2).all(|w| w[0] < w[1]), "no duplicated windows");
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

    #[test]
    fn sliding_window_is_lazy_and_supports_early_stop() {
        // A large buffer with an exhaustive step would be expensive if the
        // whole result were collected eagerly; taking one item must not
        // require scanning every window.
        let data: Vec<u8> = (0..=255u8).cycle().take(1 << 20).collect();
        let mut iter = sliding_window_entropy(&data, 4096, 1);
        assert_eq!(iter.next().map(|(offset, _)| offset), Some(0));
        drop(iter);
    }

    #[test]
    fn sliding_window_data_shorter_than_window_returns_empty() {
        let results: Vec<_> = sliding_window_entropy(b"tiny", 16, 1).collect();
        assert!(results.is_empty());
    }

    // ── Batched vs lazy equivalence ──────────────────────────────────

    /// Deterministic xorshift64 pseudo-random buffer (no external deps).
    fn deterministic_buffer(len: usize) -> Vec<u8> {
        let mut x: u64 = 0x243F_6A88_85A3_08D3;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 32) as u8
            })
            .collect()
    }

    #[test]
    fn batched_matches_lazy_bit_exact() {
        let data = deterministic_buffer(8192);
        let cases: &[(usize, usize)] = &[
            (256, 256),   // non-overlapping
            (256, 128),   // overlapping, exact division
            (256, 1),     // exhaustive
            (300, 500),   // step > window with tail
            (256, 300),   // stride skips the tail offset
            (1024, 512),  // large window, tail present
            (8192, 4096), // single full-buffer window + tail
        ];
        for &(window, step) in cases {
            let lazy: Vec<_> = sliding_window_entropy(&data, window, step).collect();
            let batched = sliding_window_entropy_batched(&data, window, step);
            assert_eq!(lazy.len(), batched.len(), "w={} s={}", window, step);
            for ((lo, lr), (bo, br)) in lazy.into_iter().zip(batched) {
                assert_eq!(lo, bo, "offset mismatch w={} s={}", window, step);
                assert_eq!(
                    lr.entropy.to_bits(),
                    br.entropy.to_bits(),
                    "entropy bits differ w={} s={} off={}",
                    window,
                    step,
                    bo
                );
                assert_eq!(lr.bytes_processed, br.bytes_processed);
            }
        }
    }

    #[test]
    fn batched_matches_lazy_on_mixed_density_data() {
        // Low/high entropy halves plus a repeating pattern: exercises both
        // histogram growth and decay through the running-window path.
        let mut data = vec![0u8; 1024];
        data.extend(deterministic_buffer(1024));
        data.extend((0..1024).map(|i| (i % 7) as u8));

        for &(window, step) in &[(128usize, 64usize), (512, 333)] {
            let lazy: Vec<_> = sliding_window_entropy(&data, window, step).collect();
            let batched = sliding_window_entropy_batched(&data, window, step);
            assert_eq!(lazy.len(), batched.len());
            for ((lo, lr), (bo, br)) in lazy.into_iter().zip(batched) {
                assert_eq!(lo, bo);
                assert_eq!(lr.entropy.to_bits(), br.entropy.to_bits());
                assert_eq!(lr.bytes_processed, br.bytes_processed);
            }
        }
    }

    #[test]
    fn batched_invalid_params_match_lazy() {
        let data = deterministic_buffer(512);
        // Truly invalid combos → both empty.
        for &(window, step) in &[(0usize, 1usize), (256, 0), (513, 1)] {
            let lazy: Vec<_> = sliding_window_entropy(&data, window, step).collect();
            let batched = sliding_window_entropy_batched(&data, window, step);
            assert!(lazy.is_empty());
            assert!(batched.is_empty(), "w={} s={}", window, step);
        }
        // Tiny window on a large buffer is valid — parity must still hold.
        let lazy: Vec<_> = sliding_window_entropy(&data, 16, 2).collect();
        let batched = sliding_window_entropy_batched(&data, 16, 2);
        assert!(!lazy.is_empty());
        assert_eq!(lazy.len(), batched.len());
        for ((lo, lr), (bo, br)) in lazy.into_iter().zip(batched) {
            assert_eq!(lo, bo);
            assert_eq!(lr.entropy.to_bits(), br.entropy.to_bits());
        }
    }

    #[test]
    fn batched_single_window_no_slide() {
        // Buffer exactly one window long: one result, no sliding occurred.
        let data = deterministic_buffer(256);
        let batched = sliding_window_entropy_batched(&data, 256, 128);
        assert_eq!(batched.len(), 1);
        assert_eq!(batched[0].0, 0);
        assert_eq!(
            batched[0].1.entropy.to_bits(),
            calculate_entropy(&data).entropy.to_bits()
        );
    }
}


