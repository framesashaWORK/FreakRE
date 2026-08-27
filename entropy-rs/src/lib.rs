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
/// Stride-aligned window start offsets plus an optional tail window anchored
/// at the buffer end — the shared layout used by both
/// [`sliding_window_entropy_batched`] and [`classify_windows`].
///
/// Mirrors the offsets emitted by the lazy [`sliding_window_entropy`]
/// iterator. Callers must guarantee
/// `window_size > 0 && step > 0 && data_len >= window_size`.
#[inline]
fn window_offsets(data_len: usize, window_size: usize, step: usize) -> Vec<usize> {
    let last_start = data_len - window_size;

    // Stride-aligned starts plus a single tail window when the stride skips
    // the final possible offset.
    let mut offsets: Vec<usize> = (0..=last_start).step_by(step).collect();
    if !last_start.is_multiple_of(step) {
        offsets.push(last_start);
    }
    offsets
}

pub fn sliding_window_entropy_batched(
    data: &[u8],
    window_size: usize,
    step: usize,
) -> Vec<(usize, EntropyResult)> {
    let valid = window_size > 0 && step > 0 && data.len() >= window_size;
    if !valid {
        return Vec::new();
    }

    let offsets = window_offsets(data.len(), window_size, step);

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

// ── Statistical region classification ────────────────────────────
//
// Entropy alone cannot separate encrypted buffers from compressed ones — both
// sit near 8 bits/byte. The chi-square goodness-of-fit statistic against a
// uniform byte distribution closes that gap: cryptographic output is
// *statistically uniform* (chi² ≈ degrees of freedom), while compressed
// streams are merely *high entropy* — Huffman / LZ77 symbol coding skews the
// byte histogram well above uniformity even though it looks random to an
// entropy meter.

/// Byte occurrence histogram over all 256 possible byte values.
///
/// Shared counting primitive used by [`calculate_entropy`],
/// [`chi_square_uniform`] and [`region_stats`]. Zero allocations.
///
/// # Examples
/// ```
/// use entropy_rs::byte_histogram;
///
/// let hist = byte_histogram(b"AAB");
/// assert_eq!(hist[b'A' as usize], 2);
/// assert_eq!(hist[b'B' as usize], 1);
/// ```
pub fn byte_histogram(data: &[u8]) -> [u64; 256] {
    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }
    freq
}

/// Degrees of freedom of the chi-square test over a 256-bucket byte
/// histogram (`k - 1 = 255`). Dividing the raw statistic by this value yields
/// the normalized score compared against [`classify_thresholds::ENCRYPTED_CHI_NORM_MAX`].
pub const CHI_SQUARE_DF: f64 = 255.0;

/// Pearson chi-square goodness-of-fit statistic of `data`'s byte histogram
/// against a **uniform** distribution (expected count `len / 256` per bucket).
///
/// Returns `0.0` for empty input. Under a true uniform source (cryptographic
/// PRNG, strong encryption) the statistic is distributed approximately
/// chi-square with 255 degrees of freedom, i.e. expectation ≈ 255 and standard
/// deviation ≈ √510 ≈ 22.6. Anything with heavy symbol skew (text, structured
/// binaries, compressed streams) produces values far above that band.
///
/// # Examples
/// ```
/// use entropy_rs::{chi_square_uniform, CHI_SQUARE_DF};
///
/// // Perfectly uniform buffer → statistic exactly 0.
/// let uniform: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
/// assert_eq!(chi_square_uniform(&uniform), 0.0);
///
/// // Single repeated byte → astronomically skewed.
/// assert!(chi_square_uniform(&[0x41; 256]) > CHI_SQUARE_DF * 10.0);
/// ```
pub fn chi_square_uniform(data: &[u8]) -> f64 {
    let hist = byte_histogram(data);
    chi_square_from_histogram(&hist, data.len())
}

/// [`chi_square_uniform`] normalized by its degrees of freedom (255).
///
/// Interpretation for a window under the null hypothesis "bytes are uniform":
/// expectation ≈ 1.0 regardless of window size, standard deviation ≈ √(2/255)
/// ≈ 0.09. Values ≤ ~1.2 indicate statistical uniformity (encryption-like);
/// compressed and textual data land far higher because their byte histograms
/// are skewed.
///
/// # Examples
/// ```
/// use entropy_rs::{chi_square_uniform_normalized, classify_thresholds};
///
/// let uniform: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
/// assert!(chi_square_uniform_normalized(&uniform) <= classify_thresholds::ENCRYPTED_CHI_NORM_MAX);
/// ```
#[inline]
pub fn chi_square_uniform_normalized(data: &[u8]) -> f64 {
    chi_square_uniform(data) / CHI_SQUARE_DF
}

/// Chi-square statistic computed from a prebuilt 256-bucket histogram.
///
/// Mirrors [`entropy_from_histogram`]: shared by the single-shot and the
/// sliding-window paths so identical histograms yield bit-identical scores.
#[inline]
fn chi_square_from_histogram(freq: &[u64; 256], byte_len: usize) -> f64 {
    if byte_len == 0 {
        return 0.0;
    }
    let expected = byte_len as f64 / 256.0;

    let mut chi = 0.0_f64;
    for &count in freq.iter() {
        let delta = count as f64 - expected;
        chi += delta * delta / expected;
    }
    chi
}

/// Thresholds used by [`classify_region`] / [`classify_windows`].
///
/// Tuned empirically on synthetic corpora (see the crate test-suite):
/// repeated-byte padding, lorem-ipsum English prose, gzip-deflated English
/// text and xorshift64 pseudo-AES output.
pub mod classify_thresholds {
    /// Entropy below this (bits/byte) means padding / repetition — decided
    /// first so fully printable filler like `"AAAA…"` still classifies as
    /// low-entropy rather than plain text.
    pub const LOW_ENTROPY_MAX: f64 = 3.5;

    /// A window with at least this fraction of printable ASCII bytes
    /// (graphics + space + tab/CR/LF) is considered text. English prose
    /// measures ≈ 0.95–0.99; binary regions almost never reach 0.90.
    pub const PLAIN_PRINTABLE_MIN: f32 = 0.90;

    /// Normalized chi-square at or below this value indicates a statistically
    /// uniform byte distribution. True uniform sources measure ≈ 1.00 ± 0.09
    /// (1σ) for ≥4 KiB windows; deflate/Huffman output measures noticeably
    /// higher because coding skews the histogram. 1.20 sits >2σ above the
    /// encrypted band while staying below every measured compressed sample.
    pub const ENCRYPTED_CHI_NORM_MAX: f64 = 1.20;

    /// Minimum entropy (bits/byte) for the encryption verdict — guards the
    /// chi-square arm against low-entropy data that happens to look uniform.
    /// Strong ciphers / PRNG measure ≈ 7.99.
    pub const ENCRYPTED_ENTROPY_MIN: f64 = 7.0;

    /// Advisory lower entropy bound for the compressed band. Deflate streams
    /// of natural text measure ≈ 7.5–7.9 bits/byte. Windows above this that
    /// fail the uniformity test are compression-like with high confidence.
    pub const COMPRESSED_ENTROPY_MIN: f64 = 6.5;
}

/// Statistical fingerprint of a byte window, combining the three signals the
/// classifier needs to tell encrypted, compressed and textual data apart:
///
/// - `entropy` — Shannon entropy in bits/byte (identical value, bit-for-bit,
///   to [`EntropyResult::entropy`] for the same window).
/// - `chi_square_norm` — [`chi_square_uniform`] divided by df=255; ≈ 1.0 for
///   cryptographically uniform data, far larger for any skewed source.
/// - `printable_ratio` — fraction of bytes that are printable ASCII
///   (graphic + space + tab/CR/LF), as `f32`.
///
/// Empty input yields all-zero fields.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RegionStats {
    /// Shannon entropy in bits per byte (0.0 – 8.0).
    pub entropy: f64,
    /// Chi-square goodness-of-fit vs uniform, normalized by df=255.
    pub chi_square_norm: f64,
    /// Fraction of printable-ASCII bytes (0.0 – 1.0).
    pub printable_ratio: f32,
}

/// Compute [`RegionStats`] for `data` in a single pass.
///
/// The `entropy` field is produced by the same shared routine as
/// [`calculate_entropy`], so the two agree bit-for-bit.
pub fn region_stats(data: &[u8]) -> RegionStats {
    if data.is_empty() {
        return RegionStats {
            entropy: 0.0,
            chi_square_norm: 0.0,
            printable_ratio: 0.0,
        };
    }

    let mut freq = [0u64; 256];
    let mut printable = 0u64;
    for &byte in data {
        freq[byte as usize] += 1;
        if is_printable_byte(byte) {
            printable += 1;
        }
    }

    RegionStats {
        entropy: entropy_from_histogram(&freq, data.len()),
        chi_square_norm: chi_square_from_histogram(&freq, data.len()) / CHI_SQUARE_DF,
        printable_ratio: printable as f32 / data.len() as f32,
    }
}

#[inline]
fn is_printable_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | b'\r') || (0x20..=0x7E).contains(&byte)
}

/// Statistical classification of a byte window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegionClass {
    /// Statistically uniform high-entropy data — consistent with encryption
    /// or a cryptographic PRNG (chi²-normalized LOW + entropy HIGH).
    EncryptedLike,
    /// High-entropy but statistically *skewed* data — consistent with
    /// compression (deflate/LZMA symbol coding raises entropy without
    /// reaching uniformity). Also the residual bucket for mid-entropy binary
    /// data such as compiled code or mixed structured blobs.
    CompressedLike,
    /// Predominantly printable ASCII — text, JSON, base64, config files.
    PlainText,
    /// Padding, repetition or near-single-symbol content (zeros, `"AAAA…"`).
    LowEntropy,
}

impl RegionClass {
    /// Stable machine-readable label.
    pub fn as_str(self) -> &'static str {
        match self {
            RegionClass::EncryptedLike => "encrypted-like",
            RegionClass::CompressedLike => "compressed-like",
            RegionClass::PlainText => "plain-text",
            RegionClass::LowEntropy => "low-entropy",
        }
    }
}

impl std::fmt::Display for RegionClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Core decision function over precomputed [`RegionStats`].
///
/// # Heuristic (evaluation order matters)
///
/// | Order | Condition                                             | Verdict         |
/// |-------|-------------------------------------------------------|-----------------|
/// | 1     | `entropy < 3.5`                                        | [`RegionClass::LowEntropy`] |
/// | 2     | `printable_ratio >= 0.90`                              | [`RegionClass::PlainText`]  |
/// | 3     | `chi_square_norm <= 1.20 && entropy >= 7.0`            | [`RegionClass::EncryptedLike`] |
/// | 4     | fallthrough                                            | [`RegionClass::CompressedLike`] |
///
/// Rationale:
/// - **LowEntropy first**: repeated printable filler (`"AAAA…"`) would
///   otherwise satisfy the printable test; entropy is the stronger signal.
/// - **PlainText second**: text has heavily skewed byte statistics
///   (chi²-normalized typically ≫ 10), so it can never be mistaken for
///   encrypted by rule 3 — checking it before the uniformity test simply
///   short-circuits cheaply and keeps base64-of-random classified as text.
/// - **EncryptedLike third**: requires *both* signals — uniformity alone is
///   not enough (tiny windows are noisy) and raw entropy alone is not enough
///   (compressed data also exceeds 7 bits/byte).
/// - **CompressedLike residual**: everything else — genuinely compressed
///   streams (high entropy, elevated chi²) plus mid-entropy non-printable
///   binary (compiled code, mixed structured data). Downstream consumers that
///   must distinguish code from compression should consult
///   `stats.entropy >= classify_thresholds::COMPRESSED_ENTROPY_MIN`.
///
/// Reliability note: chi-square sampling noise grows as windows shrink.
/// Windows of ≥1024 bytes give stable verdicts; treat sub-256-byte results
/// as advisory.
pub fn classify_from_stats(stats: RegionStats) -> RegionClass {
    use classify_thresholds as t;

    if stats.entropy < t::LOW_ENTROPY_MAX {
        RegionClass::LowEntropy
    } else if stats.printable_ratio >= t::PLAIN_PRINTABLE_MIN {
        RegionClass::PlainText
    } else if stats.chi_square_norm <= t::ENCRYPTED_CHI_NORM_MAX
        && stats.entropy >= t::ENCRYPTED_ENTROPY_MIN
    {
        RegionClass::EncryptedLike
    } else {
        // Residual bucket: entropy >= 3.5, non-printable, not statistically
        // uniform — compressed streams and other mid/high-entropy binary.
        RegionClass::CompressedLike
    }
}

/// Classify a whole buffer into one statistical region.
///
/// See [`classify_from_stats`] for the documented heuristic and
/// [`region_stats`] for the underlying measurements.
///
/// # Examples
/// ```
/// use entropy_rs::{classify_region, RegionClass};
///
/// assert_eq!(classify_region(&[0x41; 512]), RegionClass::LowEntropy);
///
/// let text = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, \
///              sed do eiusmod tempor incididunt ut labore et dolore.";
/// assert_eq!(classify_region(text), RegionClass::PlainText);
/// ```
pub fn classify_region(data: &[u8]) -> RegionClass {
    classify_from_stats(region_stats(data))
}

/// Sliding-window counterpart of [`classify_region`] reusing the exact
/// batching machinery of [`sliding_window_entropy_batched`]: one O(n) pass
/// maintains the running 256-bucket histogram (plus a running printable-byte
/// counter), and each window's entropy flows through the same shared
/// summation routine — so entropy values here are bit-identical to those from
/// [`sliding_window_entropy_batched`] / [`sliding_window_entropy`] for the
/// same offsets, while each window additionally gets a chi-square uniformity
/// score computed from the same exact integer counts.
///
/// Window offset layout (stride-aligned starts + tail window anchored at the
/// buffer end) and invalid-parameter handling (`window_size == 0`, `step == 0`,
/// buffer shorter than one window → empty result) match
/// [`sliding_window_entropy_batched`] exactly.
///
/// # Examples
/// ```
/// use entropy_rs::{classify_windows, RegionClass};
///
/// let data = vec![0u8; 512]; // all zeros → low-entropy everywhere
/// let classes = classify_windows(&data, 256, 256);
/// assert!(classes.iter().all(|&(_, c)| c == RegionClass::LowEntropy));
/// ```
pub fn classify_windows(data: &[u8], window_size: usize, step: usize) -> Vec<(usize, RegionClass)> {
    let valid = window_size > 0 && step > 0 && data.len() >= window_size;
    if !valid {
        return Vec::new();
    }

    let offsets = window_offsets(data.len(), window_size, step);

    // Initial histogram + printable count for the first window [0, window_size).
    let mut freq = [0u64; 256];
    let mut printable = 0u64;
    for &byte in &data[..window_size] {
        freq[byte as usize] += 1;
        if is_printable_byte(byte) {
            printable += 1;
        }
    }

    let mut results = Vec::with_capacity(offsets.len());
    let mut prev_start = 0usize;
    for &offset in &offsets {
        let delta = offset - prev_start;
        if delta > 0 {
            if delta < window_size {
                // Overlapping windows: slide the running state forward by
                // `delta`, exactly like the entropy-only batched pass.
                let out = &data[prev_start..offset];
                let inp = &data[prev_start + window_size..offset + window_size];
                for &byte in out {
                    freq[byte as usize] -= 1;
                    if is_printable_byte(byte) {
                        printable -= 1;
                    }
                }
                for &byte in inp {
                    freq[byte as usize] += 1;
                    if is_printable_byte(byte) {
                        printable += 1;
                    }
                }
            } else {
                // Non-overlapping or disjoint windows (`step >= window`):
                // recount from scratch — same strategy as the batched
                // entropy pass, keeping counts exact and results identical.
                freq = [0u64; 256];
                printable = 0;
                for &byte in &data[offset..offset + window_size] {
                    freq[byte as usize] += 1;
                    if is_printable_byte(byte) {
                        printable += 1;
                    }
                }
            }
            prev_start = offset;
        }

        let stats = RegionStats {
            entropy: entropy_from_histogram(&freq, window_size),
            chi_square_norm: chi_square_from_histogram(&freq, window_size) / CHI_SQUARE_DF,
            printable_ratio: printable as f32 / window_size as f32,
        };
        results.push((offset, classify_from_stats(stats)));
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

    // ── Region classification ────────────────────────────────────────

    /// Precomputed gzip stream (4104 bytes) of ~50 KiB of varied English
    /// prose, embedded as a const byte array to keep the crate dependency-
    /// free. Preferred over a flate2 dev-dependency so tests stay hermetic
    /// and the fixture byte-exact forever.
    mod gzip_fixture {
        include!("../tests/data/gzip_blob.rs");
    }

    fn gzip_blob() -> &'static [u8] {
        assert_eq!(
            &gzip_fixture::GZIP_BLOB[..3],
            &[0x1F, 0x8B, 0x08],
            "fixture must be gzip"
        );
        &gzip_fixture::GZIP_BLOB
    }

    /// Lorem-ipsum English prose (~6 KiB), pass counters included so the
    /// corpus is not pathologically repetitive.
    fn lorem_ipsum() -> Vec<u8> {
        const PARAS: [&str; 4] = [
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do \
             eiusmod tempor incididunt ut labore et dolore magna aliqua.",
            "Ut enim ad minim veniam, quis nostrud exercitation ullamco \
             laboris nisi ut aliquip ex ea commodo consequat.",
            "Duis aute irure dolor in reprehenderit in voluptate velit esse \
             cillum dolore eu fugiat nulla pariatur.",
            "Excepteur sint occaecat cupidatat non proident, sunt in culpa \
             qui officia deserunt mollit anim id est laborum.",
        ];
        let mut text = String::new();
        for pass in 0..12 {
            for (n, para) in PARAS.iter().enumerate() {
                text.push_str(para);
                text.push_str(&format!(" [pass={} para={}]\n", pass, n));
            }
        }
        text.into_bytes()
    }

    /// Deterministic xorshift64 PRNG emitting **all eight** state bytes per
    /// step (little-endian), so every byte position across the full 0..=255
    /// range is exercised — statistically indistinguishable from a cipher's
    /// output for classification purposes. No external deps.
    fn full_range_xorshift(len: usize) -> Vec<u8> {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            out.extend_from_slice(&x.to_le_bytes());
        }
        out.truncate(len);
        out
    }

    // ── Per-class tests ──────────────────────────────────────────────

    #[test]
    fn encrypted_like_full_range_xorshift() {
        use classify_thresholds as t;
        let data = full_range_xorshift(8192);
        let s = region_stats(&data);

        // The documented heuristic: uniform (chi²-norm ≤ 1.2) AND entropy > 7.
        assert!(
            s.chi_square_norm <= t::ENCRYPTED_CHI_NORM_MAX,
            "xorshift must look statistically uniform, got chi²-norm {}",
            s.chi_square_norm
        );
        assert!(s.entropy >= t::ENCRYPTED_ENTROPY_MIN);
        assert_eq!(classify_region(&data), RegionClass::EncryptedLike);

        // Every window of the buffer agrees with the whole-buffer verdict.
        assert!(classify_windows(&data, 1024, 512)
            .iter()
            .all(|&(_, c)| c == RegionClass::EncryptedLike));
    }

    #[test]
    fn compressed_like_gzip_blob() {
        use classify_thresholds as t;
        let data = gzip_blob();
        assert_eq!(classify_region(data), RegionClass::CompressedLike);

        // Compressed signature: high entropy but skewed histogram (chi² well
        // above the encrypted band).
        let s = region_stats(data);
        assert!(s.entropy >= t::ENCRYPTED_ENTROPY_MIN);
        assert!(s.chi_square_norm > t::ENCRYPTED_CHI_NORM_MAX);

        // All w=1024 windows stay inside the compressed band (measured range
        // 1.48–3.71, comfortably above ENCRYPTED_CHI_NORM_MAX).
        assert!(classify_windows(data, 1024, 512)
            .iter()
            .all(|&(_, c)| c == RegionClass::CompressedLike));
    }

    #[test]
    fn plain_text_english_prose() {
        use classify_thresholds as t;
        let text = lorem_ipsum();
        let s = region_stats(&text);
        assert!(s.printable_ratio >= t::PLAIN_PRINTABLE_MIN);
        assert_eq!(classify_region(&text), RegionClass::PlainText);

        // Sliding windows over pure text stay PlainText.
        assert!(classify_windows(&text, 512, 256)
            .iter()
            .all(|&(_, c)| c == RegionClass::PlainText));
    }

    #[test]
    fn low_entropy_repeated_byte() {
        for filler in [&[0x41u8][..], &[0x00u8][..], &[0xFFu8][..]] {
            let data = vec![filler[0]; 4096];
            assert_eq!(classify_region(&data), RegionClass::LowEntropy);
            assert!(classify_windows(&data, 512, 512)
                .iter()
                .all(|&(_, c)| c == RegionClass::LowEntropy));
        }
    }

    #[test]
    fn base64_of_random_stays_plain_text() {
        // Printable encoding of random bytes: high-ish entropy but the
        // printable rule fires first.
        let b64: Vec<u8> = full_range_xorshift(2048)
            .into_iter()
            .map(|b| b64_alphabet()[b as usize % 64])
            .collect();
        assert_eq!(classify_region(&b64), RegionClass::PlainText);
    }

    fn b64_alphabet() -> &'static [u8] {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    }

    // ── Boundary tests ───────────────────────────────────────────────

    #[test]
    fn boundary_printable_filler_is_low_entropy_not_text() {
        // 'A' * n is fully printable but rule order (LowEntropy first) must
        // win over the printable-ratio rule.
        let data = vec![b'A'; 4096];
        assert_eq!(region_stats(&data).printable_ratio, 1.0);
        assert_eq!(classify_region(&data), RegionClass::LowEntropy);
    }

    #[test]
    fn boundary_empty_input_is_low_entropy_with_zero_stats() {
        let s = region_stats(b"");
        assert_eq!(s, RegionStats { entropy: 0.0, chi_square_norm: 0.0, printable_ratio: 0.0 });
        assert_eq!(classify_region(b""), RegionClass::LowEntropy);
    }

    #[test]
    fn boundary_low_entropy_threshold_inclusive() {
        // Exactly at LOW_ENTROPY_MAX (3.5): not classified low-entropy —
        // falls through to the residual bucket (non-printable, skewed).
        let stats = RegionStats {
            entropy: classify_thresholds::LOW_ENTROPY_MAX,
            chi_square_norm: 50.0,
            printable_ratio: 0.0,
        };
        assert_eq!(classify_from_stats(stats), RegionClass::CompressedLike);

        // Just below: LowEntropy wins regardless of other signals.
        let stats = RegionStats { entropy: 3.4999, ..stats };
        assert_eq!(classify_from_stats(stats), RegionClass::LowEntropy);
    }

    #[test]
    fn boundary_encrypted_requires_both_signals() {
        use classify_thresholds as t;

        // Uniform AND at the entropy floor → EncryptedLike (both bounds are
        // inclusive: ≤ 1.2 and ≥ 7.0).
        let stats = RegionStats {
            entropy: t::ENCRYPTED_ENTROPY_MIN,
            chi_square_norm: t::ENCRYPTED_CHI_NORM_MAX,
            printable_ratio: 0.0,
        };
        assert_eq!(classify_from_stats(stats), RegionClass::EncryptedLike);

        // Uniform-looking but entropy just under the floor → not encrypted.
        let stats = RegionStats {
            entropy: 6.999,
            ..stats
        };
        assert_ne!(classify_from_stats(stats), RegionClass::EncryptedLike);

        // High entropy but chi² just above the band → not encrypted.
        let stats = RegionStats {
            entropy: 8.0,
            chi_square_norm: 1.200_001,
            ..stats
        };
        assert_eq!(classify_from_stats(stats), RegionClass::CompressedLike);
    }

    #[test]
    fn boundary_mid_entropy_binary_residual_is_compressed_like() {
        // Cycle of 16 distinct non-printable symbols → exactly 4 bits/byte:
        // above LOW_ENTROPY_MAX, non-printable, heavily skewed → residual
        // CompressedLike bucket (compiled-code-like density).
        let data: Vec<u8> = (0x10..=0x1Fu8).cycle().take(4096).collect();
        let s = region_stats(&data);
        assert!((s.entropy - 4.0).abs() < 1e-9);
        assert_eq!(s.printable_ratio, 0.0);
        assert_eq!(classify_region(&data), RegionClass::CompressedLike);
    }

    // ── classify_windows machinery-parity tests ──────────────────────

    #[test]
    fn classify_windows_matches_per_window_classify_region() {
        // Mixed-density buffer exercises slide-in/slide-out of every class
        // through the running-histogram path.
        let mut data = lorem_ipsum(); // ~6 KiB text
        data.extend(full_range_xorshift(4096)); // cipher-like
        data.extend(vec![0x41u8; 1024]); // padding

        for &(window, step) in &[
            (256usize, 256usize),
            (256, 128),
            (256, 1),
            (512, 300), // tail window anchored at buffer end
            (1024, 512),
        ] {
            let windows = classify_windows(&data, window, step);
            let expected: Vec<_> =
                sliding_window_entropy_batched(&data, window, step)
                    .into_iter()
                    .map(|(off, _)| (off, classify_region(&data[off..off + window])))
                    .collect();
            assert_eq!(windows.len(), expected.len(), "w={} s={}", window, step);
            for (got, want) in windows.into_iter().zip(expected) {
                assert_eq!(got, want, "w={} s={}", window, step);
            }
        }
    }

    #[test]
    fn classify_windows_offsets_match_batched_entropy_layout() {
        let data = full_range_xorshift(3000);
        for &(window, step) in &[(256usize, 300usize), (512, 700)] {
            let cls: Vec<usize> = classify_windows(&data, window, step)
                .into_iter()
                .map(|(o, _)| o)
                .collect();
            let ent: Vec<usize> = sliding_window_entropy_batched(&data, window, step)
                .into_iter()
                .map(|(o, _)| o)
                .collect();
            assert_eq!(cls, ent);
            assert_eq!(*cls.last().unwrap(), data.len() - window);
        }
    }

    #[test]
    fn classify_windows_invalid_params_return_empty() {
        let data = lorem_ipsum();
        assert!(classify_windows(&data, 0, 1).is_empty());
        assert!(classify_windows(&data, 256, 0).is_empty());
        assert!(classify_windows(b"tiny", 16, 1).is_empty());
    }

    #[test]
    fn classify_windows_separates_adjacent_regions() {
        let mut data = vec![0x41u8; 1024]; // LowEntropy head
        data.extend(full_range_xorshift(2048)); // EncryptedLike middle
        data.extend(lorem_ipsum()); // PlainText tail

        let results = classify_windows(&data, 512, 512);
        let classes: Vec<RegionClass> = results.iter().map(|&(_, c)| c).collect();

        assert!(classes.contains(&RegionClass::LowEntropy));
        assert!(classes.contains(&RegionClass::EncryptedLike));
        assert!(classes.contains(&RegionClass::PlainText));
        assert!(!classes.contains(&RegionClass::CompressedLike));
    }

    #[test]
    fn region_class_labels_and_display() {
        assert_eq!(RegionClass::EncryptedLike.as_str(), "encrypted-like");
        assert_eq!(RegionClass::CompressedLike.as_str(), "compressed-like");
        assert_eq!(RegionClass::PlainText.as_str(), "plain-text");
        assert_eq!(RegionClass::LowEntropy.to_string(), "low-entropy");
    }

    #[test]
    fn region_stats_entropy_bit_exact_vs_calculate_entropy() {
        for data in [
            lorem_ipsum(),
            gzip_blob().to_vec(),
            full_range_xorshift(4096),
            vec![0u8; 100],
        ] {
            assert_eq!(
                region_stats(&data).entropy.to_bits(),
                calculate_entropy(&data).entropy.to_bits()
            );
            assert_eq!(
                region_stats(&data).chi_square_norm.to_bits(),
                chi_square_uniform_normalized(&data).to_bits()
            );
        }
    }
}


