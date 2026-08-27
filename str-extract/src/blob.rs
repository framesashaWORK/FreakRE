//! Embedded payload-blob detection: long Base64 / hex runs with
//! decoded-content classification (URL / PE / shellcode / PowerShell
//! heuristics) for malware analysis.

use std::collections::VecDeque;
use std::fmt;
use std::fmt::Write as _;

use crate::{Encoding, ExtractConfig};

/// Number of leading decoded bytes searched for x86 prologues.
const PROLOGUE_SCAN_BYTES: usize = 32;
/// Entropy (bits/byte) required together with a prologue hit for shellcode.
const SHELLCODE_MIN_ENTROPY: f32 = 6.0;
/// Entropy above which any decoded blob is marked a probable payload.
const PROBABLE_PAYLOAD_ENTROPY: f32 = 6.5;
/// Bytes retained in [`BlobFinding::decoded_preview`].
const PREVIEW_LEN: usize = 64;

/// x86/x64 stack-frame prologues commonly preceding injected shellcode.
const X86_PROLOGUES: [&[u8]; 3] = [b"\x55\x8b\xec", b"\x48\x83\xec", b"\x64\xa1"];

const URL_SCHEMES: [&str; 5] = ["http://", "https://", "ftp://", "ftps://", "tcp://"];

const COMMON_TLDS: [&str; 30] = [
    "com", "net", "org", "io", "ru", "su", "cn", "xyz", "top", "info", "biz", "online", "site",
    "club", "vip", "onion", "tk", "ml", "ga", "cf", "gq", "pw", "cc", "me", "uk", "us", "de",
    "fr", "example", "test",
];

/// Kind of encoding used by the detected blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlobKind {
    /// Base64 text (`[A-Za-z0-9+/=]`).
    Base64,
    /// Long run of hexadecimal digits.
    Hex,
}

impl fmt::Display for BlobKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlobKind::Base64 => f.write_str("base64"),
            BlobKind::Hex => f.write_str("hex"),
        }
    }
}

/// A decoded payload blob found in the binary, with classification flags.
///
/// Emitted by [`crate::extract_strings_with_blobs`] alongside regular
/// [`crate::ExtractedString`] results.
#[derive(Debug, Clone, PartialEq)]
pub struct BlobFinding {
    /// Byte offset of the *encoded* run within the original buffer.
    pub offset: usize,
    /// Length of the encoded run in bytes (including `=` padding).
    pub encoded_len: usize,
    /// Length of the decoded payload in bytes.
    pub decoded_len: usize,
    /// First 64 decoded bytes, non-printables escaped as `\xNN`.
    pub decoded_preview: String,
    /// Whether the run was Base64 or hex.
    pub kind: BlobKind,
    /// How the blob was stored in the file (plain ASCII or UTF-16 wrapped).
    pub source_encoding: Encoding,
    /// Fraction of decoded bytes that are printable ASCII / whitespace.
    pub printable_ratio: f32,
    /// Shannon entropy of the decoded payload (bits/byte, 0.0-8.0).
    pub entropy: f32,
    /// Decoded content starts with http/ftp scheme or is domain-like.
    pub looks_like_url: bool,
    /// Decoded content begins with an `MZ` header.
    pub looks_like_pe: bool,
    /// High entropy + x86/x64 stack-frame prologue in the first 32 bytes.
    pub looks_like_shellcode: bool,
    /// Decoded content carries `-enc` / `-wodn` PowerShell markers.
    pub looks_like_powershell: bool,
    /// entropy > 6.5 OR PE header OR shellcode prologue.
    pub is_probable_payload: bool,
}

impl fmt::Display for BlobFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:#08x}] {}({}) enc={}B dec={}B ent={:.2} print={:.2} preview=\"{}\"",
            self.offset,
            self.kind,
            self.source_encoding,
            self.encoded_len,
            self.decoded_len,
            self.entropy,
            self.printable_ratio,
            self.decoded_preview,
        )?;
        let mut flags: Vec<&str> = Vec::new();
        if self.looks_like_url {
            flags.push("url");
        }
        if self.looks_like_pe {
            flags.push("pe");
        }
        if self.looks_like_shellcode {
            flags.push("shellcode");
        }
        if self.looks_like_powershell {
            flags.push("powershell");
        }
        if self.is_probable_payload {
            flags.push("PROBABLE-PAYLOAD");
        }
        if !flags.is_empty() {
            write!(f, " [{}]", flags.join(","))?;
        }
        Ok(())
    }
}

#[inline]
fn is_base64_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
}

#[inline]
fn is_hex_char(b: u8) -> bool {
    b.is_ascii_hexdigit()
}

fn base64_value(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Tiny streaming base64 decoder (standard alphabet, padding optional).
/// Trailing bits that cannot form a full byte are discarded.
fn base64_decode(input: &[u8]) -> Option<Vec<u8>> {
    let core_len = input.iter().position(|&b| b == b'=').unwrap_or(input.len());
    let mut out = Vec::with_capacity(core_len * 3 / 4 + 3);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in &input[..core_len] {
        acc = ((acc << 6) | base64_value(b)? as u32) & 0xFFFF;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Hex decoder; an odd trailing nibble is dropped.
fn hex_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() / 2);
    let mut nibble: Option<u8> = None;
    for &b in input {
        match hex_value(b) {
            Some(v) => match nibble.take() {
                Some(hi) => out.push(hi << 4 | v),
                None => nibble = Some(v),
            },
            None => break,
        }
    }
    out
}

/// Local Shannon entropy over a 256-bin histogram (bits per byte).
fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut hist = [0u32; 256];
    for &b in data {
        hist[b as usize] += 1;
    }
    let n = data.len() as f32;
    hist.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f32 / n;
            -p * p.log2()
        })
        .sum()
}

fn printable_ratio(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let printable = data
        .iter()
        .filter(|&&b| matches!(b, 0x20..=0x7E | b'\t' | b'\r' | b'\n'))
        .count();
    printable as f32 / data.len() as f32
}

fn escape_preview(data: &[u8]) -> String {
    let mut out = String::with_capacity(PREVIEW_LEN * 4);
    for &b in data.iter().take(PREVIEW_LEN) {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7E => out.push(b as char),
            _ => {
                let _ = write!(out, "\\x{b:02X}");
            }
        }
    }
    out
}

fn has_x86_prologue(decoded: &[u8]) -> bool {
    let window = &decoded[..decoded.len().min(PROLOGUE_SCAN_BYTES)];
    X86_PROLOGUES
        .iter()
        .any(|p| window.windows(p.len()).any(|w| w == *p))
}

fn looks_like_url(decoded: &[u8]) -> bool {
    let text = String::from_utf8_lossy(decoded);
    let trimmed = text.trim_start();
    let lower = trimmed.to_ascii_lowercase();
    if URL_SCHEMES.iter().any(|sc| lower.starts_with(sc)) || lower.contains("://") {
        return true;
    }
    let host = lower.split(['/', '\\', '?', '#', ':']).next().unwrap_or("");
    is_domain_ish(host)
}

fn is_domain_ish(host: &str) -> bool {
    if host.len() < 4
        || !host.contains('.')
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return false;
    }
    host.rsplit('.')
        .next()
        .is_some_and(|tld| COMMON_TLDS.contains(&tld))
}

fn looks_like_powershell(decoded: &[u8]) -> bool {
    let lower = String::from_utf8_lossy(decoded).to_ascii_lowercase();
    lower.contains("-enc") || lower.contains("-wodn")
}

fn make_finding(
    offset: usize,
    encoded_len: usize,
    decoded: &[u8],
    kind: BlobKind,
    source_encoding: Encoding,
) -> BlobFinding {
    let entropy = shannon_entropy(decoded);
    let looks_like_pe = decoded.len() >= 2 && decoded[0] == b'M' && decoded[1] == b'Z';
    let looks_like_shellcode = entropy >= SHELLCODE_MIN_ENTROPY && has_x86_prologue(decoded);
    BlobFinding {
        offset,
        encoded_len,
        decoded_len: decoded.len(),
        decoded_preview: escape_preview(decoded),
        kind,
        source_encoding,
        printable_ratio: printable_ratio(decoded),
        entropy,
        looks_like_url: looks_like_url(decoded),
        looks_like_pe,
        looks_like_shellcode,
        looks_like_powershell: looks_like_powershell(decoded),
        is_probable_payload: entropy > PROBABLE_PAYLOAD_ENTROPY
            || looks_like_pe
            || looks_like_shellcode,
    }
}

/// Scan the buffer for Base64 / hex payload blobs.
pub(crate) fn detect_blobs(data: &[u8], cfg: &ExtractConfig) -> Vec<BlobFinding> {
    let mut out = Vec::new();
    scan_ascii_runs(data, cfg, &mut out);
    if cfg.utf16le {
        scan_wide_runs(data, Encoding::Utf16Le, cfg, &mut out);
    }
    if cfg.utf16be {
        scan_wide_runs(data, Encoding::Utf16Be, cfg, &mut out);
    }
    out.sort_by_key(|b| b.offset);
    out
}

fn scan_ascii_runs(data: &[u8], cfg: &ExtractConfig, out: &mut Vec<BlobFinding>) {
    let mut start: Option<usize> = None;
    for i in 0..=data.len() {
        let in_run = i < data.len() && is_base64_char(data[i]);
        if in_run {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start {
            let run = &data[s..i];
            let hex_priority =
                run.len() >= cfg.min_blob_hex_len && run.iter().all(|&b| is_hex_char(b));
            if hex_priority {
                let decoded = hex_decode(run);
                out.push(make_finding(s, run.len(), &decoded, BlobKind::Hex, Encoding::Ascii));
            } else if run.len() >= cfg.min_blob_base64_len {
                let decoded = base64_decode(run).unwrap_or_default();
                out.push(make_finding(
                    s,
                    run.len(),
                    &decoded,
                    BlobKind::Base64,
                    Encoding::Ascii,
                ));
            }
            start = None;
        }
    }
}

fn scan_wide_runs(
    data: &[u8],
    encoding: Encoding,
    cfg: &ExtractConfig,
    out: &mut Vec<BlobFinding>,
) {
    let mut candidates: Vec<(usize, Vec<u8>)> = Vec::new();

    for align in 0..2usize {
        let mut i = align;
        let mut current: Option<(usize, Vec<u8>)> = None;
        while i + 1 < data.len() {
            let (lo, hi) = match encoding {
                Encoding::Utf16Le => (data[i], data[i + 1]),
                Encoding::Utf16Be => (data[i + 1], data[i]),
                Encoding::Ascii => unreachable!(),
            };
            let is_unit = hi == 0 && is_base64_char(lo);
            if is_unit {
                match current.as_mut() {
                    Some((_, buf)) => buf.push(lo),
                    None => current = Some((i, vec![lo])),
                }
            } else if let Some((s, buf)) = current.take() {
                if buf.len() >= cfg.min_blob_base64_len {
                    candidates.push((s, buf));
                }
            }
            i += 2;
        }
        if let Some((s, buf)) = current.take() {
            if buf.len() >= cfg.min_blob_base64_len {
                candidates.push((s, buf));
            }
        }
    }

    for (s, encoded) in dedup_overlapping(candidates) {
        let decoded = base64_decode(&encoded).unwrap_or_default();
        out.push(make_finding(s, encoded.len(), &decoded, BlobKind::Base64, encoding));
    }
}

fn dedup_overlapping(mut cands: Vec<(usize, Vec<u8>)>) -> Vec<(usize, Vec<u8>)> {
    cands.sort_by_key(|&(o, _)| o);
    let mut kept: VecDeque<(usize, usize)> = VecDeque::new();
    let mut out = Vec::with_capacity(cands.len());
    for (o, buf) in cands {
        let end = o + buf.len() * 2;
        while kept.front().is_some_and(|&(_, ke)| ke <= o) {
            kept.pop_front();
        }
        let overlaps = kept.front().is_some_and(|&(ko, ke)| ko < end && o < ke);
        if !overlaps {
            kept.push_back((o, end));
            out.push((o, buf));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{extract_strings, extract_strings_with_blobs};

    const B64_URL: &str = "aHR0cDovL2V2aWwuZXhhbXBsZS9wYXlsb2Fk";

    fn pseudo_random(seed: u64, n: usize) -> Vec<u8> {
        let mut state = seed;
        (0..n)
            .map(|_| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (state >> 56) as u8
            })
            .collect()
    }

    fn b64_encode(data: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = *chunk.get(1).unwrap_or(&0) as u32;
            let b2 = *chunk.get(2).unwrap_or(&0) as u32;
            let n = b0 << 16 | b1 << 8 | b2;
            out.push(T[(n >> 18) as usize & 63] as char);
            out.push(T[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                T[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                T[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    fn hex_encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn surround(payload: &str, pad: usize) -> Vec<u8> {
        let mut data = vec![0xDEu8; pad];
        data.extend_from_slice(payload.as_bytes());
        data.extend_from_slice(&[0xDE; 8]);
        data
    }

    #[test]
    fn base64_url_fires_url_flag() {
        let data = surround(B64_URL, 8);
        let (_, blobs) = extract_strings_with_blobs(&data, &ExtractConfig::default());
        let hit = blobs
            .iter()
            .find(|b| b.kind == BlobKind::Base64 && b.source_encoding == Encoding::Ascii)
            .expect("base64 blob must be found");
        assert_eq!(hit.offset, 8);
        assert!(hit.looks_like_url, "url flag must fire: {hit}");
        assert!(!hit.is_probable_payload);
        assert!(hit.decoded_preview.starts_with("http://"));
        assert_eq!(hit.decoded_len, 27);
        assert!(hit.entropy < 4.5);
    }

    #[test]
    fn base64_mz_prefix_fires_pe_flag() {
        let mut payload = b"MZ".to_vec();
        payload.extend(pseudo_random(0xC0FFEE, 254));
        let encoded = b64_encode(&payload);
        let data = surround(&encoded, 4);
        let (_, blobs) = extract_strings_with_blobs(&data, &ExtractConfig::default());
        let hit = blobs
            .iter()
            .find(|b| b.kind == BlobKind::Base64)
            .expect("mz base64 blob must be found");
        assert!(hit.looks_like_pe, "pe flag must fire: {hit}");
        assert!(hit.is_probable_payload);
        assert!(hit.entropy > 7.0);
        assert_eq!(hit.decoded_preview.get(..2), Some("MZ"));
    }

    #[test]
    fn base64_shellcode_prologue_fires_flag() {
        let mut payload = vec![0x55, 0x8B, 0xEC];
        payload.extend(pseudo_random(0xBADF00D, 253));
        let encoded = b64_encode(&payload);
        let data = surround(&encoded, 4);
        let (_, blobs) = extract_strings_with_blobs(&data, &ExtractConfig::default());
        let hit = blobs
            .iter()
            .find(|b| b.kind == BlobKind::Base64)
            .expect("shellcode base64 blob must be found");
        assert!(hit.looks_like_shellcode, "shellcode flag must fire: {hit}");
        assert!(hit.is_probable_payload);
    }

    #[test]
    fn random_short_strings_do_not_fire() {
        let data = b"Hello World\x00This is a normal binary\x01\x02with short tokens AAA21+/ zzz\x00";
        let (_, blobs) = extract_strings_with_blobs(data, &ExtractConfig::default());
        assert!(
            blobs.is_empty(),
            "no blobs expected from short benign tokens: {:?}",
            blobs
        );
    }

    #[test]
    fn utf16le_wrapped_base64_is_found() {
        let mut data = vec![0xDEu8; 8];
        for c in B64_URL.bytes() {
            data.extend_from_slice(&[c, 0x00]);
        }
        data.extend_from_slice(&[0x00, 0x00]);

        let (_, blobs) = extract_strings_with_blobs(&data, &ExtractConfig::default());
        let hit = blobs
            .iter()
            .find(|b| b.source_encoding == Encoding::Utf16Le)
            .expect("utf16le-wrapped base64 must be found");
        assert_eq!(hit.offset, 8);
        assert_eq!(hit.encoded_len, B64_URL.len());
        assert_eq!(hit.decoded_len, 27);
        assert!(hit.looks_like_url, "url flag must fire on wide blob: {hit}");
    }

    #[test]
    fn utf16be_wrapped_base64_is_found_at_odd_offset() {
        let mut data = vec![0x90u8];
        for c in B64_URL.bytes() {
            data.extend_from_slice(&[0x00, c]);
        }
        data.extend_from_slice(&[0x00, 0x00]);

        let (_, blobs) = extract_strings_with_blobs(&data, &ExtractConfig::default());
        let hit = blobs
            .iter()
            .find(|b| b.source_encoding == Encoding::Utf16Be)
            .expect("utf16be-wrapped base64 must be found");
        assert_eq!(hit.offset, 1);
        assert!(hit.looks_like_url, "url flag must fire on wide blob: {hit}");
    }

    #[test]
    fn long_hex_run_fires_hex_and_pe_flags() {
        let mut payload = b"MZ".to_vec();
        payload.extend(pseudo_random(0xFEED42, 254));
        let hexed = hex_encode(&payload);
        assert!(hexed.len() >= 64);
        let data = surround(&hexed, 4);

        let (_, blobs) = extract_strings_with_blobs(&data, &ExtractConfig::default());
        let hit = blobs.iter().find(|b| b.kind == BlobKind::Hex).expect("hex blob must be found");
        assert_eq!(hit.offset, 4);
        assert_eq!(hit.encoded_len, hexed.len());
        assert_eq!(hit.decoded_len, payload.len());
        assert!(hit.looks_like_pe, "pe flag must fire on hex mz blob: {hit}");
        assert!(hit.is_probable_payload);
        assert_eq!(blobs.iter().filter(|b| b.offset == 4).count(), 1, "hex run must not double-report as base64");
    }

    #[test]
    fn powershell_markers_detected_after_decode() {
        let payload = b"-enc JABBAExBAAAAZZZZZZQQQQ== tail";
        let encoded = b64_encode(payload);
        let data = surround(&encoded, 0);
        let (_, blobs) = extract_strings_with_blobs(&data, &ExtractConfig::default());
        let hit = blobs.iter().find(|b| b.kind == BlobKind::Base64).expect("blob must be found");
        assert!(hit.looks_like_powershell, "powershell flag must fire: {hit}");
    }

    #[test]
    fn config_min_lengths_are_honored() {
        let encoded_len = B64_URL.len();
        let data = surround(B64_URL, 8);

        let cfg = ExtractConfig {
            min_blob_base64_len: encoded_len + 1,
            ..Default::default()
        };
        let (_, blobs) = extract_strings_with_blobs(&data, &cfg);
        assert!(blobs.is_empty(), "above threshold nothing may fire: {:?}", blobs);

        let cfg = ExtractConfig {
            min_blob_base64_len: encoded_len - 1,
            ..Default::default()
        };
        let (_, blobs) = extract_strings_with_blobs(&data, &cfg);
        assert_eq!(blobs.len(), 1);
    }

    #[test]
    fn detect_blobs_can_be_disabled() {
        let data = surround(B64_URL, 8);
        let cfg = ExtractConfig {
            detect_blobs: false,
            ..Default::default()
        };
        let (_, blobs) = extract_strings_with_blobs(&data, &cfg);
        assert!(blobs.is_empty());
    }

    #[test]
    fn preview_escapes_control_bytes() {
        let payload = b"AAAABBBB\x00\x01\x02TAILTAILTAILTAILTAILTAILTAILTAILTAIL";
        let encoded = b64_encode(payload);
        let data = surround(&encoded, 0);
        let (_, blobs) = extract_strings_with_blobs(&data, &ExtractConfig::default());
        let hit = blobs.iter().find(|b| b.kind == BlobKind::Base64).expect("blob must be found");
        assert!(hit.decoded_preview.contains("\\x00\\x01\\x02"));
        assert!(!hit.decoded_preview.contains('\0'));
        // "AAAABBBB" (8) + TAIL*9 (36) printable; \x00\x01\x02 are not.
        let expected_ratio = 44.0 / payload.len() as f32;
        assert!((hit.printable_ratio - expected_ratio).abs() < 1e-6);
    }

    #[test]
    fn old_api_matches_new_api_strings() {
        let mut data = surround(B64_URL, 4);
        data.extend_from_slice(b"\x00H\x00i\x00\x00plain text here\x00");

        let cfg = ExtractConfig::default();
        let (strings_new, _) = extract_strings_with_blobs(&data, &cfg);
        let strings_old = extract_strings(&data, &cfg);
        assert_eq!(strings_old, strings_new);
        assert!(strings_new.iter().any(|s| s.value.contains("aHR0")));
    }

    #[test]
    fn internal_decoder_roundtrip() {
        for len in 0..48usize {
            let raw: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let enc = b64_encode(&raw);
            let dec = base64_decode(enc.as_bytes()).expect("decode must succeed");
            assert_eq!(dec, raw, "roundtrip failed at len {len}");
        }
        assert_eq!(base64_decode(b"aHR0").as_deref(), Some(&b"htt"[..]));
        assert_eq!(base64_decode(b"aHR").as_deref(), Some(&b"ht"[..]));
        assert_eq!(base64_decode(b"h").as_deref(), Some(&b""[..]));
    }

    #[test]
    fn entropy_helper_sanity() {
        assert_eq!(shannon_entropy(b""), 0.0);
        assert_eq!(shannon_entropy(b"aaaa"), 0.0);
        let two = shannon_entropy(b"aabb");
        assert!((two - 1.0).abs() < 1e-6);
        assert!(shannon_entropy(&pseudo_random(1, 512)) > 7.0);
    }
}
