//! String recovery from emulator-written memory.
//!
//! The typical dynamic-analysis loop for packed / XOR-encoded payloads:
//! run the stub under [`crate::Emulator`], then sweep every guest-written
//! region for freshly materialised strings. Anything found here did not
//! exist in the static image — it was *decrypted or decompressed at run
//! time*, which is precisely what analysts (and detectors) care about.

use str_extract::{extract_strings, ExtractConfig};

use crate::env::EmuEnv;
use crate::exec::Emulator;

/// Per-region scan cap: a runaway stub scribbling gigabytes must not turn
/// recovery into an OOM. Regions are truncated, never skipped outright.
pub const MAX_REGION_SCAN: u64 = 1 << 20;

/// One string recovered from guest-written memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredString {
    /// Guest VA where the string starts.
    pub address: u64,
    /// Decoded text.
    pub text: String,
    /// How it was encoded in guest memory.
    pub encoding: str_extract::Encoding,
}

/// Sweep all [`crate::Memory::written_regions`] of `emu` for strings of at
/// least `min_len` characters. Results are sorted by address.
///
/// Only memory the guest *wrote* is scanned, so static image strings never
/// pollute the output: every hit is runtime-produced by definition.
pub fn recover_written_strings<E: EmuEnv>(
    emu: &Emulator<E>,
    min_len: usize,
) -> Vec<RecoveredString> {
    let cfg = ExtractConfig::windows_pe(min_len);
    let mut out = Vec::new();
    for region in emu.memory().written_regions() {
        let len = region.len.min(MAX_REGION_SCAN) as usize;
        if len == 0 {
            continue;
        }
        let mut buf = vec![0u8; len];
        emu.memory().read_bytes(region.start, &mut buf);
        for s in extract_strings(&buf, &cfg) {
            out.push(RecoveredString {
                address: region.start.wrapping_add(s.offset as u64),
                text: s.value,
                encoding: s.encoding,
            });
        }
    }
    out.sort_by_key(|s| s.address);
    out
}
