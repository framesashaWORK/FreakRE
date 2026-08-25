//! # Entropy Mapper Plugin
//!
//! Maps entropy across the entire binary in sliding windows, identifies
//! packed/encrypted regions, and annotates them in the project database.
//! Essential for finding hidden payloads, encrypted resources, and packer stubs.

use plugins::{Plugin, PluginContext, PluginMetadata, MenuItem};
use crate::util;

const WINDOW_SIZE: usize = 256;
const STEP_SIZE: usize = 128;
/// Entropy threshold above which a region is considered packed/encrypted
const HIGH_ENTROPY_THRESHOLD: f64 = 7.0;
/// Very high entropy — likely compressed or encrypted
const VERY_HIGH_ENTROPY_THRESHOLD: f64 = 7.5;
/// Very low entropy — padding, zeros, or repetitive data
const LOW_ENTROPY_THRESHOLD: f64 = 1.0;

pub struct EntropyMapperPlugin;
impl Default for EntropyMapperPlugin { fn default() -> Self { Self } }

/// A contiguous run of function bytes within the analysis buffer and the
/// virtual address where it actually lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CodeRange {
    /// Offset of the first byte of this function inside the buffer.
    buf_start: usize,
    /// One past the last byte of this function inside the buffer.
    buf_end: usize,
    /// Virtual address corresponding to `buf_start`.
    va: u64,
}

impl CodeRange {
    fn translate(&self, offset: usize) -> Option<u64> {
        if offset >= self.buf_start && offset < self.buf_end {
            Some(self.va + (offset - self.buf_start) as u64)
        } else {
            None
        }
    }
}

/// Translate a buffer offset into a VA via the sorted range list.
///
/// Returns `None` for offsets that fall in a gap between functions (padding
/// the buffer inserted between non-contiguous functions).
fn offset_to_va(ranges: &[CodeRange], offset: usize) -> Option<u64> {
    let idx = ranges.partition_point(|r| r.buf_end <= offset);
    let r = ranges.get(idx)?;
    r.translate(offset)
}

/// Map a whole window `[offset, offset + len)` back to its true VA.
///
/// Returns `None` when the window starts in a gap or spans past its
/// function's end (i.e., crosses a gap into another function): such windows
/// mix bytes from disjoint memory regions and cannot be pinned to one VA.
fn map_window(ranges: &[CodeRange], offset: usize, len: usize) -> Option<u64> {
    let idx = ranges.partition_point(|r| r.buf_end <= offset);
    let r = ranges.get(idx)?;
    if offset < r.buf_start || offset + len > r.buf_end {
        return None;
    }
    Some(r.va + (offset - r.buf_start) as u64)
}

impl Plugin for EntropyMapperPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "Entropy Mapper".into(),
            version: "1.0.0".into(),
            author: Some("FreakRE Team".into()),
            description: "Sliding-window entropy analysis to find packed/encrypted/padding regions.".into(),
            license: Some("MIT".into()),
            homepage: None,
        }
    }
    fn menu_items(&self) -> Vec<MenuItem> {
        vec![MenuItem::new("Analyze/Entropy Map", "Map Binary Entropy").with_shortcut("Ctrl+Shift+E")]
    }
    fn on_menu_item(&mut self, ctx: &mut PluginContext, path: &str) {
        if path == "Analyze/Entropy Map" { self.analyze(ctx); }
    }
    fn analyze(&mut self, ctx: &mut PluginContext) {
        ctx.println("[EntropyMapper] Computing sliding-window entropy...");

        // Get raw binary data from the functions' code bytes as proxy.
        // In production, ProjectDatabase would store the full binary.
        let mut functions = match ctx.db.list_functions() {
            Ok(f) => f, Err(e) => { ctx.println(&format!("Error: {}", e)); return; }
        };

        if functions.is_empty() {
            ctx.println("[EntropyMapper] No functions loaded.");
            return;
        }

        // Concatenate all function bytes into one analysis buffer, but track
        // each function's span within it so buffer offsets can be translated
        // back to true VAs. Functions may be sparse in address space — using a
        // single base_addr + offset would place annotations on wrong addresses.
        functions.sort_by_key(|f| f.address);
        let mut all_code: Vec<u8> = Vec::new();
        let mut ranges: Vec<CodeRange> = Vec::new();
        for func in &functions {
            if let Some(bytes) = &func.code_bytes {
                if bytes.is_empty() { continue; }
                ranges.push(CodeRange {
                    buf_start: all_code.len(),
                    buf_end: all_code.len() + bytes.len(),
                    va: func.address,
                });
                all_code.extend_from_slice(bytes);
            }
        }

        if all_code.len() < WINDOW_SIZE {
            ctx.println("[EntropyMapper] Not enough data for entropy analysis.");
            return;
        }

        let mut high_entropy_regions: Vec<(u64, u64, f64)> = Vec::new();
        let mut low_entropy_regions: Vec<(u64, u64, f64)> = Vec::new();
        let mut max_entropy = 0.0f64;
        let mut min_entropy = 8.0f64;
        let total_windows = (all_code.len() - WINDOW_SIZE) / STEP_SIZE + 1;
        let mut skipped_windows = 0usize;

        for i in 0..total_windows {
            let offset = i * STEP_SIZE;
            let window = &all_code[offset..offset + WINDOW_SIZE];
            let entropy = shannon_entropy(window);

            if entropy > max_entropy { max_entropy = entropy; }
            if entropy < min_entropy { min_entropy = entropy; }

            // Translate the window start through the per-function ranges.
            // Windows that straddle a gap between functions are skipped:
            // their bytes are not contiguous in memory, so annotating any
            // single VA would be misleading.
            match map_window(&ranges, offset, WINDOW_SIZE) {
                Some(abs_addr) => {
                    if entropy >= VERY_HIGH_ENTROPY_THRESHOLD {
                        high_entropy_regions.push((abs_addr, abs_addr + WINDOW_SIZE as u64, entropy));
                    } else if entropy <= LOW_ENTROPY_THRESHOLD {
                        low_entropy_regions.push((abs_addr, abs_addr + WINDOW_SIZE as u64, entropy));
                    }
                }
                None => skipped_windows += 1,
            }
        }

        // Merge adjacent high-entropy regions
        let merged_high = merge_regions(&high_entropy_regions);
        let merged_low = merge_regions(&low_entropy_regions);

        // Annotate in database (never clobbering user labels/comments)
        for (start, end, ent) in &merged_high {
            let label = if *ent >= VERY_HIGH_ENTROPY_THRESHOLD {
                format!("packed_region_{:X}", start)
            } else {
                format!("high_entropy_{:X}", start)
            };
            util::set_label_if_free(&mut ctx.db, *start, label);
            util::upsert_tagged_comment(
                &mut ctx.db,
                *start,
                "[ENTROPY]",
                &format!("[ENTROPY] High entropy region: {:.2} bits/byte (0x{:X}-0x{:X}, {} bytes)",
                    ent, start, end, end - start),
            );
        }

        for (start, end, ent) in &merged_low {
            util::upsert_tagged_comment(
                &mut ctx.db,
                *start,
                "[ENTROPY]",
                &format!("[ENTROPY] Low entropy/padding: {:.2} bits/byte (0x{:X}-0x{:X})",
                    ent, start, end),
            );
        }

        ctx.println(&format!(
            "[EntropyMapper] Analyzed {} windows ({} bytes). Max={:.2}, Min={:.2}",
            total_windows, all_code.len(), max_entropy, min_entropy
        ));
        ctx.println(&format!(
            "[EntropyMapper] Found {} high-entropy region(s), {} low-entropy region(s) ({} window(s) skipped across function gaps)",
            merged_high.len(), merged_low.len(), skipped_windows
        ));

        for (start, end, ent) in &merged_high {
            ctx.println(&format!(
                "  🔴 PACKED: 0x{:X}-0x{:X} ({:.2} bits/byte, {} bytes)",
                start, end, ent, end - start
            ));
        }
    }
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut freq = [0usize; 256];
    for &b in data { freq[b as usize] += 1; }
    let len = data.len() as f64;
    let mut entropy = 0.0f64;
    for &count in &freq {
        if count == 0 { continue; }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

fn merge_regions(regions: &[(u64, u64, f64)]) -> Vec<(u64, u64, f64)> {
    if regions.is_empty() { return Vec::new(); }
    let mut sorted = regions.to_vec();
    sorted.sort_by_key(|r| r.0);
    let mut merged: Vec<(u64, u64, f64)> = vec![sorted[0]];
    for &(start, end, ent) in &sorted[1..] {
        let last = merged.last_mut().unwrap();
        if start <= last.1 + STEP_SIZE as u64 {
            last.1 = last.1.max(end);
            last.2 = last.2.max(ent);
        } else {
            merged.push((start, end, ent));
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_zeros() {
        let data = vec![0u8; 256];
        assert!(shannon_entropy(&data) < 0.01);
    }

    #[test]
    fn test_entropy_uniform() {
        // All 256 byte values equally distributed → max entropy = 8.0
        let mut data = Vec::new();
        for _ in 0..4 {
            for b in 0..=255u8 { data.push(b); }
        }
        let ent = shannon_entropy(&data);
        assert!(ent > 7.9, "Uniform distribution should have ~8.0 entropy, got {}", ent);
    }

    #[test]
    fn test_merge_adjacent() {
        let regions = vec![
            (0x1000, 0x1100, 7.5),
            (0x1100, 0x1200, 7.6),
            (0x2000, 0x2100, 7.3),
        ];
        let merged = merge_regions(&regions);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].0, 0x1000);
        assert_eq!(merged[0].1, 0x1200);
    }

    // ─── Per-function address mapping (sparse functions) ───────────────

    /// Two sparse functions: 512 bytes at 0x1000 and 512 bytes at 0x9000.
    fn sparse_ranges() -> (Vec<u8>, Vec<CodeRange>) {
        let f1 = vec![0x41u8; 512];
        let f2 = vec![0xFFu8; 512];
        let mut buf = Vec::new();
        let ranges = vec![
            CodeRange { buf_start: 0, buf_end: 512, va: 0x1000 },
            CodeRange { buf_start: 512, buf_end: 1024, va: 0x9000 },
        ];
        buf.extend_from_slice(&f1);
        buf.extend_from_slice(&f2);
        (buf, ranges)
    }

    #[test]
    fn test_offset_to_va_uses_per_function_bases() {
        let (_buf, ranges) = sparse_ranges();
        // Old code computed base_addr + offset → buffer offset 600 would map
        // to 0x1258; the true VA is inside the second function at 0x9258.
        assert_eq!(offset_to_va(&ranges, 0), Some(0x1000));
        assert_eq!(offset_to_va(&ranges, 511), Some(0x11FF));
        assert_eq!(offset_to_va(&ranges, 512), Some(0x9000));
        assert_eq!(offset_to_va(&ranges, 600), Some(0x9058)); // 0x9000 + (600-512)
        assert_eq!(offset_to_va(&ranges, 1024), None); // past end
    }

    #[test]
    fn test_map_window_inside_function() {
        let (_buf, ranges) = sparse_ranges();
        // Window fully inside function 2 must map to its real VA.
        assert_eq!(map_window(&ranges, 512 + 128, WINDOW_SIZE), Some(0x9080));
        assert_eq!(map_window(&ranges, 0, WINDOW_SIZE), Some(0x1000));
        // Last window that still fits entirely in function 2:
        // starts at buffer offset 768 → VA 0x9000 + (768-512) = 0x9100
        assert_eq!(map_window(&ranges, 1024 - WINDOW_SIZE, WINDOW_SIZE), Some(0x9100));
    }

    #[test]
    fn test_map_window_spanning_gap_is_skipped() {
        let (_buf, ranges) = sparse_ranges();
        // Window starting at 384 extends to 640 — crosses the boundary
        // between function 1 and function 2 → no single valid VA.
        assert_eq!(map_window(&ranges, 384, WINDOW_SIZE), None);
        // Starts exactly at a gap-less boundary is fine (handled above).
        assert_eq!(map_window(&ranges, 512, WINDOW_SIZE), Some(0x9000));
    }
}
