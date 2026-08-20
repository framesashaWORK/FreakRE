//! # Entropy Mapper Plugin
//!
//! Maps entropy across the entire binary in sliding windows, identifies
//! packed/encrypted regions, and annotates them in the project database.
//! Essential for finding hidden payloads, encrypted resources, and packer stubs.

use plugins::{Plugin, PluginContext, PluginMetadata, MenuItem};

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

        // Get raw binary data from the first function's code bytes as proxy
        // In production, ProjectDatabase would store the full binary
        let functions = match ctx.db.list_functions() {
            Ok(f) => f, Err(e) => { ctx.println(&format!("Error: {}", e)); return; }
        };

        if functions.is_empty() {
            ctx.println("[EntropyMapper] No functions loaded.");
            return;
        }

        // Collect all code bytes into a contiguous buffer for analysis
        let mut all_code: Vec<u8> = Vec::new();
        let mut base_addr: u64 = u64::MAX;
        for func in &functions {
            if func.address < base_addr { base_addr = func.address; }
            if let Some(ref bytes) = func.code_bytes {
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

        for i in 0..total_windows {
            let offset = i * STEP_SIZE;
            let window = &all_code[offset..offset + WINDOW_SIZE];
            let entropy = shannon_entropy(window);

            if entropy > max_entropy { max_entropy = entropy; }
            if entropy < min_entropy { min_entropy = entropy; }

            let abs_addr = base_addr + offset as u64;

            if entropy >= VERY_HIGH_ENTROPY_THRESHOLD {
                high_entropy_regions.push((abs_addr, abs_addr + WINDOW_SIZE as u64, entropy));
            } else if entropy <= LOW_ENTROPY_THRESHOLD {
                low_entropy_regions.push((abs_addr, abs_addr + WINDOW_SIZE as u64, entropy));
            }
        }

        // Merge adjacent high-entropy regions
        let merged_high = merge_regions(&high_entropy_regions);
        let merged_low = merge_regions(&low_entropy_regions);

        // Annotate in database
        for (start, end, ent) in &merged_high {
            let label = if *ent >= VERY_HIGH_ENTROPY_THRESHOLD {
                format!("packed_region_{:X}", start)
            } else {
                format!("high_entropy_{:X}", start)
            };
            let _ = ctx.db.set_label(*start, label);
            let _ = ctx.db.set_comment(
                *start,
                format!("[ENTROPY] High entropy region: {:.2} bits/byte (0x{:X}-0x{:X}, {} bytes)",
                    ent, start, end, end - start),
            );
        }

        for (start, end, ent) in &merged_low {
            let _ = ctx.db.set_comment(
                *start,
                format!("[ENTROPY] Low entropy/padding: {:.2} bits/byte (0x{:X}-0x{:X})",
                    ent, start, end),
            );
        }

        ctx.println(&format!(
            "[EntropyMapper] Analyzed {} windows ({} bytes). Max={:.2}, Min={:.2}",
            total_windows, all_code.len(), max_entropy, min_entropy
        ));
        ctx.println(&format!(
            "[EntropyMapper] Found {} high-entropy region(s), {} low-entropy region(s)",
            merged_high.len(), merged_low.len()
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
}
