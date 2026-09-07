//! gpu-scan test suite.
//!
//! GPU-dependent tests detect adapter availability at runtime and skip with a
//! clear log line when none exists (headless-safe); everything else runs
//! everywhere.

use gpu_scan::{cpu, GpuScanner, LiteralScan, MAX_MATCHES};

/// Deterministic xorshift64 pseudo-random bytes (no external deps).
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

/// Returns a GPU-backed scanner or `None`, logging a clear reason on skip.
fn try_gpu() -> Option<GpuScanner> {
    match GpuScanner::try_new() {
        Ok(s) => {
            if s.is_gpu_active() {
                Some(s)
            } else {
                eprintln!(
                    "[gpu-scan][skip] no active GPU adapter (reason: {:?}) — skipping GPU-dependent test",
                    s.fallback_reason()
                );
                None
            }
        }
        Err(e) => {
            eprintln!("[gpu-scan][skip] GPU init failed ({e}) — skipping GPU-dependent test");
            None
        }
    }
}

fn cpu_only_scanner() -> GpuScanner {
    GpuScanner::try_new_with_backends(gpu_scan::Backends::empty())
        .expect("CPU-only construction cannot fail")
}

/// Serialize GPU-body tests: parallel `wgpu` device init + dispatch from one
/// process contends badly (multi-minute stalls observed with default test
/// threads on real hardware). CPU-only tests stay parallel; every `gpu_*`
/// test holds this guard for its whole body.
static GPU_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_gpu() -> std::sync::MutexGuard<'static, ()> {
    GPU_SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

// ── Fallback / API behavior (headless-safe) ─────────────────────────

#[test]
fn empty_backends_yield_cpu_fallback_scanner() {
    let mut s = cpu_only_scanner();
    assert!(!s.is_gpu_active());
    assert_eq!(
        s.fallback_reason(),
        Some(gpu_scan::FallbackReason::NoAdapter)
    );

    let data = deterministic_buffer(4096);
    let got = s.scan_entropy(&data, 256, 128);
    let want = cpu::scan_entropy(&data, 256, 128);
    assert_eq!(got.len(), want.len());
    for ((go, ge), (wo, we)) in got.iter().zip(&want) {
        assert_eq!(go, wo);
        assert_eq!(ge.to_bits(), we.to_bits());
    }

    let needle = b"\xDE\xAD\xBE\xEF";
    let mut data2 = deterministic_buffer(2048);
    data2[100..104].copy_from_slice(needle);
    data2[1500..1504].copy_from_slice(needle);
    let got = s.find_literal(&data2, needle);
    let want = cpu::find_literal(&data2, needle);
    assert_eq!(got, want);
}

#[test]
fn cpu_entropy_matches_entropy_rs_reference_bit_exact() {
    let data = deterministic_buffer(8192);
    for &(window, step) in &[
        (256usize, 128usize),
        (256, 300), // stride skips the tail offset
        (1024, 512),
        (300, 500),
    ] {
        let ours = cpu::scan_entropy(&data, window, step);
        let reference: Vec<(usize, f32)> = entropy_rs::sliding_window_entropy(&data, window, step)
            .map(|(o, r)| (o, r.entropy as f32))
            .collect();
        assert_eq!(ours.len(), reference.len(), "w={window} s={step}");
        for ((oo, oe), (ro, re)) in ours.iter().zip(&reference) {
            assert_eq!(oo, ro, "offset layout w={window} s={step}");
            assert_eq!(oe.to_bits(), re.to_bits());
        }
    }
}

#[test]
fn cpu_entropy_invalid_params_return_empty() {
    let data = deterministic_buffer(512);
    assert!(cpu::scan_entropy(&data, 0, 1).is_empty());
    assert!(cpu::scan_entropy(&data, 256, 0).is_empty());
    assert!(cpu::scan_entropy(b"tiny", 16, 1).is_empty());
}

#[test]
fn entropy_extremes_match_reference_within_tolerance() {
    let zeros = vec![0u8; 4096];
    let uniform: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    for data in [&zeros, &uniform] {
        let got = cpu::scan_entropy(data, 256, 128);
        for (off, e) in got {
            let reference = entropy_rs::calculate_entropy(&data[off..off + 256]);
            assert!(
                (e - reference.entropy as f32).abs() <= 1e-4,
                "off={off} gpu={} ref={}",
                e,
                reference.entropy
            );
        }
    }
}

#[test]
fn cpu_find_literal_edge_cases() {
    // Empty needle convention.
    assert_eq!(cpu::find_literal(b"abc", b""), LiteralScan::default());
    // Needle longer than data.
    assert_eq!(cpu::find_literal(b"ab", b"abc"), LiteralScan::default());
    // Needle == data.
    let scan = cpu::find_literal(b"needle", b"needle");
    assert_eq!(scan.offsets, vec![0]);
    assert_eq!(scan.total, 1);
    // Match at the very last possible position.
    let scan = cpu::find_literal(b"xxhaystack", b"stack");
    assert_eq!(scan.offsets, vec![5]);
    // Overlapping matches all found.
    let scan = cpu::find_literal(b"AAAA", b"AA");
    assert_eq!(scan.offsets, vec![0, 1, 2]);
    assert_eq!(scan.total, 3);
    assert!(!scan.truncated);
    // Single byte needle.
    let scan = cpu::find_literal(&[7u8, 0, 7, 7], &[7u8]);
    assert_eq!(scan.offsets, vec![0, 2, 3]);
}

#[test]
fn cpu_find_literal_respects_cap_and_reports_exact_total() {
    let pattern = [0xAAu8, 0xBB];
    let data = vec![pattern.as_slice(); MAX_MATCHES + 50].concat();
    let scan = cpu::find_literal(&data, &pattern);
    assert_eq!(scan.offsets.len(), MAX_MATCHES);
    assert_eq!(scan.total as usize, MAX_MATCHES + 50);
    assert!(scan.truncated);
    assert!(
        scan.offsets.windows(2).all(|w| w[1] > w[0]),
        "offsets ascending"
    );
}

#[test]
fn cpu_find_masked_matches_wildcards_and_overlaps() {
    let pattern = [0xAA, 0x00, 0xCC];
    let mask = [0xFF, 0x00, 0xFF];
    let scan = cpu::find_masked(&[0xAA, 1, 0xCC, 0xAA, 2, 0xCC], &pattern, &mask);

    assert_eq!(scan.offsets, vec![0, 3]);
    assert_eq!(scan.total, 2);
    assert!(!scan.truncated);

    let scan = cpu::find_masked(b"AAAA", b"AA", &[0xFF, 0]);
    assert_eq!(scan.offsets, vec![0, 1, 2]);
}

#[test]
fn cpu_find_masked_empty_and_bounds_return_no_matches() {
    assert_eq!(cpu::find_masked(b"abc", b"", &[]), LiteralScan::default());
    assert_eq!(cpu::find_masked(b"abc", b"a", &[]), LiteralScan::default());
    assert_eq!(
        cpu::find_masked(b"a", b"ab", &[0xFF, 0xFF]),
        LiteralScan::default()
    );
    assert_eq!(
        cpu::find_masked(b"abc", b"abcd", &[0xFF; 4]),
        LiteralScan::default()
    );
}

#[test]
fn cpu_find_masked_respects_cap_and_reports_exact_total() {
    let pattern = [0xAA, 0xBB, 0xCC];
    let mask = [0xFF, 0x00, 0xFF];
    let data = vec![pattern.as_slice(); MAX_MATCHES + 50].concat();
    let scan = cpu::find_masked(&data, &pattern, &mask);

    assert_eq!(scan.offsets.len(), MAX_MATCHES);
    assert_eq!(scan.total as usize, MAX_MATCHES + 50);
    assert!(scan.truncated);
}

#[test]
fn scanner_find_masked_uses_exact_cpu_fallback() {
    let mut scanner = cpu_only_scanner();
    let pattern = [0x10, 0x00, 0x30];
    let mask = [0xFF, 0x00, 0xFF];
    assert_eq!(
        scanner.find_masked(b"\x10\xFF\x30\x10\x00\x31", &pattern, &mask),
        cpu::find_masked(b"\x10\xFF\x30\x10\x00\x31", &pattern, &mask)
    );
}

// ── GPU kernels (runtime-detected; skip cleanly without an adapter) ──

/// Property test: kernel A vs `entropy-rs` on random buffers whose window
/// count/length cross workgroup boundaries, including the tail window.
#[test]
fn gpu_windowed_entropy_matches_cpu_within_1e4() {
    let _gpu = lock_gpu();
    let Some(mut scanner) = try_gpu() else { return };

    // ~100 KiB: 99_744 % 128 != 0 → tail window exercised; window starts cross
    // workgroup boundaries throughout.
    let data = deterministic_buffer(100_000);
    let cases: &[(usize, usize)] = &[(256, 128), (256, 256), (512, 333)];

    for &(window, step) in cases {
        let gpu_out = scanner.scan_entropy(&data, window, step);
        let reference: Vec<(usize, f64)> = entropy_rs::sliding_window_entropy(&data, window, step)
            .map(|(o, r)| (o, r.entropy))
            .collect();

        assert_eq!(
            gpu_out.len(),
            reference.len(),
            "window count w={window} s={step}"
        );
        for ((g_off, g_ent), (r_off, r_ent)) in gpu_out.iter().zip(&reference) {
            assert_eq!(g_off, r_off, "offset layout w={window} s={step}");
            let diff = (*g_ent - *r_ent as f32).abs();
            assert!(
                diff <= 1e-4,
                "w={window} s={step} off={r_off}: gpu={g_ent} cpu={r_ent} |d|={diff}"
            );
        }
    }
}

#[test]
fn gpu_entropy_handles_unaligned_lengths_and_extremes() {
    let _gpu = lock_gpu();
    let Some(mut scanner) = try_gpu() else { return };

    // Lengths not multiples of 4 exercise the padding path.
    for len in [257usize, 1000, 1023, 4097] {
        let data = deterministic_buffer(len);
        let gpu_out = scanner.scan_entropy(&data, 256, 128);
        for (off, g) in gpu_out {
            let r = entropy_rs::calculate_entropy(&data[off..off + 256]).entropy as f32;
            assert!((g - r).abs() <= 1e-4, "len={len} off={off}: {g} vs {r}");
        }
    }

    // Extremes: all-zero ≈ 0 bits, full-cycle uniform ≈ 8 bits.
    let zeros = vec![0u8; 2048];
    for (_, e) in scanner.scan_entropy(&zeros, 256, 128) {
        assert!(e.abs() < 1e-4);
    }
    let uniform: Vec<u8> = (0..=255u8).cycle().take(2048).collect();
    for (_, e) in scanner.scan_entropy(&uniform, 256, 128) {
        assert!((e - 8.0).abs() <= 1e-4, "uniform window measured {e}");
    }
}

/// Kernel B: planted needles at workgroup-stride edge positions plus random
/// locations; results must equal the CPU reference exactly.
#[test]
fn gpu_find_literal_planted_matches_at_stride_edges() {
    let _gpu = lock_gpu();
    let Some(mut scanner) = try_gpu() else { return };

    let needle: &[u8] = b"\x90\xFC\x48\x83\xE4";
    let mut data = deterministic_buffer(10_000);

    // Plant at positions straddling every 64-thread workgroup boundary and at
    // buffer edges, never overlapping a previous plant (overlaps would destroy
    // earlier matches and muddy the bookkeeping; kernel correctness is anyway
    // asserted via equality with the CPU reference on the final bytes).
    let mut reserved = vec![false; data.len()];
    let plant_at = |data: &mut Vec<u8>, reserved: &mut [bool], pos: usize| -> Option<usize> {
        if pos + needle.len() > data.len() || reserved[pos..pos + needle.len()].iter().any(|&r| r) {
            return None;
        }
        data[pos..pos + needle.len()].copy_from_slice(needle);
        for r in &mut reserved[pos..pos + needle.len()] {
            *r = true;
        }
        Some(pos)
    };

    let mut planted = Vec::new();
    for k in 0..(10_000 / 64) {
        let base = (k * 64) as i64;
        for delta in [-1i64, 0, 1] {
            let pos = base + delta;
            if pos >= 0 {
                if let Some(p) = plant_at(&mut data, &mut reserved, pos as usize) {
                    planted.push(p);
                }
            }
        }
    }
    // Position 0 was already planted by the stride loop above (k=0, delta=0);
    // only the tail edge still needs an explicit plant.
    planted.push(
        plant_at(&mut data, &mut reserved, 10_000 - needle.len())
            .expect("last position plants cleanly"),
    );
    planted.sort_unstable();
    planted.dedup();

    let scan = scanner.find_literal(&data, needle);
    let expected = cpu::find_literal(&data, needle);
    assert_eq!(scan, expected, "GPU must match naive CPU scan exactly");
    assert!(!scan.truncated);
    assert!(scan.total >= planted.len() as u32);
    for p in planted {
        assert!(
            scan.offsets.binary_search(&(p as u32)).is_ok(),
            "planted match at {p} missing from {:#x?}",
            scan.offsets
        );
    }

    // Single-byte needle across the whole buffer.
    assert_eq!(
        scanner.find_literal(&data, b"\x90"),
        cpu::find_literal(&data, b"\x90")
    );

    // Needle equal to the whole (small) buffer.
    let whole: Vec<u8> = data[..64].to_vec();
    let scan = scanner.find_literal(&whole, &whole);
    assert_eq!(scan.offsets, vec![0]);
}

#[test]
fn gpu_find_literal_cap_behavior_matches_cpu() {
    let _gpu = lock_gpu();
    let Some(mut scanner) = try_gpu() else { return };
    let pattern = [0xCAu8, 0xFE];
    let data = vec![pattern.as_slice(); MAX_MATCHES + 10].concat();

    let gpu_scan = scanner.find_literal(&data, &pattern);
    let cpu_scan = cpu::find_literal(&data, &pattern);

    // Totals and cap behavior must agree exactly.
    assert_eq!(gpu_scan.total, cpu_scan.total);
    assert_eq!(gpu_scan.total as usize, MAX_MATCHES + 10);
    assert!(gpu_scan.truncated && cpu_scan.truncated);
    assert_eq!(gpu_scan.offsets.len(), MAX_MATCHES);

    // Which offsets survive truncation is scheduler-dependent on GPU, so
    // compare as sets: every reported offset must be a genuine match.
    let mut sorted = gpu_scan.offsets.clone();
    sorted.sort_unstable();
    assert!(sorted.windows(2).all(|w| w[0] < w[1]), "no duplicates");
    for off in &sorted {
        assert_eq!(&data[*off as usize..*off as usize + 2], &pattern);
    }
}

#[test]
fn gpu_scanner_reports_active_and_reason_is_none() {
    let _gpu = lock_gpu();
    let Some(mut scanner) = try_gpu() else { return };
    assert_eq!(scanner.fallback_reason(), None);

    // A successful GPU run keeps the backend active.
    let data = deterministic_buffer(4096);
    let _ = scanner.scan_entropy(&data, 256, 128);
    let _ = scanner.find_literal(&data, b"abc");
    assert!(scanner.is_gpu_active());
}
