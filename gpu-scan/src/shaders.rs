//! WGSL compute kernels for `gpu-scan`.
//!
//! ## Kernel A — `windowed_entropy`
//! One **workgroup per window** (workgroup size 256 == histogram size).
//! Phase 1: the workgroup cooperatively zeroes a `var<workgroup>`
//! `array<atomic<u32>, 256>` histogram. Phase 2: each invocation atomically
//! increments the bucket of its strided share of the window's bytes (bytes are
//! unpacked from the `array<u32>` data buffer with shift/mask, so inputs of any
//! length work). After a barrier, invocation 0 sums `-p * log2(p)` over the
//! buckets **serially**, in ascending bucket order — mirroring
//! `entropy-rs::calculate_entropy`'s summation order so the f32 result stays
//! within 1e-4 of the f64 CPU value.
//!
//! ## Kernel B — `literal_scan`
//! Naive per-thread compare: one invocation per candidate position
//! (`data_len - needle_len + 1` positions, workgroup size 64). Each invocation
//! compares up to 64 needle bytes; on a full match it claims a slot with
//! `atomicAdd` on a shared counter and appends its offset to a capped output
//! array (slots past the cap bump the counter but write nothing, so the total
//! match count is always exact even when results are truncated).

/// Workgroup size of kernel B.
pub const SCAN_WORKGROUP_SIZE: u32 = 64;

pub const WINDOWED_ENTROPY_WGSL: &str = r#"
struct EntropyParams {
    num_windows: u32,
    window_size: u32,
    _pad0: u32,
    _pad1: u32,
};

@group(0) @binding(0) var<storage, read> data : array<u32>;
@group(0) @binding(1) var<uniform> params : EntropyParams;
@group(0) @binding(2) var<storage, read> window_starts : array<u32>;
@group(0) @binding(3) var<storage, read_write> entropies : array<f32>;

var<workgroup> hist : array<atomic<u32>, 256>;

fn load_byte(i : u32) -> u32 {
    return (data[i >> 2u] >> ((i & 3u) << 3u)) & 0xFFu;
}

@compute @workgroup_size(256)
fn main(@builtin(workgroup_id) wid : vec3<u32>,
        @builtin(local_invocation_index) lii : u32) {
    let w = wid.x;
    if (w >= params.num_windows) {
        return;
    }

    hist[lii] = 0u;
    workgroupBarrier();

    let start = window_starts[w];
    var i = lii;
    while (i < params.window_size) {
        let b = load_byte(start + i);
        atomicAdd(&hist[b], 1u);
        i = i + 256u;
    }
    workgroupBarrier();

    if (lii == 0u) {
        var e = 0.0;
        let n = f32(params.window_size);
        for (var b = 0u; b < 256u; b = b + 1u) {
            let c = atomicLoad(&hist[b]);
            if (c != 0u) {
                let p = f32(c) / n;
                e = e - p * log2(p);
            }
        }
        entropies[w] = e;
    }
}
"#;

pub const LITERAL_SCAN_WGSL: &str = r#"
struct ScanParams {
    data_bytes: u32,
    needle_bytes: u32,
    max_matches: u32,
    _pad: u32,
};

@group(0) @binding(0) var<storage, read> data : array<u32>;
@group(0) @binding(1) var<storage, read> needle_words : array<u32>;
@group(0) @binding(2) var<uniform> sp : ScanParams;
@group(0) @binding(3) var<storage, read_write> match_offsets : array<u32>;
@group(0) @binding(4) var<storage, read_write> match_count : array<atomic<u32>, 1>;

fn data_byte(i : u32) -> u32 {
    return (data[i >> 2u] >> ((i & 3u) << 3u)) & 0xFFu;
}

fn needle_byte(i : u32) -> u32 {
    return (needle_words[i >> 2u] >> ((i & 3u) << 3u)) & 0xFFu;
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid : vec3<u32>) {
    let pos = gid.x;
    let last = sp.data_bytes - sp.needle_bytes;
    if (pos > last) {
        return;
    }

    var matched = true;
    var j = 0u;
    while (j < sp.needle_bytes) {
        if (data_byte(pos + j) != needle_byte(j)) {
            matched = false;
            break;
        }
        j = j + 1u;
    }

    if (matched) {
        let slot = atomicAdd(&match_count[0], 1u);
        if (slot < sp.max_matches) {
            match_offsets[slot] = pos;
        }
    }
}
"#;
