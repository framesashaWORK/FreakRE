//! gpu-scan: wgpu compute-shader stage for mass byte operations.
//!
//! Scope: windowed entropy map + literal pattern scan on GPU,
//! automatic CPU fallback when no adapter is available.
//!
//! # Design
//!
//! * [`GpuScanner::try_new`] is **headless-safe**: when no GPU adapter can be
//!   obtained it still returns `Ok`, recording a [`FallbackReason`] instead of
//!   erroring, so CI machines without GPUs work out of the box. `Err` is
//!   reserved for truly unexpected initialization failures.
//! * [`GpuScanner::scan_entropy`] mirrors the exact window layout of
//!   `entropy-rs::sliding_window_entropy` (stride-aligned starts plus an extra
//!   tail window anchored at the buffer end) and returns `f32` entropies that
//!   agree with `entropy-rs::calculate_entropy` to within 1e-4.
//! * [`GpuScanner::find_literal`] reports every match offset for a needle of up
//!   to 64 bytes (longer needles transparently use the CPU path), capped at
//!   [`MAX_MATCHES`] stored offsets with an always-exact total count.
//! * Both scan methods silently fall back to the CPU implementations in
//!   [`cpu`] whenever GPU init failed or a runtime GPU error occurred;
//!   [`GpuScanner::is_gpu_active`] reports which path was used.
//!
//! # Example — intended pipeline usage
//!
//! ```
//! use gpu_scan::GpuScanner;
//!
//! # fn main() -> Result<(), gpu_scan::GpuError> {
//! let mut scanner = GpuScanner::try_new()?;
//! println!("gpu active: {}", scanner.is_gpu_active());
//!
//! let blob = std::fs::read("sample_shellcode.bin")?;
//!
//! // Stage 1: flag packed/encrypted regions with windowed entropy.
//! for (offset, entropy) in scanner.scan_entropy(&blob, 256, 128) {
//!     if entropy > 7.2 {
//!         println!("packed region at {offset:#x} ({entropy:.2} bits/byte)");
//!     }
//! }
//!
//! // Stage 2: literal needle scan for a code prologue.
//! let hits = scanner.find_literal(&blob, b"\xFC\x48\x83\xE4\xF0");
//! if hits.truncated {
//!     println!("match cap reached, total = {}", hits.total);
//! }
//! if let Some(first) = hits.offsets.first() {
//!     println!("prologue at {first:#x}");
//! }
//! # Ok(())
//! # }
//! ```

use std::borrow::Cow;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use wgpu::util::DeviceExt;

pub use wgpu::Backends;

mod shaders;

/// Maximum needle length handled by the GPU kernel; longer needles fall back
/// to the CPU path automatically.
pub const MAX_NEEDLE_BYTES: usize = 64;

/// Maximum number of match offsets retained by [`find_literal`].
///
/// The GPU kernel keeps counting matches past this cap (the counter stays
/// exact); only stored offsets are truncated.
///
/// [`find_literal`]: GpuScanner::find_literal
pub const MAX_MATCHES: usize = 4096;

/// Windows dispatched per compute pass (keeps dispatch dimensions and output
/// buffers comfortably inside default device limits).
const ENTROPY_WINDOWS_PER_PASS: usize = 16_384;

/// Error type. Note that "no adapter" is *not* an error: see [`FallbackReason`]
/// and [`GpuScanner::try_new`].
#[derive(Debug)]
pub enum GpuError {
    /// A GPU operation was attempted while the GPU side never initialized or
    /// was deactivated.
    Unavailable,
    /// An adapter existed but the logical device could not be created.
    DeviceRequest(String),
    /// Invalid parameters for a GPU operation.
    InvalidParams(String),
    /// A GPU operation failed at runtime.
    Execution(String),
}

impl fmt::Display for GpuError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GpuError::Unavailable => write!(f, "GPU backend not initialized"),
            GpuError::DeviceRequest(m) => write!(f, "device request failed: {m}"),
            GpuError::InvalidParams(m) => write!(f, "invalid parameters: {m}"),
            GpuError::Execution(m) => write!(f, "GPU execution failed: {m}"),
        }
    }
}

impl std::error::Error for GpuError {}

/// Why the scanner is running on the CPU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FallbackReason {
    /// No compatible GPU adapter was found (typical on headless CI), or GPU
    /// backends were disabled explicitly.
    NoAdapter,
    /// An adapter was found but the logical device could not be created.
    DeviceInitFailed(String),
    /// The GPU side initialized but later failed; permanently deactivated.
    RuntimeFailure(String),
}

/// Result of a literal needle scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LiteralScan {
    /// Match offsets in ascending order, capped at [`MAX_MATCHES`].
    pub offsets: Vec<u32>,
    /// Exact number of matches found (may exceed `offsets.len()`).
    pub total: u32,
    /// True when matches beyond [`MAX_MATCHES`] were dropped from `offsets`.
    pub truncated: bool,
}

/// Reference CPU implementations, also serving as the automatic fallback path.
pub mod cpu {
    use super::{LiteralScan, MAX_MATCHES};

    /// Windowed Shannon entropy matching
    /// `entropy-rs::sliding_window_entropy` exactly (same offsets, same values
    /// narrowed to `f32`).
    pub fn scan_entropy(data: &[u8], window_size: usize, step: usize) -> Vec<(usize, f32)> {
        entropy_rs::sliding_window_entropy(data, window_size, step)
            .map(|(offset, r)| (offset, r.entropy as f32))
            .collect()
    }

    /// Naive literal scan. Empty needles yield no matches by convention.
    pub fn find_literal(data: &[u8], needle: &[u8]) -> LiteralScan {
        if needle.is_empty() || needle.len() > data.len() {
            return LiteralScan::default();
        }
        let mut scan = LiteralScan {
            offsets: Vec::new(),
            total: 0,
            truncated: false,
        };
        for pos in 0..=(data.len() - needle.len()) {
            if &data[pos..pos + needle.len()] == needle {
                scan.total += 1;
                if scan.offsets.len() < MAX_MATCHES {
                    scan.offsets.push(pos as u32);
                }
            }
        }
        scan.truncated = scan.total as usize > scan.offsets.len();
        scan
    }
}

/// Window start offsets replicating `entropy-rs::sliding_window_entropy`:
/// stride-aligned starts plus one tail window anchored at the buffer end when
/// the stride skips it.
fn window_offsets(len: usize, window_size: usize, step: usize) -> Vec<usize> {
    let valid = window_size > 0 && step > 0 && len >= window_size;
    if !valid {
        return Vec::new();
    }
    let last_start = len - window_size;
    let mut offsets: Vec<usize> = (0..=last_start).step_by(step).collect();
    if !last_start.is_multiple_of(step) {
        offsets.push(last_start);
    }
    offsets
}

struct GpuInner {
    device: wgpu::Device,
    queue: wgpu::Queue,
    entropy_pipeline: wgpu::ComputePipeline,
    entropy_bgl: wgpu::BindGroupLayout,
    scan_pipeline: wgpu::ComputePipeline,
    scan_bgl: wgpu::BindGroupLayout,
}

/// GPU-accelerated byte scanner with automatic CPU fallback.
///
/// Cheap to construct on any machine: see [`GpuScanner::try_new`].
pub struct GpuScanner {
    inner: Mutex<Option<GpuInner>>,
    reason: Mutex<Option<FallbackReason>>,
    poisoned: Arc<AtomicBool>,
}

impl GpuScanner {
    /// Initialize a scanner, preferring the GPU and falling back to CPU.
    ///
    /// Headless-safe: with no adapter this returns `Ok` with a recorded
    /// [`FallbackReason::NoAdapter`] and [`is_gpu_active`](Self::is_gpu_active)
    /// == false; scans then run through [`cpu`]. `Err` only surfaces from
    /// unexpected failures.
    ///
    /// Uses `pollster::block_on` internally; do not call from an async context.
    pub fn try_new() -> Result<Self, GpuError> {
        Self::try_new_with_backends(Backends::all())
    }

    /// Like [`try_new`](GpuScanner::try_new) but restricts adapter enumeration
    /// to `backends`. Passing `Backends::empty()` deterministically produces a
    /// CPU-only scanner (useful for tests and opt-out configurations).
    pub fn try_new_with_backends(backends: Backends) -> Result<Self, GpuError> {
        let adapter = if backends.is_empty() {
            log::info!("gpu-scan: GPU backends disabled, using CPU fallback");
            None
        } else {
            let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor::default());
            pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                compatible_surface: None,
                force_fallback_adapter: false,
            }))
        };

        let Some(adapter) = adapter else {
            log::info!("gpu-scan: no compatible GPU adapter found, using CPU fallback");
            return Ok(Self::cpu_only(FallbackReason::NoAdapter));
        };

        let info = adapter.get_info();
        log::info!(
            "gpu-scan: using adapter \"{}\" ({:?}, {:?})",
            info.name,
            info.backend,
            info.device_type
        );

        let (device, queue) =
            match pollster::block_on(adapter.request_device(
                &wgpu::DeviceDescriptor {
                    label: Some("gpu-scan.device"),
                    ..Default::default()
                },
                None,
            )) {
                Ok(pair) => pair,
                Err(e) => {
                    log::warn!("gpu-scan: device request failed ({e}), using CPU fallback");
                    return Ok(Self::cpu_only(FallbackReason::DeviceInitFailed(
                        e.to_string(),
                    )));
                }
            };

        let poisoned = Arc::new(AtomicBool::new(false));
        {
            let poisoned = Arc::clone(&poisoned);
            device.on_uncaptured_error(Box::new(move |err| {
                log::error!("gpu-scan: uncaptured wgpu error: {err}");
                poisoned.store(true, Ordering::SeqCst);
            }));
        }

        let entropy_module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("gpu-scan.windowed_entropy.wgsl"),
            source: wgpu::ShaderSource::Wgsl(Cow::Borrowed(shaders::WINDOWED_ENTROPY_WGSL)),
        });
        let scan_module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("gpu-scan.literal_scan.wgsl"),
            source: wgpu::ShaderSource::Wgsl(Cow::Borrowed(shaders::LITERAL_SCAN_WGSL)),
        });

        let entropy_bgl = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("gpu-scan.entropy.bgl"),
            entries: &[
                storage_entry(0, true),
                uniform_entry(1),
                storage_entry(2, true),
                storage_entry(3, false),
            ],
        });
        let scan_bgl = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("gpu-scan.literal.bgl"),
            entries: &[
                storage_entry(0, true),
                storage_entry(1, true),
                uniform_entry(2),
                storage_entry(3, false),
                storage_entry(4, false),
            ],
        });

        let make_pipeline = |label: &str,
                             module: &wgpu::ShaderModule,
                             bgl: &wgpu::BindGroupLayout| {
            let layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
                label: Some(label),
                bind_group_layouts: &[bgl],
                push_constant_ranges: &[],
            });
            device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
                label: Some(label),
                layout: Some(&layout),
                module,
                entry_point: Some("main"),
                compilation_options: wgpu::PipelineCompilationOptions::default(),
                cache: None,
            })
        };

        let entropy_pipeline =
            make_pipeline("gpu-scan.entropy.pipeline", &entropy_module, &entropy_bgl);
        let scan_pipeline = make_pipeline("gpu-scan.literal.pipeline", &scan_module, &scan_bgl);

        Ok(Self {
            inner: Mutex::new(Some(GpuInner {
                device,
                queue,
                entropy_pipeline,
                entropy_bgl,
                scan_pipeline,
                scan_bgl,
            })),
            reason: Mutex::new(None),
            poisoned,
        })
    }

    /// Build a scanner that never touches the GPU.
    pub fn cpu_only(reason: FallbackReason) -> Self {
        Self {
            inner: Mutex::new(None),
            reason: Mutex::new(Some(reason)),
            poisoned: Arc::new(AtomicBool::new(false)),
        }
    }

    /// True when the GPU backend is initialized and healthy, i.e. scans run on
    /// the compute shaders.
    pub fn is_gpu_active(&self) -> bool {
        let initialized = self.inner.lock().map(|g| g.is_some()).unwrap_or(false);
        initialized && !self.poisoned.load(Ordering::SeqCst)
    }

    /// Why the scanner is (currently) falling back to the CPU, if it is.
    pub fn fallback_reason(&self) -> Option<FallbackReason> {
        self.reason.lock().ok()?.clone()
    }

    fn deactivate(&self, msg: String) {
        if let Ok(mut guard) = self.inner.lock() {
            *guard = None;
        }
        if let Ok(mut reason) = self.reason.lock() {
            *reason = Some(FallbackReason::RuntimeFailure(msg));
        }
    }

    fn active_inner(&self) -> Result<std::sync::MutexGuard<'_, Option<GpuInner>>, GpuError> {
        if self.poisoned.load(Ordering::SeqCst) {
            self.deactivate("uncaptured wgpu error".into());
        }
        let guard = self.inner.lock().map_err(|_| GpuError::Unavailable)?;
        if guard.is_none() {
            return Err(GpuError::Unavailable);
        }
        Ok(guard)
    }

    /// Windowed entropy over `data` (`window_size` bytes advanced by `step`),
    /// mirroring `entropy-rs::sliding_window_entropy` offsets. Uses the GPU
    /// kernel when available, otherwise [`cpu::scan_entropy`]. Either way every
    /// value is within 1e-4 bits/byte of the `entropy-rs` f64 reference.
    pub fn scan_entropy(
        &mut self,
        data: &[u8],
        window_size: usize,
        step: usize,
    ) -> Vec<(usize, f32)> {
        if self.is_gpu_active() {
            match self.gpu_scan_entropy(data, window_size, step) {
                Ok(results) => return results,
                Err(e) => {
                    log::warn!("gpu-scan: entropy scan fell back to CPU: {e}");
                    self.deactivate(e.to_string());
                }
            }
        }
        cpu::scan_entropy(data, window_size, step)
    }

    /// Literal needle scan. Needles of up to [`MAX_NEEDLE_BYTES`] run on the
    /// GPU kernel when available; anything else runs on the CPU. Matches past
    /// [`MAX_MATCHES`] are counted but not stored (`truncated == true`).
    pub fn find_literal(&mut self, data: &[u8], needle: &[u8]) -> LiteralScan {
        if self.is_gpu_active() && !needle.is_empty() && needle.len() <= MAX_NEEDLE_BYTES {
            match self.gpu_find_literal(data, needle) {
                Ok(scan) => return scan,
                Err(e) => {
                    log::warn!("gpu-scan: literal scan fell back to CPU: {e}");
                    self.deactivate(e.to_string());
                }
            }
        }
        cpu::find_literal(data, needle)
    }

    fn gpu_scan_entropy(
        &self,
        data: &[u8],
        window_size: usize,
        step: usize,
    ) -> Result<Vec<(usize, f32)>, GpuError> {
        let guard = self.active_inner()?;
        let gpu = guard.as_ref().expect("active_inner guarantees Some");

        let starts = window_offsets(data.len(), window_size, step);
        if starts.is_empty() {
            return Ok(Vec::new());
        }
        if window_size > u32::MAX as usize {
            return Err(GpuError::InvalidParams("window_size exceeds u32".into()));
        }
        if data.len() > u32::MAX as usize {
            return Err(GpuError::InvalidParams("buffer exceeds u32 length".into()));
        }
        let window_u32 = window_size as u32;

        let padded_len = data.len().div_ceil(4) * 4;
        let mut padded = vec![0u8; padded_len];
        padded[..data.len()].copy_from_slice(data);
        let data_buf = gpu.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("gpu-scan.entropy.data"),
            contents: &padded,
            usage: wgpu::BufferUsages::STORAGE,
        });
        drop(padded);

        let starts_bytes: Vec<u8> = starts.iter().flat_map(|o| (*o as u32).to_le_bytes()).collect();
        let starts_buf = gpu.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("gpu-scan.entropy.starts"),
            contents: &starts_bytes,
            usage: wgpu::BufferUsages::STORAGE,
        });
        drop(starts_bytes);

        let out_buf = gpu.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("gpu-scan.entropy.out"),
            size: (starts.len() * 4) as u64,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });

        let mut results = Vec::with_capacity(starts.len());
        for (chunk_idx, chunk) in starts.chunks(ENTROPY_WINDOWS_PER_PASS).enumerate() {
            let params = params_uniform(chunk.len() as u32, window_u32, 0, 0);
            let params_buf = gpu.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
                label: Some("gpu-scan.entropy.params"),
                contents: &params,
                usage: wgpu::BufferUsages::UNIFORM,
            });

            let base = chunk_idx * ENTROPY_WINDOWS_PER_PASS;
            let bind = gpu.device.create_bind_group(&wgpu::BindGroupDescriptor {
                label: Some("gpu-scan.entropy.bind"),
                layout: &gpu.entropy_bgl,
                entries: &[
                    wgpu::BindGroupEntry {
                        binding: 0,
                        resource: data_buf.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 1,
                        resource: params_buf.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 2,
                        resource: wgpu::BindingResource::Buffer(wgpu::BufferBinding {
                            buffer: &starts_buf,
                            offset: (base * 4) as u64,
                            size: wgpu::BufferSize::new((chunk.len() * 4) as u64),
                        }),
                    },
                    wgpu::BindGroupEntry {
                        binding: 3,
                        resource: wgpu::BindingResource::Buffer(wgpu::BufferBinding {
                            buffer: &out_buf,
                            offset: (base * 4) as u64,
                            size: wgpu::BufferSize::new((chunk.len() * 4) as u64),
                        }),
                    },
                ],
            });

            let mut encoder = gpu
                .device
                .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                    label: Some("gpu-scan.encoder"),
                });
            {
                let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                    label: Some("gpu-scan.entropy.pass"),
                    timestamp_writes: None,
                });
                pass.set_pipeline(&gpu.entropy_pipeline);
                pass.set_bind_group(0, &bind, &[]);
                pass.dispatch_workgroups(chunk.len() as u32, 1, 1);
            }
            gpu.queue.submit([encoder.finish()]);

            let raw =
                read_back(&gpu.device, &gpu.queue, &out_buf, (base * 4) as u64, chunk.len() * 4)?;
            for (i, quad) in raw.chunks_exact(4).enumerate() {
                results.push((
                    starts[base + i],
                    f32::from_le_bytes([quad[0], quad[1], quad[2], quad[3]]),
                ));
            }
        }
        Ok(results)
    }

    fn gpu_find_literal(&self, data: &[u8], needle: &[u8]) -> Result<LiteralScan, GpuError> {
        debug_assert!(!needle.is_empty() && needle.len() <= MAX_NEEDLE_BYTES);
        let guard = self.active_inner()?;
        let gpu = guard.as_ref().expect("active_inner guarantees Some");

        if data.len() < needle.len() || data.len() > u32::MAX as usize {
            return Ok(cpu::find_literal(data, needle));
        }
        let candidates = data.len() - needle.len() + 1;

        let padded_len = data.len().div_ceil(4) * 4;
        let mut padded = vec![0u8; padded_len];
        padded[..data.len()].copy_from_slice(data);
        let data_buf = gpu.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("gpu-scan.lit.data"),
            contents: &padded,
            usage: wgpu::BufferUsages::STORAGE,
        });
        drop(padded);

        let needle_padded = needle.len().div_ceil(4) * 4;
        let mut packed = vec![0u8; needle_padded];
        packed[..needle.len()].copy_from_slice(needle);
        let needle_buf = gpu.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("gpu-scan.lit.needle"),
            contents: &packed,
            usage: wgpu::BufferUsages::STORAGE,
        });
        drop(packed);

        let params = params_uniform(
            data.len() as u32,
            needle.len() as u32,
            MAX_MATCHES as u32,
            0,
        );
        let params_buf = gpu.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("gpu-scan.lit.params"),
            contents: &params,
            usage: wgpu::BufferUsages::UNIFORM,
        });

        let matches_buf = gpu.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("gpu-scan.lit.matches"),
            size: (MAX_MATCHES * 4) as u64,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });
        let count_buf = gpu.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("gpu-scan.lit.count"),
            contents: &0u32.to_le_bytes(),
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
        });

        let threads = shaders::SCAN_WORKGROUP_SIZE as usize;
        let candidates_per_pass = 65_535 * threads;

        let mut encoder = gpu
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("gpu-scan.lit.encoder"),
            });
        let mut done = 0usize;
        while done < candidates {
            let n = (candidates - done).min(candidates_per_pass);
            let bind = gpu.device.create_bind_group(&wgpu::BindGroupDescriptor {
                label: Some("gpu-scan.lit.bind"),
                layout: &gpu.scan_bgl,
                entries: &[
                    wgpu::BindGroupEntry {
                        binding: 0,
                        resource: data_buf.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 1,
                        resource: needle_buf.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 2,
                        resource: params_buf.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 3,
                        resource: matches_buf.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 4,
                        resource: count_buf.as_entire_binding(),
                    },
                ],
            });
            {
                let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                    label: Some("gpu-scan.lit.pass"),
                    timestamp_writes: None,
                });
                pass.set_pipeline(&gpu.scan_pipeline);
                pass.set_bind_group(0, &bind, &[]);
                pass.dispatch_workgroups(n.div_ceil(threads) as u32, 1, 1);
            }
            done += n;
        }
        gpu.queue.submit([encoder.finish()]);

        let count_raw = read_back(&gpu.device, &gpu.queue, &count_buf, 0, 4)?;
        let count = u32::from_le_bytes([count_raw[0], count_raw[1], count_raw[2], count_raw[3]]);
        let keep = (count as usize).min(MAX_MATCHES);
        let matches_raw = if keep == 0 {
            Vec::new()
        } else {
            read_back(&gpu.device, &gpu.queue, &matches_buf, 0, keep * 4)?
        };
        let mut offsets: Vec<u32> = matches_raw
            .chunks_exact(4)
            .map(|q| u32::from_le_bytes([q[0], q[1], q[2], q[3]]))
            .collect();
        offsets.sort_unstable();

        Ok(LiteralScan {
            offsets,
            total: count,
            truncated: count as usize > MAX_MATCHES,
        })
    }
}

fn storage_entry(binding: u32, read_only: bool) -> wgpu::BindGroupLayoutEntry {
    wgpu::BindGroupLayoutEntry {
        binding,
        visibility: wgpu::ShaderStages::COMPUTE,
        ty: wgpu::BindingType::Buffer {
            ty: wgpu::BufferBindingType::Storage { read_only },
            has_dynamic_offset: false,
            min_binding_size: wgpu::BufferSize::new(4),
        },
        count: None,
    }
}

fn uniform_entry(binding: u32) -> wgpu::BindGroupLayoutEntry {
    wgpu::BindGroupLayoutEntry {
        binding,
        visibility: wgpu::ShaderStages::COMPUTE,
        ty: wgpu::BindingType::Buffer {
            ty: wgpu::BufferBindingType::Uniform,
            has_dynamic_offset: false,
            min_binding_size: wgpu::BufferSize::new(16),
        },
        count: None,
    }
}

fn params_uniform(a: u32, b: u32, c: u32, d: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a.to_le_bytes());
    out[4..8].copy_from_slice(&b.to_le_bytes());
    out[8..12].copy_from_slice(&c.to_le_bytes());
    out[12..16].copy_from_slice(&d.to_le_bytes());
    out
}

fn read_back(
    device: &wgpu::Device,
    queue: &wgpu::Queue,
    buf: &wgpu::Buffer,
    offset: u64,
    len_bytes: usize,
) -> Result<Vec<u8>, GpuError> {
    if len_bytes == 0 {
        return Ok(Vec::new());
    }
    let size = len_bytes as u64;
    let staging = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("gpu-scan.staging"),
        size,
        usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });
    let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
        label: Some("gpu-scan.readback.encoder"),
    });
    encoder.copy_buffer_to_buffer(buf, offset, &staging, 0, size);
    queue.submit([encoder.finish()]);

    let slice = staging.slice(..);
    let (tx, rx) = std::sync::mpsc::channel();
    slice.map_async(wgpu::MapMode::Read, move |result| {
        let _ = tx.send(result);
    });
    let _ = device.poll(wgpu::Maintain::Wait);

    rx.recv()
        .map_err(|_| GpuError::Execution("map callback dropped".into()))?
        .map_err(|e| GpuError::Execution(format!("buffer map failed: {e}")))?;

    let view = slice.get_mapped_range();
    let out = view.to_vec();
    drop(view);
    staging.unmap();
    Ok(out)
}
