//! Criterion benchmarks for freakre-scanner hot paths.
//!
//! Usage:
//!   cargo bench -p scanner -- --quick     # fast pass (small sample size/time)
//!   cargo bench -p scanner -- <filter>    # e.g. `cargo bench -p scanner -- backdoor`
//!
//! All synthetic buffers are built from a seeded LCG (no rand dependency),
//! so numbers are comparable across runs and machines.

use criterion::{black_box, Criterion};
use std::sync::LazyLock;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Deterministic buffer generation (seeded LCG, no external rng)
// ---------------------------------------------------------------------------

struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        // Knuth MMIX constants
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn fill_bytes(&mut self, buf: &mut [u8]) {
        let mut chunk = self.next_u64();
        for (i, b) in buf.iter_mut().enumerate() {
            if i % 8 == 0 {
                chunk = self.next_u64();
            }
            *b = (chunk >> ((i % 8) * 8)) as u8;
        }
    }
}

/// Minimal but structurally valid PE32+ header:
/// DOS header (`MZ`, e_lfanew -> `PE\0\0`) + COFF header + PE32+ optional magic.
fn minimal_pe_header() -> Vec<u8> {
    let mut buf = vec![0u8; 512];
    buf[0..2].copy_from_slice(b"MZ");

    const PE_OFF: usize = 0x40;
    buf[0x3C..0x40].copy_from_slice(&(PE_OFF as u32).to_le_bytes());
    buf[PE_OFF..PE_OFF + 4].copy_from_slice(b"PE\0\0");

    // COFF file header (20 bytes)
    let coff = PE_OFF + 4;
    buf[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // x64
    buf[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes()); // section count
    buf[coff + 8..coff + 12].copy_from_slice(&0xDEADBEEFu32.to_le_bytes()); // timestamp
    buf[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes()); // size of optional header
    buf[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes()); // characteristics

    // Optional header: PE32+ magic 0x20B at PE_OFF+24 (what detect_file_type reads)
    let opt = coff + 20;
    buf[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
    buf[opt + 2] = 14; // linker major version
    buf[opt + 3] = 29; // linker minor version

    buf
}

const KIB: usize = 1024;

static ENTROPY_BUF: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let mut buf = vec![0u8; 256 * KIB];
    Lcg::new(0x5EED_0001).fill_bytes(&mut buf);
    buf
});

static MB_BUF: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let mut buf = vec![0u8; 1024 * KIB];
    Lcg::new(0x5EED_0002).fill_bytes(&mut buf);
    buf
});

/// 1 MiB of junk interleaved with null-terminated printable strings,
/// mirroring realistic binary string density for str-extract.
static STRING_BUF: LazyLock<Vec<u8>> = LazyLock::new(|| {
    const LITERALS: &[&[u8]] = &[
        b"kernel32.dll",
        b"C:\\Windows\\System32\\ntdll.dll",
        b"https://update.vendor-cdn.com/payload.bin",
        b"CreateRemoteThread failed with error code",
        b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        b"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
        b"This program cannot be run in DOS mode",
        b"cmd.exe /c powershell -nop -w hidden -enc",
    ];
    let len = 1024 * KIB;
    let mut buf = vec![0u8; len];
    Lcg::new(0x5EED_0003).fill_bytes(&mut buf);
    let mut off = 64;
    let mut i = 0usize;
    while off + 128 < len {
        let lit = LITERALS[i % LITERALS.len()];
        let end = (off + lit.len()).min(off + 120);
        buf[off..end].copy_from_slice(&lit[..end - off]);
        buf[end] = 0;
        i += 1;
        off += 128;
    }
    buf
});

/// 500 import names: real hot APIs mixed with filler, sized to exercise the
/// HashSet-based signature lookup in backdoor-analyzer.
static IMPORTS: LazyLock<Vec<String>> = LazyLock::new(|| {
    const REAL_APIS: &[&str] = &[
        "CreateProcessA",
        "CreateProcessW",
        "WinExec",
        "ShellExecuteA",
        "system",
        "VirtualAlloc",
        "VirtualAllocEx",
        "VirtualProtect",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "CreateRemoteThread",
        "SetWindowsHookExA",
        "GetAsyncKeyState",
        "socket",
        "connect",
        "send",
        "recv",
        "WSASocketA",
        "InternetOpenA",
        "InternetOpenUrlA",
        "HttpSendRequestA",
        "URLDownloadToFileA",
        "RegSetValueExA",
        "RegCreateKeyExA",
        "CryptEncrypt",
        "CryptAcquireContextA",
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "LoadLibraryA",
        "GetProcAddress",
        "SetThreadContext",
        "CreateServiceA",
    ];
    let mut v = Vec::with_capacity(500);
    for i in 0..500 {
        if i % 8 == 0 {
            v.push(REAL_APIS[(i / 8) % REAL_APIS.len()].to_string());
        } else {
            v.push(format!("ordinal_func_{i}"));
        }
    }
    v
});

/// 2000 extracted strings, mostly benign with periodic suspicious hits —
/// the input shape analyze_backdoors sees after str-extract on a real sample.
static BD_STRINGS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let mut v = Vec::with_capacity(2000);
    for i in 0..2000 {
        match i % 25 {
            0 => v.push("cmd.exe /c powershell -nop -w hidden -enc".to_string()),
            13 => v.push("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string()),
            _ => match i % 5 {
                0 => v.push(format!("C:\\Program Files\\Vendor{0}\\bin{0}.dll", i % 97)),
                1 => v.push(format!("HKCU\\Software\\Vendor{}\\Config", i % 89)),
                2 => v.push(format!("http://cdn.vendor{}.com/update.bin", i % 71)),
                3 => v.push(format!("log_{:04}.txt", i % 1009)),
                _ => v.push(format!("str_{i}_padding_padding_padding")),
            },
        }
    }
    v
});
static BD_STRING_REFS: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| BD_STRINGS.iter().map(|s| s.as_str()).collect());

/// 1 MiB pseudorandom buffer with planted literal/hex hits for every rule below.
static YARA_BUF: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let mut buf = vec![0u8; 1024 * KIB];
    Lcg::new(0x5EED_0004).fill_bytes(&mut buf);

    let plants: &[&[u8]] = &[
        b"This program cannot be run in DOS mode\r\n$",                       // BenchDosStub
        b"https://malware.example-c2.net/gate.php",                          // BenchC2Gate ($gate)
        b"MOZILLA/4.0 (COMPATIBLE; MSIE)",                                   // BenchC2Gate ($ua, nocase)
        &[0x4D, 0x5A, 0xA7, 0x90, 0x00, 0x3C, 0xBB, 0xCC],                   // BenchMzPrologue hex
        b"software\\microsoft\\windows\\currentversion\\run",                // BenchRunKey (nocase)
    ];
    let mut off = 0x10_000;
    for p in plants {
        buf[off..off + p.len()].copy_from_slice(p);
        off += 0x30_000;
        if off + 256 >= buf.len() {
            break;
        }
    }
    buf
});

const YARA_RULES: &str = r#"rule BenchDosStub
{
    strings:
        $dos = "This program cannot be run in DOS mode" ascii
    condition:
        $dos
}

rule BenchC2Gate
{
    strings:
        $gate = "https://malware.example-c2.net/gate.php" ascii
        $ua = "mozilla/4.0 (compatible; msie)" nocase
    condition:
        $gate or $ua
}

rule BenchMzPrologue
{
    strings:
        $prologue = { 4D 5A ?? 90 00 ?? ?? CC }
    condition:
        $prologue
}

rule BenchRunKey
{
    strings:
        $run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase
    condition:
        $run
}
"#;

// ---------------------------------------------------------------------------
// Benchmark groups
// ---------------------------------------------------------------------------

fn bench_detect_file_type(c: &mut Criterion) {
    use freakre_scanner::scanner::detect_file_type;

    let pe = minimal_pe_header();
    let mut unknown = vec![0u8; 256];
    Lcg::new(0x5EED_0005).fill_bytes(&mut unknown);

    let mut g = c.benchmark_group("detect_file_type");
    assert_eq!(detect_file_type(&pe), "PE32+");
    g.bench_function("pe32plus_header", |b| {
        b.iter(|| detect_file_type(black_box(&pe)))
    });
    // Worst case: no early-exit magic matches, full fall-through chain.
    g.bench_function("unknown_fallthrough", |b| {
        b.iter(|| detect_file_type(black_box(&unknown)))
    });
    g.finish();
}

fn bench_entropy_section_map(c: &mut Criterion) {
    // Mirrors the per-section loop in Scanner::scan_file, which calls
    // entropy_rs::calculate_entropy on every section's raw data followed by
    // classify_section. Scanner exposes no narrower wrapper for this path.
    let mut g = c.benchmark_group("entropy_section_map");
    g.bench_function("random_256k_classify", |b| {
        b.iter(|| {
            let r = entropy_rs::calculate_entropy(black_box(&ENTROPY_BUF));
            black_box(r.classify_section(".text"));
            black_box(r.entropy)
        })
    });
    g.finish();
}

fn bench_string_extraction(c: &mut Criterion) {
    // Exact call shape used by Scanner::scan_file (ExtractConfig::windows_pe(4)).
    let config = str_extract::ExtractConfig::windows_pe(4);
    let mut g = c.benchmark_group("string_extraction");
    g.bench_function("windows_pe_min4_1mb_planted", |b| {
        b.iter(|| {
            black_box(str_extract::extract_strings(
                black_box(&STRING_BUF),
                black_box(&config),
            ))
        })
    });
    g.finish();
}

fn bench_backdoor_analysis(c: &mut Criterion) {
    // Same argument shapes as Scanner::scan_file: raw data + cached imports +
    // extracted string values. Exercises the hashset-based import lookup.
    let mut g = c.benchmark_group("backdoor_analysis");
    g.bench_function("imports500_strings2000_data1mb", |b| {
        b.iter(|| {
            black_box(backdoor_analyzer::analyze_backdoors(
                black_box(&MB_BUF),
                black_box(&IMPORTS),
                black_box(&BD_STRING_REFS),
            ))
        })
    });
    g.finish();
}

fn bench_yara_lite(c: &mut Criterion) {
    // Compile path mirrors Scanner::with_yara_rules (parse + compile + build).
    let mut g = c.benchmark_group("yara_lite");
    g.bench_function("compile_4_rules", |b| {
        b.iter(|| {
            let parsed = yara_lite::parse_rules(YARA_RULES).unwrap();
            let compiled: Vec<_> = parsed
                .iter()
                .map(yara_lite::compile_rule)
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            black_box(yara_lite::Scanner::new(compiled).unwrap())
        })
    });

    let parsed = yara_lite::parse_rules(YARA_RULES).unwrap();
    let compiled: Vec<_> = parsed
        .iter()
        .map(yara_lite::compile_rule)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let scanner = yara_lite::Scanner::new(compiled).unwrap();
    assert!(!scanner.scan(&YARA_BUF).matches.is_empty());
    g.bench_function("scan_1mb_planted_hits", |b| {
        b.iter(|| black_box(scanner.scan(black_box(&YARA_BUF))).matches.len())
    });
    g.finish();
}

fn bench_sha256_baseline(c: &mut Criterion) {
    // I/O-bound reference point: scanner's own sha256+hex path over 1 MiB.
    let mut g = c.benchmark_group("hash_baseline");
    g.bench_function("sha256_hex_1mb", |b| {
        b.iter(|| black_box(freakre_scanner::scanner::hex_sha256(black_box(&MB_BUF))))
    });
    g.finish();
}

fn main() {
    // `--quick` is not a native criterion flag: strip it here and shrink the
    // measurement parameters so a full pass stays fast. Other criterion CLI
    // args (bench-name filters etc.) are forwarded via with_filter.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let quick = args.iter().any(|a| a == "--quick");
    let filter = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .cloned()
        .next_back();

    let mut c = Criterion::default()
        .warm_up_time(Duration::from_millis(if quick { 200 } else { 500 }))
        .measurement_time(Duration::from_millis(if quick { 400 } else { 1_000 }))
        .sample_size(if quick { 10 } else { 20 });
    if let Some(f) = filter {
        c = c.with_filter(f);
    }

    bench_detect_file_type(&mut c);
    bench_entropy_section_map(&mut c);
    bench_string_extraction(&mut c);
    bench_backdoor_analysis(&mut c);
    bench_yara_lite(&mut c);
    bench_sha256_baseline(&mut c);

    c.final_summary();
}
