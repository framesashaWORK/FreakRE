#[cfg(not(feature = "cli"))]
compile_error!("The 'cli' feature is required to build the freakre binary");

use clap::Parser;
use freakre_scanner::{
    output,
    report::{FileReport, Finding, ScanSummary, Severity, Verdict},
    Scanner,
};
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use walkdir::WalkDir;

const PROGRESS_STEP: usize = 100;

#[derive(Parser, Debug)]
#[command(
    name = "bibleteks",
    about = "Non-AI Malware & Backdoor Checker — Static Analysis Engine",
    version,
    long_about = "A deterministic, rule-based malware scanner built in Rust.\n\
                  Combines PE parsing, entropy analysis, import inspection,\n\
                  string extraction, and YARA-lite pattern matching."
)]
struct Cli {
    /// File or directory to scan
    #[arg(required = true)]
    target: PathBuf,

    /// Path to YARA rules file (.yar)
    #[arg(short, long)]
    rules: Option<PathBuf>,

    /// Output format
    #[arg(short, long, default_value = "pretty", value_parser = ["pretty", "json", "csv", "html"])]
    format: String,

    /// Recursion depth for directories (0 = unlimited)
    #[arg(short, long, default_value_t = 10)]
    depth: usize,

    /// Number of parallel threads (0 = auto)
    #[arg(short = 'j', long, alias = "jobs", default_value_t = 0)]
    threads: usize,

    /// Only show files with findings
    #[arg(long)]
    findings_only: bool,

    /// Minimum severity to display (info, low, medium, high, critical)
    #[arg(long, default_value = "info")]
    min_severity: String,

    /// Output file (default: stdout)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Quiet mode — suppress progress output
    #[arg(short, long)]
    quiet: bool,

    /// Verbose mode — show detailed analysis info
    #[arg(short, long)]
    verbose: bool,

    /// Signature-base tier: low (~1.2M, fast), basic (~2.7M, default),
    /// freak (all ~2.9M, max recall)
    #[arg(long, default_value = "basic", value_parser = ["low", "basic", "freak"])]
    sigs_tier: String,
}

fn main() {
    let cli = Cli::parse();
    let scan_start = Instant::now();

    // Tier must be set before the first overlay load (Scanner::new / build_scanner).
    std::env::set_var("FREAKRE_SIGS_TIER", &cli.sigs_tier);

    // Configure thread pool
    if cli.threads > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(cli.threads)
            .build_global()
            .ok();
    }

    // Build scanner (Scanner::new best-effort loads the harvested overlay).
    let scanner = match build_scanner(&cli.rules) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("Error initializing scanner: {}", e);
            std::process::exit(1);
        }
    };
    if !cli.quiet {
        eprintln!(
            "FLIRT signatures: {} embedded + {} harvested overlay (tier: {})",
            func_sigs::db_signature_count() - func_sigs::overlay_signature_count(),
            func_sigs::overlay_signature_count(),
            cli.sigs_tier
        );
    }

    // Collect files
    let files: Vec<PathBuf> = collect_files(&cli.target, cli.depth);
    let total_files = files.len();

    if total_files == 0 {
        eprintln!("No files found at {:?}", cli.target);
        std::process::exit(1);
    }

    let num_threads = if cli.threads > 0 {
        cli.threads
    } else {
        rayon::current_num_threads()
    };

    if !cli.quiet {
        eprintln!(
            "Scanning {} file(s) with {} thread(s)...",
            total_files, num_threads
        );
    }

    // Parallel scan — lock-free collection via par_iter().map().collect()
    let completed = AtomicUsize::new(0);
    let read_errors = AtomicUsize::new(0);

    let mut reports: Vec<FileReport> = files
        .par_iter()
        .map(|path| {
            let report = scanner.scan_file(path);
            if report.verdict == Verdict::Error {
                read_errors.fetch_add(1, Ordering::Relaxed);
            }
            let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
            if !cli.quiet && (done.is_multiple_of(PROGRESS_STEP) || done == total_files) {
                eprintln!("Scanned {}/{} file(s)...", done, total_files);
            }
            report
        })
        .collect();

    let err_count = read_errors.load(Ordering::Relaxed);
    if err_count > 0 {
        eprintln!(
            "Warning: {} file(s) could not be read and are marked as ERROR",
            err_count
        );
    }

    reports.sort_by(|a, b| a.path.cmp(&b.path));

    let scan_duration = scan_start.elapsed().as_millis();

    // Build summary
    let summary = ScanSummary {
        total_files,
        scanned_files: reports.len(),
        clean: reports
            .iter()
            .filter(|r| r.verdict == Verdict::Clean)
            .count(),
        suspicious: reports
            .iter()
            .filter(|r| r.verdict == Verdict::Suspicious)
            .count(),
        malicious: reports
            .iter()
            .filter(|r| r.verdict == Verdict::Malicious)
            .count(),
        errors: reports
            .iter()
            .filter(|r| r.verdict == Verdict::Error)
            .count(),
        total_findings: reports.iter().map(|r| r.findings.len()).sum(),
        critical_findings: reports
            .iter()
            .flat_map(|r| &r.findings)
            .filter(|f| f.severity == Severity::Critical)
            .count(),
        scan_duration_ms: scan_duration,
    };

    // Output
    let min_sev = parse_severity(&cli.min_severity);

    match cli.format.as_str() {
        "json" => {
            let filtered: Vec<&FileReport> = if cli.findings_only {
                reports.iter().filter(|r| !r.findings.is_empty()).collect()
            } else {
                reports.iter().collect()
            };
            let json_output = match serde_json::to_string_pretty(&filtered) {
                Ok(j) => j,
                Err(e) => {
                    eprintln!("Failed to serialize JSON: {}", e);
                    std::process::exit(1);
                }
            };
            if let Some(ref output_path) = cli.output {
                std::fs::write(output_path, &json_output).unwrap_or_else(|e| {
                    eprintln!("Failed to write to {}: {}", output_path.display(), e);
                    std::process::exit(1);
                });
                eprintln!("JSON output written to {}", output_path.display());
            } else {
                println!("{}", json_output);
            }
        }
        "csv" => print_csv(&reports, &summary),
        "html" => {
            let html_output = generate_html(&reports, &summary, cli.verbose);
            if let Some(ref output_path) = cli.output {
                std::fs::write(output_path, &html_output).unwrap_or_else(|e| {
                    eprintln!("Failed to write to {}: {}", output_path.display(), e);
                    std::process::exit(1);
                });
                if !cli.quiet {
                    eprintln!("HTML output written to {}", output_path.display());
                }
            } else {
                println!("{}", html_output);
            }
        }
        _ => {
            for report in &reports {
                if cli.findings_only && report.findings.is_empty() {
                    continue;
                }
                let visible: Vec<Finding> = report
                    .findings
                    .iter()
                    .filter(|f| f.severity >= min_sev)
                    .cloned()
                    .collect();
                if cli.findings_only && visible.is_empty() {
                    continue;
                }
                let mut display_report = report.clone();
                display_report.findings = visible;
                output::print_report(&display_report);
            }
            output::print_summary(&summary);
        }
    }

    // Exit code: non-zero if malicious found
    if summary.malicious > 0 {
        std::process::exit(2);
    } else if summary.suspicious > 0 {
        std::process::exit(1);
    }
}

fn build_scanner(rules_path: &Option<PathBuf>) -> Result<Scanner, String> {
    let scanner = Scanner::new();
    match rules_path {
        Some(p) => scanner.with_yara_rules(p),
        None => Ok(scanner),
    }
}

fn collect_files(target: &Path, max_depth: usize) -> Vec<PathBuf> {
    if target.is_file() {
        return vec![target.to_path_buf()];
    }
    WalkDir::new(target)
        .max_depth(if max_depth == 0 {
            usize::MAX
        } else {
            max_depth
        })
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect()
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => Severity::Info,
    }
}

fn csv_escape(field: &str) -> String {
    let mut out = String::with_capacity(field.len() + 2);
    out.push('"');
    for c in field.chars() {
        if c == '"' {
            out.push_str("\"\"");
        } else {
            out.push(c);
        }
    }
    out.push('"');
    out
}

fn generate_html(reports: &[FileReport], summary: &ScanSummary, verbose: bool) -> String {
    let mut html = String::with_capacity(4096);
    html.push_str(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FreakRE Scan Report</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;margin:0;padding:20px;background:#0d1117;color:#c9d1d9}
h1{color:#58a6ff;border-bottom:2px solid #30363d;padding-bottom:10px}
.summary{display:flex;gap:20px;margin:20px 0;flex-wrap:wrap}
.stat{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:15px 20px;min-width:120px}
.stat .num{font-size:28px;font-weight:bold}
.stat .label{color:#8b949e;font-size:12px;text-transform:uppercase}
.clean .num{color:#3fb950}.suspicious .num{color:#d29922}.malicious .num{color:#f85149}.error .num{color:#8b949e}
.file{background:#161b22;border:1px solid #30363d;border-radius:8px;margin:10px 0;padding:15px}
.file-header{display:flex;justify-content:space-between;align-items:center}
.file-name{font-weight:bold;color:#58a6ff;font-size:14px}
.verdict{padding:3px 10px;border-radius:12px;font-size:12px;font-weight:bold}
.v-clean{background:#238636;color:#fff}.v-suspicious{background:#9e6a03;color:#fff}
.v-malicious{background:#da3633;color:#fff}.v-error{background:#30363d;color:#8b949e}
.meta{color:#8b949e;font-size:12px;margin-top:5px}
.findings{margin-top:10px}
.finding{padding:5px 10px;margin:3px 0;border-radius:4px;font-size:13px;border-left:3px solid}
.f-critical{background:#3d1214;border-color:#f85149}.f-high{background:#3d2a05;border-color:#d29922}
.f-medium{background:#2a2a05;border-color:#e3b341}.f-low{background:#0c2d6b;border-color:#58a6ff}
.f-info{background:#161b22;border-color:#30363d}
.sev{font-weight:bold;margin-right:5px}
.rule{color:#58a6ff;margin-right:8px}
.detail{color:#8b949e;font-size:12px;margin-left:20px}
.section-row{display:flex;gap:10px;align-items:center;font-size:12px;color:#8b949e;margin:2px 0}
.entropy-bar{width:80px;height:8px;background:#21262d;border-radius:4px;overflow:hidden}
.entropy-fill{height:100%;border-radius:4px}
</style>
</head>
<body>
<h1>FreakRE Scan Report</h1>
<div class="summary">
  <div class="stat"><div class="num">"#);
    html.push_str(&summary.total_files.to_string());
    html.push_str(
        r#"</div><div class="label">Total Files</div></div>
  <div class="stat clean"><div class="num">"#,
    );
    html.push_str(&summary.clean.to_string());
    html.push_str(
        r#"</div><div class="label">Clean</div></div>
  <div class="stat suspicious"><div class="num">"#,
    );
    html.push_str(&summary.suspicious.to_string());
    html.push_str(
        r#"</div><div class="label">Suspicious</div></div>
  <div class="stat malicious"><div class="num">"#,
    );
    html.push_str(&summary.malicious.to_string());
    html.push_str(
        r#"</div><div class="label">Malicious</div></div>
  <div class="stat"><div class="num">"#,
    );
    html.push_str(&summary.total_findings.to_string());
    html.push_str(
        r#"</div><div class="label">Findings</div></div>
  <div class="stat"><div class="num">"#,
    );
    html.push_str(&format!("{}ms", summary.scan_duration_ms));
    html.push_str(
        r#"</div><div class="label">Scan Time</div></div>
</div>
<hr style="border-color:#30363d">
"#,
    );

    for r in reports {
        let vclass = match r.verdict {
            Verdict::Clean => "v-clean",
            Verdict::Suspicious => "v-suspicious",
            Verdict::Malicious => "v-malicious",
            Verdict::Error => "v-error",
        };
        html.push_str(&format!(
            r#"<div class="file"><div class="file-header"><span class="file-name">{}</span><span class="verdict {}">{}</span></div>"#,
            htmlescape(&r.path.display().to_string()),
            vclass,
            r.verdict
        ));
        html.push_str(&format!(
            r#"<div class="meta">Size: {} bytes | Type: {} | SHA256: {}... | Score: {:.2} | {}ms</div>"#,
            r.size,
            htmlescape(&r.file_type),
            &r.sha256[..r.sha256.len().min(16)],
            r.suspicion_score,
            r.scan_duration_ms
        ));

        if verbose && !r.sections_entropy.is_empty() {
            html.push_str(r#"<div class="findings">"#);
            for s in &r.sections_entropy {
                let pct = ((s.entropy / 8.0) * 100.0) as u32;
                let color = if s.entropy > 7.0 {
                    "#f85149"
                } else if s.entropy > 6.0 {
                    "#d29922"
                } else {
                    "#3fb950"
                };
                html.push_str(&format!(
                    r#"<div class="section-row"><div class="entropy-bar"><div class="entropy-fill" style="width:{}%;background:{}"></div></div> {} ({:.2}) {}</div>"#,
                    pct, color, htmlescape(&s.name), s.entropy, htmlescape(&s.classification)
                ));
            }
            html.push_str("</div>");
        }

        if !r.findings.is_empty() {
            html.push_str(r#"<div class="findings">"#);
            for f in &r.findings {
                let fclass = match f.severity {
                    Severity::Critical => "f-critical",
                    Severity::High => "f-high",
                    Severity::Medium => "f-medium",
                    Severity::Low => "f-low",
                    Severity::Info => "f-info",
                };
                html.push_str(&format!(
                    r#"<div class="finding {}"><span class="sev">[{}]</span><span class="rule">{}</span>{}</div>"#,
                    fclass, f.severity, htmlescape(&f.rule_id), htmlescape(&f.description)
                ));
                if verbose {
                    if let Some(ref details) = f.details {
                        html.push_str(&format!(
                            r#"<div class="detail">{}</div>"#,
                            htmlescape(details)
                        ));
                    }
                }
            }
            html.push_str("</div>");
        }
        html.push_str("</div>\n");
    }

    html.push_str(r#"<hr style="border-color:#30363d"><p style="color:#8b949e;font-size:12px">Generated by FreakRE — Non-AI Malware & Backdoor Checker</p></body></html>"#);
    html
}

fn htmlescape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn print_csv(reports: &[FileReport], summary: &ScanSummary) {
    println!(
        "path,size,sha256,file_type,suspicion_score,verdict,findings_count,critical_findings,scan_ms"
    );
    for r in reports {
        let crit = r
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        println!(
            "{},{},{},{},{:.4},{},{},{},{}",
            csv_escape(&r.path.display().to_string()),
            r.size,
            csv_escape(&r.sha256),
            csv_escape(&r.file_type),
            r.suspicion_score,
            csv_escape(&r.verdict.to_string()),
            r.findings.len(),
            crit,
            r.scan_duration_ms
        );
    }
    eprintln!(
        "\n# Summary: {} files, {} malicious, {} suspicious, {} clean",
        summary.total_files, summary.malicious, summary.suspicious, summary.clean
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn fingerprint(reports: &[FileReport]) -> BTreeSet<(String, String)> {
        reports
            .iter()
            .map(|r| (r.path.display().to_string(), r.md5.clone()))
            .collect()
    }

    #[test]
    fn parallel_scan_matches_sequential() {
        let dir = tempfile::tempdir().unwrap();
        let names = ["a.bin", "b.txt", "c.dat", "d.exe", "e", "f.dll"];
        for (i, name) in names.iter().enumerate() {
            let mut data = vec![b'A' + i as u8; 64 * (i + 1)];
            data.extend_from_slice(name.as_bytes());
            std::fs::write(dir.path().join(name), &data).unwrap();
        }

        let files = collect_files(dir.path(), 0);
        assert_eq!(files.len(), names.len());

        let scanner = Arc::new(Scanner::new());

        let mut sequential: Vec<FileReport> = files.iter().map(|p| scanner.scan_file(p)).collect();
        sequential.sort_by(|a, b| a.path.cmp(&b.path));

        let mut parallel: Vec<FileReport> =
            files.par_iter().map(|p| scanner.scan_file(p)).collect();
        assert_eq!(
            files.len(),
            parallel.len(),
            "par_iter().collect() must preserve input order"
        );
        parallel.sort_by(|a, b| a.path.cmp(&b.path));

        assert_eq!(fingerprint(&sequential), fingerprint(&parallel));
        for (s, p) in sequential.iter().zip(parallel.iter()) {
            assert_eq!(s.verdict, p.verdict);
            assert_eq!(s.findings.len(), p.findings.len());
        }
    }

    #[test]
    fn depth_zero_means_unlimited() {
        let dir = tempfile::tempdir().unwrap();
        let deep = dir.path().join("a").join("b").join("c");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("deep.txt"), b"x").unwrap();

        assert_eq!(collect_files(dir.path(), 0).len(), 1);
        assert!(collect_files(dir.path(), 1).is_empty());
        assert!(collect_files(dir.path(), 3).is_empty());
        assert_eq!(collect_files(dir.path(), 4).len(), 1);
    }

    #[test]
    fn csv_field_escaping() {
        assert_eq!(csv_escape("plain"), "\"plain\"");
        assert_eq!(csv_escape("C:\\a\"b,c.csv"), "\"C:\\a\"\"b,c.csv\"");
        assert_eq!(csv_escape(""), "\"\"");
    }
}
