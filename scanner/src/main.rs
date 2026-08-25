#[cfg(not(feature = "cli"))]
compile_error!("The 'cli' feature is required to build the freakre binary");

use freakre_scanner::{
    output,
    report::{FileReport, Finding, ScanSummary, Severity, Verdict},
    Scanner,
};
use clap::Parser;
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
    #[arg(short, long, default_value = "pretty", value_parser = ["pretty", "json", "csv"])]
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
}

fn main() {
    let cli = Cli::parse();
    let scan_start = Instant::now();

    // Configure thread pool
    if cli.threads > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(cli.threads)
            .build_global()
            .ok();
    }

    // Build scanner
    let scanner = match build_scanner(&cli.rules) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("Error initializing scanner: {}", e);
            std::process::exit(1);
        }
    };

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

    eprintln!(
        "Scanning {} file(s) with {} thread(s)...",
        total_files, num_threads
    );

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
            if done.is_multiple_of(PROGRESS_STEP) || done == total_files {
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
        clean: reports.iter().filter(|r| r.verdict == Verdict::Clean).count(),
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
            let json_output = serde_json::to_string_pretty(&filtered).unwrap();
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

        let mut sequential: Vec<FileReport> =
            files.iter().map(|p| scanner.scan_file(p)).collect();
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
