#[cfg(not(feature = "cli"))]
compile_error!("The 'cli' feature is required to build the bibleteks binary");

use bibleteks_scanner::{
    output,
    report::{FileReport, Finding, ScanSummary, Severity, Verdict},
    Scanner,
};
use clap::Parser;
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use walkdir::WalkDir;

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
    #[arg(short, long, default_value_t = 0)]
    jobs: usize,

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
    if cli.jobs > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(cli.jobs)
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

    eprintln!(
        "Scanning {} file(s) with {} thread(s)...",
        total_files,
        rayon::current_num_threads()
    );

    // Parallel scan — lock-free collection via par_iter().map().collect()
    let mut reports: Vec<FileReport> = files
        .par_iter()
        .map(|path| scanner.scan_file(path))
        .collect();
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
        .max_depth(max_depth)
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
            "\"{}\",{},{},{},{:.4},{},{},{},{}",
            r.path.display(),
            r.size,
            r.sha256,
            r.file_type,
            r.suspicion_score,
            r.verdict,
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
