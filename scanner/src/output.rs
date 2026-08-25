use crate::report::*;
#[cfg(feature = "cli")]
use colored::*;

/// Pretty-print a single file report to stdout
#[cfg(feature = "cli")]
pub fn print_report(report: &FileReport) {
    println!();
    let verdict_color = match report.verdict {
        Verdict::Clean => "green",
        Verdict::Suspicious => "yellow",
        Verdict::Malicious => "red",
        Verdict::Error => "blue",
    };

    println!(
        "{} {}",
        "━━━ FILE REPORT ━━━".bold(),
        report.path.display().to_string().bold()
    );
    println!(
        "  {} {:>10} bytes | {} {} | {} {}",
        "Size:".dimmed(),
        report.size,
        "Type:".dimmed(),
        report.file_type,
        "SHA256:".dimmed(),
        &report.sha256[..report.sha256.len().min(16)]
    );
    println!(
        "  {} {:.2} | {} {} | {} {} ms",
        "Score:".dimmed(),
        report.suspicion_score,
        "Verdict:".dimmed(),
        report.verdict.to_string().color(verdict_color).bold(),
        "Time:".dimmed(),
        report.scan_duration_ms
    );

    if !report.sections_entropy.is_empty() {
        println!("  {} Sections:", "📊".dimmed());
        for s in &report.sections_entropy {
            let bar = entropy_bar(s.entropy);
            println!(
                "     {} {:8} | {:.2} | {} | {}",
                bar,
                s.name,
                s.entropy,
                s.classification,
                if s.entropy > 7.0 {
                    "⚠ HIGH".red().to_string()
                } else {
                    String::new()
                }
            );
        }
    }

    // Backdoor summary
    if let Some(ref bd) = report.backdoor_report {
        let bd_color = if bd.risk_score >= 0.7 { "red" } else if bd.risk_score >= 0.3 { "yellow" } else { "green" };
        println!(
            "  {} Backdoor: risk={:.2} | {} | {} finding(s) | MITRE: {}",
            "🚪".dimmed(),
            bd.risk_score,
            bd.verdict.color(bd_color).bold(),
            bd.num_findings,
            if bd.mitre_techniques.is_empty() { "—".to_string() } else { bd.mitre_techniques.join(", ") }
        );
    }

    // Shellcode summary
    if let Some(ref sc) = report.shellcode_report {
        println!(
            "  {} Shellcode: {} | {} finding(s) | {} API hash(es) resolved",
            "💉".dimmed(),
            sc.verdict.bold(),
            sc.num_findings,
            sc.api_hashes_resolved.len()
        );
        if !sc.patterns_detected.is_empty() {
            println!("     Patterns: {}", sc.patterns_detected.join(", ").dimmed());
        }
    }

    // ELF summary
    if let Some(ref elf) = report.elf_info {
        println!(
            "  {} ELF: {} {} | {} sections | {} segments | static={} stripped={}",
            "🐧".dimmed(),
            elf.class,
            elf.machine,
            elf.num_sections,
            elf.num_segments,
            elf.is_statically_linked,
            elf.is_stripped
        );
        if !elf.rwx_sections.is_empty() {
            println!("     ⚠ RWX sections: {}", elf.rwx_sections.join(", ").red());
        }
    }

    // Mach-O summary
    if let Some(ref macho) = report.macho_info {
        println!(
            "  {} Mach-O: {} {} | {} segments | {} sections | PIE={} encrypted={}",
            "🍎".dimmed(),
            macho.cpu_type,
            macho.file_type,
            macho.num_segments,
            macho.num_sections,
            macho.is_pie,
            macho.is_encrypted
        );
        if !macho.imported_dylibs.is_empty() {
            println!("     Dylibs: {}", macho.imported_dylibs.join(", ").dimmed());
        }
        if !macho.rwx_segments.is_empty() {
            println!("     ⚠ RWX segments: {}", macho.rwx_segments.join(", ").red());
        }
    }

    if !report.findings.is_empty() {
        println!("  {} Findings ({}):", "🔍".dimmed(), report.findings.len());
        for f in &report.findings {
            let icon = match f.severity {
                Severity::Critical => "🔴",
                Severity::High => "🟠",
                Severity::Medium => "🟡",
                Severity::Low => "🔵",
                Severity::Info => "⚪",
            };
            println!(
                "     {} [{}] {} :: {}",
                icon,
                f.module.dimmed(),
                f.rule_id.bold(),
                f.description
            );
            if let Some(ref details) = f.details {
                println!("        {}", details.dimmed());
            }
        }
    } else {
        println!("  {} No findings — file appears clean", "✅".green());
    }

    println!("{}", "━".repeat(60).dimmed());
}

/// No-op print_report when CLI feature is disabled
#[cfg(not(feature = "cli"))]
pub fn print_report(_report: &FileReport) {
    // CLI feature disabled - use JSON output or library API instead
}

/// Print scan summary
#[cfg(feature = "cli")]
pub fn print_summary(summary: &ScanSummary) {
    println!();
    println!("{}", "═══ SCAN SUMMARY ═══".bold());
    println!(
        "  Files: {} total | {} scanned | {} clean | {} suspicious | {} malicious | {} errors",
        summary.total_files,
        summary.scanned_files,
        summary.clean.to_string().green(),
        summary.suspicious.to_string().yellow(),
        summary.malicious.to_string().red(),
        summary.errors.to_string().blue()
    );
    println!(
        "  Findings: {} total | {} critical",
        summary.total_findings,
        summary.critical_findings
    );
    println!("  Duration: {} ms", summary.scan_duration_ms);
    println!("{}", "═".repeat(60).dimmed());
}

/// No-op print_summary when CLI feature is disabled
#[cfg(not(feature = "cli"))]
pub fn print_summary(_summary: &ScanSummary) {
    // CLI feature disabled - use JSON output or library API instead
}

#[cfg(feature = "cli")]
fn entropy_bar(entropy: f64) -> String {
    let filled = (entropy / 8.0 * 20.0).round() as usize;
    let empty = 20usize.saturating_sub(filled);
    let color = if entropy > 7.0 {
        "red"
    } else if entropy > 6.0 {
        "yellow"
    } else {
        "green"
    };
    let bar = format!("{}{}", "█".repeat(filled), "░".repeat(empty));
    bar.color(color).to_string()
}
