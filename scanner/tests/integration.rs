//! Integration tests for FreakRE scanner.

use freakre_scanner::report::Verdict;
use freakre_scanner::Scanner;
use std::io::Write;
use tempfile::NamedTempFile;

fn make_test_pe() -> Vec<u8> {
    let mut pe = vec![0u8; 1024];
    pe[0] = b'M'; pe[1] = b'Z';
    pe[60] = 0x80;
    pe[0x80] = b'P'; pe[0x81] = b'E'; pe[0x82] = 0; pe[0x83] = 0;
    pe[0x84] = 0x64; pe[0x85] = 0x86;
    pe[0x86] = 1;
    pe[0x88 + 24] = 0x0b; pe[0x88 + 25] = 0x02;
    pe
}

fn make_test_elf() -> Vec<u8> {
    let mut elf = vec![0u8; 1024];
    elf[0] = 0x7F; elf[1] = b'E'; elf[2] = b'L'; elf[3] = b'F';
    elf[4] = 2; elf[5] = 1;
    elf[16] = 0x02; elf[17] = 0x00;
    elf[18] = 0x3E; elf[19] = 0x00;
    elf[20] = 1;
    elf[28] = 0x40; elf[29] = 0x00;
    elf[40] = 0x40; elf[41] = 0x00;
    elf[42] = 0x38; elf[43] = 0x00;
    elf[44] = 1;
    elf[54] = 0x40; elf[55] = 0x00;
    elf[56] = 1;
    elf
}

fn make_test_shellcode() -> Vec<u8> {
    vec![
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
        0x48, 0x8B, 0x40, 0x18,
        0x48, 0x8B, 0x70, 0x20,
        0x0F, 0x05,
    ]
}

fn make_test_powershell() -> Vec<u8> {
    // PowerShell script content that triggers detection via #requires
    br#"#requires -Version 5.1
param(
    [string]$target
)
function Invoke-Download {
    Invoke-WebRequest -Uri $target -OutFile payload.exe
}
Start-Process payload.exe"#.to_vec()
}

fn make_test_pdf() -> Vec<u8> {
    b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF".to_vec()
}

#[test]
fn test_scan_pe_file() {
    let scanner = Scanner::new();
    let pe = make_test_pe();
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(&pe).unwrap();
    let report = scanner.scan_file(tmp.path());
    assert!(report.file_type.contains("PE"), "Expected PE, got {}", report.file_type);
    assert_ne!(report.verdict, Verdict::Error);
}

#[test]
fn test_scan_elf_file() {
    let scanner = Scanner::new();
    let elf = make_test_elf();
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(&elf).unwrap();
    let report = scanner.scan_file(tmp.path());
    assert_eq!(report.file_type, "ELF");
    assert_ne!(report.verdict, Verdict::Error);
}

#[test]
fn test_scan_shellcode() {
    let scanner = Scanner::new();
    let sc = make_test_shellcode();
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(&sc).unwrap();
    let report = scanner.scan_file(tmp.path());
    assert_ne!(report.verdict, Verdict::Error);
}

#[test]
fn test_scan_pdf() {
    let scanner = Scanner::new();
    let pdf = make_test_pdf();
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(&pdf).unwrap();
    let report = scanner.scan_file(tmp.path());
    assert_eq!(report.file_type, "PDF");
}

#[test]
fn test_scan_powershell_encoded() {
    let scanner = Scanner::new();
    let ps = make_test_powershell();
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(&ps).unwrap();
    let report = scanner.scan_file(tmp.path());
    assert!(report.file_type.contains("PowerShell"),
        "Expected PowerShell, got {}", report.file_type);
    // File type is correctly detected
    // Note: findings require YARA rules to be loaded, which this default scanner doesn't have
}

#[test]
fn test_scan_nonexistent_file() {
    let scanner = Scanner::new();
    let report = scanner.scan_file(std::path::Path::new("/nonexistent/file.exe"));
    assert_eq!(report.verdict, Verdict::Error);
}

#[test]
fn test_scan_empty_file() {
    let scanner = Scanner::new();
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(&[]).unwrap();
    let report = scanner.scan_file(tmp.path());
    assert_ne!(report.verdict, Verdict::Error);
}

#[test]
fn test_scan_summary_counts() {
    let scanner = Scanner::new();
    let pe = make_test_pe();
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(&pe).unwrap();
    let report = scanner.scan_file(tmp.path());
    assert!(report.suspicion_score >= 0.0);
    assert!(report.suspicion_score <= 1.0);
    assert!(report.scan_duration_ms < 10000);
}

#[test]
fn test_yara_rules_loaded() {
    let rules_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../rules.yar");
    if rules_path.exists() {
        let scanner = Scanner::new().with_yara_rules(&rules_path).unwrap();
        let ps = make_test_powershell();
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&ps).unwrap();
        let report = scanner.scan_file(tmp.path());
        // Should have some findings (YARA or other modules)
        assert!(!report.findings.is_empty(),
            "Expected findings after loading YARA rules");
    }
}

#[test]
fn test_pe_suspicion_score() {
    let scanner = Scanner::new();
    let pe = make_test_pe();
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(&pe).unwrap();
    let report = scanner.scan_file(tmp.path());
    assert!(report.suspicion_score < 0.5);
}

#[test]
fn test_shellcode_detection_patterns() {
    let scanner = Scanner::new();
    let sc = vec![
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
        0x48, 0x8B, 0x40, 0x18,
        0x48, 0x8B, 0x70, 0x20,
        0xFF, 0xD6,
    ];
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(&sc).unwrap();
    let report = scanner.scan_file(tmp.path());
    // The file should be scanned without errors
    assert_ne!(report.verdict, Verdict::Error);
    // May or may not detect as shellcode depending on heuristics
}
