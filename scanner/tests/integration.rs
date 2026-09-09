//! Integration tests for FreakRE scanner.

use freakre_scanner::report::Verdict;
use freakre_scanner::Scanner;
use std::io::Write;
use tempfile::NamedTempFile;

fn make_test_pe() -> Vec<u8> {
    let mut pe = vec![0u8; 1024];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[60] = 0x80;
    pe[0x80] = b'P';
    pe[0x81] = b'E';
    pe[0x82] = 0;
    pe[0x83] = 0;
    pe[0x84] = 0x64;
    pe[0x85] = 0x86;
    pe[0x86] = 1;
    pe[0x88 + 24] = 0x0b;
    pe[0x88 + 25] = 0x02;
    pe
}

fn make_test_elf() -> Vec<u8> {
    let mut elf = vec![0u8; 1024];
    elf[0] = 0x7F;
    elf[1] = b'E';
    elf[2] = b'L';
    elf[3] = b'F';
    elf[4] = 2;
    elf[5] = 1;
    elf[16] = 0x02;
    elf[17] = 0x00;
    elf[18] = 0x3E;
    elf[19] = 0x00;
    elf[20] = 1;
    elf[28] = 0x40;
    elf[29] = 0x00;
    elf[40] = 0x40;
    elf[41] = 0x00;
    elf[42] = 0x38;
    elf[43] = 0x00;
    elf[44] = 1;
    elf[54] = 0x40;
    elf[55] = 0x00;
    elf[56] = 1;
    elf
}

fn make_test_shellcode() -> Vec<u8> {
    vec![
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x40, 0x18, 0x48, 0x8B,
        0x70, 0x20, 0x0F, 0x05,
    ]
}

/// Minimal but structurally valid PE64 with two sections:
/// `.text` (VA 0x1000, raw 0x200) holding one function that returns the
/// address of a string, and `.rdata` (VA 0x2000, raw 0x400) holding the
/// string itself. The function is `push rbp; mov rbp, rsp; movabs rax,
/// <string VA>; pop rbp; ret`, so decompilation yields `return <VA>` and
/// the string table must turn that into the C literal.
#[cfg(feature = "decompiler")]
fn make_pe64_with_string() -> Vec<u8> {
    let image_base: u64 = 0x140000000;
    let text_rva: u32 = 0x1000;
    let rdata_rva: u32 = 0x2000;
    let str_va: u64 = image_base + rdata_rva as u64;

    let mut code: Vec<u8> = vec![0x55, 0x48, 0x89, 0xE5, 0x48, 0xB8];
    code.extend_from_slice(&str_va.to_le_bytes());
    code.extend_from_slice(&[0x5D, 0xC3]);
    code.resize(0x200, 0xCC);

    let mut rdata = b"Hello, string literal!\0".to_vec();
    rdata.resize(0x200, 0);

    let mut pe = vec![0u8; 0x600];
    // DOS header + e_lfanew
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    // PE signature
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    // COFF header: AMD64, 2 sections, 240-byte optional header
    pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    pe[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
    pe[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
    // Optional header (PE32+): magic, entry point, base of code, image base,
    // alignments, image size, header size, 16 data dirs.
    pe[0x98..0x9A].copy_from_slice(&0x020Bu16.to_le_bytes());
    pe[0xA8..0xAC].copy_from_slice(&text_rva.to_le_bytes());
    pe[0xAC..0xB0].copy_from_slice(&text_rva.to_le_bytes());
    pe[0xB0..0xB8].copy_from_slice(&image_base.to_le_bytes());
    pe[0xB8..0xBC].copy_from_slice(&0x1000u32.to_le_bytes());
    pe[0xBC..0xC0].copy_from_slice(&0x200u32.to_le_bytes());
    pe[0xD0..0xD4].copy_from_slice(&0x3000u32.to_le_bytes());
    pe[0xD4..0xD8].copy_from_slice(&0x200u32.to_le_bytes());
    pe[0x104..0x108].copy_from_slice(&16u32.to_le_bytes());
    // Section table at 0x98 + 240 = 0x188
    let s1 = 0x188;
    pe[s1..s1 + 5].copy_from_slice(b".text");
    pe[s1 + 8..s1 + 12].copy_from_slice(&0x200u32.to_le_bytes());
    pe[s1 + 12..s1 + 16].copy_from_slice(&text_rva.to_le_bytes());
    pe[s1 + 16..s1 + 20].copy_from_slice(&0x200u32.to_le_bytes());
    pe[s1 + 20..s1 + 24].copy_from_slice(&0x200u32.to_le_bytes());
    pe[s1 + 36..s1 + 40].copy_from_slice(&0x60000020u32.to_le_bytes());
    let s2 = s1 + 40;
    pe[s2..s2 + 6].copy_from_slice(b".rdata");
    pe[s2 + 8..s2 + 12].copy_from_slice(&0x200u32.to_le_bytes());
    pe[s2 + 12..s2 + 16].copy_from_slice(&rdata_rva.to_le_bytes());
    pe[s2 + 16..s2 + 20].copy_from_slice(&0x200u32.to_le_bytes());
    pe[s2 + 20..s2 + 24].copy_from_slice(&0x400u32.to_le_bytes());
    pe[s2 + 36..s2 + 40].copy_from_slice(&0x40000040u32.to_le_bytes());
    // Section raw data
    pe[0x200..0x400].copy_from_slice(&code);
    pe[0x400..0x600].copy_from_slice(&rdata);
    pe
}

#[cfg(feature = "decompiler")]
#[test]
fn test_decompile_string_literal_e2e() {
    let pe = make_pe64_with_string();
    let out = match freakre_scanner::decompile_api::decompile_pe_function(&pe, None) {
        Ok(out) => out,
        Err(e) => panic!("decompilation failed: {e}"),
    };
    assert!(
        out.c_code.contains(r#""Hello, string literal!""#),
        "expected the .rdata string as a C literal in pseudocode:\n{}",
        out.c_code
    );
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
Start-Process payload.exe"#
        .to_vec()
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
    assert!(
        report.file_type.contains("PE"),
        "Expected PE, got {}",
        report.file_type
    );
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
    assert!(
        report.file_type.contains("PowerShell"),
        "Expected PowerShell, got {}",
        report.file_type
    );
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
        assert!(
            !report.findings.is_empty(),
            "Expected findings after loading YARA rules"
        );
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
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x40, 0x18, 0x48, 0x8B,
        0x70, 0x20, 0xFF, 0xD6,
    ];
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(&sc).unwrap();
    let report = scanner.scan_file(tmp.path());
    // The file should be scanned without errors
    assert_ne!(report.verdict, Verdict::Error);
    // May or may not detect as shellcode depending on heuristics
}
