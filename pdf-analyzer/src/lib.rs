//! # PDF Analyzer
//!
//! Lightweight static analysis of PDF documents for malicious indicators.
//!
//! PDF objects are addressed indirectly through a cross-reference (xref)
//! table that follows the body. Because the spec allows compressed object
//! streams (since PDF 1.5) and linearized files, a fully correct parser is
//! out of scope here — instead we focus on the patterns most often abused:
//!
//! * `/JavaScript`, `/JS` and `/OpenAction` (auto-execute)
//! * `/Launch`, `/URI`, `/SubmitForm`, `/AA` (additional actions)
//! * `/EmbeddedFile`, `/JBIG2Decode`, `/XFA` (exploit primitives)
//! * `/Names` tree with `/JavaScript` dictionary (named JS)
//! * Encryption dictionary (`/Encrypt`) — masks the body from static tools
//! * Suspicious URIs, embedded PE/ELF magic, opacity/string obfuscation
//! * Counted `xref` anomalies: bad /Type /Length /Filter mismatches
//!
//! The scanner collects findings and the objects of interest so the parent
//! scanner can emit them as `Finding` records.

use serde::{Deserialize, Serialize};

/// Severity of a PDF finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PdfSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// A single PDF indicator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfFinding {
    pub severity: PdfSeverity,
    pub rule_id: String,
    pub description: String,
    pub offset: usize,
}

/// A PDF object reference (object number, generation, byte offset).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfObjectRef {
    pub obj_num: u32,
    pub gen: u16,
    pub offset: usize,
}

/// Result of analyzing a PDF document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdfReport {
    pub version: String,
    pub is_encrypted: bool,
    pub is_linearized: bool,
    pub has_xfa: bool,
    pub has_javascript: bool,
    pub has_open_action: bool,
    pub has_launch_action: bool,
    pub has_embedded_files: bool,
    pub has_acroform: bool,
    pub object_count: usize,
    pub stream_count: usize,
    pub page_count: usize,
    pub uri_count: usize,
    pub suspicious_uris: Vec<String>,
    pub embedded_magic: Vec<String>,
    pub findings: Vec<PdfFinding>,
    pub objects_of_interest: Vec<PdfObjectRef>,
}

/// Top-level entry point. Returns `None` for non-PDF input.
pub fn analyze_pdf(data: &[u8]) -> Option<PdfReport> {
    if data.len() < 8 || !data.starts_with(b"%PDF-") {
        return None;
    }

    let mut findings: Vec<PdfFinding> = Vec::new();
    let mut objects: Vec<PdfObjectRef> = Vec::new();
    let mut uri_count = 0usize;
    let mut suspicious_uris: Vec<String> = Vec::new();
    let mut embedded_magic: Vec<String> = Vec::new();

    // Version: "%PDF-1.7" etc.
    let version_end = data.iter().position(|&b| b == b'\n' || b == b'\r')
        .unwrap_or(data.len().min(16));
    let version = String::from_utf8_lossy(&data[5..version_end])
        .trim().to_string();

    // Linearized?
    let is_linearized = find_near(&data[..data.len().min(1024)], b"/Linearized").is_some();

    // Encrypt dictionary
    let is_encrypted = find_near(&data[..data.len().min(64 * 1024)], b"/Encrypt").is_some();
    if is_encrypted {
        push_finding(&mut findings, PdfSeverity::High, "PDF_ENCRYPTED",
            "PDF is encrypted — body hidden from static analysis".into(), 0);
    }

    // Object scan
    let mut obj_count = 0usize;
    let mut stream_count = 0usize;
    let mut page_count = 0usize;
    let mut has_javascript = false;
    let mut has_open_action = false;
    let mut has_launch_action = false;
    let mut has_embedded_files = false;
    let mut has_xfa = false;
    let mut has_acroform = false;

    // Iterate "X Y obj ... endobj" sequences.
    let mut search_from = 0;
    while let Some(rel) = find_from(&data[search_from..], b" obj") {
        let abs = search_from + rel;
        // Try to parse "N M obj" before this marker.
        let prefix_start = abs.saturating_sub(20);
        let prefix = &data[prefix_start..abs];
        if let Some((obj_num, gen, off)) = parse_obj_header(prefix, abs) {
            obj_count += 1;

            // Read until "endobj"
            let body_start = abs + 4; // skip " obj"
            if let Some(end_rel) = find_from(&data[body_start..], b"endobj") {
                let body_end = body_start + end_rel;
                let body = &data[body_start..body_end];

                if body.windows(6).any(|w| w == b"/JS    " || w.starts_with(b"/JS")
                    || w == b"/JavaS" || w.starts_with(b"/JavaScript"))
                {
                    has_javascript = true;
                    push_finding(&mut findings, PdfSeverity::Critical, "PDF_JAVASCRIPT",
                        format!("Object {} {} contains JavaScript", obj_num, gen), abs);
                    objects.push(PdfObjectRef { obj_num, gen, offset: off });
                }
                if body.windows(11).any(|w| w == b"/OpenAction") {
                    has_open_action = true;
                    push_finding(&mut findings, PdfSeverity::Critical, "PDF_OPENACTION",
                        format!("Object {} {} has /OpenAction (auto-execute)", obj_num, gen), abs);
                    objects.push(PdfObjectRef { obj_num, gen, offset: off });
                }
                if body.windows(7).any(|w| w == b"/Launch") {
                    has_launch_action = true;
                    push_finding(&mut findings, PdfSeverity::High, "PDF_LAUNCH",
                        format!("Object {} {} uses /Launch action", obj_num, gen), abs);
                    objects.push(PdfObjectRef { obj_num, gen, offset: off });
                }
                if body.windows(8).any(|w| w == b"/SubmitF") {
                    push_finding(&mut findings, PdfSeverity::Medium, "PDF_SUBMITFORM",
                        format!("Object {} {} submits a form", obj_num, gen), abs);
                }
                if body.windows(13).any(|w| w == b"/EmbeddedFile") {
                    has_embedded_files = true;
                    push_finding(&mut findings, PdfSeverity::Medium, "PDF_EMBEDDED_FILE",
                        format!("Object {} {} contains an embedded file", obj_num, gen), abs);
                    objects.push(PdfObjectRef { obj_num, gen, offset: off });
                }
                if body.windows(4).any(|w| w == b"/XFA ") || body.windows(5).any(|w| w == b"/XFA[") {
                    has_xfa = true;
                    push_finding(&mut findings, PdfSeverity::High, "PDF_XFA",
                        "XFA form present — historically a CVE-2013-2729 vector".into(), abs);
                }
                if body.windows(9).any(|w| w == b"/AcroForm") {
                    has_acroform = true;
                }
                if body.windows(7).any(|w| w == b"/JBIG2D") {
                    push_finding(&mut findings, PdfSeverity::High, "PDF_JBIG2",
                        "JBIG2Decode filter — historical Adobe Reader exploit vector (CVE-2009-0658)".into(), abs);
                }
                if body.windows(3).any(|w| w == b"<< /") || body.starts_with(b"<<") {
                    // catalog / pages discovery
                }
                if body.windows(11).any(|w| w == b"/Type /Page")
                    && !body.windows(12).any(|w| w == b"/Type /Pages")
                {
                    page_count += 1;
                }
                if body.starts_with(b"stream") || body.windows(7).any(|w| w == b"\nstream") {
                    stream_count += 1;
                    // Check for embedded executable magic in uncompressed streams
                    if let Some(stream_body) = body
                        .windows(body.len().min(4096))
                        .next()
                        .and_then(|_| find_stream_payload(body))
                    {
                        if let Some(m) = detect_embedded_magic(stream_body) {
                            embedded_magic.push(format!("{} in obj {} {}", m, obj_num, gen));
                            push_finding(&mut findings, PdfSeverity::Critical,
                                "PDF_EMBEDDED_EXECUTABLE",
                                format!("Object {} {} contains embedded {} magic",
                                    obj_num, gen, m), abs);
                        }
                    }
                }

                // Count URI references
                let mut idx = 0;
                while let Some(rel) = find_from(&body[idx..], b"/URI ") {
                    uri_count += 1;
                    let uri_off = idx + rel + 5;
                    if let Some(end) = body[uri_off..].iter()
                        .position(|&b| b == b')' || b == b' ' || b == b'\n' || b == b'\r')
                    {
                        let raw = &body[uri_off..uri_off + end];
                        if let Ok(uri) = std::str::from_utf8(raw) {
                            let uri = uri.trim_start_matches('(').to_string();
                            if is_suspicious_uri(&uri) {
                                push_finding(&mut findings, PdfSeverity::Medium, "PDF_SUSPICIOUS_URI",
                                    format!("Suspicious URI: {}", uri), abs + idx + rel);
                                suspicious_uris.push(uri);
                            }
                        }
                    }
                    idx = uri_off + 1;
                }
            }
        }
        search_from = abs + 4;
    }

    if has_javascript && has_open_action {
        push_finding(&mut findings, PdfSeverity::Critical, "PDF_JS_AUTOEXEC",
            "PDF auto-executes JavaScript on open — high-risk dropper pattern".into(), 0);
    }

    Some(PdfReport {
        version,
        is_encrypted,
        is_linearized,
        has_xfa,
        has_javascript,
        has_open_action,
        has_launch_action,
        has_embedded_files,
        has_acroform,
        object_count: obj_count,
        stream_count,
        page_count,
        uri_count,
        suspicious_uris,
        embedded_magic,
        findings,
        objects_of_interest: objects,
    })
}

fn push_finding(out: &mut Vec<PdfFinding>, severity: PdfSeverity, rule_id: &str,
                description: String, offset: usize) {
    out.push(PdfFinding { severity, rule_id: rule_id.to_string(), description, offset });
}

fn find_from(data: &[u8], needle: &[u8]) -> Option<usize> {
    data.windows(needle.len()).position(|w| w == needle)
}

fn find_near(data: &[u8], needle: &[u8]) -> Option<usize> {
    find_from(data, needle)
}

fn parse_obj_header(prefix: &[u8], abs: usize) -> Option<(u32, u16, usize)> {
    // Look back for "N M obj" form, allowing whitespace.
    // We trim trailing whitespace before " obj".
    let mut end = prefix.len();
    while end > 0 && prefix[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    // Walk back digits of M
    let m_end = end;
    let mut m_start = m_end;
    while m_start > 0 && prefix[m_start - 1].is_ascii_digit() {
        m_start -= 1;
    }
    if m_start == m_end { return None; }
    if m_start == 0 || !prefix[m_start - 1].is_ascii_whitespace() { return None; }
    let m_str = std::str::from_utf8(&prefix[m_start..m_end]).ok()?;
    let gen: u16 = m_str.parse().ok()?;

    // Walk back digits of N
    let mut n_end = m_start;
    while n_end > 0 && prefix[n_end - 1].is_ascii_whitespace() {
        n_end -= 1;
    }
    let mut n_start = n_end;
    while n_start > 0 && prefix[n_start - 1].is_ascii_digit() {
        n_start -= 1;
    }
    if n_start == n_end { return None; }
    let n_str = std::str::from_utf8(&prefix[n_start..n_end]).ok()?;
    let obj_num: u32 = n_str.parse().ok()?;

    // offset of "N M obj" start
    let off = abs - (prefix.len() - n_start);
    Some((obj_num, gen, off))
}

fn find_stream_payload(body: &[u8]) -> Option<&[u8]> {
    // Stream begins after "stream\n" or "stream\r\n" and ends before "endstream"
    let lower = body;
    let pos = lower.windows(7).position(|w| w == b"stream\n")
        .or_else(|| lower.windows(8).position(|w| w == b"stream\r\n"))
        .or_else(|| lower.windows(6).position(|w| w == b"stream"))?;
    let start = pos + if lower[pos + 6..].first() == Some(&b'\n') { 7 }
                  else if lower[pos + 6..].first() == Some(&b'\r') { 8 } else { 6 };
    let end = lower.len().min(start + 4096);
    Some(&lower[start..end])
}

fn detect_embedded_magic(payload: &[u8]) -> Option<&'static str> {
    if payload.len() < 4 { return None; }
    if payload.starts_with(b"MZ") { return Some("PE/MZ"); }
    if payload.starts_with(b"\x7FELF") { return Some("ELF"); }
    if payload.starts_with(b"\xCA\xFE\xBA\xBE") { return Some("Mach-O Fat / Java class"); }
    if payload.starts_with(b"%PDF-") { return Some("nested PDF"); }
    if payload.starts_with(b"PK\x03\x04") { return Some("ZIP / DOCX / XLSX"); }
    if payload.starts_with(b"Rar!") { return Some("RAR"); }
    if payload.starts_with(b"7z\xBC\xAF\x27\x1C") { return Some("7z"); }
    if payload.starts_with(b"\x1F\x8B") { return Some("gzip"); }
    if payload.starts_with(b"\xFD7zXZ") { return Some("xz"); }
    None
}

fn is_suspicious_uri(uri: &str) -> bool {
    let lower = uri.to_ascii_lowercase();
    // Non-hierarchical dangerous schemes carry no `://` — check them before
    // the gate below (previously these arms were dead code: the early return
    // rejected every URI without `://`, including `javascript:` itself).
    if lower.starts_with("javascript:") || lower.starts_with("data:") {
        return true;
    }
    let scheme_pos = lower.find("://");
    if scheme_pos.is_none() { return false; }
    // file://, ftp://, smb://, ldap://, gopher:// are unusual in PDFs
    let scheme = &lower[..scheme_pos.unwrap() + 3];
    if matches!(scheme, "file://" | "ftp://" | "smb://" | "ldap://" | "tftp://"
                     | "gopher://")
    {
        return true;
    }
    if lower.contains(".exe") || lower.contains(".scr") || lower.contains(".bat")
        || lower.contains(".ps1") || lower.contains(".vbs") || lower.contains(".hta")
        || lower.contains(".lnk")
    {
        return true;
    }
    if lower.contains('@') { return true; }  // @ in URL: phishing / bypass
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_pdf() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"%PDF-1.4\n");
        v.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        v.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
        v.extend_from_slice(b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n");
        v.extend_from_slice(b"xref\n0 4\n");
        v.extend_from_slice(b"0000000000 65535 f \n");
        v.extend_from_slice(b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n0\n%%EOF\n");
        v
    }

    #[test]
    fn test_basic_pdf() {
        let pdf = make_minimal_pdf();
        let r = analyze_pdf(&pdf).unwrap();
        assert_eq!(r.version, "1.4");
        assert_eq!(r.object_count, 3);
        assert!(!r.is_encrypted);
    }

    #[test]
    fn test_javascript_detection() {
        let mut pdf = make_minimal_pdf();
        let inj = b"\n4 0 obj\n<< /S /JavaScript /JS (app.alert(1)) >>\nendobj\n";
        pdf.extend_from_slice(inj);
        let r = analyze_pdf(&pdf).unwrap();
        assert!(r.has_javascript);
        assert!(r.findings.iter().any(|f| f.rule_id == "PDF_JAVASCRIPT"));
    }

    #[test]
    fn test_open_action_detection() {
        let mut pdf = make_minimal_pdf();
        let inj = b"\n4 0 obj\n<< /OpenAction 5 0 R >>\nendobj\n";
        pdf.extend_from_slice(inj);
        let r = analyze_pdf(&pdf).unwrap();
        assert!(r.has_open_action);
    }

    #[test]
    fn test_suspicious_uri() {
        assert!(is_suspicious_uri("file:///c:/windows/system32/cmd.exe"));
        assert!(is_suspicious_uri("http://evil.com/payload.exe"));
        assert!(is_suspicious_uri("javascript:alert(1)"));
        assert!(!is_suspicious_uri("https://example.com/"));
    }
}
