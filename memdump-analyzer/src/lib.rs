//! # Memory Dump Analyzer
//!
//! Triage for `.dmp` files and raw memory blobs:
//!
//! * **Windows Minidump** (`MDMP` signature) — header streams
//! * **ELF core** (`\x7FELF` + `e_type == ET_CORE = 4`)
//! * **Mach-O core** (`MH_MAGIC`/`MH_MAGIC_64` + `filetype == 4`)
//! * **In-memory PE scanning** — walks the file for `MZ` magic and reports
//!   candidate loaded modules. Allows the parent scanner to recurse on the
//!   embedded PE.
//!
//! We do not attempt full process state reconstruction; the goal is to
//! give the operator the high-level layout and a list of modules to
//! analyze further.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DumpKind {
    Minidump,
    ElfCore,
    MachoCore,
    RawMemory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpReport {
    pub kind: DumpKind,
    /// 16-byte stream GUIDs (Minidump).
    pub streams: Vec<MinidumpStream>,
    /// Candidate PEs found inside the dump.
    pub embedded_pe: Vec<EmbeddedPe>,
    /// Candidate MZ hits that did not pass validation.
    pub raw_mz_hits: usize,
    pub findings: Vec<DumpFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinidumpStream {
    pub kind: u32,
    pub kind_name: String,
    pub offset: usize,
    pub size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedPe {
    pub offset: usize,
    pub size_estimate: usize,
    pub machine: String,
    pub is_64bit: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DumpSeverity { Info, Low, Medium, High, Critical }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpFinding {
    pub severity: DumpSeverity,
    pub rule_id: String,
    pub description: String,
    pub offset: usize,
}

const MINIDUMP_STREAM_TYPES: &[(&str, u32)] = &[
    ("Unused", 0),
    ("ThreadList", 3),
    ("ModuleList", 4),
    ("MemoryList", 5),
    ("Exception", 6),
    ("SystemInfo", 7),
    ("ThreadExList", 8),
    ("Memory64List", 9),
    ("CommentA", 10),
    ("CommentW", 11),
    ("HandleData", 12),
    ("FunctionTable", 13),
    ("UnloadedModuleList", 14),
    ("MiscInfo", 15),
    ("MemoryInfoList", 16),
    ("ThreadInfoList", 17),
];

/// Top-level entry point. Returns `Some(_)` for recognized dump types
/// (including `RawMemory` if MZ candidates are present).
pub fn analyze_dump(data: &[u8]) -> Option<DumpReport> {
    if data.len() < 32 { return None; }

    // Windows Minidump: "MDMP" + signature1 + signature2 + NumberOfStreams
    if data.starts_with(b"MDMP") {
        return Some(analyze_minidump(data));
    }
    // ELF core
    if data.starts_with(b"\x7FELF") && data.len() >= 0x14 {
        let e_type = u16::from_le_bytes([data[0x10], data[0x11]]);
        if e_type == 4 {
            return Some(analyze_elf_core(data));
        }
    }
    // Mach-O core
    let magic_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if data.len() >= 0x10 && matches!(magic_le, 0xFEEDFACE | 0xFEEDFACF) {
        let filetype = u32::from_le_bytes([data[0x0C], data[0x0D], data[0x0E], data[0x0F]]);
        if filetype == 4 {
            return Some(analyze_macho_core(data));
        }
    }

    // Fallback: raw memory, only return Some if we find at least one MZ
    let hits = scan_for_mz(data);
    if hits.is_empty() { return None; }
    let mut report = DumpReport {
        kind: DumpKind::RawMemory,
        streams: Vec::new(),
        embedded_pe: Vec::new(),
        raw_mz_hits: hits.len(),
        findings: Vec::new(),
    };
    for h in hits.into_iter().take(64) {
        if let Some(pe) = try_parse_pe_at(data, h) {
            report.embedded_pe.push(pe);
        }
    }
    if !report.embedded_pe.is_empty() {
        report.findings.push(DumpFinding {
            severity: DumpSeverity::Info,
            rule_id: "DUMP_EMBEDDED_PE".into(),
            description: format!("{} embedded PE candidate(s) found",
                report.embedded_pe.len()),
            offset: 0,
        });
    }
    Some(report)
}

fn analyze_minidump(data: &[u8]) -> DumpReport {
    let mut report = DumpReport {
        kind: DumpKind::Minidump,
        streams: Vec::new(),
        embedded_pe: Vec::new(),
        raw_mz_hits: 0,
        findings: Vec::new(),
    };
    if data.len() < 32 { return report; }
    let num_streams = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
    let mut p = 32;
    for _ in 0..num_streams {
        if p + 12 > data.len() { break; }
        let kind = u32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
        let size = u32::from_le_bytes([data[p + 8], data[p + 9], data[p + 10], data[p + 11]]) as usize;
        let kind_name = MINIDUMP_STREAM_TYPES.iter()
            .find(|(_, k)| *k == kind)
            .map(|(n, _)| n.to_string())
            .unwrap_or_else(|| format!("Stream_{}", kind));
        report.streams.push(MinidumpStream {
            kind,
            kind_name: kind_name.clone(),
            offset: p + 12,
            size,
        });
        if kind == 4 {
            report.findings.push(DumpFinding {
                severity: DumpSeverity::Info,
                rule_id: "DUMP_MODULE_LIST".into(),
                description: "Minidump contains ModuleList — list of loaded modules".into(),
                offset: p + 12,
            });
        }
        p += 12 + size;
    }
    // Now scan for embedded PEs
    for h in scan_for_mz(data).into_iter().take(128) {
        if let Some(pe) = try_parse_pe_at(data, h) {
            report.embedded_pe.push(pe);
        }
    }
    if !report.embedded_pe.is_empty() {
        report.findings.push(DumpFinding {
            severity: DumpSeverity::Info,
            rule_id: "DUMP_EMBEDDED_PE".into(),
            description: format!("{} embedded PE candidate(s) found in dump",
                report.embedded_pe.len()),
            offset: 0,
        });
    }
    report
}

fn analyze_elf_core(data: &[u8]) -> DumpReport {
    let mut report = DumpReport {
        kind: DumpKind::ElfCore,
        streams: Vec::new(),
        embedded_pe: Vec::new(),
        raw_mz_hits: 0,
        findings: Vec::new(),
    };
    if data.len() >= 0x12 {
        let e_type = u16::from_le_bytes([data[0x10], data[0x11]]);
        report.findings.push(DumpFinding {
            severity: DumpSeverity::Info,
            rule_id: "DUMP_ELF_CORE".into(),
            description: format!("ELF core dump, e_type = {}", e_type),
            offset: 0,
        });
    }
    for h in scan_for_mz(data).into_iter().take(128) {
        if let Some(pe) = try_parse_pe_at(data, h) {
            report.embedded_pe.push(pe);
        }
    }
    report
}

fn analyze_macho_core(data: &[u8]) -> DumpReport {
    let mut report = DumpReport {
        kind: DumpKind::MachoCore,
        streams: Vec::new(),
        embedded_pe: Vec::new(),
        raw_mz_hits: 0,
        findings: Vec::new(),
    };
    report.findings.push(DumpFinding {
        severity: DumpSeverity::Info,
        rule_id: "DUMP_MACHO_CORE".into(),
        description: "Mach-O core dump".into(),
        offset: 0,
    });
    for h in scan_for_mz(data).into_iter().take(128) {
        if let Some(pe) = try_parse_pe_at(data, h) {
            report.embedded_pe.push(pe);
        }
    }
    report
}

fn scan_for_mz(data: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let step = 0x1000; // aligned to 4 KiB page boundary; typical for OS loaders
    let mut p = 0;
    while p + 2 < data.len() {
        if data[p] == b'M' && data[p + 1] == b'Z' {
            out.push(p);
            p += step;
        } else {
            p += step;
        }
    }
    out
}

fn try_parse_pe_at(data: &[u8], off: usize) -> Option<EmbeddedPe> {
    if off + 0x40 > data.len() { return None; }
    if data[off] != b'M' || data[off + 1] != b'Z' { return None; }
    let pe_off = read_u32(data, off + 0x3C)? as usize;
    let pe_abs = off.checked_add(pe_off)?;
    if pe_abs + 24 > data.len() { return None; }
    if &data[pe_abs..pe_abs + 4] != b"PE\0\0" { return None; }
    let coff = pe_abs + 4;
    let machine = read_u16(data, coff)?;
    let machine_name = match machine {
        0x14C => "x86",
        0x8664 => "x86_64",
        0x1C0 => "ARM",
        0xAA64 => "AArch64",
        0x1C4 => "ARMNT",
        _ => return None,
    };
    let opt_off = coff + 20;
    if opt_off + 2 > data.len() { return None; }
    let opt_magic = read_u16(data, opt_off)?;
    let is_64bit = opt_magic == 0x20B;
    Some(EmbeddedPe {
        offset: off,
        size_estimate: 0,
        machine: machine_name.into(),
        is_64bit,
    })
}

fn read_u16(data: &[u8], off: usize) -> Option<u16> {
    if off + 2 > data.len() { return None; }
    Some(u16::from_le_bytes([data[off], data[off + 1]]))
}
fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    if off + 4 > data.len() { return None; }
    Some(u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_dump_returns_none() {
        assert!(analyze_dump(b"random data without magic").is_none());
    }

    #[test]
    fn test_minidump_magic() {
        let mut v = b"MDMP".to_vec();
        v.extend_from_slice(&[0, 0, 0, 0]);  // signature1
        v.extend_from_slice(&[0, 0, 0, 0]);  // signature2
        v.extend_from_slice(&0u32.to_le_bytes()); // NumberOfStreams
        v.extend_from_slice(&0u32.to_le_bytes()); // StreamDirectoryRva
        v.extend_from_slice(&0u32.to_le_bytes()); // CheckSum
        v.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
        v.extend_from_slice(&0u64.to_le_bytes()); // Flags
        let r = analyze_minidump(&v);
        assert_eq!(r.kind, DumpKind::Minidump);
    }

    #[test]
    fn test_elf_core() {
        let mut v = b"\x7FELF".to_vec();
        v.resize(0x14, 0);
        v[0x10] = 4; v[0x11] = 0; // e_type = ET_CORE
        let r = analyze_elf_core(&v);
        assert_eq!(r.kind, DumpKind::ElfCore);
    }
}
