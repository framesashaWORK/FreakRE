//! # Firmware / UEFI / BIOS Analyzer
//!
//! Surface analysis of firmware blobs:
//!
//! * **UEFI Firmware Volume** (`_FVH` header)
//! * **FFS (Firmware File System)**: parses the FFS entry header, the EFI_GUID
//!   identifying the file (e.g. DXE drivers, PE32 sections, raw volumes)
//! * **GPT partition table**: protective MBR + main header + entries
//! * **MBR partition table** (legacy BIOS)
//! * **Embedded PE32**: any `_FVH`/`_FV` body may contain a UEFI PE image
//!   with subsystem `EFI_APPLICATION`, `EFI_BOOT_SERVICE_DRIVER`,
//!   `EFI_RUNTIME_DRIVER` or `EFI_ROM`. We record the offsets so the
//!   parent scanner can run a full PE analysis on the embedded image.
//!
//! The output is metadata + findings; a full UEFI security analysis
//! (SMM/SMI handlers, S3 boot script, secure boot variables) is out of
//! scope but the surface is enough to triage a sample.

use serde::{Deserialize, Serialize};

/// Outcome of analyzing a firmware blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareReport {
    pub kind: FirmwareKind,
    /// UEFI / BIOS volumes discovered.
    pub volumes: Vec<VolumeInfo>,
    /// GPT partition entries (if any).
    pub gpt_partitions: Vec<GptPartition>,
    /// MBR partition entries (if any).
    pub mbr_partitions: Vec<MbrPartition>,
    /// Embedded PE32 images with EFI subsystems.
    pub embedded_pe: Vec<EmbeddedPe>,
    /// Severity-tagged findings.
    pub findings: Vec<FirmwareFinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FirmwareKind {
    Mbr,
    GptDisk,
    UefiFirmwareVolume,
    UefiFfs,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FirmwareSeverity { Info, Low, Medium, High, Critical }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareFinding {
    pub severity: FirmwareSeverity,
    pub rule_id: String,
    pub description: String,
    pub offset: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeInfo {
    pub offset: usize,
    pub size: usize,
    pub signature: String,
    pub revision: u32,
    pub ffs_count: usize,
    pub ffs_guids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GptPartition {
    pub name: String,
    pub type_guid: String,
    pub unique_guid: String,
    pub first_lba: u64,
    pub last_lba: u64,
    pub attributes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MbrPartition {
    pub index: u8,
    pub status: u8,
    pub partition_type: u8,
    pub start_lba: u32,
    pub sector_count: u32,
    pub bootable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedPe {
    pub offset: usize,
    pub size_estimate: usize,
    pub subsystem: u16,
    pub subsystem_name: String,
}

/// Top-level entry point. Returns `Some(_)` whenever the input looks like
/// firmware; `None` for unrelated content.
pub fn analyze_firmware(data: &[u8]) -> Option<FirmwareReport> {
    if data.len() < 512 { return None; }

    let mut report = FirmwareReport {
        kind: FirmwareKind::Unknown,
        volumes: Vec::new(),
        gpt_partitions: Vec::new(),
        mbr_partitions: Vec::new(),
        embedded_pe: Vec::new(),
        findings: Vec::new(),
    };

    // ─── MBR / GPT ──────────────────────────────────────────────────
    if data.len() >= 0x200 && data[0x1FE] == 0x55 && data[0x1FF] == 0xAA {
        let kind = if data.len() >= 0x400 && &data[0x200..0x208] == b"EFI PART" {
            FirmwareKind::GptDisk
        } else {
            FirmwareKind::Mbr
        };
        report.kind = kind;
        report.mbr_partitions = parse_mbr(data);
        if matches!(kind, FirmwareKind::GptDisk) {
            report.gpt_partitions = parse_gpt(data);
            push_finding(&mut report.findings, FirmwareSeverity::Info, "FW_GPT",
                format!("GPT disk with {} partitions", report.gpt_partitions.len()),
                0x200);
        } else {
            push_finding(&mut report.findings, FirmwareSeverity::Info, "FW_MBR",
                format!("MBR disk with {} partitions", report.mbr_partitions.len()),
                0);
        }
    }

    // ─── UEFI Firmware Volume ──────────────────────────────────────
    let mut p = 0;
    while p + 56 < data.len() {
        if &data[p..p + 4] == b"_FVH" {
            if let Some(v) = parse_firmware_volume(data, p) {
                report.volumes.push(v.clone());
                push_finding(&mut report.findings, FirmwareSeverity::Info, "FW_FVH",
                    format!("UEFI Firmware Volume at 0x{:X} ({} bytes, {} FFS files)",
                        v.offset, v.size, v.ffs_count),
                    p);
                if let Some(pe) = find_embedded_pe(&data[p..p + v.size]) {
                    report.embedded_pe.push(pe);
                }
                p += v.size;
                continue;
            }
        }
        p += 0x10;
    }
    if !report.volumes.is_empty() && matches!(report.kind, FirmwareKind::Unknown) {
        report.kind = FirmwareKind::UefiFirmwareVolume;
    }

    if report.kind == FirmwareKind::Unknown && report.volumes.is_empty()
        && report.mbr_partitions.is_empty() {
        return None;
    }
    Some(report)
}

fn push_finding(out: &mut Vec<FirmwareFinding>, severity: FirmwareSeverity, rule_id: &str,
                description: String, offset: usize) {
    out.push(FirmwareFinding { severity, rule_id: rule_id.to_string(), description, offset });
}

fn parse_mbr(data: &[u8]) -> Vec<MbrPartition> {
    let mut out = Vec::new();
    if data.len() < 0x1BE { return out; }
    for i in 0..4 {
        let off = 0x1BE + i * 16;
        let status = data[off];
        let ptype = data[off + 4];
        if ptype == 0 { continue; }
        let lba_start = u32::from_le_bytes([data[off + 8], data[off + 9], data[off + 10], data[off + 11]]);
        let lba_count = u32::from_le_bytes([data[off + 12], data[off + 13], data[off + 14], data[off + 15]]);
        out.push(MbrPartition {
            index: i as u8,
            status,
            partition_type: ptype,
            start_lba: lba_start,
            sector_count: lba_count,
            bootable: status == 0x80,
        });
    }
    out
}

fn parse_gpt(data: &[u8]) -> Vec<GptPartition> {
    let mut out = Vec::new();
    if data.len() < 0x400 { return out; }
    let header = &data[0x200..];
    if &header[0..8] != b"EFI PART" { return out; }
    let part_entry_lba = u64::from_le_bytes([
        header[0x48], header[0x49], header[0x4A], header[0x4B],
        header[0x4C], header[0x4D], header[0x4E], header[0x4F],
    ]);
    let part_count = u32::from_le_bytes([header[0x50], header[0x51], header[0x52], header[0x53]]) as usize;
    let part_size = u32::from_le_bytes([header[0x54], header[0x55], header[0x56], header[0x57]]) as usize;
    if part_entry_lba == 0 || part_size < 128 { return out; }
    let start_off = (part_entry_lba as usize) * 512;
    for i in 0..part_count {
        let off = start_off + i * part_size;
        if off + part_size > data.len() { break; }
        let e = &data[off..off + part_size];
        // Empty entry: all zero type GUID
        if e[0..16].iter().all(|&b| b == 0) { continue; }
        let type_guid = format_guid(&e[0..16]);
        let unique_guid = format_guid(&e[16..32]);
        let first_lba = u64::from_le_bytes([
            e[32], e[33], e[34], e[35], e[36], e[37], e[38], e[39],
        ]);
        let last_lba = u64::from_le_bytes([
            e[40], e[41], e[42], e[43], e[44], e[45], e[46], e[47],
        ]);
        let attributes = u64::from_le_bytes([
            e[48], e[49], e[50], e[51], e[52], e[53], e[54], e[55],
        ]);
        let name_bytes = &e[56..128];
        let name: String = name_bytes
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .filter_map(|u| char::from_u32(u as u32))
            .take_while(|c| *c != '\0')
            .collect();
        out.push(GptPartition {
            name,
            type_guid,
            unique_guid,
            first_lba,
            last_lba,
            attributes,
        });
    }
    out
}

fn parse_firmware_volume(data: &[u8], off: usize) -> Option<VolumeInfo> {
    // EFI_FIRMWARE_VOLUME_HEADER
    if off + 56 > data.len() { return None; }
    let h = &data[off..off + 56];
    if &h[0..4] != b"_FVH" { return None; }
    let _rsvd0 = &h[4..16];
    let header_length = u32::from_le_bytes([h[16], h[17], h[18], h[19]]) as usize;
    let sig = u32::from_le_bytes([h[20], h[21], h[22], h[23]]);
    let _attr = u32::from_le_bytes([h[24], h[25], h[26], h[27]]);
    let header_length = if header_length == 0 { 56 } else { header_length };
    let header_length = header_length.min(data.len() - off);
    let fv_length = u64::from_le_bytes([
        h[32], h[33], h[34], h[35], h[36], h[37], h[38], h[39],
    ]) as usize;
    let _rev = u32::from_le_bytes([h[40], h[41], h[42], h[43]]);
    let _block_map_off = h[44];

    let signature = match sig {
        0x4856465F => "EFI_FVH",
        _ => "UNKNOWN",
    }.to_string();

    // Walk the FFS files inside. FFS header is 24 bytes, aligned to 8.
    let mut p = off + header_length;
    let end = (off + fv_length).min(data.len());
    let mut ffs_count = 0;
    let mut ffs_guids: Vec<String> = Vec::new();
    while p + 24 <= end {
        let f = &data[p..p + 24];
        // FFS file name: 16-byte GUID
        if f[0..16].iter().all(|&b| b == 0xFF) { p += 8; continue; }
        if f[0..16].iter().all(|&b| b == 0) { p += 8; continue; }
        let size = u32::from_le_bytes([f[16], f[17], f[18], f[19]]) as usize;
        if size < 24 || p + size > end { break; }
        let guid = format_guid(&f[0..16]);
        ffs_guids.push(guid);
        ffs_count += 1;
        p += (size + 7) & !7;
    }
    Some(VolumeInfo {
        offset: off,
        size: fv_length.min(end - off),
        signature,
        revision: u32::from_le_bytes([h[40], h[41], h[42], h[43]]),
        ffs_count,
        ffs_guids,
    })
}

fn find_embedded_pe(data: &[u8]) -> Option<EmbeddedPe> {
    // Look for MZ signature followed by a PE header within the volume.
    let mut p = 0;
    while p + 64 < data.len() {
        if data[p] == b'M' && data[p + 1] == b'Z' {
            if let Some(pe_off) = read_u32(data, p + 0x3C) {
                let pe = p + pe_off as usize;
                if pe + 24 < data.len() && &data[pe..pe + 4] == b"PE\0\0" {
                    let coff = pe + 4;
                    let opt_off = coff + 20;
                    if opt_off + 2 < data.len() {
                        let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
                        if matches!(magic, 0x10B | 0x20B) {
                            let opt_size = u16::from_le_bytes([data[opt_off + 16], data[opt_off + 17]]) as usize;
                            // Subsystem at +68 within optional header (PE32)
                            let subs_off = opt_off + 68;
                            if subs_off + 2 < data.len() {
                                let subsystem = u16::from_le_bytes([data[subs_off], data[subs_off + 1]]);
                                let name = match subsystem {
                                    0x0B => "EFI_APPLICATION",
                                    0x0C => "EFI_BOOT_SERVICE_DRIVER",
                                    0x0D => "EFI_RUNTIME_DRIVER",
                                    0x12 => "EFI_ROM",
                                    _ => return None,
                                };
                                return Some(EmbeddedPe {
                                    offset: p,
                                    size_estimate: opt_size,
                                    subsystem,
                                    subsystem_name: name.into(),
                                });
                            }
                        }
                    }
                }
            }
        }
        p += 1;
    }
    None
}

fn format_guid(g: &[u8]) -> String {
    if g.len() < 16 { return String::new(); }
    let d1 = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
    let d2 = u16::from_le_bytes([g[4], g[5]]);
    let d3 = u16::from_le_bytes([g[6], g[7]]);
    format!("{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        d1, d2, d3, g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15])
}

fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    if off + 4 > data.len() { return None; }
    Some(u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mbr() -> Vec<u8> {
        let mut v = vec![0u8; 512];
        v[0x1FE] = 0x55;
        v[0x1FF] = 0xAA;
        // partition entry 0: status=0x80, type=0x83, start LBA=2048, size 0x10000
        v[0x1BE] = 0x80; v[0x1BE + 4] = 0x83;
        v[0x1BE + 8..0x1BE + 12].copy_from_slice(&2048u32.to_le_bytes());
        v[0x1BE + 12..0x1BE + 16].copy_from_slice(&0x10000u32.to_le_bytes());
        v
    }

    #[test]
    fn test_mbr() {
        let data = make_mbr();
        let r = analyze_firmware(&data).unwrap();
        assert_eq!(r.kind, FirmwareKind::Mbr);
        assert_eq!(r.mbr_partitions.len(), 1);
        assert!(r.mbr_partitions[0].bootable);
    }

    #[test]
    fn test_gpt() {
        let mut data = vec![0u8; 0x10000];
        // MBR signature
        data[0x1FE] = 0x55; data[0x1FF] = 0xAA;
        // GPT header at LBA1
        let h = 0x200;
        data[h..h + 8].copy_from_slice(b"EFI PART");
        data[h + 0x48..h + 0x50].copy_from_slice(&2u64.to_le_bytes()); // partition array LBA
        data[h + 0x50..h + 0x54].copy_from_slice(&4u32.to_le_bytes());  // count
        data[h + 0x54..h + 0x58].copy_from_slice(&128u32.to_le_bytes()); // size
        // one partition at LBA 2
        let e = 2 * 512;
        data[e..e + 16].copy_from_slice(&[1u8; 16]);
        data[e + 16..e + 32].copy_from_slice(&[2u8; 16]);
        data[e + 32..e + 40].copy_from_slice(&2048u64.to_le_bytes());
        data[e + 40..e + 48].copy_from_slice(&4096u64.to_le_bytes());
        let r = analyze_firmware(&data).unwrap();
        assert_eq!(r.kind, FirmwareKind::GptDisk);
        assert_eq!(r.gpt_partitions.len(), 1);
    }
}
