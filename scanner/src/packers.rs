//! Packer / protector detection (extracted from `scanner.rs`).
//!
//! Section-name markers + byte-level masked signatures. Specific and
//! low-false-positive, unlike the generic high-entropy heuristic.

use crate::report::{Finding, Severity};
use entropy_rs::calculate_entropy;
use pe_parser::PeFile;

/// (section-name substring, display name, rule suffix, severity)
const PACKER_MARKERS: &[(&str, &str, &str, Severity)] = &[
    ("upx", "UPX", "UPX", Severity::Medium),
    ("themida", "Themida / WinLicense", "THEMIDA", Severity::High),
    (
        "winlicense",
        "Themida / WinLicense",
        "THEMIDA",
        Severity::High,
    ),
    ("vmp", "VMProtect", "VMPROTECT", Severity::High),
    (".vmp0", "VMProtect", "VMPROTECT", Severity::High),
    (".vmp1", "VMProtect", "VMPROTECT", Severity::High),
    ("obsidium", "Obsidium", "OBSIDIUM", Severity::High),
    ("enigma", "Enigma Protector", "ENIGMA", Severity::High),
    ("aspack", "ASPack", "ASPACK", Severity::Medium),
    ("fsg", "FSG", "FSG", Severity::Medium),
    ("mew", "MEW", "MEW", Severity::Medium),
    ("nsp", "NSPack", "NSPACK", Severity::Medium),
    ("pespin", "PESpin", "PESPIN", Severity::Medium),
    ("petite", "Petite", "PETITE", Severity::Medium),
    ("yoda", "Yoda's Protector", "YODA", Severity::Medium),
    ("packed", "Generic Packer", "GENERIC", Severity::Medium),
    ("packman", "Packman", "PACKMAN", Severity::Medium),
    ("molebox", "Molebox", "MOLEBOX", Severity::Medium),
    ("telock", "tElock", "TELOCK", Severity::Medium),
    ("upack", "UPack", "UPACK", Severity::Medium),
    ("boxedapp", "BoxedApp", "BOXEDAPP", Severity::Medium),
    ("stf", "StarForce", "STARFORCE", Severity::High),
    (".neolite", "NeoLite", "NEOLITE", Severity::Medium),
    ("slv", "SLV", "SLV", Severity::Medium),
];

/// Match a section name against known packer markers.
#[must_use]
pub fn match_packer(name: &str) -> Option<(&'static str, &'static str, Severity)> {
    let lower = name.to_ascii_lowercase();
    PACKER_MARKERS
        .iter()
        .find(|(marker, _, _, _)| lower.contains(marker))
        .map(|(_, display, suffix, sev)| (*display, *suffix, *sev))
}

/// Byte-level packer/protector signatures. `needle`/`mask` pairs: bytes where the
/// corresponding `mask` byte is `0xFF` must match exactly; `0x00` = wildcard (`??`).
/// Catches packers even when section names are renamed or stripped.
type PackerByteSig = (
    &'static str,
    &'static str,
    Severity,
    &'static [u8],
    &'static [u8],
);
const PACKER_BYTE_SIGS: &[PackerByteSig] = &[
    // ASPack 2.x entry stub: pushad; call $+5; pop ebp; sub ebp,0D; add ebp,[...]
    (
        "ASPack",
        "ASPACK",
        Severity::High,
        &[
            0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x83, 0xED, 0x0D, 0x03, 0x2D,
        ],
        &[
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ],
    ),
    // VMProtect 2.x/3.x: push imm32; call rel32; pushfd; push imm32; call rel32; pushfd
    (
        "VMProtect",
        "VMPROTECT",
        Severity::High,
        &[
            0x68, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x9C, 0x68, 0x00, 0x00,
            0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x9C,
        ],
        &[
            0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
            0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF,
        ],
    ),
    // Themida 2.x polymorphic entry: jmp rel32; push esi; push edi; mov edi,[esi+imm]
    (
        "Themida / WinLicense",
        "THEMIDA",
        Severity::High,
        &[0xE9, 0x00, 0x00, 0x00, 0x00, 0x56, 0x57, 0x8B, 0x7E, 0x00],
        &[0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00],
    ),
];

/// Does `data` contain `needle` at any offset, honouring the `mask` (0x00 = wildcard)?
#[must_use]
pub fn masked_contains(data: &[u8], needle: &[u8], mask: &[u8]) -> bool {
    if needle.len() != mask.len() || needle.is_empty() {
        return false;
    }
    data.windows(needle.len()).any(|w| {
        w.iter()
            .zip(needle.iter().zip(mask.iter()))
            .all(|(b, (n, m))| *m == 0x00 || *b == *n)
    })
}

/// Identify known packers / protectors in a PE file.
pub fn detect_packers(pe: &PeFile<'_>, data: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen: std::collections::HashSet<&'static str> = std::collections::HashSet::new();

    for section in &pe.sections {
        let name = section.name_string();
        if let Some((display, suffix, sev)) = match_packer(&name) {
            if seen.insert(suffix) {
                let raw = section.raw_data(data);
                let ent = if raw.is_empty() {
                    0.0
                } else {
                    calculate_entropy(raw).entropy
                };
                findings.push(Finding {
                    severity: sev,
                    module: "pe-parser".into(),
                    rule_id: format!("PE_PACKER_{}", suffix),
                    description: format!(
                        "Likely packed / protected with {} (section '{}', entropy {:.2})",
                        display, name, ent
                    ),
                    details: Some(format!("section: {}; entropy: {:.2}", name, ent)),
                });
            }
        }
    }

    // UPX leaves a distinctive "UPX!" magic even when section names are renamed.
    if data.windows(4).any(|w| w == b"UPX!") && seen.insert("UPX") {
        findings.push(Finding {
            severity: Severity::Medium,
            module: "pe-parser".into(),
            rule_id: "PE_PACKER_UPX".into(),
            description: "UPX magic 'UPX!' found in binary — packed with UPX".into(),
            details: Some("UPX! signature detected".into()),
        });
    }

    // Byte-level signatures (work even when section names are obfuscated).
    for (display, suffix, sev, needle, mask) in PACKER_BYTE_SIGS {
        if masked_contains(data, needle, mask) && seen.insert(*suffix) {
            findings.push(Finding {
                severity: *sev,
                module: "pe-parser".into(),
                rule_id: format!("PE_PACKER_{}", suffix),
                description: format!(
                    "Packer/protector byte-signature match for {} (High confidence)",
                    display
                ),
                details: Some(format!(
                    "matched {} byte pattern at {}",
                    needle.len(),
                    suffix.to_ascii_lowercase()
                )),
            });
        }
    }

    findings
}

/// True if the PE is a shared library (DLL) — i.e. the COFF File Header
/// `Characteristics` has the `IMAGE_FILE_DLL` (0x2000) bit set.
pub fn pe_is_library(data: &[u8]) -> bool {
    if data.len() < 64 {
        return false;
    }
    let lfanew = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    let coff = lfanew + 4; // skip the "PE\0\0" signature
    if coff + 20 > data.len() {
        return false;
    }
    let characteristics = u16::from_le_bytes([data[coff + 18], data[coff + 19]]);
    characteristics & 0x2000 != 0
}

/// Entropy of the section containing `offset`, or `None` if the offset is
/// outside any section (e.g. an overlay).
pub fn section_index_for_offset(pe: &PeFile<'_>, offset: usize) -> Option<usize> {
    pe.sections.iter().position(|s| {
        let start = s.raw_data_offset as usize;
        let end = start.saturating_add(s.raw_data_size as usize);
        offset >= start && offset < end
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_match_packer_markers() {
        // UPX section names should resolve to UPX (Medium).
        let (display, suffix, sev) = match_packer("UPX0").unwrap();
        assert_eq!(display, "UPX");
        assert_eq!(suffix, "UPX");
        assert_eq!(sev, Severity::Medium);

        // VMProtect virtual section → High severity.
        let (_, suffix, sev) = match_packer(".vmp0").unwrap();
        assert_eq!(suffix, "VMPROTECT");
        assert_eq!(sev, Severity::High);

        // Themida → High severity.
        let (_, _, sev) = match_packer(".themida").unwrap();
        assert_eq!(sev, Severity::High);

        // Ordinary section names must not match anything.
        assert!(match_packer(".text").is_none());
        assert!(match_packer(".rdata").is_none());
        assert!(match_packer(".rsrc").is_none());
    }
}
