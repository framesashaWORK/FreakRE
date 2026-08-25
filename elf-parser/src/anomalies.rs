//! ELF anomaly detection for malware analysis.

use crate::error::{ElfWarning, ElfWarningKind};
use crate::header::ElfIdent;
use crate::program::{ProgramHeader, ProgramType};
use crate::sections::SectionHeader;

/// Detect structural anomalies in an ELF64 binary.
pub fn detect_anomalies_elf64(
    data: &[u8],
    program_headers: &[ProgramHeader],
    section_headers: &[SectionHeader<'_>],
    ident: &ElfIdent,
    warnings: &mut Vec<ElfWarning>,
) {
    check_static_linking(program_headers, warnings);
    check_stripped(section_headers, warnings);
    check_executable_segment_exists(program_headers, section_headers, warnings);
    check_missing_protections(program_headers, warnings);
    check_suspicious_interpreter(program_headers, data, warnings);
    check_unusual_architecture(ident, warnings);
}

/// Detect structural anomalies in an ELF32 binary.
pub fn detect_anomalies_elf32(
    data: &[u8],
    program_headers: &[ProgramHeader],
    section_headers: &[SectionHeader<'_>],
    ident: &ElfIdent,
    warnings: &mut Vec<ElfWarning>,
) {
    // Same checks apply to both 32 and 64 bit
    detect_anomalies_elf64(data, program_headers, section_headers, ident, warnings);
}

/// Statically linked binaries are common in IoT malware (no libc dependency).
fn check_static_linking(program_headers: &[ProgramHeader], warnings: &mut Vec<ElfWarning>) {
    let has_interp = program_headers.iter().any(|p| p.p_type == ProgramType::Interp);
    if !has_interp && !program_headers.is_empty() {
        warnings.push(ElfWarning {
            kind: ElfWarningKind::StaticallyLinked,
            message: "No INTERP segment found - statically linked binary".into(),
        });
    }
}

/// Stripped binaries hide symbol information (common in malware).
fn check_stripped(section_headers: &[SectionHeader<'_>], warnings: &mut Vec<ElfWarning>) {
    let has_symtab = section_headers.iter().any(|s| s.name == ".symtab");
    if !has_symtab && !section_headers.is_empty() {
        warnings.push(ElfWarning {
            kind: ElfWarningKind::StrippedBinary,
            message: "No .symtab section found - binary is stripped".into(),
        });
    }
}

/// Check if the binary has at least one executable LOAD segment.
/// Without an executable segment, the entry point cannot be reached.
/// Renamed from `check_entry_point_bounds` since we don't have direct access
/// to the entry point value here — full bounds checking is done in lib.rs.
fn check_executable_segment_exists(
    program_headers: &[ProgramHeader],
    _section_headers: &[SectionHeader<'_>],
    warnings: &mut Vec<ElfWarning>,
) {
    let has_exec_load = program_headers
        .iter()
        .any(|p| p.p_type == ProgramType::Load && p.is_executable());

    if !has_exec_load && !program_headers.is_empty() {
        warnings.push(ElfWarning {
            kind: ElfWarningKind::EntryPointOutOfBounds,
            message: "No executable LOAD segment found - entry point may be unreachable".into(),
        });
    }
}

/// Check for missing security protections (NX, RELRO).
fn check_missing_protections(program_headers: &[ProgramHeader], warnings: &mut Vec<ElfWarning>) {
    let has_gnu_stack = program_headers.iter().any(|p| p.p_type == ProgramType::GnuStack);
    let has_relro = program_headers.iter().any(|p| p.p_type == ProgramType::GnuRelro);

    if !has_gnu_stack && !program_headers.is_empty() {
        warnings.push(ElfWarning {
            kind: ElfWarningKind::MissingProtection,
            message: "No GNU_STACK segment - NX protection status unknown".into(),
        });
    }

    if !has_relro && !program_headers.is_empty() {
        warnings.push(ElfWarning {
            kind: ElfWarningKind::MissingProtection,
            message: "No GNU_RELRO segment - partial/full RELRO not enabled".into(),
        });
    }
}

/// Check for suspicious interpreter paths.
fn check_suspicious_interpreter(
    program_headers: &[ProgramHeader],
    data: &[u8],
    warnings: &mut Vec<ElfWarning>,
) {
    for ph in program_headers {
        if ph.p_type != ProgramType::Interp {
            continue;
        }

        let start = ph.offset as usize;
        let end = match start.checked_add(ph.filesz as usize) {
            Some(e) if e <= data.len() => e,
            _ => continue,
        };

        let interp_path = String::from_utf8_lossy(&data[start..end]);
        let path = interp_path.trim_end_matches('\0');

        // Normal interpreters
        let normal_paths = [
            "/lib64/ld-linux-x86-64.so",
            "/lib/ld-linux.so",
            "/lib/ld-linux-aarch64.so",
            "/lib/ld-musl-",
            "/usr/lib/",
        ];

        let is_normal = normal_paths.iter().any(|n| path.contains(n));

        if !is_normal && !path.is_empty() {
            warnings.push(ElfWarning {
                kind: ElfWarningKind::SuspiciousInterpreter,
                message: format!("Unusual interpreter path: '{}'", path),
            });
        }
    }
}

/// Flag unusual architectures that might indicate cross-compiled malware.
fn check_unusual_architecture(_ident: &ElfIdent, _warnings: &mut Vec<ElfWarning>) {
    // This is informational - unusual arch alone isn't malicious
    // but combined with other indicators it's relevant for IoT malware
    // Placeholder for future arch-specific checks
}
