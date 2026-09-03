//! File-type detection + hashing helpers (extracted from `scanner.rs`).
//!
//! Pure functions, no I/O. `detect_file_type` is the single entry point for
//! the future `BinaryFormat` trait.

use freakre_hash::{md5 as freakre_md5, sha256 as freakre_sha256};

/// Strip UTF-8 BOM (`EF BB BF`) from the start of `data`, if present.
pub fn strip_utf8_bom(data: &[u8]) -> Option<&[u8]> {
    if data.len() >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
        Some(&data[3..])
    } else {
        None
    }
}

/// Returns true if `haystack` contains any of `needles`.
pub fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

pub fn detect_file_type(data: &[u8]) -> String {
    if data.len() < 4 {
        return "unknown".into();
    }

    // ─── PE / DOS ───
    if data.starts_with(b"MZ") {
        if data.len() > 60 {
            let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
            if pe_offset + 4 <= data.len() && &data[pe_offset..pe_offset + 4] == b"PE\0\0"
                // Reads 2 bytes of optional-header magic ([pe_offset+24],
                // [pe_offset+25]) — both indices must be in bounds.
                && pe_offset + 26 <= data.len() {
                    let magic = u16::from_le_bytes([data[pe_offset + 24], data[pe_offset + 25]]);
                    return if magic == 0x20B {
                        "PE32+".into()
                    } else {
                        "PE32".into()
                    };
                }
        }
        return "DOS".into();
    }

    // ─── ELF ───
    if data.starts_with(b"\x7FELF") {
        return "ELF".into();
    }

    // ─── WebAssembly ───
    if data.len() >= 8 && &data[0..4] == b"\x00asm" {
        return "WebAssembly".into();
    }

    // ─── DEX (Android Dalvik Executable) ───
    if data.len() >= 8 && &data[0..4] == b"dex\n" {
        return "DEX".into();
    }

    // ─── COFF (no magic, heuristic detection) ───
    if coff_parser::is_coff(data) {
        return "COFF".into();
    }

    // ─── Intel HEX ───
    if data.starts_with(b":") && data.len() > 10 {
        // Intel HEX lines start with ':' and have specific format
        let line = String::from_utf8_lossy(&data[..data.len().min(80)]);
        if line.contains('\n') || line.len() >= 11 {
            // Basic validation: :BBAAAATT[DD..]CC
            return "Intel HEX".into();
        }
    }

    // ─── Motorola S-Record ───
    if data.starts_with(b"S0") || data.starts_with(b"S1") || data.starts_with(b"S2") || data.starts_with(b"S3") {
        return "Motorola S-Record".into();
    }

    // ─── Mach-O ───
    // Mach-O magic values:
    //   0xFEEDFACE = MH_MAGIC    (32-bit, native byte order)
    //   0xFEEDFACF = MH_MAGIC_64 (64-bit, native byte order)
    //   0xCEFAEDFE = MH_CIGAM    (32-bit, swapped byte order)
    //   0xCFFAEDFE = MH_CIGAM_64 (64-bit, swapped byte order)
    //   0xCAFEBABE = FAT_MAGIC   (Universal/Fat binary)
    //   0xBEBAFECA = FAT_CIGAM   (Universal/Fat binary, swapped)
    if data.len() >= 4 {
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        match magic {
            // Fat/Universal binary (contains multiple architectures)
            0xCAFEBABE | 0xBEBAFECA => return "Mach-O Fat".into(),
            _ => {}
        }
        let magic_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        match magic_le {
            0xFEEDFACE => return "Mach-O 32-bit".into(),
            0xFEEDFACF => return "Mach-O 64-bit".into(),
            _ => {}
        }
        // Check big-endian variants (MH_CIGAM / MH_CIGAM_64)
        let magic_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        match magic_be {
            0xFEEDFACE => return "Mach-O 32-bit (BE)".into(),
            0xFEEDFACF => return "Mach-O 64-bit (BE)".into(),
            0xCEFAEDFE => return "Mach-O 32-bit (swapped)".into(),
            0xCFFAEDFE => return "Mach-O 64-bit (swapped)".into(),
            _ => {}
        }
    }

    // ─── Script files (shebang detection) ───
    if data.starts_with(b"#!") {
        // Read first line to identify interpreter
        let first_line_end = data.iter().position(|&b| b == b'\n').unwrap_or(data.len().min(256));
        let first_line = String::from_utf8_lossy(&data[2..first_line_end]);
        let line = first_line.to_lowercase();

        if line.contains("python") || line.contains("python3") || line.contains("python2") {
            return "Script/Python".into();
        }
        if line.contains("bash") || line.contains("sh") || line.contains("zsh") || line.contains("ksh") {
            return "Script/Shell".into();
        }
        if line.contains("perl") {
            return "Script/Perl".into();
        }
        if line.contains("ruby") {
            return "Script/Ruby".into();
        }
        if line.contains("node") || line.contains("js") || line.contains("deno") {
            return "Script/JavaScript".into();
        }
        if line.contains("php") {
            return "Script/PHP".into();
        }
        if line.contains("lua") {
            return "Script/Lua".into();
        }
        if line.contains("awk") {
            return "Script/Awk".into();
        }
        return "Script/Unknown".into();
    }

    // ─── Batch / PowerShell scripts (no shebang) ───
    // Batch files often start with @echo off or @rem
    if data.starts_with(b"@echo") || data.starts_with(b"@ECHO") || data.starts_with(b"@rem") {
        return "Script/Batch".into();
    }

    // PowerShell scripts often start with UTF-8 BOM or specific patterns
    if data.len() >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
        // UTF-8 BOM — could be PS1, check further
        let body = &data[3..];
        let preview = String::from_utf8_lossy(&body[..body.len().min(128)]).to_lowercase();
        if preview.contains("param(") || preview.contains("function ") || preview.contains("invoke-") || preview.contains("get-") {
            return "Script/PowerShell".into();
        }
    }

    // --- PowerShell (BOM-less) ---
    if let Some(rest) = strip_utf8_bom(data) {
        let preview = String::from_utf8_lossy(&rest[..rest.len().min(256)]).to_lowercase();
        if preview.contains("param(") || preview.contains("invoke-")
            || preview.contains("new-object") || preview.contains("add-type")
            || preview.contains("start-process") || preview.contains("downloadstring")
            || preview.contains("[reflection.assembly]") || preview.contains("iesecurity")
        {
            return "Script/PowerShell".into();
        }
    }

    // --- PowerShell modules/manifests ---
    if data.len() >= 4 {
        let head = String::from_utf8_lossy(&data[..data.len().min(64)]).to_lowercase();
        if head.contains("#requires") || head.contains("using module")
            || head.contains("functions-toexport")
        {
            return "Script/PowerShell".into();
        }
    }

    // --- VBScript ---
    if data.len() >= 32 {
        let lower = String::from_utf8_lossy(&data[..data.len().min(512)]).to_lowercase();
        if lower.contains("wscript") || lower.contains("createobject(\"adodb")
            || lower.contains("createobject(\"msxml2")
        {
            return "Script/VBScript".into();
        }
    }

    // --- AutoIt (AU3) ---
    if data.len() >= 64 {
        let lower = String::from_utf8_lossy(&data[..data.len().min(4096)]).to_lowercase();
        let has_au3 = contains_any(&lower, &[
            "autoit", "au3", "func ", "send(", "mouseclick", "controlclick", "opt_winwait",
        ]);
        if has_au3 && !lower.contains("ahk") && !lower.contains("autohotkey")
            && (lower.contains("func ") || lower.contains("endfunc"))
        {
            return "Script/AutoIt".into();
        }
    }

    // --- AutoHotkey v1/v2 (AHK) ---
    if data.len() >= 32 {
        let lower = String::from_utf8_lossy(&data[..data.len().min(4096)]).to_lowercase();
        if lower.contains("autohotkey")
            || lower.contains("#singleinstance")
            || lower.contains("#requires autohotkey")
            || lower.contains("ahk_class")
        {
            return "Script/AutoHotkey".into();
        }
        if lower.contains("::")
            && (lower.contains("send ") || lower.contains("click ") || lower.contains("run "))
            && !lower.contains("func ")
        {
            return "Script/AutoHotkey".into();
        }
    }

    // --- Python compiled (.pyc / .pyo) ---
    if data.len() >= 8 {
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let py3_magic = (magic & 0xFFFF_0000) == 0x0A0D_0000 && (magic & 0xFFFF) >= 0x0100;
        let known = matches!(magic,
            0x0A0D0C00 | 0x0A0D0C0A | 0x0A0D0D0A | 0x0A0DEB0A | 0x0A0DF20A | 0x0A0DF50A |
            0x0A0DF70A | 0x0A0DF80A | 0x0A0DF90A | 0x0A0DFA0A | 0x0A0DFB0A | 0x0A0DFC0A |
            0x0A0DFD0A | 0x0A0DFE0A | 0x0A0DFF0A | 0x0A0D000B
        );
        if known || py3_magic {
            return "Python/Compiled".into();
        }
    }

    // --- PDF ---
    if data.len() >= 5 && data.starts_with(b"%PDF-") {
        return "PDF".into();
    }

    // --- Memory dumps (Windows Minidump, Mach-O core, ELF core) ---
    if data.len() >= 8 {
        if &data[0..4] == b"MDMP" {
            return "Minidump".into();
        }
        let magic_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let magic_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if (matches!(magic_le, 0xFEEDFACE | 0xFEEDFACF)
            || matches!(magic_be, 0xFEEDFACE | 0xFEEDFACF))
            && data.len() >= 0x10
        {
            let filetype_le = u32::from_le_bytes([data[0x0C], data[0x0D], data[0x0E], data[0x0F]]);
            if filetype_le == 0x4 {
                return "Mach-O Core".into();
            }
        }
        if data.starts_with(b"\x7FELF") && data.len() >= 0x14 {
            let e_type = u16::from_le_bytes([data[0x10], data[0x11]]);
            if e_type == 4 {
                return "ELF Core".into();
            }
        }
    }

    // --- UEFI / Firmware ---
    if data.len() >= 40 {
        if &data[0..4] == b"_FVH" {
            return "UEFI/FirmwareVolume".into();
        }
        if &data[0..16] == b"\x8C\x8C\xE5\x78\x8A\x3D\x4F\x1C\x99\x35\x89\x61\x85\xC3\x2D\xD3" {
            return "UEFI/FFS".into();
        }
    }
    if data.len() >= 0x200 && data[0x1FE] == 0x55 && data[0x1FF] == 0xAA {
        return "BIOS/MBR".into();
    }
    if data.len() >= 0x400 && &data[0x200..0x208] == b"EFI PART" {
        return "UEFI/GPT-Disk".into();
    }

    "unknown".into()
}

pub fn hex_sha256(data: &[u8]) -> String {
    let digest = freakre_sha256(data);
    // Manual hex encode (no external `hex` crate)
    let mut s = String::with_capacity(64);
    for b in &digest {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn hex_md5(data: &[u8]) -> String {
    let digest = freakre_md5(data);
    let mut s = String::with_capacity(32);
    for b in &digest {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_file_type() {
        assert_eq!(detect_file_type(b"MZ\x90\x00"), "DOS");
        assert_eq!(detect_file_type(b"\x7FELF"), "ELF");
        assert_eq!(detect_file_type(b"AAAA"), "unknown");
        assert_eq!(detect_file_type(b""), "unknown");

        // Mach-O 64-bit (little-endian)
        let mut macho64 = [0u8; 32];
        macho64[0] = 0xCF; macho64[1] = 0xFA; macho64[2] = 0xED; macho64[3] = 0xFE;
        assert_eq!(detect_file_type(&macho64), "Mach-O 64-bit");

        // Mach-O 32-bit (little-endian)
        let mut macho32 = [0u8; 32];
        macho32[0] = 0xCE; macho32[1] = 0xFA; macho32[2] = 0xED; macho32[3] = 0xFE;
        assert_eq!(detect_file_type(&macho32), "Mach-O 32-bit");

        // Mach-O Fat binary
        let mut fat = [0u8; 32];
        fat[0] = 0xCA; fat[1] = 0xFE; fat[2] = 0xBA; fat[3] = 0xBE;
        assert_eq!(detect_file_type(&fat), "Mach-O Fat");

        // Python script
        let py = b"#!/usr/bin/env python3\nprint('hello')";
        assert_eq!(detect_file_type(py), "Script/Python");

        // Shell script
        let sh = b"#!/bin/bash\necho hello";
        assert_eq!(detect_file_type(sh), "Script/Shell");

        // Batch file
        let bat = b"@echo off\necho hello";
        assert_eq!(detect_file_type(bat), "Script/Batch");
    }

    #[test]
    fn test_detect_file_type_truncated_pe_optional_header() {
        // Regression: a PE whose optional-header magic is truncated must not
        // index out of bounds (previously panicked and killed the scan batch).
        let mut trunc = vec![0u8; 65];
        trunc[0] = b'M';
        trunc[1] = b'Z';
        trunc[40..44].copy_from_slice(b"PE\0\0");
        trunc[60..64].copy_from_slice(&40u32.to_le_bytes());
        assert_eq!(detect_file_type(&trunc), "DOS");

        // One more byte is enough to read the PE32 magic (0x10B LE).
        let mut full = trunc.clone();
        full.push(0);
        full[64] = 0x0B;
        full[65] = 0x01;
        assert_eq!(detect_file_type(&full), "PE32");
    }
}
