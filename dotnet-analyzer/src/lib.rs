//! # .NET / C# Assembly Analyzer
//!
//! Inspects the CLI / CLR portion of a managed assembly:
//!
//! * **CLR header** (`IMAGE_COR20_HEADER`): flags, entry point, metadata RVAs,
//!   strong-name signature, v-table fixups
//! * **#~ stream** (metadata tables): Module, TypeRef, MethodDef, MemberRef,
//!   AssemblyRef, StandAloneSig, etc.
//! * **`#Strings` heap**: type / member / namespace names
//! * **`#US` heap**: user-string literals (often contain juicy constants)
//! * **`#GUID` heap**: MVID
//!
//! The scanner collects counts and surfaces high-signal findings:
//!
//! * Native entry point (rare, often a managed→native loader)
//! * Unmanaged exports / v-table fixups (COM interop or unmanaged callbacks)
//! * Reflection / dynamic-load methods (`System.Reflection.Assembly`)
//! * Strings like "powershell", "cmd", "http", "Base64", suspicious APIs
//!
//! A real, full-fledged managed disassembler (dnSpy/ILSpy level) is
//! intentionally out of scope.

use serde::{Deserialize, Serialize};

/// Outcome of analyzing a .NET assembly. Returned by [`analyze_dotnet`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DotnetReport {
    pub is_managed: bool,
    pub metadata_version: Option<String>,
    pub runtime_version: Option<String>,
    pub entry_point_token: Option<String>,
    pub flags: Vec<String>,
    pub strong_name_signed: bool,
    pub module_name: Option<String>,
    pub assembly_name: Option<String>,
    pub type_ref_count: usize,
    pub method_def_count: usize,
    pub member_ref_count: usize,
    pub assembly_ref_count: usize,
    pub user_string_count: usize,
    pub assembly_refs: Vec<String>,
    pub type_refs_sample: Vec<String>,
    pub member_refs_sample: Vec<String>,
    pub user_strings_sample: Vec<String>,
    pub suspicious_strings: Vec<String>,
    pub findings: Vec<DotnetFinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DotnetSeverity {
    Info, Low, Medium, High, Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DotnetFinding {
    pub severity: DotnetSeverity,
    pub rule_id: String,
    pub description: String,
    pub offset: usize,
}

/// Top-level entry point. Returns `Some(_)` if `data` is a PE that
/// contains a CLR header.
pub fn analyze_dotnet(data: &[u8]) -> Option<DotnetReport> {
    if data.len() < 128 || !data.starts_with(b"MZ") { return None; }

    let pe_off = read_u32(data, 0x3C).map(|v| v as usize)?;
    if pe_off + 24 > data.len() || &data[pe_off..pe_off + 4] != b"PE\0\0" { return None; }

    let coff = pe_off + 4;
    let opt_hdr_off = coff + 20;
    if opt_hdr_off + 2 > data.len() { return None; }
    let magic = read_u16(data, opt_hdr_off)?;
    let (is_pe32_plus, opt_size) = match magic {
        0x10B => (false, read_u16(data, opt_hdr_off + 16)? as usize),
        0x20B => (true, read_u16(data, opt_hdr_off + 16)? as usize),
        _ => return None,
    };
    if opt_size < 112 || opt_hdr_off + opt_size > data.len() { return None; }

    // Number of data directories (PE32: at +96, PE32+: at +112)
    let num_dd_off = if is_pe32_plus { opt_hdr_off + 108 } else { opt_hdr_off + 92 };
    let num_dd = read_u32(data, num_dd_off)? as usize;
    if num_dd < 15 { return None; }

    // DataDirectories start at opt_hdr_off + (PE32+ uses 112, PE32 uses 96)
    let dd_off = if is_pe32_plus { opt_hdr_off + 112 } else { opt_hdr_off + 96 };
    if dd_off + 15 * 8 > data.len() { return None; }

    // CLR header is data directory #14 (COM descriptor) per PE spec.
    let clr_rva = read_u32(data, dd_off + 14 * 8)? as usize;
    let clr_size = read_u32(data, dd_off + 14 * 8 + 4)? as usize;
    if clr_rva == 0 || clr_size < 72 { return None; }

    // We need to translate the CLR RVA to a file offset using the section
    // table (right after the optional header).
    let sect_off = opt_hdr_off + opt_size;
    if sect_off + 40 > data.len() { return None; }
    let num_sect = read_u16(data, coff + 2)? as usize;
    if sect_off + num_sect * 40 > data.len() { return None; }
    let clr_off = rva_to_offset(clr_rva, &data[sect_off..sect_off + num_sect * 40])?;
    if clr_off + 72 > data.len() { return None; }

    let clr = &data[clr_off..clr_off + 72];
    let metadata_rva = read_u32(clr, 8)? as usize;
    let metadata_size = read_u32(clr, 12)? as usize;
    let flags_raw = read_u32(clr, 16)?;
    let entry_token = read_u32(clr, 20)?;
    let _resources_rva = read_u32(clr, 24)?;
    let strong_name_rva = read_u32(clr, 36)?;
    let vtable_fixups_rva = read_u32(clr, 44)?;
    let native_entry_rva = read_u32(clr, 48)?;
    let md_off = rva_to_offset(metadata_rva, &data[sect_off..sect_off + num_sect * 40])?;
    if md_off + metadata_size > data.len() { return None; }
    let md = &data[md_off..md_off + metadata_size];

    let mut findings: Vec<DotnetFinding> = Vec::new();
    let mut flags: Vec<String> = Vec::new();
    if flags_raw & 0x01 != 0 { flags.push("ILONLY".into()); }
    if flags_raw & 0x02 != 0 { flags.push("32BITREQUIRED".into()); }
    if flags_raw & 0x04 != 0 { flags.push("IL_LIBRARY".into()); }
    if flags_raw & 0x08 != 0 { flags.push("STRONGNAMESIGNED".into()); }
    if flags_raw & 0x10 != 0 { flags.push("NATIVE_ENTRYPOINT".into()); }
    if flags_raw & 0x20 != 0 { flags.push("TRACKDEBUGDATA".into()); }

    let strong_name_signed = strong_name_rva != 0;
    if native_entry_rva != 0 {
        push_finding(&mut findings, DotnetSeverity::High, "DOTNET_NATIVE_ENTRYPOINT",
            "CLR has a native entry point — often a managed→native loader".into(), clr_off);
    }
    if vtable_fixups_rva != 0 {
        push_finding(&mut findings, DotnetSeverity::Medium, "DOTNET_VTABLE_FIXUPS",
            "CLR contains v-table fixups — COM interop or unmanaged callbacks".into(), clr_off);
    }

    // Parse metadata header
    let (md_version, _md_streams_off) = parse_metadata_header(md).unwrap_or((None, 0));

    // Parse #~ stream and supporting heaps. We rely on the stream directory
    // that follows the metadata header signature.
    let mut report = DotnetReport {
        is_managed: true,
        metadata_version: md_version.clone(),
        runtime_version: md_version,
        entry_point_token: Some(format!("0x{:08X}", entry_token)),
        flags,
        strong_name_signed,
        module_name: None,
        assembly_name: None,
        type_ref_count: 0,
        method_def_count: 0,
        member_ref_count: 0,
        assembly_ref_count: 0,
        user_string_count: 0,
        assembly_refs: Vec::new(),
        type_refs_sample: Vec::new(),
        member_refs_sample: Vec::new(),
        user_strings_sample: Vec::new(),
        suspicious_strings: Vec::new(),
        findings,
    };

    if let Some((streams, _)) = parse_stream_dir(md) {
        for s in &streams {
            if s.name == "#~" {
                if let Some(tables) = parse_tables_stream(md, s.offset, s.size) {
                    report.type_ref_count = tables.type_ref_count;
                    report.method_def_count = tables.method_def_count;
                    report.member_ref_count = tables.member_ref_count;
                    report.assembly_ref_count = tables.assembly_ref_count;
                    report.assembly_refs = tables.assembly_refs;
                    report.type_refs_sample = tables.type_refs_sample;
                    report.member_refs_sample = tables.member_refs_sample;
                    report.module_name = tables.module_name;
                }
            } else if s.name == "#US" {
                    if let Some(us) = parse_user_strings(md, s.offset, s.size) {
                        report.user_string_count = us.count;
                        report.user_strings_sample = us.sample;
                        let sus_count = us.suspicious.len();
                        report.suspicious_strings = us.suspicious;
                        if sus_count > 0 {
                            push_finding(&mut report.findings, DotnetSeverity::High,
                                "DOTNET_SUSPICIOUS_USER_STRINGS",
                                format!("User strings contain {} suspicious entries", sus_count),
                                s.offset);
                        }
                    }
            } else if s.name == "#Strings" {
                if let Some(names) = parse_strings_heap(md, s.offset, s.size) {
                    if let Some(_name) = names.iter().find(|n| n.starts_with("System.")) {
                        // could be assembly-level name, just take first namespace
                    }
                    if let Some(m) = names.iter().find(|n| n.ends_with(".dll")
                        && !n.starts_with("System."))
                    {
                        report.assembly_name = Some(m.clone());
                    }
                }
            }
        }
    }

    // High-signal findings from refs
    if report.member_ref_count > 0 {
        let suspicious_refs: Vec<&String> = report.member_refs_sample.iter()
            .filter(|s| s.contains("Process") || s.contains("Shell")
                || s.contains("WinExec") || s.contains("VirtualAlloc")
                || s.contains("LoadLibrary") || s.contains("GetProcAddress")
                || s.contains("CreateThread") || s.contains("WriteProcessMemory")
                || s.contains("QueueUserAPC") || s.contains("SetWindowsHookEx")
                || s.contains("InternetOpen") || s.contains("HttpSendRequest")
                || s.contains("RegSetValueEx") || s.contains("AdjustTokenPrivileges")
                || s.contains("OpenProcessToken") || s.contains("LookupPrivilegeValue")
            )
            .collect();
        if !suspicious_refs.is_empty() {
            push_finding(&mut report.findings, DotnetSeverity::High,
                "DOTNET_SUSPICIOUS_NATIVE_REF",
                format!("Suspicious native API references: {}",
                    suspicious_refs.iter().take(5).map(|s| s.as_str()).collect::<Vec<_>>().join(", ")),
                0);
        }
    }

    Some(report)
}

fn push_finding(out: &mut Vec<DotnetFinding>, severity: DotnetSeverity, rule_id: &str,
                description: String, offset: usize) {
    out.push(DotnetFinding { severity, rule_id: rule_id.to_string(), description, offset });
}

fn read_u16(data: &[u8], off: usize) -> Option<u16> {
    if off + 2 > data.len() { return None; }
    Some(u16::from_le_bytes([data[off], data[off + 1]]))
}
fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    if off + 4 > data.len() { return None; }
    Some(u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]))
}

fn rva_to_offset(rva: usize, sections: &[u8]) -> Option<usize> {
    let count = sections.len() / 40;
    for i in 0..count {
        let s = &sections[i * 40..(i + 1) * 40];
        let va = read_u32(s, 12)? as usize;
        let raw_sz = read_u32(s, 16)? as usize;
        let raw_off = read_u32(s, 20)? as usize;
        if rva >= va && rva < va + raw_sz {
            return Some(raw_off + (rva - va));
        }
    }
    None
}

fn parse_metadata_header(md: &[u8]) -> Option<(Option<String>, usize)> {
    // BSJB signature: 0x424A5342
    let sig = read_u32(md, 0)?;
    if sig != 0x424A_5342 { return None; }
    let version_len = read_u32(md, 12)? as usize;
    let version_end = 16 + version_len;
    if version_end > md.len() { return None; }
    let ver = String::from_utf8_lossy(&md[16..version_end])
        .trim_end_matches('\0').to_string();
    let mut off = version_end;
    // flags (2) + streams (2)
    off += 4;
    Some((Some(ver), off))
}

#[derive(Debug, Clone)]
struct StreamDir {
    name: String,
    offset: usize,
    size: usize,
}

fn parse_stream_dir(md: &[u8]) -> Option<(Vec<StreamDir>, usize)> {
    let (ver, off0) = parse_metadata_header(md)?;
    let _ = ver;
    let mut p = off0;
    // skip 2 bytes flags, 2 bytes streams count
    let count = read_u16(md, p)? as usize;
    p += 4;
    let mut out = Vec::new();
    for _ in 0..count {
        if p + 8 > md.len() { break; }
        let offset = read_u32(md, p)? as usize;
        let size = read_u32(md, p + 4)? as usize;
        p += 8;
        // name: null-terminated, padded to 4-byte boundary
        let name_start = p;
        while p < md.len() && md[p] != 0 { p += 1; }
        if p >= md.len() { break; }
        let name = String::from_utf8_lossy(&md[name_start..p]).into_owned();
        p += 1; // skip null
        p = (p + 3) & !3; // align
        out.push(StreamDir { name, offset, size });
    }
    Some((out, p))
}

#[derive(Default)]
struct TablesInfo {
    type_ref_count: usize,
    method_def_count: usize,
    member_ref_count: usize,
    assembly_ref_count: usize,
    assembly_refs: Vec<String>,
    type_refs_sample: Vec<String>,
    member_refs_sample: Vec<String>,
    module_name: Option<String>,
}

fn parse_tables_stream(md: &[u8], off: usize, size: usize) -> Option<TablesInfo> {
    if off + 24 > md.len() { return None; }
    let s = &md[off..off + size.min(md.len() - off)];
    // #~ header: reserved(4) + major(1) + minor(1) + heap_sizes(1) + reserved(1) + valid(8) + sorted(8)
    let heap_sizes = s[6];
    let valid = u64::from_le_bytes(s[8..16].try_into().ok()?);
    let _strings_idx_size = if heap_sizes & 0x01 == 0 { 2 } else { 4 };
    let _guid_idx_size = if heap_sizes & 0x02 == 0 { 2 } else { 4 };
    let _blob_idx_size = if heap_sizes & 0x04 == 0 { 2 } else { 4 };

    let table_names = [
        "Module", "TypeRef", "TypeDef", "FieldPtr", "Field", "MethodPtr", "MethodDef",
        "ParamPtr", "Param", "InterfaceImpl", "MemberRef", "Constant", "CustomAttribute",
        "FieldMarshal", "DeclSecurity", "ClassLayout", "FieldLayout", "StandAloneSig",
        "EventMap", "EventPtr", "Event", "PropertyMap", "PropertyPtr", "Property",
        "MethodSemantics", "MethodImpl", "ModuleRef", "TypeSpec", "ImplMap", "FieldRVA",
        "ENCLog", "ENCMap", "Assembly", "AssemblyProcessor", "AssemblyOS", "AssemblyRef",
        "AssemblyRefProcessor", "AssemblyRefOS", "File", "ExportedType", "ManifestResource",
        "NestedClass", "GenericParam", "MethodSpec", "GenericParamConstraint",
    ];

    let mut row_counts: [usize; 64] = [0; 64];
    let mut p = 24;
    for (i, _) in table_names.iter().enumerate() {
        if valid & (1u64 << i) != 0 {
            if p + 4 > s.len() { return None; }
            row_counts[i] = read_u32(s, p)? as usize;
            p += 4;
        }
    }

    // The string table we want is #Strings (handled separately). For Module
    // table we read a single Generation (u16) + Name (string) + Mvid (guid)
    // + EncId (guid) + EncBaseId (guid). For TypeRef: ResolutionScope(coded) +
    // TypeName(string) + TypeNamespace(string). For MethodDef: many fields.
    // For MemberRef: Class(coded) + Name(string) + Signature(blob).
    //
    // We just count rows, and the actual string/heap content comes from
    // #Strings and #US.

    let mut info = TablesInfo {
        type_ref_count: row_counts[1],
        method_def_count: row_counts[6],
        member_ref_count: row_counts[10],
        assembly_ref_count: row_counts[35],
        ..Default::default()
    };

    // Sample the #Strings heap entries. We just collect up to 200 string
    // entries from the heap and pick out the ones that look like type
    // names referenced in TypeRef / MemberRef.
    if let Some((streams, _)) = parse_stream_dir(md) {
        let strings_stream = streams.iter().find(|s| s.name == "#Strings");
        if let Some(strs) = strings_stream {
            let all = collect_strings_heap(md, strs.offset, strs.size);
            info.assembly_refs = all.iter()
                .filter(|n| n.ends_with(".dll") || n.ends_with(".exe"))
                .take(64)
                .cloned()
                .collect();
            info.type_refs_sample = all.iter()
                .filter(|n| !n.is_empty() && n.contains('.'))
                .take(128)
                .cloned()
                .collect();
            info.member_refs_sample = all.iter()
                .filter(|n| n.contains('(') || n.contains("Get") || n.contains("Set")
                    || n.contains("Read") || n.contains("Write") || n.contains("Create"))
                .take(128)
                .cloned()
                .collect();
            info.module_name = all.first().cloned();
        }
    }

    Some(info)
}

fn collect_strings_heap(md: &[u8], off: usize, size: usize) -> Vec<String> {
    let end = (off + size).min(md.len());
    let mut out = Vec::new();
    let mut p = off + 1; // skip the leading 0 byte
    while p < end {
        let start = p;
        while p < end && md[p] != 0 { p += 1; }
        if p > start {
            if let Ok(s) = std::str::from_utf8(&md[start..p]) {
                if !s.is_empty() { out.push(s.to_string()); }
            }
        }
        p += 1;
    }
    out
}

fn parse_strings_heap(md: &[u8], off: usize, size: usize) -> Option<Vec<String>> {
    Some(collect_strings_heap(md, off, size))
}

#[derive(Default)]
struct UserStrings {
    count: usize,
    sample: Vec<String>,
    suspicious: Vec<String>,
}

fn parse_user_strings(md: &[u8], off: usize, size: usize) -> Option<UserStrings> {
    let end = (off + size).min(md.len());
    let mut p = off + 1;
    let mut out = UserStrings::default();
    let suspicious_kw = ["powershell", "cmd.exe", "cmd", "frombase64", "http://", "https://",
        "virtualalloc", "createthread", "loadlibrary", "winexec", "shellexecute",
        "msfvenom", "shellcode", "mimikatz", "meterpreter", "keylog", "screenshot",
        "Get-Process", "Invoke-WebRequest", "DownloadFile", "WebClient",
        "crypt", "AES", "DES", "MD5", "SHA", "RSA", "wallet", "metamask",
    ];
    while p < end {
        let start = p;
        // blob: compressed length prefix (1 or 4 bytes)
        if p >= end { break; }
        let b = md[p];
        let len = if b < 0x80 {
            p += 1;
            b as usize
        } else if b == 0x80 {
            p += 1;
            continue;
        } else if b < 0xC0 {
            if p + 2 > end { break; }
            let l = (((b & 0x3F) as usize) << 8) | md[p + 1] as usize;
            p += 2;
            l
        } else {
            if p + 4 > end { break; }
            let l = (((b & 0x1F) as usize) << 24)
                | ((md[p + 1] as usize) << 16)
                | ((md[p + 2] as usize) << 8)
                | (md[p + 3] as usize);
            p += 4;
            l
        };
        if p + len > end { break; }
        let s = &md[p..p + len];
        // US strings are little-endian UTF-16 with a trailing byte.
        if len >= 2 {
            let mut chars = Vec::with_capacity(len / 2);
            let mut i = 0;
            while i + 1 < len {
                let cu = u16::from_le_bytes([s[i], s[i + 1]]);
                if let Some(c) = char::from_u32(cu as u32) {
                    chars.push(c);
                }
                i += 2;
            }
            let text: String = chars.into_iter().collect();
            if !text.is_empty() {
                out.count += 1;
                if out.sample.len() < 200 { out.sample.push(text.clone()); }
                let lower = text.to_ascii_lowercase();
                if suspicious_kw.iter().any(|k| lower.contains(k)) {
                    out.suspicious.push(text);
                }
            }
        }
        p += len;
        if p == start { break; } // safety
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_pe_returns_none() {
        assert!(analyze_dotnet(b"hello world").is_none());
    }

    #[test]
    fn test_strings_heap_iter() {
        // Real strings heap: starts with a single 0 byte, then null-terminated entries.
        let payload = b"\x00System.Net.Http\x00Foo\x00";
        let v = collect_strings_heap(payload, 0, payload.len());
        assert!(v.contains(&"System.Net.Http".to_string()));
        assert!(v.contains(&"Foo".to_string()));
    }
}
