use pe_parser::PeFile;

use crate::types::{AnalysisReport, ImportDescriptor, ImportedFunction, ImportedModule};
use crate::rules;

/// Safety cap on parsed import descriptors (prevents DoS on crafted IDTs).
const MAX_IMPORT_DESCRIPTORS: usize = 1024;

/// PE import table analyzer.
/// Uses already-parsed PE structures from `pe-parser` to avoid re-parsing.
pub struct ImportAnalyzer<'a> {
    data: &'a [u8],
    pe: &'a PeFile<'a>,
}

impl<'a> ImportAnalyzer<'a> {
    pub fn new(data: &'a [u8], pe: &'a PeFile<'a>) -> Self {
        Self { data, pe }
    }

    /// Perform full import analysis.
    /// Leverages the PE parser's import directory helpers and RVA resolution
    /// to avoid re-parsing PE headers from scratch.
    pub fn analyze(&self) -> AnalysisReport {
        let mut report = AnalysisReport::new();

        // Get Import Directory from DataDirectory[1] via PE parser helper.
        // A missing IDT no longer aborts analysis: delay imports are still merged.
        let descriptors = match self.pe.import_directory() {
            Some((rva, size)) if rva != 0 && size != 0 => {
                self.parse_import_descriptors(rva, size, &mut report)
            }
            _ => {
                report.warnings.push("Import Directory not found in DataDirectory".into());
                Vec::new()
            }
        };

        for desc in &descriptors {
            if desc.is_null() {
                continue;
            }
            if let Some(m) = self.parse_module(desc, &mut report) {
                report.modules.push(m);
            }
        }

        // Merge delay-load DLLs (DataDirectory[13], already parsed by pe-parser)
        // into the module set so the same rule pipeline covers them.
        self.merge_delay_imports(&mut report);

        // Apply detection rules
        let matches = rules::evaluate_rules(&report.modules);
        report.rule_matches = matches;

        // Calculate overall suspicion score
        report.suspicion_score = self.calculate_suspicion_score(&report);

        report
    }

    /// Merge delay-import DLL names (parsed by `pe-parser`) into the module
    /// list. Entries are marked with `is_delay_load = true` so evidence lists
    /// can show their source; DLLs already present in the regular IDT set are
    /// skipped to avoid double-counting.
    fn merge_delay_imports(&self, report: &mut AnalysisReport) {
        let existing: std::collections::HashSet<String> = report
            .modules
            .iter()
            .map(|m| m.name.to_lowercase())
            .collect();

        let mut merged = 0usize;
        for dll in self.pe.delay_imports() {
            if existing.contains(&dll.to_lowercase()) {
                continue;
            }
            report.modules.push(ImportedModule {
                name: dll,
                name_rva: 0,
                functions: Vec::new(),
                is_delay_load: true,
            });
            merged += 1;
        }

        if merged > 0 {
            report.warnings.push(format!(
                "Merged {} delay-load DLL(s) into rule evaluation",
                merged
            ));
        }
    }

    /// RVA to file offset conversion — delegates to PE parser's section table.
    fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        self.pe.rva_to_offset(rva)
    }

    /// Read a null-terminated string at the given RVA — delegates to PE parser.
    fn read_string_at_rva(&self, rva: u32) -> Option<String> {
        self.pe.read_cstring_at_rva(rva, 256)
    }

    fn parse_import_descriptors(
        &self,
        import_rva: u32,
        import_size: u32,
        report: &mut AnalysisReport,
    ) -> Vec<ImportDescriptor> {
        let mut descriptors = Vec::new();
        let base_offset = match self.rva_to_offset(import_rva) {
            Some(o) => o,
            None => {
                report.warnings.push(format!(
                    "Cannot convert Import Directory RVA {:#x} to file offset",
                    import_rva
                ));
                return descriptors;
            }
        };

        let max_descriptors = ((import_size as usize) / ImportDescriptor::SIZE)
            .min(MAX_IMPORT_DESCRIPTORS);

        for i in 0..max_descriptors {
            let offset = base_offset + i * ImportDescriptor::SIZE;
            if offset + ImportDescriptor::SIZE > self.data.len() {
                break;
            }

            let d = &self.data[offset..offset + ImportDescriptor::SIZE];
            let desc = ImportDescriptor {
                original_first_thunk: u32::from_le_bytes([d[0], d[1], d[2], d[3]]),
                time_date_stamp: u32::from_le_bytes([d[4], d[5], d[6], d[7]]),
                forwarder_chain: u32::from_le_bytes([d[8], d[9], d[10], d[11]]),
                name_rva: u32::from_le_bytes([d[12], d[13], d[14], d[15]]),
                first_thunk: u32::from_le_bytes([d[16], d[17], d[18], d[19]]),
            };

            if desc.is_null() {
                break;
            }
            descriptors.push(desc);
        }

        // If the safety cap bound the loop and another non-null descriptor
        // follows, report it instead of silently truncating.
        if descriptors.len() == MAX_IMPORT_DESCRIPTORS {
            let next = base_offset + MAX_IMPORT_DESCRIPTORS * ImportDescriptor::SIZE;
            if next + ImportDescriptor::SIZE <= self.data.len()
                && self.data[next..next + ImportDescriptor::SIZE].iter().any(|&b| b != 0)
            {
                report.warnings.push(format!(
                    "Import descriptor limit ({}) reached; additional descriptors ignored",
                    MAX_IMPORT_DESCRIPTORS
                ));
            }
        }

        descriptors
    }

    fn parse_module(
        &self,
        desc: &ImportDescriptor,
        report: &mut AnalysisReport,
    ) -> Option<ImportedModule> {
        let name = self.read_string_at_rva(desc.name_rva).unwrap_or_else(|| {
            report.warnings.push(format!(
                "Cannot read DLL name at RVA {:#x}",
                desc.name_rva
            ));
            format!("<unknown@{:#x}>", desc.name_rva)
        });

        let thunk_rva = if desc.original_first_thunk != 0 {
            desc.original_first_thunk
        } else {
            desc.first_thunk
        };

        let functions = self.parse_thunk_table(thunk_rva, &name, report);

        Some(ImportedModule {
            name,
            name_rva: desc.name_rva,
            functions,
            is_delay_load: false,
        })
    }

    fn parse_thunk_table(
        &self,
        thunk_rva: u32,
        dll_name: &str,
        report: &mut AnalysisReport,
    ) -> Vec<ImportedFunction> {
        let mut functions = Vec::new();
        // Use PE parser helpers for thunk entry size and ordinal flag
        let entry_size = self.pe.thunk_entry_size();
        let ordinal_flag = self.pe.ordinal_flag();

        let base_offset = match self.rva_to_offset(thunk_rva) {
            Some(o) => o,
            None => {
                report.warnings.push(format!(
                    "Cannot convert thunk RVA {:#x} for '{}'",
                    thunk_rva, dll_name
                ));
                return functions;
            }
        };

        // FIXED: Hard cap at 8192 import entries per module to prevent DoS.
        // Legitimate PE files rarely exceed a few hundred imports per DLL.
        // The previous dynamic limit (based on file size) could be exploited
        // by crafting a large file with thousands of fake thunk entries,
        // causing excessive memory allocation and CPU usage.
        const MAX_IMPORTS_PER_MODULE: usize = 8192;
        let max_entries = ((self.data.len().saturating_sub(base_offset)) / entry_size)
            .min(MAX_IMPORTS_PER_MODULE);

        for i in 0..max_entries {
            let offset = base_offset + i * entry_size;
            if offset + entry_size > self.data.len() {
                break;
            }

            let raw_value: u64 = if self.pe.is_64bit {
                u64::from_le_bytes([
                    self.data[offset], self.data[offset + 1],
                    self.data[offset + 2], self.data[offset + 3],
                    self.data[offset + 4], self.data[offset + 5],
                    self.data[offset + 6], self.data[offset + 7],
                ])
            } else {
                u32::from_le_bytes([
                    self.data[offset], self.data[offset + 1],
                    self.data[offset + 2], self.data[offset + 3],
                ]) as u64
            };

            if raw_value == 0 {
                break;
            }

            let func = if raw_value & ordinal_flag != 0 {
                ImportedFunction {
                    name: None,
                    ordinal: Some((raw_value & 0xFFFF) as u16),
                    hint: 0,
                    ilt_rva: thunk_rva + (i * entry_size) as u32,
                    is_forwarder: false,
                }
            } else {
                let hint_rva = raw_value as u32;
                let (hint, name) = self.parse_import_by_name(hint_rva);
                ImportedFunction {
                    name,
                    ordinal: None,
                    hint,
                    ilt_rva: thunk_rva + (i * entry_size) as u32,
                    is_forwarder: false,
                }
            };

            functions.push(func);
        }

        // If the safety cap bound the loop and another non-zero thunk entry
        // follows, report it instead of silently truncating.
        if functions.len() == MAX_IMPORTS_PER_MODULE {
            let next = base_offset + MAX_IMPORTS_PER_MODULE * entry_size;
            if next + entry_size <= self.data.len()
                && self.data[next..next + entry_size].iter().any(|&b| b != 0)
            {
                report.warnings.push(format!(
                    "Import thunk limit ({}) reached for '{}'; additional entries ignored",
                    MAX_IMPORTS_PER_MODULE, dll_name
                ));
            }
        }

        functions
    }

    fn parse_import_by_name(&self, rva: u32) -> (u16, Option<String>) {
        let offset = match self.rva_to_offset(rva) {
            Some(o) => o,
            None => return (0, None),
        };

        // FIXED off-by-one: `offset + 2 >= len` wrongly rejected a valid
        // hint/name entry whose 2-byte hint sits in the last two bytes of the
        // file (offset + 2 == len). The correct bound is `offset + 2 > len`;
        // the name reader handles an empty tail gracefully.
        if offset + 2 > self.data.len() {
            return (0, None);
        }

        let hint = u16::from_le_bytes([self.data[offset], self.data[offset + 1]]);
        // Use PE parser's cstring reader for the function name (max 512 chars)
        let name = self.pe.read_cstring_at(offset + 2, 512);

        (hint, name)
    }

    fn calculate_suspicion_score(&self, report: &AnalysisReport) -> f64 {
        if report.rule_matches.is_empty() {
            return 0.0;
        }
        // Noisy-OR aggregation: each rule independently pushes toward 1.0 and
        // piling up weak hits cannot linearly saturate the score.
        let mut no_risk = 1.0_f64;
        for rm in &report.rule_matches {
            let w = (rm.confidence * rm.level.weight()).clamp(0.0, 0.99);
            no_risk *= 1.0 - w;
        }
        (1.0 - no_risk).clamp(0.0, 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal PE32: one .rdata section mapping RVA 0x1000 -> file 0x600,
    /// with `raw_size` file-backed bytes and 16 data directory slots.
    fn build_test_pe(buf_len: usize, raw_size: u32) -> Vec<u8> {
        let mut data = vec![0u8; buf_len];
        data[0] = 0x4D;
        data[1] = 0x5A;
        data[60] = 0x80; // e_lfanew = 0x80
        data[0x80..0x84].copy_from_slice(&0x0000_4550u32.to_le_bytes()); // PE\0\0
        data[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes()); // i386
        data[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // 1 section
        data[0x98..0x9A].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32 magic
        data[0xF4..0xF8].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

        let sec = 0xF8 + 16 * 8;
        data[sec..sec + 6].copy_from_slice(b".rdata");
        data[sec + 8..sec + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
        data[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VA
        data[sec + 16..sec + 20].copy_from_slice(&raw_size.to_le_bytes()); // RawSize
        data[sec + 20..sec + 24].copy_from_slice(&0x600u32.to_le_bytes()); // RawOffset
        data[sec + 36..sec + 40].copy_from_slice(&0x4000_0040u32.to_le_bytes());
        data
    }

    fn set_data_dir(data: &mut [u8], index: usize, rva: u32, size: u32) {
        let dd = 0xF8 + index * 8;
        data[dd..dd + 4].copy_from_slice(&rva.to_le_bytes());
        data[dd + 4..dd + 8].copy_from_slice(&size.to_le_bytes());
    }

    #[test]
    fn test_import_descriptor_is_null() {
        let desc = ImportDescriptor {
            original_first_thunk: 0,
            time_date_stamp: 0,
            forwarder_chain: 0,
            name_rva: 0,
            first_thunk: 0,
        };
        assert!(desc.is_null());
    }

    #[test]
    fn test_last_two_byte_hint_entry_parsed() {
        // Off-by-one boundary: a hint/name entry whose 2-byte hint sits in the
        // LAST two bytes of the file (offset + 2 == data.len()) must still be
        // parsed. The old `offset + 2 >= len` condition dropped it entirely.
        let mut data = build_test_pe(0x682, 0x400);

        // Import descriptor at RVA 0x1000 (file 0x600).
        let desc = 0x600usize;
        data[desc..desc + 4].copy_from_slice(&0x1030u32.to_le_bytes()); // OFT -> RVA 0x1030
        data[desc + 12..desc + 16].copy_from_slice(&0x1040u32.to_le_bytes()); // DLL name RVA
        data[desc + 16..desc + 20].copy_from_slice(&0x1050u32.to_le_bytes()); // FT

        // DLL name "test.dll" at RVA 0x1040 (file 0x640).
        data[0x640..0x649].copy_from_slice(b"test.dll\0");

        // ILT at RVA 0x1030 (file 0x630): one name-import entry pointing at
        // hint/name table RVA 0x1080, then the null terminator.
        data[0x630..0x634].copy_from_slice(&0x1080u32.to_le_bytes());

        // Hint/name entry at RVA 0x1080 (file 0x680): hint = 0x0012 occupies
        // the final two bytes of the truncated file.
        data[0x680] = 0x12;
        data[0x681] = 0x00;
        assert_eq!(data.len(), 0x682); // offset + 2 == len exactly

        set_data_dir(&mut data, 1, 0x1000, 0x28);

        let pe = pe_parser::PeFile::parse(&data).unwrap();
        let report = ImportAnalyzer::new(&data, &pe).analyze();

        let m = report
            .modules
            .iter()
            .find(|m| m.name == "test.dll")
            .expect("module must parse");
        assert_eq!(m.functions.len(), 1);
        assert_eq!(m.functions[0].hint, 0x0012, "last-two-byte hint must be read");
        assert!(m.functions[0].name.is_none()); // no room for a name — expected
        assert!(m.functions[0].ordinal.is_none());
    }

    #[test]
    fn test_delay_load_dlls_merged_with_marker() {
        // No regular IDT at all; only a delay import directory (dir[13]).
        // Delay-load DLLs must still reach the rule pipeline and evidence
        // must show their source.
        let mut data = build_test_pe(4096, 0x400);

        // Delay directory at RVA 0x1200 (file 0x800).
        set_data_dir(&mut data, 13, 0x1200, 0x40);

        // ImgDelayDescriptor (32 bytes): grAttrs=1 (fields are RVAs),
        // rvaDLLName=0x1300, rvaHmod=0x1310 (non-zero => not terminator).
        data[0x800..0x804].copy_from_slice(&1u32.to_le_bytes());
        data[0x804..0x808].copy_from_slice(&0x1300u32.to_le_bytes());
        data[0x808..0x80C].copy_from_slice(&0x1310u32.to_le_bytes());

        // Delay-loaded suspicious DLL name at RVA 0x1300 (file 0x900).
        data[0x900..0x90C].copy_from_slice(b"version.dll\0");

        let pe = pe_parser::PeFile::parse(&data).unwrap();
        let report = ImportAnalyzer::new(&data, &pe).analyze();

        let delay_mod = report
            .modules
            .iter()
            .find(|m| m.name == "version.dll")
            .expect("delay-loaded DLL must be merged into modules");
        assert!(delay_mod.is_delay_load, "merged module must be marked as delay-load");

        let dll_match = report
            .rule_matches
            .iter()
            .find(|m| m.rule_id == "DLL_SUSPICIOUS")
            .expect("suspicious delay-loaded DLL must trigger DLL_SUSPICIOUS");
        assert!(
            dll_match.triggered_by.iter().any(|t| t.contains("version.dll") && t.contains("[delay-load]")),
            "evidence must show the delay-load source, got: {:?}",
            dll_match.triggered_by
        );
    }

    #[test]
    fn test_descriptor_cap_emits_warning() {
        // 1025 non-null descriptors: parsing stops at the 1024 cap and a
        // warning must be emitted instead of silently truncating.
        let total = MAX_IMPORT_DESCRIPTORS + 1;
        let desc_area_end = 0x600 + total * ImportDescriptor::SIZE; // 0x600 + 20500
        let buf_len = desc_area_end + 0x100;
        let raw_size = (buf_len - 0x600) as u32;

        let mut data = build_test_pe(buf_len, raw_size);

        // Import dir covers all descriptors so min(size/SIZE, cap) hits the cap.
        set_data_dir(&mut data, 1, 0x1000, (total * ImportDescriptor::SIZE) as u32);

        for i in 0..total {
            let off = 0x600 + i * ImportDescriptor::SIZE;
            data[off + 4..off + 8].copy_from_slice(&1u32.to_le_bytes()); // TimeDateStamp != 0
            data[off + 12..off + 16].copy_from_slice(&0x1100u32.to_le_bytes()); // name RVA
            data[off + 16..off + 20].copy_from_slice(&0x1400u32.to_le_bytes()); // FT (zeroed ILT)
        }

        // DLL name at RVA 0x1100 (file 0x700).
        data[0x700..0x709].copy_from_slice(b"many.dll\0");

        let pe = pe_parser::PeFile::parse(&data).unwrap();
        let report = ImportAnalyzer::new(&data, &pe).analyze();

        assert_eq!(report.modules.len(), MAX_IMPORT_DESCRIPTORS);
        assert!(
            report.warnings.iter().any(|w| w.contains("descriptor limit")),
            "cap truncation must produce a warning, got: {:?}",
            report.warnings
        );
    }

    #[test]
    fn test_thunk_cap_emits_warning() {
        // 8193 non-zero thunk entries: parsing stops at the 8192 cap and a
        // warning must be emitted instead of silently truncating.
        let entries = 8193usize;
        let thunk_start = 0x630usize;
        let thunk_end = thunk_start + entries * 4;
        let buf_len = thunk_end + 0x100;
        let raw_size = (buf_len - 0x600) as u32;

        let mut data = build_test_pe(buf_len, raw_size);

        // One descriptor at RVA 0x1000 (file 0x600): OFT -> RVA 0x1030.
        let desc = 0x600usize;
        data[desc..desc + 4].copy_from_slice(&0x1030u32.to_le_bytes());
        // DLL name placed past the end of the thunk table so it is not
        // overwritten by the filled entries.
        let name_off = thunk_end + 0x20;
        let name_rva = 0x1000u32 + (name_off - 0x600) as u32;
        data[desc + 12..desc + 16].copy_from_slice(&name_rva.to_le_bytes());
        data[desc + 16..desc + 20].copy_from_slice(&0x1050u32.to_le_bytes());

        // DLL name at its reserved spot after the thunk table.
        data[name_off..name_off + 8].copy_from_slice(b"big.dll\0");

        // Fill thunk table with non-zero name-import entries. hint_rva=1 is
        // unmapped, so each parses cheaply to an unnamed function.
        for i in 0..entries {
            let off = thunk_start + i * 4;
            data[off..off + 4].copy_from_slice(&1u32.to_le_bytes());
        }

        set_data_dir(&mut data, 1, 0x1000, 0x28);

        let pe = pe_parser::PeFile::parse(&data).unwrap();
        let report = ImportAnalyzer::new(&data, &pe).analyze();

        let m = report
            .modules
            .iter()
            .find(|m| m.name == "big.dll")
            .expect("module must parse");
        assert_eq!(m.functions.len(), 8192);
        assert!(
            report.warnings.iter().any(|w| w.contains("thunk limit") && w.contains("big.dll")),
            "thunk cap must produce a warning, got: {:?}",
            report.warnings
        );
    }
}
