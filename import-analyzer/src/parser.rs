use pe_parser::PeFile;

use crate::types::{AnalysisReport, ImportDescriptor, ImportedFunction, ImportedModule};
use crate::rules;

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

        // Get Import Directory from DataDirectory[1] via PE parser helper
        let (import_rva, import_size) = match self.pe.import_directory() {
            Some((rva, size)) if rva != 0 && size != 0 => (rva, size),
            _ => {
                report.warnings.push("Import Directory not found in DataDirectory".into());
                return report;
            }
        };

        // Parse import descriptors
        let descriptors = self.parse_import_descriptors(import_rva, import_size, &mut report);

        for desc in &descriptors {
            if desc.is_null() {
                continue;
            }
            if let Some(m) = self.parse_module(desc, &mut report) {
                report.modules.push(m);
            }
        }

        // Apply detection rules
        let matches = rules::evaluate_rules(&report.modules);
        report.rule_matches = matches;

        // Calculate overall suspicion score
        report.suspicion_score = self.calculate_suspicion_score(&report);

        report
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

        let max_descriptors = ((import_size as usize) / ImportDescriptor::SIZE).min(1024);

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

        // Dynamic limit based on available data — avoid hardcoded ceiling
        // that malware can bypass by placing imports beyond 4096 entries.
        // Still cap at 65536 to prevent DoS via malformed PE.
        let max_entries = ((self.data.len().saturating_sub(base_offset)) / entry_size)
            .min(65_536);

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

        functions
    }

    fn parse_import_by_name(&self, rva: u32) -> (u16, Option<String>) {
        let offset = match self.rva_to_offset(rva) {
            Some(o) => o,
            None => return (0, None),
        };

        if offset + 2 >= self.data.len() {
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
        let mut score = 0.0;
        for rm in &report.rule_matches {
            score += rm.confidence * rm.level.weight();
        }
        score.min(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
