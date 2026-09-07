//! Main function analyzer combining all discovery methods

use crate::patterns::*;
use crate::recursive::*;
use crate::{
    Architecture, CodeRegion, DiscoveredFunction, FinderConfig, FinderError, FinderResult,
    FinderStats, FunctionSource, Result,
};
use func_sigs::{scan_signatures, SigScanConfig};
use std::collections::HashMap;

/// Main function analyzer
pub struct FunctionAnalyzer {
    arch: Architecture,
    config: FinderConfig,
}

impl FunctionAnalyzer {
    pub fn new(arch: Architecture) -> Self {
        Self {
            arch,
            config: FinderConfig::default(),
        }
    }

    pub fn with_config(arch: Architecture, config: FinderConfig) -> Self {
        Self { arch, config }
    }

    /// Analyze a binary to find all functions
    pub fn analyze(
        &self,
        code_regions: Vec<CodeRegion>,
        entry_points: Vec<u64>,
        symbols: Option<&HashMap<u64, String>>,
    ) -> Result<FinderResult> {
        if code_regions.is_empty() {
            return Err(FinderError::NoCodeSections);
        }

        let mut stats = FinderStats::default();
        let mut all_functions: HashMap<u64, DiscoveredFunction> = HashMap::new();

        // Phase 1: Symbol table (if available)
        if let Some(syms) = symbols {
            for (addr, name) in syms {
                let func = DiscoveredFunction {
                    address: *addr,
                    size: 0, // Will be determined later
                    source: FunctionSource::SymbolTable,
                    confidence: 1.0,
                    name: Some(name.clone()),
                    is_thunk: false,
                    thunk_target: None,
                    blocks: vec![],
                };
                all_functions.insert(*addr, func);
                stats.symbol_count += 1;
            }
        }

        // Phase 2: Prologue scanning
        if self.config.scan_prologues {
            let prologue_funcs = self.scan_prologues(&code_regions)?;
            for func in prologue_funcs {
                if let std::collections::hash_map::Entry::Vacant(e) =
                    all_functions.entry(func.address)
                {
                    e.insert(func);
                    stats.prologue_count += 1;
                }
            }
        }

        // Phase 3: Recursive descent from all known entry points
        if self.config.recursive_descent {
            // Only seed from candidates that meet the confidence threshold;
            // low-confidence prologue hits (e.g. weak 0x55/0x4-sub matches) must
            // not spawn recursive descent at bogus mid-stream addresses.
            let mut entry_addrs: Vec<u64> = all_functions
                .values()
                .filter(|f| f.confidence >= self.config.min_confidence)
                .map(|f| f.address)
                .collect();
            entry_addrs.extend(entry_points);

            let mut analyzer = RecursiveAnalyzer::new(self.arch, self.config.clone());
            analyzer.add_entry_points(entry_addrs);

            let recursive_funcs = analyzer.analyze(&code_regions)?;
            for func in recursive_funcs {
                if let std::collections::hash_map::Entry::Vacant(e) =
                    all_functions.entry(func.address)
                {
                    e.insert(func);
                    stats.recursive_count += 1;
                }
            }
        }

        // Phase 4: Signature matching (using func-sigs)
        if self.config.signature_matching {
            stats.signature_count += self.match_signatures(&mut all_functions, &code_regions);
        }

        // Filter by minimum confidence
        let functions: Vec<DiscoveredFunction> = all_functions
            .into_values()
            .filter(|f| f.confidence >= self.config.min_confidence)
            .collect();

        // Calculate total stats
        for func in &functions {
            stats.bytes_analyzed += func.size;
            stats.total_blocks += func.blocks.len();
            if func.is_thunk {
                stats.thunk_count += 1;
            }
        }

        Ok(FinderResult {
            functions,
            code_regions,
            stats,
        })
    }

    /// Scan for function prologues in all code regions
    fn scan_prologues(&self, regions: &[CodeRegion]) -> Result<Vec<DiscoveredFunction>> {
        let prologues = prologues_for_arch(self.arch);
        let epilogues = epilogues_for_arch(self.arch);
        let mut functions = Vec::new();

        for region in regions {
            if !region.executable {
                continue;
            }

            for offset in 0..region.data.len() {
                for pattern in &prologues {
                    if pattern.matches(&region.data, offset) {
                        let address = region.address + offset as u64;

                        // Try to find the end of the function by looking for epilogues
                        let func_end = self.find_function_end(&region.data, offset, &epilogues);

                        let size = if let Some(end_offset) = func_end {
                            end_offset - offset
                        } else {
                            // Fallback: estimate size as distance to next prologue or region end
                            self.estimate_function_size(&region.data, offset, &prologues)
                        };

                        if size >= self.config.min_function_size
                            && size <= self.config.max_function_size
                        {
                            functions.push(DiscoveredFunction {
                                address,
                                size,
                                source: FunctionSource::Prologue,
                                confidence: pattern.confidence,
                                name: None,
                                is_thunk: false,
                                thunk_target: None,
                                blocks: vec![], // Will be filled in by recursive analysis
                            });
                        }

                        // Don't match overlapping patterns
                        break;
                    }
                }
            }
        }

        Ok(functions)
    }

    /// Match discovered functions against the func-sigs signature database.
    /// Returns how many functions were annotated with a signature match.
    fn match_signatures(
        &self,
        functions: &mut HashMap<u64, DiscoveredFunction>,
        regions: &[CodeRegion],
    ) -> usize {
        let config = SigScanConfig {
            step: 1,
            max_matches: 4096,
            detect_compiler: false,
        };
        let mut applied = 0;

        for region in regions {
            if !region.executable {
                continue;
            }

            let scan = scan_signatures(&region.data, 0, &config);
            for m in scan.matches {
                let addr = region.address + m.offset as u64;
                let candidate = functions
                    .values_mut()
                    .filter(|f| f.address <= addr)
                    .max_by_key(|f| f.address);

                if let Some(func) = candidate {
                    let known_end = func.address + func.size.max(m.signature.min_func_len) as u64;
                    if addr >= known_end {
                        continue;
                    }

                    if func.name.is_none() {
                        func.name = Some(format!(
                            "{}::{}",
                            m.signature.library, m.signature.function_name
                        ));
                    }
                    func.source = FunctionSource::SignatureMatch;
                    let confidence = m.confidence as f32;
                    if confidence > func.confidence {
                        func.confidence = confidence;
                    }
                    applied += 1;
                }
            }
        }

        applied
    }

    /// Find the end of a function by looking for epilogue patterns
    fn find_function_end(
        &self,
        data: &[u8],
        start_offset: usize,
        epilogues: &[BytePattern],
    ) -> Option<usize> {
        let max_scan = (start_offset + self.config.max_function_size).min(data.len());

        for offset in (start_offset + self.config.min_function_size)..max_scan {
            for pattern in epilogues {
                if pattern.matches(data, offset) {
                    // Epilogue found - function ends after this instruction
                    return Some(offset + pattern.len());
                }
            }
        }

        None
    }

    /// Estimate function size by looking for the next prologue
    fn estimate_function_size(
        &self,
        data: &[u8],
        start_offset: usize,
        prologues: &[BytePattern],
    ) -> usize {
        let max_scan = (start_offset + self.config.max_function_size).min(data.len());

        // Start scanning after minimum function size
        let scan_start = start_offset + self.config.min_function_size;

        for offset in scan_start..max_scan {
            // Check for alignment padding (common between functions)
            if offset + 4 < data.len() {
                let slice = &data[offset..offset + 4];
                if slice.iter().all(|&b| b == 0xCC || b == 0x90 || b == 0x00) {
                    return offset - start_offset;
                }
            }

            // Check for next prologue
            for pattern in prologues {
                if pattern.confidence >= 0.8 && pattern.matches(data, offset) {
                    return offset - start_offset;
                }
            }
        }

        // Default: use a reasonable size
        self.config.min_function_size.max(64)
    }

    /// Quick analysis using only prologue scanning (fast but less accurate)
    pub fn quick_analyze(&self, code_regions: Vec<CodeRegion>) -> Result<FinderResult> {
        let mut config = self.config.clone();
        config.recursive_descent = false;
        config.signature_matching = false;

        let analyzer = FunctionAnalyzer::with_config(self.arch, config);
        analyzer.analyze(code_regions, vec![], None)
    }
}

/// Builder for configuring a FunctionAnalyzer
pub struct FunctionAnalyzerBuilder {
    arch: Option<Architecture>,
    config: FinderConfig,
}

impl FunctionAnalyzerBuilder {
    pub fn new() -> Self {
        Self {
            arch: None,
            config: FinderConfig::default(),
        }
    }

    pub fn architecture(mut self, arch: Architecture) -> Self {
        self.arch = Some(arch);
        self
    }

    pub fn scan_prologues(mut self, enable: bool) -> Self {
        self.config.scan_prologues = enable;
        self
    }

    pub fn recursive_descent(mut self, enable: bool) -> Self {
        self.config.recursive_descent = enable;
        self
    }

    pub fn min_function_size(mut self, size: usize) -> Self {
        self.config.min_function_size = size;
        self
    }

    pub fn max_function_size(mut self, size: usize) -> Self {
        self.config.max_function_size = size;
        self
    }

    pub fn min_confidence(mut self, conf: f32) -> Self {
        self.config.min_confidence = conf;
        self
    }

    pub fn build(self) -> Result<FunctionAnalyzer> {
        let arch = self.arch.ok_or_else(|| {
            FinderError::UnsupportedArch("Architecture not specified".to_string())
        })?;

        Ok(FunctionAnalyzer::with_config(arch, self.config))
    }
}

impl Default for FunctionAnalyzerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_code_region(addr: u64, data: Vec<u8>) -> CodeRegion {
        CodeRegion {
            address: addr,
            data,
            executable: true,
        }
    }

    #[test]
    fn test_find_simple_function() {
        // push rbp; mov rbp, rsp; xor eax, eax; pop rbp; ret
        let code = vec![
            0x55, 0x48, 0x89, 0xE5, // prologue
            0x31, 0xC0, // xor eax, eax
            0x5D, // pop rbp
            0xC3, // ret
            0xCC, 0xCC, 0xCC, 0xCC, // padding
        ];

        let region = make_code_region(0x401000, code);
        let analyzer = FunctionAnalyzer::new(Architecture::X86_64);
        let result = analyzer
            .analyze(vec![region], vec![0x401000], None)
            .unwrap();

        assert!(result.function_count() >= 1);
    }

    #[test]
    fn test_multiple_functions() {
        let mut code = Vec::new();

        // Function 1
        code.extend_from_slice(&[0x55, 0x48, 0x89, 0xE5]);
        code.extend_from_slice(&[0x31, 0xC0]);
        code.extend_from_slice(&[0x5D, 0xC3]);
        code.extend_from_slice(&[0xCC, 0xCC, 0xCC, 0xCC]);

        // Function 2
        code.extend_from_slice(&[0x55, 0x48, 0x89, 0xE5]);
        code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]);
        code.extend_from_slice(&[0x48, 0x89, 0xEC]);
        code.extend_from_slice(&[0x5D, 0xC3]);

        let region = make_code_region(0x401000, code);
        let analyzer = FunctionAnalyzer::new(Architecture::X86_64);
        let result = analyzer.quick_analyze(vec![region]).unwrap();

        // Should find at least 2 functions via prologue scanning
        assert!(result.function_count() >= 2);
    }

    #[test]
    fn test_builder() {
        let analyzer = FunctionAnalyzerBuilder::new()
            .architecture(Architecture::X86_64)
            .scan_prologues(true)
            .recursive_descent(false)
            .min_function_size(8)
            .max_function_size(0x10000)
            .min_confidence(0.7)
            .build()
            .unwrap();

        assert_eq!(analyzer.arch, Architecture::X86_64);
        assert!(analyzer.config.scan_prologues);
        assert!(!analyzer.config.recursive_descent);
        assert_eq!(analyzer.config.min_function_size, 8);
    }

    #[test]
    fn test_signature_phase_runs() {
        let code = vec![
            0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC,
        ];

        let config = FinderConfig {
            signature_matching: true,
            min_function_size: 4,
            ..Default::default()
        };

        let region = make_code_region(0x401000, code);
        let analyzer = FunctionAnalyzer::with_config(Architecture::X86_64, config);
        let result = analyzer
            .analyze(vec![region], vec![0x401000], None)
            .unwrap();

        assert!(result.function_count() >= 1);
    }

    #[test]
    fn test_lone_push_bytes_are_not_functions() {
        // Bare 0x55 (push rbp/ebp) bytes used to match a single-byte prologue
        // pattern at every offset; they must not produce any function now.
        let code = vec![0x55, 0xC3, 0x55, 0xC3, 0x55, 0xC3, 0x55, 0xC3];
        let region = make_code_region(0x401000, code);

        let result = FunctionAnalyzer::new(Architecture::X86_64)
            .quick_analyze(vec![region])
            .unwrap();

        assert_eq!(result.function_count(), 0);
    }

    #[test]
    fn test_modern_x64_function_decodes_through_two_byte_ops() {
        // Prologue + movzx/setcc/cmov/jcc-near + epilogue: before the LDE fix
        // the first 0F opcode truncated the recursive sweep almost immediately.
        let mut code = vec![
            0x55, // push rbp
            0x48, 0x89, 0xE5, // mov rbp, rsp
            0x31, 0xC9, // xor ecx, ecx
            0x0F, 0xB6, 0xC1, // movzx eax, cl
            0x0F, 0x95, 0xC2, // setne dl
            0x85, 0xD2, // test edx, edx
            0x74, 0x02, // jz +2
            0x90, // nop
            0x0F, 0x44, 0xCA, // cmove ecx, edx
            0x5D, // pop rbp
            0xC3, // ret
        ];
        code.extend_from_slice(&[0xCC; 8]); // padding must stay outside

        let region = make_code_region(0x401000, code);
        let mut analyzer = RecursiveAnalyzer::new(Architecture::X86_64, FinderConfig::default());
        analyzer.add_entry_point(0x401000);
        let funcs = analyzer.analyze(&[region]).unwrap();

        assert_eq!(funcs.len(), 1);
        // The full 22-byte body was swept: last block ends at the RET.
        let end = funcs[0].blocks.iter().map(|b| b.end).max().unwrap();
        assert_eq!(end, 0x401015); // offset of the final C3
    }
}
