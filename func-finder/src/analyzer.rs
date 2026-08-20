//! Main function analyzer combining all discovery methods

use crate::{
    Architecture, CodeRegion, DiscoveredFunction, FinderConfig, FinderError,
    FinderResult, FinderStats, FunctionSource, Result,
};
use crate::patterns::*;
use crate::recursive::*;
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
                if !all_functions.contains_key(&func.address) {
                    all_functions.insert(func.address, func);
                    stats.prologue_count += 1;
                }
            }
        }

        // Phase 3: Recursive descent from all known entry points
        if self.config.recursive_descent {
            let mut entry_addrs: Vec<u64> = all_functions.keys().cloned().collect();
            entry_addrs.extend(entry_points);

            let mut analyzer = RecursiveAnalyzer::new(self.arch, self.config.clone());
            analyzer.add_entry_points(entry_addrs);

            let recursive_funcs = analyzer.analyze(&code_regions)?;
            for func in recursive_funcs {
                if !all_functions.contains_key(&func.address) {
                    all_functions.insert(func.address, func);
                    stats.recursive_count += 1;
                }
            }
        }

        // Phase 4: Signature matching (using func-sigs)
        if self.config.signature_matching {
            // TODO: integrate with func-sigs crate
            // For now, this is a placeholder
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
                        let func_end = self.find_function_end(
                            &region.data,
                            offset,
                            &epilogues,
                        );

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
            0x55, 0x48, 0x89, 0xE5,  // prologue
            0x31, 0xC0,               // xor eax, eax
            0x5D,                     // pop rbp
            0xC3,                     // ret
            0xCC, 0xCC, 0xCC, 0xCC,  // padding
        ];

        let region = make_code_region(0x401000, code);
        let analyzer = FunctionAnalyzer::new(Architecture::X86_64);
        let result = analyzer.analyze(vec![region], vec![0x401000], None).unwrap();

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
}
