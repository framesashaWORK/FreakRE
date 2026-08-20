#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz import analyzer with minimal PE header
    if data.len() < 64 { return; }
    
    // Try to parse as PE first
    if let Ok(pe) = pe_parser::PeFile::parse(data) {
        let analyzer = import_analyzer::ImportAnalyzer::new(data, &pe);
        let _ = analyzer.analyze();
    }
});
