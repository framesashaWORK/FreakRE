use bibleteks_scanner::report::FileReport;
use std::path::Path;

/// Wrapper around the scanner library for web usage
pub struct ScannerWrapper {
    inner: bibleteks_scanner::scanner::Scanner,
}

impl ScannerWrapper {
    pub fn new() -> Self {
        Self {
            inner: bibleteks_scanner::scanner::Scanner::new(),
        }
    }

    pub fn scan_file(&self, path: &Path) -> FileReport {
        self.inner.scan_file(path)
    }
}
