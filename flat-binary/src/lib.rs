//! # Flat Binary Parser
//!
//! Handles raw binary files without any container format.
//! Used for shellcode, firmware dumps, ROM images, and raw memory dumps.

use serde::{Deserialize, Serialize};
use std::fmt;

const MAX_OUTPUT_SIZE: usize = 256 * 1024 * 1024;

/// Represents a flat binary file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlatBinary {
    /// Raw bytes
    pub data: Vec<u8>,
    /// Base address (where the binary should be loaded)
    pub base_address: u64,
    /// Optional entry point offset from base_address
    pub entry_point: Option<u64>,
}

impl FlatBinary {
    /// Create a new flat binary
    pub fn new(data: Vec<u8>, base_address: u64) -> Self {
        Self {
            data,
            base_address,
            entry_point: None,
        }
    }

    /// Create from a slice
    pub fn from_slice(data: &[u8], base_address: u64) -> Self {
        Self::new(data.to_vec(), base_address)
    }

    /// Set entry point
    pub fn with_entry_point(mut self, entry: u64) -> Self {
        self.entry_point = Some(entry);
        self
    }

    /// Total size in bytes
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Read byte at offset
    pub fn read_byte(&self, offset: usize) -> Option<u8> {
        self.data.get(offset).copied()
    }

    /// Read word (16-bit LE) at offset
    pub fn read_word_le(&self, offset: usize) -> Option<u16> {
        if offset + 2 > self.data.len() {
            return None;
        }
        Some(u16::from_le_bytes([self.data[offset], self.data[offset + 1]]))
    }

    /// Read double word (32-bit LE) at offset
    pub fn read_dword_le(&self, offset: usize) -> Option<u32> {
        if offset + 4 > self.data.len() {
            return None;
        }
        Some(u32::from_le_bytes([
            self.data[offset],
            self.data[offset + 1],
            self.data[offset + 2],
            self.data[offset + 3],
        ]))
    }

    /// Read quad word (64-bit LE) at offset
    pub fn read_qword_le(&self, offset: usize) -> Option<u64> {
        if offset + 8 > self.data.len() {
            return None;
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.data[offset..offset + 8]);
        Some(u64::from_le_bytes(bytes))
    }

    /// Get a slice of the binary
    pub fn slice(&self, start: usize, end: usize) -> Option<&[u8]> {
        if start > end || end > self.data.len() {
            return None;
        }
        Some(&self.data[start..end])
    }

    /// Find pattern in binary
    pub fn find_pattern(&self, pattern: &[u8]) -> Option<usize> {
        if pattern.is_empty() {
            return None;
        }
        self.data.windows(pattern.len()).position(|w| w == pattern)
    }

    /// Find all occurrences of a pattern
    pub fn find_all_patterns(&self, pattern: &[u8]) -> Vec<usize> {
        if pattern.is_empty() {
            return Vec::new();
        }
        self.data.windows(pattern.len())
            .enumerate()
            .filter_map(|(i, w)| if w == pattern { Some(i) } else { None })
            .collect()
    }

    /// Calculate entropy of the entire binary
    pub fn entropy(&self) -> f64 {
        if self.data.is_empty() {
            return 0.0;
        }

        let mut freq = [0u32; 256];
        for &byte in &self.data {
            freq[byte as usize] += 1;
        }

        let len = self.data.len() as f64;
        let mut entropy = 0.0;
        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    /// Detect if this looks like shellcode (high entropy, no null bytes at start, etc.)
    pub fn looks_like_shellcode(&self) -> bool {
        if self.data.len() < 4 {
            return false;
        }

        // Shellcode typically has:
        // 1. High entropy (above 4.0)
        // 2. Few or no null bytes in the first portion
        // 3. Common shellcode patterns

        let entropy = self.entropy();
        if entropy < 4.0 {
            return false;
        }

        // Check first 32 bytes for nulls
        let null_count = self.data.iter().take(32).filter(|&&b| b == 0).count();
        if null_count > 8 {
            return false;
        }

        true
    }

    /// Common shellcode signatures
    pub fn detect_shellcode_type(&self) -> Option<&'static str> {
        // Windows x86 shellcode patterns
        if self.data.windows(3).any(|w| w == [0x64, 0xA1, 0x30]) {
            // mov eax, fs:[0x30] - PEB access (Windows x86)
            return Some("Windows x86 shellcode (PEB access)");
        }

        // Windows x64 shellcode patterns
        if self.data.windows(3).any(|w| w == [0x65, 0x48, 0x8B]) {
            // mov rax, gs:[...] - PEB access (Windows x64)
            return Some("Windows x64 shellcode (PEB access)");
        }

        // Linux x86 shellcode patterns
        if self.data.windows(2).any(|w| w == [0xCD, 0x80]) {
            // int 0x80 - Linux syscall
            return Some("Linux x86 shellcode (syscall)");
        }

        // Linux x64 shellcode patterns
        if self.data.windows(2).any(|w| w == [0x0F, 0x05]) {
            // syscall - Linux x64 syscall
            return Some("Linux x64 shellcode (syscall)");
        }

        None
    }
}

/// Errors when working with flat binaries
#[derive(Debug)]
pub enum FlatBinaryError {
    EmptyFile,
    OutOfBounds,
    Io(std::io::Error),
}

impl fmt::Display for FlatBinaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyFile => write!(f, "Flat binary is empty"),
            Self::OutOfBounds => write!(f, "Offset out of bounds"),
            Self::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for FlatBinaryError {}
impl From<std::io::Error> for FlatBinaryError {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}

/// Load flat binary from file
pub fn load_flat_binary(path: &str, base_address: u64) -> Result<FlatBinary, FlatBinaryError> {
    let data = std::fs::read(path)?;
    if data.is_empty() {
        return Err(FlatBinaryError::EmptyFile);
    }
    Ok(FlatBinary::new(data, base_address))
}

/// Intel HEX format support (for firmware files)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelHex {
    pub records: Vec<IntelHexRecord>,
    pub data: Vec<u8>,
    pub start_address: Option<u32>,
}

/// Intel HEX record types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntelHexRecordType {
    Data,
    EndOfFile,
    ExtendedSegmentAddress,
    StartSegmentAddress,
    ExtendedLinearAddress,
    StartLinearAddress,
}

/// Single Intel HEX record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelHexRecord {
    pub byte_count: u8,
    pub address: u16,
    pub record_type: IntelHexRecordType,
    pub data: Vec<u8>,
}

/// Decode a single ASCII hex digit, returning None for any other byte.
fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parse a byte slice as a big-endian hex number (ASCII only).
/// Operates on bytes so multibyte UTF-8 input can never panic on slicing.
fn hex_to_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || bytes.len() > 16 {
        return None;
    }
    let mut value: u64 = 0;
    for &b in bytes {
        value = (value << 4) | hex_digit(b)? as u64;
    }
    Some(value)
}

impl IntelHex {
    /// Parse Intel HEX format
    pub fn parse(text: &str) -> Result<Self, FlatBinaryError> {
        let mut records = Vec::new();
        let mut data = Vec::new();
        let mut base_address: u32 = 0;
        let mut start_address = None;

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || !line.starts_with(':') {
                continue;
            }

            // Work on raw bytes: str byte-ranges would panic on
            // multibyte UTF-8 characters at char boundaries.
            let bytes = line.as_bytes();
            let hex = &bytes[1..];
            if hex.len() < 10 {
                continue;
            }

            let byte_count = u8::try_from(hex_to_u64(&hex[0..2]).ok_or(FlatBinaryError::OutOfBounds)?)
                .map_err(|_| FlatBinaryError::OutOfBounds)?;
            let address = u16::try_from(hex_to_u64(&hex[2..6]).ok_or(FlatBinaryError::OutOfBounds)?)
                .map_err(|_| FlatBinaryError::OutOfBounds)?;
            let record_type_byte = u8::try_from(hex_to_u64(&hex[6..8]).ok_or(FlatBinaryError::OutOfBounds)?)
                .map_err(|_| FlatBinaryError::OutOfBounds)?;

            let record_type = match record_type_byte {
                0x00 => IntelHexRecordType::Data,
                0x01 => IntelHexRecordType::EndOfFile,
                0x02 => IntelHexRecordType::ExtendedSegmentAddress,
                0x03 => IntelHexRecordType::StartSegmentAddress,
                0x04 => IntelHexRecordType::ExtendedLinearAddress,
                0x05 => IntelHexRecordType::StartLinearAddress,
                _ => continue, // Unknown, skip
            };

            let data_start = 8;
            let data_end = data_start + (byte_count as usize * 2);
            if data_end > hex.len() {
                continue;
            }

            let mut record_data = Vec::with_capacity(byte_count as usize);
            for i in (data_start..data_end).step_by(2) {
                let byte = u8::try_from(hex_to_u64(&hex[i..i+2]).ok_or(FlatBinaryError::OutOfBounds)?)
                    .map_err(|_| FlatBinaryError::OutOfBounds)?;
                record_data.push(byte);
            }

            let record = IntelHexRecord {
                byte_count,
                address,
                record_type,
                data: record_data.clone(),
            };

            match record_type {
                IntelHexRecordType::Data => {
                    let addr = base_address + address as u32;
                    let end = addr as usize + record_data.len();
                    if end > MAX_OUTPUT_SIZE {
                        return Err(FlatBinaryError::OutOfBounds);
                    }
                    // Ensure data vector is large enough
                    if end > data.len() {
                        data.resize(end, 0xFF);
                    }
                    data[addr as usize..addr as usize + record_data.len()].copy_from_slice(&record_data);
                }
                IntelHexRecordType::ExtendedLinearAddress => {
                    if record_data.len() >= 2 {
                        base_address = ((record_data[0] as u32) << 24) | ((record_data[1] as u32) << 16);
                    }
                }
                IntelHexRecordType::StartLinearAddress => {
                    if record_data.len() >= 4 {
                        start_address = Some(u32::from_be_bytes([
                            record_data[0],
                            record_data[1],
                            record_data[2],
                            record_data[3],
                        ]));
                    }
                }
                IntelHexRecordType::EndOfFile => {
                    // Record the EOF marker, then stop processing further lines.
                }
                _ => {}
            }

            records.push(record);
        }

        Ok(IntelHex { records, data, start_address })
    }

    /// Convert to FlatBinary
    pub fn to_flat_binary(&self, base_address: u64) -> FlatBinary {
        let mut bin = FlatBinary::new(self.data.clone(), base_address);
        if let Some(start) = self.start_address {
            bin = bin.with_entry_point(start as u64);
        }
        bin
    }
}

/// Motorola S-Record format support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SRecord {
    pub records: Vec<SRecordEntry>,
    pub data: Vec<u8>,
    pub start_address: Option<u32>,
}

/// S-Record entry types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SRecordType {
    S0, // Header
    S1, // 16-bit address data
    S2, // 24-bit address data
    S3, // 32-bit address data
    S5, // Record count
    S7, // 32-bit start address
    S8, // 24-bit start address
    S9, // 16-bit start address
}

/// Single S-Record entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SRecordEntry {
    pub record_type: SRecordType,
    pub byte_count: u8,
    pub address: u32,
    pub data: Vec<u8>,
}

impl SRecord {
    /// Parse Motorola S-Record format
    pub fn parse(text: &str) -> Result<Self, FlatBinaryError> {
        let mut records = Vec::new();
        let mut data = Vec::new();
        let mut start_address = None;

        for line in text.lines() {
            let line = line.trim();
            if line.len() < 4 || !line.starts_with('S') {
                continue;
            }

            // Work on raw bytes: str byte-ranges would panic on
            // multibyte UTF-8 characters at char boundaries.
            let bytes = line.as_bytes();

            let record_type = match bytes[1] {
                b'0' => SRecordType::S0,
                b'1' => SRecordType::S1,
                b'2' => SRecordType::S2,
                b'3' => SRecordType::S3,
                b'5' => SRecordType::S5,
                b'7' => SRecordType::S7,
                b'8' => SRecordType::S8,
                b'9' => SRecordType::S9,
                _ => continue,
            };

            let byte_count = u8::try_from(hex_to_u64(&bytes[2..4]).ok_or(FlatBinaryError::OutOfBounds)?)
                .map_err(|_| FlatBinaryError::OutOfBounds)?;

            let (addr_len, _data_start) = match record_type {
                SRecordType::S0 | SRecordType::S1 | SRecordType::S5 | SRecordType::S9 => (2, 4),
                SRecordType::S2 | SRecordType::S8 => (3, 6),
                SRecordType::S3 | SRecordType::S7 => (4, 8),
            };

            let addr_end = 4 + (addr_len * 2);
            if addr_end > bytes.len() {
                continue;
            }

            let address = u32::try_from(hex_to_u64(&bytes[4..addr_end]).ok_or(FlatBinaryError::OutOfBounds)?)
                .map_err(|_| FlatBinaryError::OutOfBounds)?;

            let data_len = match (byte_count as usize).checked_sub(addr_len + 1) {
                Some(n) => n * 2,
                None => continue,
            };
            let data_end = addr_end + data_len;
            if data_end > bytes.len() {
                continue;
            }

            let mut record_data = Vec::new();
            for i in (addr_end..data_end).step_by(2) {
                let byte = u8::try_from(hex_to_u64(&bytes[i..i+2]).ok_or(FlatBinaryError::OutOfBounds)?)
                    .map_err(|_| FlatBinaryError::OutOfBounds)?;
                record_data.push(byte);
            }

            let entry = SRecordEntry {
                record_type,
                byte_count,
                address,
                data: record_data.clone(),
            };

            match record_type {
                SRecordType::S1 | SRecordType::S2 | SRecordType::S3 => {
                    let end = address as usize + record_data.len();
                    if end > MAX_OUTPUT_SIZE {
                        return Err(FlatBinaryError::OutOfBounds);
                    }
                    if end > data.len() {
                        data.resize(end, 0xFF);
                    }
                    data[address as usize..address as usize + record_data.len()].copy_from_slice(&record_data);
                }
                SRecordType::S7 | SRecordType::S8 | SRecordType::S9 => {
                    start_address = Some(address);
                }
                _ => {}
            }

            records.push(entry);
        }

        Ok(SRecord { records, data, start_address })
    }

    /// Convert to FlatBinary
    pub fn to_flat_binary(&self, base_address: u64) -> FlatBinary {
        let mut bin = FlatBinary::new(self.data.clone(), base_address);
        if let Some(start) = self.start_address {
            bin = bin.with_entry_point(start as u64);
        }
        bin
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flat_binary_basic() {
        let bin = FlatBinary::new(vec![0x48, 0x65, 0x6C, 0x6C, 0x6F], 0x1000);
        assert_eq!(bin.size(), 5);
        assert_eq!(bin.read_byte(0), Some(0x48));
        assert_eq!(bin.read_byte(4), Some(0x6F));
        assert_eq!(bin.read_byte(5), None);
    }

    #[test]
    fn test_flat_binary_read_words() {
        let bin = FlatBinary::new(vec![0x34, 0x12, 0x78, 0x56], 0);
        assert_eq!(bin.read_word_le(0), Some(0x1234));
        assert_eq!(bin.read_dword_le(0), Some(0x56781234));
    }

    #[test]
    fn test_find_pattern() {
        let bin = FlatBinary::new(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55], 0);
        assert_eq!(bin.find_pattern(&[0x22, 0x33]), Some(2));
        assert_eq!(bin.find_pattern(&[0xFF]), None);
    }

    #[test]
    fn test_entropy() {
        let bin = FlatBinary::new(vec![0; 256], 0);
        assert_eq!(bin.entropy(), 0.0); // All same byte = 0 entropy

        let bin2 = FlatBinary::new((0..=255).collect(), 0);
        assert!((bin2.entropy() - 8.0).abs() < 0.01); // Uniform distribution = 8 bits
    }

    #[test]
    fn test_intel_hex_parse() {
        let hex = ":100000000102030405060708090A0B0C0D0E0F1078\n:00000001FF";
        let ihex = IntelHex::parse(hex).unwrap();
        assert_eq!(ihex.records.len(), 2);
        assert_eq!(ihex.data.len(), 16);
        assert_eq!(ihex.data[0], 0x01);
        assert_eq!(ihex.data[15], 0x10);
    }

    #[test]
    fn test_srecord_parse() {
        let srec = "S11300000102030405060708090A0B0C0D0E0F1078\nS9030000FC";
        let srec_parsed = SRecord::parse(srec).unwrap();
        assert_eq!(srec_parsed.records.len(), 2);
        assert_eq!(srec_parsed.data.len(), 16);
        assert_eq!(srec_parsed.start_address, Some(0));
    }
}
