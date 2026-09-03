//! # DEX Parser — Android Dalvik Executable
//!
//! Parses the Dalvik Executable format (.dex), used by Android's Dalvik and ART runtimes.
//! This is a relatively lightweight format compared to PE/ELF but contains rich metadata
//! about Java/Kotlin classes and methods.
//!
//! ## Format overview
//!
//! ```text
//! ┌─────────────────────────────────────┐
//! │  Header (0x70 = 112 bytes)          │
//! │  - Magic: dex\n035\0                │
//! │  - Checksum, SHA-1, file size       │
//! │  - Header size, endian tag          │
//! │  - Map offset                       │
//! │  - String IDs, Type IDs, Proto IDs  │
//! │  - Field IDs, Method IDs, Class Defs│
//! │  - Data section offset & size       │
//! ├─────────────────────────────────────┤
//! │  String IDs table                   │
//! │  Type IDs table                     │
//! │  Proto IDs table                    │
//! │  Field IDs table                    │
//! │  Method IDs table                   │
//! │  Class definitions                  │
//! │  Data section (strings, code, etc.) │
//! └─────────────────────────────────────┘
//! ```

use adler::Adler32;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::fmt;
use std::hash::Hasher;

/// DEX magic: "dex\n035\0" (or "dex\n037\0" for newer versions)
pub const DEX_MAGIC: &[u8; 8] = b"dex\n035\0";
pub const DEX_MAGIC_037: &[u8; 8] = b"dex\n037\0";

/// DEX header (112 bytes)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DexHeader {
    pub magic: [u8; 8],
    pub checksum: u32,
    pub signature: [u8; 20],
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub link_size: u32,
    pub link_offset: u32,
    pub map_offset: u32,
    pub string_ids_size: u32,
    pub string_ids_offset: u32,
    pub type_ids_size: u32,
    pub type_ids_offset: u32,
    pub proto_ids_size: u32,
    pub proto_ids_offset: u32,
    pub field_ids_size: u32,
    pub field_ids_offset: u32,
    pub method_ids_size: u32,
    pub method_ids_offset: u32,
    pub class_defs_size: u32,
    pub class_defs_offset: u32,
    pub data_size: u32,
    pub data_offset: u32,
}

impl DexHeader {
    /// DEX version string (e.g., "035", "037", "039")
    pub fn version(&self) -> String {
        String::from_utf8_lossy(&self.magic[4..7]).into_owned()
    }
}

/// String ID item (4 bytes)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct StringId {
    pub data_offset: u32,
}

/// Type ID item (4 bytes)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TypeId {
    pub descriptor_idx: u32,
}

/// Proto ID item (12 bytes) - method prototype
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ProtoId {
    pub shorty_idx: u32,
    pub return_type_idx: u32,
    pub parameters_offset: u32,
}

/// Field ID item (8 bytes)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FieldId {
    pub class_idx: u16,
    pub type_idx: u16,
    pub name_idx: u32,
}

/// Method ID item (8 bytes)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MethodId {
    pub class_idx: u16,
    pub proto_idx: u16,
    pub name_idx: u32,
}

/// Class definition item (32 bytes)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ClassDef {
    pub class_idx: u32,
    pub access_flags: u32,
    pub superclass_idx: u32,
    pub interfaces_offset: u32,
    pub source_file_idx: u32,
    pub annotations_offset: u32,
    pub class_data_offset: u32,
    pub static_values_offset: u32,
}

impl ClassDef {
    /// Is this class public?
    pub fn is_public(&self) -> bool {
        self.access_flags & 0x0001 != 0
    }

    /// Is this class final?
    pub fn is_final(&self) -> bool {
        self.access_flags & 0x0010 != 0
    }

    /// Is this class abstract?
    pub fn is_abstract(&self) -> bool {
        self.access_flags & 0x0400 != 0
    }

    /// Is this class an interface?
    pub fn is_interface(&self) -> bool {
        self.access_flags & 0x0200 != 0
    }

    /// Is this class an enum?
    pub fn is_enum(&self) -> bool {
        self.access_flags & 0x4000 != 0
    }
}

/// Access flags
pub mod access_flags {
    pub const ACC_PUBLIC: u32 = 0x0001;
    pub const ACC_PRIVATE: u32 = 0x0002;
    pub const ACC_PROTECTED: u32 = 0x0004;
    pub const ACC_STATIC: u32 = 0x0008;
    pub const ACC_FINAL: u32 = 0x0010;
    pub const ACC_SYNCHRONIZED: u32 = 0x0020;
    pub const ACC_VOLATILE: u32 = 0x0040;
    pub const ACC_BRIDGE: u32 = 0x0040;
    pub const ACC_TRANSIENT: u32 = 0x0080;
    pub const ACC_VARARGS: u32 = 0x0080;
    pub const ACC_NATIVE: u32 = 0x0100;
    pub const ACC_INTERFACE: u32 = 0x0200;
    pub const ACC_ABSTRACT: u32 = 0x0400;
    pub const ACC_STRICT: u32 = 0x0800;
    pub const ACC_SYNTHETIC: u32 = 0x1000;
    pub const ACC_ANNOTATION: u32 = 0x2000;
    pub const ACC_ENUM: u32 = 0x4000;
    pub const ACC_CONSTRUCTOR: u32 = 0x10000;
    pub const ACC_DECLARED_SYNCHRONIZED: u32 = 0x20000;
}

/// Parsed DEX file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexFile {
    pub header: DexHeader,
    pub strings: Vec<String>,
    pub type_ids: Vec<TypeId>,
    pub proto_ids: Vec<ProtoId>,
    pub field_ids: Vec<FieldId>,
    pub method_ids: Vec<MethodId>,
    pub class_defs: Vec<ClassDef>,
}

impl DexFile {
    /// Get string by index
    pub fn get_string(&self, idx: u32) -> Option<&str> {
        self.strings.get(idx as usize).map(|s| s.as_str())
    }

    /// Get type descriptor by index
    pub fn get_type_descriptor(&self, idx: u32) -> Option<&str> {
        let type_id = self.type_ids.get(idx as usize)?;
        self.get_string(type_id.descriptor_idx)
    }

    /// Get class name
    pub fn get_class_name(&self, class_def: &ClassDef) -> Option<String> {
        self.get_type_descriptor(class_def.class_idx)
            .map(demangle_type)
    }

    /// Get method name
    pub fn get_method_name(&self, method_id: &MethodId) -> Option<&str> {
        self.get_string(method_id.name_idx)
    }

    /// Get all method names
    pub fn all_method_names(&self) -> Vec<String> {
        self.method_ids.iter()
            .filter_map(|m| self.get_method_name(m))
            .map(|s| s.to_string())
            .collect()
    }

    /// Count of all methods
    pub fn method_count(&self) -> usize {
        self.method_ids.len()
    }

    /// Count of all classes
    pub fn class_count(&self) -> usize {
        self.class_defs.len()
    }
}

/// Demangle a DEX type descriptor to human-readable form
/// e.g., "Ljava/lang/String;" → "java.lang.String"
///       "I" → "int"
///       "[I" → "int[]"
pub fn demangle_type(descriptor: &str) -> String {
    let mut result = String::new();
    let mut array_depth = 0;
    let chars: Vec<char> = descriptor.chars().collect();
    let mut i = 0;

    // Count array dimensions
    while i < chars.len() && chars[i] == '[' {
        array_depth += 1;
        i += 1;
    }

    if i >= chars.len() {
        return descriptor.to_string();
    }

    let base_type = match chars[i] {
        'V' => "void",
        'Z' => "boolean",
        'B' => "byte",
        'S' => "short",
        'C' => "char",
        'I' => "int",
        'J' => "long",
        'F' => "float",
        'D' => "double",
        'L' => {
            // Object type: "Ljava/lang/Object;"
            let start = i + 1;
            let end = chars.iter().skip(start).position(|&c| c == ';')
                .map(|p| start + p)
                .unwrap_or(chars.len());
            let class_name: String = chars[start..end].iter().collect();
            result.push_str(&class_name.replace('/', "."));
            &result.clone()[..]
        }
        _ => {
            return descriptor.to_string();
        }
    };

    if chars[i] == 'L' {
        // Already handled above
    } else {
        result.push_str(base_type);
    }

    for _ in 0..array_depth {
        result.push_str("[]");
    }

    result
}

/// DEX parsing errors
#[derive(Debug)]
pub enum DexError {
    InvalidMagic,
    FileTooSmall,
    InvalidHeader,
    UnsupportedEndian,
    TruncatedData,
    InvalidUtf8,
    InvalidUleb,
    Io(std::io::Error),
}

impl fmt::Display for DexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "Invalid DEX magic"),
            Self::FileTooSmall => write!(f, "DEX file too small"),
            Self::InvalidHeader => write!(f, "Invalid DEX header"),
            Self::UnsupportedEndian => write!(f, "Unsupported endian tag (big-endian)"),
            Self::TruncatedData => write!(f, "Truncated DEX data"),
            Self::InvalidUtf8 => write!(f, "Invalid UTF-8 in DEX"),
            Self::InvalidUleb => write!(f, "ULEB128 integer does not fit in u32"),
            Self::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for DexError {}
impl From<std::io::Error> for DexError {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}

fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    let remaining = data.len().checked_sub(offset)?;
    if remaining < 2 { return None; }
    Some(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    let remaining = data.len().checked_sub(offset)?;
    if remaining < 4 { return None; }
    Some(u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]))
}

/// Read ULEB128 (unsigned LEB128)
fn read_uleb128(data: &[u8], offset: &mut usize) -> Result<u32, DexError> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *offset >= data.len() { return Err(DexError::TruncatedData); }
        let byte = data[*offset];
        *offset += 1;
        if shift >= 35 { return Err(DexError::InvalidUleb); }
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            if result > u32::MAX as u64 { return Err(DexError::InvalidUleb); }
            return Ok(result as u32);
        }
        shift += 7;
    }
}

/// Read MUTF-8 string (modified UTF-8 used in DEX).
/// `utf16_len` is the number of UTF-16 code units (not bytes).
/// Bytes are decoded unit-by-unit; invalid sequences become U+FFFD
/// without cutting mid-character; surrogate pairs are joined into
/// real characters (CESU-8 style supplementary encoding).
fn read_mutf8_string(data: &[u8], offset: usize, utf16_len: usize) -> Option<String> {
    if offset > data.len() { return None; }
    // utf16_len comes from ULEB128 and can claim up to u32::MAX; never
    // pre-allocate more than the remaining input bytes could yield
    // (each unit decodes from >=1 byte), capped at a sane maximum.
    const MAX_PREALLOC_UNITS: usize = 16 * 1024 * 1024;
    let capacity = utf16_len
        .min(data.len() - offset)
        .min(MAX_PREALLOC_UNITS);
    let mut units: Vec<u16> = Vec::with_capacity(capacity);
    let mut pos = offset;

    while units.len() < utf16_len {
        let b = match data.get(pos) {
            Some(&b) => b,
            None => break,
        };
        pos += 1;
        match b {
            0x00 => break,
            0x01..=0x7F => units.push(b as u16),
            0xC0..=0xDF => {
                let b2 = data.get(pos).copied().unwrap_or(0);
                if b2 & 0xC0 == 0x80 {
                    pos += 1;
                    units.push((((b as u16) & 0x1F) << 6) | ((b2 as u16) & 0x3F));
                } else {
                    units.push(0xFFFD);
                }
            }
            0xE0..=0xEF => {
                let b2 = data.get(pos).copied().unwrap_or(0);
                let b3 = data.get(pos + 1).copied().unwrap_or(0);
                if b2 & 0xC0 == 0x80 && b3 & 0xC0 == 0x80 {
                    pos += 2;
                    units.push(
                        (((b as u16) & 0x0F) << 12)
                            | (((b2 as u16) & 0x3F) << 6)
                            | ((b3 as u16) & 0x3F),
                    );
                } else {
                    units.push(0xFFFD);
                }
            }
            _ => units.push(0xFFFD),
        }
    }

    Some(String::from_utf16_lossy(&units))
}

/// Parse DEX file from raw bytes
pub fn parse_dex(data: &[u8]) -> Result<DexFile, DexError> {
    if data.len() < 112 {
        return Err(DexError::FileTooSmall);
    }

    // Check magic
    let magic: [u8; 8] = data[0..8].try_into().map_err(|_| DexError::InvalidMagic)?;
    if &magic != DEX_MAGIC && &magic != DEX_MAGIC_037 && &magic[..4] != b"dex\n" {
        return Err(DexError::InvalidMagic);
    }

    let header = DexHeader {
        magic,
        checksum: read_u32_le(data, 8).ok_or(DexError::InvalidHeader)?,
        signature: data[12..32].try_into().map_err(|_| DexError::InvalidHeader)?,
        file_size: read_u32_le(data, 32).ok_or(DexError::InvalidHeader)?,
        header_size: read_u32_le(data, 36).ok_or(DexError::InvalidHeader)?,
        endian_tag: read_u32_le(data, 40).ok_or(DexError::InvalidHeader)?,
        link_size: read_u32_le(data, 44).ok_or(DexError::InvalidHeader)?,
        link_offset: read_u32_le(data, 48).ok_or(DexError::InvalidHeader)?,
        map_offset: read_u32_le(data, 52).ok_or(DexError::InvalidHeader)?,
        string_ids_size: read_u32_le(data, 56).ok_or(DexError::InvalidHeader)?,
        string_ids_offset: read_u32_le(data, 60).ok_or(DexError::InvalidHeader)?,
        type_ids_size: read_u32_le(data, 64).ok_or(DexError::InvalidHeader)?,
        type_ids_offset: read_u32_le(data, 68).ok_or(DexError::InvalidHeader)?,
        proto_ids_size: read_u32_le(data, 72).ok_or(DexError::InvalidHeader)?,
        proto_ids_offset: read_u32_le(data, 76).ok_or(DexError::InvalidHeader)?,
        field_ids_size: read_u32_le(data, 80).ok_or(DexError::InvalidHeader)?,
        field_ids_offset: read_u32_le(data, 84).ok_or(DexError::InvalidHeader)?,
        method_ids_size: read_u32_le(data, 88).ok_or(DexError::InvalidHeader)?,
        method_ids_offset: read_u32_le(data, 92).ok_or(DexError::InvalidHeader)?,
        class_defs_size: read_u32_le(data, 96).ok_or(DexError::InvalidHeader)?,
        class_defs_offset: read_u32_le(data, 100).ok_or(DexError::InvalidHeader)?,
        data_size: read_u32_le(data, 104).ok_or(DexError::InvalidHeader)?,
        data_offset: read_u32_le(data, 108).ok_or(DexError::InvalidHeader)?,
    };

    if header.endian_tag == 0x7856_3412 {
        return Err(DexError::UnsupportedEndian);
    }

    // Validate Adler-32 checksum over bytes [12..file_size]
    let checksum_end = (header.file_size as usize).min(data.len());
    if checksum_end < 12 {
        return Err(DexError::InvalidHeader);
    }
    let mut adler = Adler32::new();
    adler.write(&data[12..checksum_end]);
    let computed_checksum = adler.checksum();
    if computed_checksum != header.checksum {
        return Err(DexError::InvalidHeader);
    }

    // Validate SHA-1 signature over bytes [32..file_size]
    let sig_end = (header.file_size as usize).min(data.len());
    if sig_end < 32 {
        return Err(DexError::InvalidHeader);
    }
    let mut sha = Sha1::new();
    sha.update(&data[32..sig_end]);
    let computed_sig: [u8; 20] = sha.finalize().into();
    if computed_sig != header.signature {
        return Err(DexError::InvalidHeader);
    }

    // Parse strings
    let mut strings = Vec::with_capacity(header.string_ids_size.min(1_000_000) as usize);
    for i in 0..header.string_ids_size {
        let base = header.string_ids_offset.checked_add(i.checked_mul(4).ok_or(DexError::TruncatedData)?)
            .ok_or(DexError::TruncatedData)? as usize;
        let str_data_offset = read_u32_le(data, base).ok_or(DexError::TruncatedData)? as usize;

        // String data format: ULEB128 length (UTF-16 code units) + MUTF-8 data + null terminator
        let mut str_offset = str_data_offset;
        let str_len = read_uleb128(data, &mut str_offset)?;

        // Read MUTF-8 string, decoding exactly str_len UTF-16 code units
        let s = read_mutf8_string(data, str_offset, str_len as usize)
            .unwrap_or_else(|| format!("<invalid_string_{}>", i));
        strings.push(s);
    }

    // Parse type IDs
    let mut type_ids = Vec::with_capacity(header.type_ids_size.min(1_000_000) as usize);
    for i in 0..header.type_ids_size {
        let base = header.type_ids_offset.checked_add(i.checked_mul(4).ok_or(DexError::TruncatedData)?)
            .ok_or(DexError::TruncatedData)? as usize;
        let descriptor_idx = read_u32_le(data, base).ok_or(DexError::TruncatedData)?;
        type_ids.push(TypeId { descriptor_idx });
    }

    // Parse proto IDs
    let mut proto_ids = Vec::with_capacity(header.proto_ids_size.min(1_000_000) as usize);
    for i in 0..header.proto_ids_size {
        let base = header.proto_ids_offset.checked_add(i.checked_mul(12).ok_or(DexError::TruncatedData)?)
            .ok_or(DexError::TruncatedData)? as usize;
        let shorty_idx = read_u32_le(data, base).ok_or(DexError::TruncatedData)?;
        let return_type_idx = read_u32_le(data, base + 4).ok_or(DexError::TruncatedData)?;
        let parameters_offset = read_u32_le(data, base + 8).ok_or(DexError::TruncatedData)?;
        proto_ids.push(ProtoId { shorty_idx, return_type_idx, parameters_offset });
    }

    // Parse field IDs
    let mut field_ids = Vec::with_capacity(header.field_ids_size.min(1_000_000) as usize);
    for i in 0..header.field_ids_size {
        let base = header.field_ids_offset.checked_add(i.checked_mul(8).ok_or(DexError::TruncatedData)?)
            .ok_or(DexError::TruncatedData)? as usize;
        let class_idx = read_u16_le(data, base).ok_or(DexError::TruncatedData)?;
        let type_idx = read_u16_le(data, base + 2).ok_or(DexError::TruncatedData)?;
        let name_idx = read_u32_le(data, base + 4).ok_or(DexError::TruncatedData)?;
        field_ids.push(FieldId { class_idx, type_idx, name_idx });
    }

    // Parse method IDs
    let mut method_ids = Vec::with_capacity(header.method_ids_size.min(1_000_000) as usize);
    for i in 0..header.method_ids_size {
        let base = header.method_ids_offset.checked_add(i.checked_mul(8).ok_or(DexError::TruncatedData)?)
            .ok_or(DexError::TruncatedData)? as usize;
        let class_idx = read_u16_le(data, base).ok_or(DexError::TruncatedData)?;
        let proto_idx = read_u16_le(data, base + 2).ok_or(DexError::TruncatedData)?;
        let name_idx = read_u32_le(data, base + 4).ok_or(DexError::TruncatedData)?;
        method_ids.push(MethodId { class_idx, proto_idx, name_idx });
    }

    // Parse class definitions
    let mut class_defs = Vec::with_capacity(header.class_defs_size.min(1_000_000) as usize);
    for i in 0..header.class_defs_size {
        let base = header.class_defs_offset.checked_add(i.checked_mul(32).ok_or(DexError::TruncatedData)?)
            .ok_or(DexError::TruncatedData)? as usize;
        let class_idx = read_u32_le(data, base).ok_or(DexError::TruncatedData)?;
        let access_flags = read_u32_le(data, base + 4).ok_or(DexError::TruncatedData)?;
        let superclass_idx = read_u32_le(data, base + 8).ok_or(DexError::TruncatedData)?;
        let interfaces_offset = read_u32_le(data, base + 12).ok_or(DexError::TruncatedData)?;
        let source_file_idx = read_u32_le(data, base + 16).ok_or(DexError::TruncatedData)?;
        let annotations_offset = read_u32_le(data, base + 20).ok_or(DexError::TruncatedData)?;
        let class_data_offset = read_u32_le(data, base + 24).ok_or(DexError::TruncatedData)?;
        let static_values_offset = read_u32_le(data, base + 28).ok_or(DexError::TruncatedData)?;
        class_defs.push(ClassDef {
            class_idx,
            access_flags,
            superclass_idx,
            interfaces_offset,
            source_file_idx,
            annotations_offset,
            class_data_offset,
            static_values_offset,
        });
    }

    Ok(DexFile {
        header,
        strings,
        type_ids,
        proto_ids,
        field_ids,
        method_ids,
        class_defs,
    })
}

/// Check if data is a DEX file
pub fn is_dex(data: &[u8]) -> bool {
    data.len() >= 8 && &data[0..4] == b"dex\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_dex() {
        assert!(is_dex(b"dex\n035\0\x00\x00"));
        assert!(!is_dex(b"MZ\x90\x00"));
        assert!(!is_dex(b"\x7fELF"));
    }

    #[test]
    fn test_demangle_primitive() {
        assert_eq!(demangle_type("I"), "int");
        assert_eq!(demangle_type("J"), "long");
        assert_eq!(demangle_type("Z"), "boolean");
        assert_eq!(demangle_type("V"), "void");
    }

    #[test]
    fn test_demangle_object() {
        assert_eq!(demangle_type("Ljava/lang/String;"), "java.lang.String");
        assert_eq!(demangle_type("Ljava/util/List;"), "java.util.List");
    }

    #[test]
    fn test_demangle_array() {
        assert_eq!(demangle_type("[I"), "int[]");
        assert_eq!(demangle_type("[[I"), "int[][]");
        assert_eq!(demangle_type("[Ljava/lang/Object;"), "java.lang.Object[]");
    }

    #[test]
    fn test_class_def_flags() {
        let cd = ClassDef {
            class_idx: 0,
            access_flags: 0x0011, // PUBLIC | FINAL
            superclass_idx: 0,
            interfaces_offset: 0,
            source_file_idx: 0,
            annotations_offset: 0,
            class_data_offset: 0,
            static_values_offset: 0,
    };

        assert!(cd.is_public());
        assert!(cd.is_final());
        assert!(!cd.is_abstract());
    }
}
