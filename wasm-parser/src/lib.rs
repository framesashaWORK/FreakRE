//! # WebAssembly Binary Parser
//!
//! Parses the WebAssembly binary format (.wasm files), a lightweight stack-based
//! virtual machine designed for efficient execution in web browsers and beyond.
//!
//! ## Format overview
//!
//! ```text
//! ┌─────────────────────────────────────┐
//! │  Magic: \0asm (4 bytes)             │
//! │  Version: 1 (4 bytes, u32 LE)       │
//! ├─────────────────────────────────────┤
//! │  Sections (variable length, ordered)│
//! │  ┌─────────────────────────────┐    │
//! │  │ Section ID (1 byte)         │    │
//! │  │ Section Size (LEB128 u32)   │    │
//! │  │ Section Contents            │    │
//! │  └─────────────────────────────┘    │
//! └─────────────────────────────────────┘
//! ```
//!
//! ## Section IDs
//!
//! | ID | Name        | Description                        |
//! |----|-------------|------------------------------------|
//! | 0  | Custom      | Debug info, names, metadata        |
//! | 1  | Type        | Function signatures                |
//! | 2  | Import      | Imported functions/memory/tables   |
//! | 3  | Function    | Function declarations (type index) |
//! | 4  | Table       | Table declarations                 |
//! | 5  | Memory      | Memory declarations                |
//! | 6  | Global      | Global variables                   |
//! | 7  | Export      | Exported items                     |
//! | 8  | Start       | Start function index               |
//! | 9  | Element     | Element segments (table init)      |
//! | 10 | Code        | Function bodies                    |
//! | 11 | Data        | Data segments (memory init)        |
//! | 12 | Data Count  | Number of data segments (bulk mem) |

use serde::{Deserialize, Serialize};
use std::fmt;

/// WASM value types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueType {
    I32,
    I64,
    F32,
    F64,
    V128,
    FuncRef,
    ExternRef,
}

impl ValueType {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x7F => Some(Self::I32),
            0x7E => Some(Self::I64),
            0x7D => Some(Self::F32),
            0x7C => Some(Self::F64),
            0x7B => Some(Self::V128),
            0x70 => Some(Self::FuncRef),
            0x6F => Some(Self::ExternRef),
            _ => None,
        }
    }

    pub fn to_byte(self) -> u8 {
        match self {
            Self::I32 => 0x7F,
            Self::I64 => 0x7E,
            Self::F32 => 0x7D,
            Self::F64 => 0x7C,
            Self::V128 => 0x7B,
            Self::FuncRef => 0x70,
            Self::ExternRef => 0x6F,
        }
    }

    pub fn size(&self) -> usize {
        match self {
            Self::I32 | Self::F32 => 4,
            Self::I64 | Self::F64 => 8,
            Self::V128 => 16,
            _ => 4,
        }
    }
}

/// Function type (signature)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuncType {
    pub params: Vec<ValueType>,
    pub results: Vec<ValueType>,
}

/// Import entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Import {
    pub module: String,
    pub name: String,
    pub kind: ImportKind,
}

/// Import kind
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImportKind {
    Function(u32),       // type index
    Table(TableType),
    Memory(MemType),
    Global(GlobalType),
}

/// Export entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Export {
    pub name: String,
    pub kind: ExportKind,
    pub index: u32,
}

/// Export kind
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportKind {
    Function,
    Table,
    Memory,
    Global,
}

impl ExportKind {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::Function),
            0x01 => Some(Self::Table),
            0x02 => Some(Self::Memory),
            0x03 => Some(Self::Global),
            _ => None,
        }
    }
}

/// Table type
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TableType {
    pub elem_type: ValueType,
    pub limits: Limits,
}

/// Memory type
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MemType {
    pub limits: Limits,
}

/// Limits (min, optional max)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Limits {
    pub min: u32,
    pub max: Option<u32>,
}

/// Global type
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GlobalType {
    pub value_type: ValueType,
    pub mutable: bool,
}

/// Global variable
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Global {
    pub typ: GlobalType,
    pub init_expr: Vec<u8>, // init expression bytecode
}

/// Function body
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Function {
    pub type_idx: u32,
    pub locals: Vec<(u32, ValueType)>, // (count, type)
    pub code: Vec<u8>,                  // bytecode
}

/// Data segment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSegment {
    pub memory_idx: u32,
    pub offset_expr: Vec<u8>,
    pub data: Vec<u8>,
}

/// Element segment kind
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ElementKind {
    Active,
    Passive,
    Declarative,
}

/// Element segment (table initialization)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElementSegment {
    pub kind: ElementKind,
    pub active: bool,
    pub table_idx: u32,
    pub offset: Vec<u8>,
    pub func_indices: Vec<u32>,
}

/// Custom section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomSection {
    pub name: String,
    pub data: Vec<u8>,
}

/// WASM section ID constants
pub mod section_id {
    pub const CUSTOM: u8 = 0;
    pub const TYPE: u8 = 1;
    pub const IMPORT: u8 = 2;
    pub const FUNCTION: u8 = 3;
    pub const TABLE: u8 = 4;
    pub const MEMORY: u8 = 5;
    pub const GLOBAL: u8 = 6;
    pub const EXPORT: u8 = 7;
    pub const START: u8 = 8;
    pub const ELEMENT: u8 = 9;
    pub const CODE: u8 = 10;
    pub const DATA: u8 = 11;
    pub const DATA_COUNT: u8 = 12;
}

/// Parsed WASM module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmModule {
    pub version: u32,
    pub types: Vec<FuncType>,
    pub imports: Vec<Import>,
    pub functions: Vec<Function>,
    pub tables: Vec<TableType>,
    pub memories: Vec<MemType>,
    pub globals: Vec<Global>,
    pub exports: Vec<Export>,
    pub start: Option<u32>,
    pub elements: Vec<ElementSegment>,
    pub data: Vec<DataSegment>,
    pub custom_sections: Vec<CustomSection>,
}

impl WasmModule {
    /// Count of all function definitions (imports + local)
    pub fn total_functions(&self) -> usize {
        let imported_funcs = self.imports.iter()
            .filter(|i| matches!(i.kind, ImportKind::Function(_)))
            .count();
        imported_funcs + self.functions.len()
    }

    /// Get all imported function names
    pub fn imported_function_names(&self) -> Vec<String> {
        self.imports.iter()
            .filter(|i| matches!(i.kind, ImportKind::Function(_)))
            .map(|i| format!("{}.{}", i.module, i.name))
            .collect()
    }

    /// Get all exported function names
    pub fn exported_function_names(&self) -> Vec<String> {
        self.exports.iter()
            .filter(|e| e.kind == ExportKind::Function)
            .map(|e| e.name.clone())
            .collect()
    }

    /// Total code size in bytes
    pub fn total_code_size(&self) -> usize {
        self.functions.iter().map(|f| f.code.len()).sum()
    }
}

/// WASM parsing errors
#[derive(Debug)]
pub enum WasmError {
    InvalidMagic,
    InvalidVersion(u32),
    UnexpectedEnd,
    InvalidSectionId(u8),
    InvalidUtf8,
    InvalidValueType(u8),
    InvalidExportKind(u8),
    InvalidImportKind(u8),
    InvalidLeb,
    Unsupported(String),
    Io(std::io::Error),
}

impl fmt::Display for WasmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "Invalid WASM magic number"),
            Self::InvalidVersion(v) => write!(f, "Invalid WASM version: {}", v),
            Self::UnexpectedEnd => write!(f, "Unexpected end of file"),
            Self::InvalidSectionId(id) => write!(f, "Invalid section ID: {}", id),
            Self::InvalidUtf8 => write!(f, "Invalid UTF-8 string"),
            Self::InvalidValueType(b) => write!(f, "Invalid value type: 0x{:02x}", b),
            Self::InvalidExportKind(b) => write!(f, "Invalid export kind: 0x{:02x}", b),
            Self::InvalidImportKind(b) => write!(f, "Invalid import kind: 0x{:02x}", b),
            Self::InvalidLeb => write!(f, "LEB128 integer does not fit in u32"),
            Self::Unsupported(what) => write!(f, "Unsupported WASM feature: {}", what),
            Self::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for WasmError {}
impl From<std::io::Error> for WasmError {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}

/// LEB128 unsigned integer decoder
fn read_leb128_u32(data: &[u8], offset: &mut usize) -> Result<u32, WasmError> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    loop {
        if *offset >= data.len() {
            return Err(WasmError::UnexpectedEnd);
        }
        let byte = data[*offset];
        *offset += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            if result > u32::MAX as u64 {
                return Err(WasmError::InvalidLeb);
            }
            return Ok(result as u32);
        }
        shift += 7;
        if shift >= 35 {
            return Err(WasmError::UnexpectedEnd);
        }
    }
}

fn read_name(data: &[u8], offset: &mut usize) -> Result<String, WasmError> {
    let len = read_leb128_u32(data, offset)? as usize;
    if len.checked_add(*offset).is_none_or(|end| end > data.len()) {
        return Err(WasmError::UnexpectedEnd);
    }
    let s = std::str::from_utf8(&data[*offset..*offset + len])
        .map_err(|_| WasmError::InvalidUtf8)?;
    *offset += len;
    Ok(s.to_string())
}

fn read_value_type(data: &[u8], offset: &mut usize) -> Result<ValueType, WasmError> {
    if *offset >= data.len() {
        return Err(WasmError::UnexpectedEnd);
    }
    let b = data[*offset];
    *offset += 1;
    ValueType::from_byte(b).ok_or(WasmError::InvalidValueType(b))
}

fn read_init_expr(data: &[u8], offset: &mut usize, end: usize) -> Result<Vec<u8>, WasmError> {
    let start = *offset;
    while *offset < end {
        let b = data.get(*offset).copied().ok_or(WasmError::UnexpectedEnd)?;
        *offset += 1;
        if b == 0x0B {
            return Ok(data[start..*offset].to_vec());
        }
    }
    Err(WasmError::UnexpectedEnd)
}

fn read_func_index_vec(data: &[u8], offset: &mut usize) -> Result<Vec<u32>, WasmError> {
    let num_funcs = read_leb128_u32(data, offset)?;
    let mut func_indices = Vec::with_capacity(num_funcs.min(100_000) as usize);
    for _ in 0..num_funcs {
        func_indices.push(read_leb128_u32(data, offset)?);
    }
    Ok(func_indices)
}

fn read_limits(data: &[u8], offset: &mut usize) -> Result<Limits, WasmError> {
    if *offset >= data.len() {
        return Err(WasmError::UnexpectedEnd);
    }
    let flags = data[*offset];
    *offset += 1;
    let min = read_leb128_u32(data, offset)?;
    let max = if flags & 0x01 != 0 {
        Some(read_leb128_u32(data, offset)?)
    } else {
        None
    };
    Ok(Limits { min, max })
}

/// Parse WASM module from raw bytes
pub fn parse_wasm(data: &[u8]) -> Result<WasmModule, WasmError> {
    if data.len() < 8 {
        return Err(WasmError::UnexpectedEnd);
    }

    // Check magic: \0asm
    if &data[0..4] != b"\x00asm" {
        return Err(WasmError::InvalidMagic);
    }

    let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    if version != 1 {
        return Err(WasmError::InvalidVersion(version));
    }

    let mut module = WasmModule {
        version,
        types: Vec::new(),
        imports: Vec::new(),
        functions: Vec::new(),
        tables: Vec::new(),
        memories: Vec::new(),
        globals: Vec::new(),
        exports: Vec::new(),
        start: None,
        elements: Vec::new(),
        data: Vec::new(),
        custom_sections: Vec::new(),
    };

    let mut offset = 8;
    let mut func_type_indices: Vec<u32> = Vec::new();

    while offset < data.len() {
        let section_id = data[offset];
        offset += 1;
        let section_size = read_leb128_u32(data, &mut offset)? as usize;
        let section_end = match offset.checked_add(section_size) {
            Some(e) => e,
            None => return Err(WasmError::UnexpectedEnd),
        };

        if section_end > data.len() {
            return Err(WasmError::UnexpectedEnd);
        }

        match section_id {
            section_id::CUSTOM => {
                let name = read_name(data, &mut offset)?;
                if offset > section_end {
                    return Err(WasmError::UnexpectedEnd);
                }
                let remaining = section_end - offset;
                let custom_data = data[offset..offset + remaining].to_vec();
                module.custom_sections.push(CustomSection {
                    name,
                    data: custom_data,
                });
            }
            section_id::TYPE => {
                let count = read_leb128_u32(data, &mut offset)?;
                for _ in 0..count {
                    if offset >= section_end { break; }
                    let form = data.get(offset).copied().ok_or(WasmError::UnexpectedEnd)?;
                    if form != 0x60 {
                        return Err(WasmError::InvalidValueType(form));
                    }
                    offset += 1;

                    let param_count = read_leb128_u32(data, &mut offset)?;
                    let mut params = Vec::with_capacity(param_count.min(100_000) as usize);
                    for _ in 0..param_count {
                        params.push(read_value_type(data, &mut offset)?);
                    }

                    let result_count = read_leb128_u32(data, &mut offset)?;
                    let mut results = Vec::with_capacity(result_count.min(100_000) as usize);
                    for _ in 0..result_count {
                        results.push(read_value_type(data, &mut offset)?);
                    }

                    module.types.push(FuncType { params, results });
                }
            }
            section_id::IMPORT => {
                let count = read_leb128_u32(data, &mut offset)?;
                for _ in 0..count {
                    if offset >= section_end { break; }
                    let mod_name = read_name(data, &mut offset)?;
                    let name = read_name(data, &mut offset)?;
                    let kind_byte = data.get(offset).copied().ok_or(WasmError::UnexpectedEnd)?;
                    offset += 1;
                    let kind = match kind_byte {
                        0x00 => {
                            let type_idx = read_leb128_u32(data, &mut offset)?;
                            ImportKind::Function(type_idx)
                        }
                        0x01 => {
                            let elem_type = read_value_type(data, &mut offset)?;
                            let limits = read_limits(data, &mut offset)?;
                            ImportKind::Table(TableType { elem_type, limits })
                        }
                        0x02 => {
                            let limits = read_limits(data, &mut offset)?;
                            ImportKind::Memory(MemType { limits })
                        }
                        0x03 => {
                            let vt = read_value_type(data, &mut offset)?;
                            let mutable = data.get(offset).copied().ok_or(WasmError::UnexpectedEnd)? != 0;
                            offset += 1;
                            ImportKind::Global(GlobalType { value_type: vt, mutable })
                        }
                        _ => return Err(WasmError::InvalidImportKind(kind_byte)),
                    };
                    module.imports.push(Import { module: mod_name, name, kind });
                }
            }
            section_id::FUNCTION => {
                let count = read_leb128_u32(data, &mut offset)?;
                for _ in 0..count {
                    if offset >= section_end { break; }
                    let type_idx = read_leb128_u32(data, &mut offset)?;
                    func_type_indices.push(type_idx);
                }
            }
            section_id::TABLE => {
                let count = read_leb128_u32(data, &mut offset)?;
                for _ in 0..count {
                    if offset >= section_end { break; }
                    let elem_type = read_value_type(data, &mut offset)?;
                    let limits = read_limits(data, &mut offset)?;
                    module.tables.push(TableType { elem_type, limits });
                }
            }
            section_id::MEMORY => {
                let count = read_leb128_u32(data, &mut offset)?;
                for _ in 0..count {
                    if offset >= section_end { break; }
                    let limits = read_limits(data, &mut offset)?;
                    module.memories.push(MemType { limits });
                }
            }
            section_id::GLOBAL => {
                let count = read_leb128_u32(data, &mut offset)?;
                for _ in 0..count {
                    if offset >= section_end { break; }
                    let vt = read_value_type(data, &mut offset)?;
                    let mutable = data.get(offset).copied().ok_or(WasmError::UnexpectedEnd)? != 0;
                    offset += 1;
                    // Read init expression until 0x0B (end opcode)
                    let expr_start = offset;
                    while offset < section_end {
                        let b = data.get(offset).copied().ok_or(WasmError::UnexpectedEnd)?;
                        offset += 1;
                        if b == 0x0B { break; }
                    }
                    let init_expr = data[expr_start..offset].to_vec();
                    module.globals.push(Global {
                        typ: GlobalType { value_type: vt, mutable },
                        init_expr,
                    });
                }
            }
            section_id::EXPORT => {
                let count = read_leb128_u32(data, &mut offset)?;
                for _ in 0..count {
                    if offset >= section_end { break; }
                    let name = read_name(data, &mut offset)?;
                    let kind_byte = data.get(offset).copied().ok_or(WasmError::UnexpectedEnd)?;
                    offset += 1;
                    let kind = ExportKind::from_byte(kind_byte)
                        .ok_or(WasmError::InvalidExportKind(kind_byte))?;
                    let index = read_leb128_u32(data, &mut offset)?;
                    module.exports.push(Export { name, kind, index });
                }
            }
            section_id::START => {
                module.start = Some(read_leb128_u32(data, &mut offset)?);
            }
            section_id::ELEMENT => {
                let count = read_leb128_u32(data, &mut offset)?;
                for _ in 0..count {
                    if offset >= section_end { break; }
                    let flags = read_leb128_u32(data, &mut offset)?;
                    let segment = match flags {
                        0 => {
                            let offset_expr = read_init_expr(data, &mut offset, section_end)?;
                            let func_indices = read_func_index_vec(data, &mut offset)?;
                            ElementSegment {
                                kind: ElementKind::Active,
                                active: true,
                                table_idx: 0,
                                offset: offset_expr,
                                func_indices,
                            }
                        }
                        1 => {
                            let elemkind = data.get(offset).copied().ok_or(WasmError::UnexpectedEnd)?;
                            offset += 1;
                            if elemkind != 0x00 {
                                return Err(WasmError::Unsupported(format!("element kind 0x{:02x}", elemkind)));
                            }
                            let func_indices = read_func_index_vec(data, &mut offset)?;
                            ElementSegment {
                                kind: ElementKind::Passive,
                                active: false,
                                table_idx: 0,
                                offset: Vec::new(),
                                func_indices,
                            }
                        }
                        2 => {
                            let table_idx = read_leb128_u32(data, &mut offset)?;
                            let offset_expr = read_init_expr(data, &mut offset, section_end)?;
                            let elemkind = data.get(offset).copied().ok_or(WasmError::UnexpectedEnd)?;
                            offset += 1;
                            if elemkind != 0x00 {
                                return Err(WasmError::Unsupported(format!("element kind 0x{:02x}", elemkind)));
                            }
                            let func_indices = read_func_index_vec(data, &mut offset)?;
                            ElementSegment {
                                kind: ElementKind::Active,
                                active: true,
                                table_idx,
                                offset: offset_expr,
                                func_indices,
                            }
                        }
                        3 => {
                            let elemkind = data.get(offset).copied().ok_or(WasmError::UnexpectedEnd)?;
                            offset += 1;
                            if elemkind != 0x00 {
                                return Err(WasmError::Unsupported(format!("element kind 0x{:02x}", elemkind)));
                            }
                            let func_indices = read_func_index_vec(data, &mut offset)?;
                            ElementSegment {
                                kind: ElementKind::Declarative,
                                active: false,
                                table_idx: 0,
                                offset: Vec::new(),
                                func_indices,
                            }
                        }
                        other => {
                            return Err(WasmError::Unsupported(format!("element segment flags {}", other)));
                        }
                    };
                    module.elements.push(segment);
                }
            }
            section_id::CODE => {
                let count = read_leb128_u32(data, &mut offset)?;
                for i in 0..count {
                    if offset >= section_end { break; }
                    let body_size = read_leb128_u32(data, &mut offset)? as usize;
                    let body_end = match offset.checked_add(body_size) {
                        Some(e) if e <= section_end && e <= data.len() => e,
                        _ => return Err(WasmError::UnexpectedEnd),
                    };

                    // Read locals (bounded to this function body)
                    let local_count = read_leb128_u32(data, &mut offset)?;
                    let mut locals = Vec::with_capacity(local_count.min(100_000) as usize);
                    for _ in 0..local_count {
                        if offset >= body_end {
                            return Err(WasmError::UnexpectedEnd);
                        }
                        let n = read_leb128_u32(data, &mut offset)?;
                        let vt = read_value_type(data, &mut offset)?;
                        if offset > body_end {
                            return Err(WasmError::UnexpectedEnd);
                        }
                        locals.push((n, vt));
                    }

                    // Read code
                    if offset > body_end {
                        return Err(WasmError::UnexpectedEnd);
                    }
                    let code = data[offset..body_end].to_vec();
                    offset = body_end;

                    let type_idx = func_type_indices.get(i as usize).copied().unwrap_or(0);
                    module.functions.push(Function { type_idx, locals, code });
                }
            }
            section_id::DATA => {
                let count = read_leb128_u32(data, &mut offset)?;
                for _ in 0..count {
                    if offset >= section_end { break; }
                    let flags = read_leb128_u32(data, &mut offset)?;
                    let (memory_idx, offset_expr) = match flags {
                        0 => (0u32, read_init_expr(data, &mut offset, section_end)?),
                        1 => (0u32, Vec::new()),
                        2 => {
                            let memory_idx = read_leb128_u32(data, &mut offset)?;
                            (memory_idx, read_init_expr(data, &mut offset, section_end)?)
                        }
                        other => {
                            return Err(WasmError::Unsupported(format!("data segment flags {}", other)));
                        }
                    };
                    let data_len = read_leb128_u32(data, &mut offset)? as usize;
                    let seg_end = match offset.checked_add(data_len) {
                        Some(e) => e,
                        None => return Err(WasmError::UnexpectedEnd),
                    };
                    if seg_end > section_end {
                        return Err(WasmError::UnexpectedEnd);
                    }
                    let segment_data = data[offset..seg_end].to_vec();
                    offset = seg_end;
                    module.data.push(DataSegment {
                        memory_idx,
                        offset_expr,
                        data: segment_data,
                    });
                }
            }
            section_id::DATA_COUNT => {
                // Just skip, we already parse the data section
            }
            _ => {
                // Unknown section, skip
            }
        }

        // Ensure we're at section end
        offset = section_end;
    }

    Ok(module)
}

/// Check if data is a WASM module
pub fn is_wasm(data: &[u8]) -> bool {
    data.len() >= 8 && &data[0..4] == b"\x00asm"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_magic() {
        assert!(is_wasm(b"\x00asm\x01\x00\x00\x00"));
        assert!(!is_wasm(b"MZ\x90\x00"));
        assert!(!is_wasm(b"\x7fELF"));
    }

    #[test]
    fn test_value_type_roundtrip() {
        for vt in [ValueType::I32, ValueType::I64, ValueType::F32, ValueType::F64] {
            let b = vt.to_byte();
            assert_eq!(ValueType::from_byte(b), Some(vt));
        }
    }

    #[test]
    fn test_parse_minimal_wasm() {
        // Minimal valid WASM module: magic + version + empty type section
        let data = b"\x00asm\x01\x00\x00\x00\x01\x04\x01\x60\x00\x00";
        let module = parse_wasm(data).unwrap();
        assert_eq!(module.version, 1);
        assert_eq!(module.types.len(), 1);
        assert_eq!(module.types[0].params.len(), 0);
        assert_eq!(module.types[0].results.len(), 0);
    }

    #[test]
    fn test_invalid_magic() {
        let data = b"\x00Xsm\x01\x00\x00\x00";
        assert!(parse_wasm(data).is_err());
    }

    #[test]
    fn test_invalid_version() {
        let data = b"\x00asm\x02\x00\x00\x00";
        assert!(parse_wasm(data).is_err());
    }
}
