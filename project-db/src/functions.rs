use crate::types::Type;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub enum FunctionType {
    #[default]
    Normal,
    Thunk,       // Jump table entry
    Trampoline,  // Import thunk
    Library,     // Recognized standard library function
    UserDefined, // Manually created by user
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub enum AnalysisStatus {
    #[default]
    NotAnalyzed,
    Analyzing,
    Analyzed,
    Failed(String),
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct FunctionEntry {
    pub address: u64,
    pub name: String,
    pub size: usize,
    pub function_type: FunctionType,
    pub analysis_status: AnalysisStatus,

    // Function signature
    pub return_type: Option<Type>,
    pub parameters: Vec<FunctionParameter>,
    pub local_variables: Vec<LocalVariable>,

    // Analysis results
    pub stack_frame_size: Option<i64>,
    pub has_return: bool,
    pub is_variadic: bool,

    // Decompiled code
    pub decompiled_code: Option<String>,

    // Raw function bytes (for plugin analysis)
    #[serde(default)]
    pub code_bytes: Option<Vec<u8>>,

    // Metadata
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub modified_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FunctionParameter {
    pub name: String,
    pub param_type: Type,
    pub location: ParameterLocation,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ParameterLocation {
    Register(String),
    Stack(i64), // offset from frame pointer
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LocalVariable {
    pub name: String,
    pub var_type: Type,
    pub location: VariableLocation,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum VariableLocation {
    Stack(i64), // offset from frame pointer
    Register(String),
    Unknown,
}

impl FunctionEntry {
    pub fn new(address: u64, name: String, size: usize) -> Self {
        let now = chrono::Utc::now();
        Self {
            address,
            name,
            size,
            function_type: FunctionType::Normal,
            analysis_status: AnalysisStatus::NotAnalyzed,
            return_type: None,
            parameters: Vec::new(),
            local_variables: Vec::new(),
            stack_frame_size: None,
            has_return: false,
            is_variadic: false,
            decompiled_code: None,
            code_bytes: None,
            created_at: now,
            modified_at: now,
        }
    }

    pub fn with_signature(mut self, return_type: Type, parameters: Vec<FunctionParameter>) -> Self {
        self.return_type = Some(return_type);
        self.parameters = parameters;
        self
    }

    pub fn add_parameter(&mut self, param: FunctionParameter) {
        self.parameters.push(param);
    }

    pub fn add_local_variable(&mut self, var: LocalVariable) {
        self.local_variables.push(var);
    }

    pub fn set_decompiled_code(&mut self, code: String) {
        self.decompiled_code = Some(code);
        self.modified_at = chrono::Utc::now();
    }

    pub fn mark_analyzed(&mut self) {
        self.analysis_status = AnalysisStatus::Analyzed;
        self.modified_at = chrono::Utc::now();
    }

    pub fn mark_failed(&mut self, error: String) {
        self.analysis_status = AnalysisStatus::Failed(error);
        self.modified_at = chrono::Utc::now();
    }

    pub fn signature_string(&self, type_db: &crate::TypeDatabase) -> String {
        let return_ty = self
            .return_type
            .as_ref()
            .map(|t| t.display(type_db))
            .unwrap_or_else(|| "void".to_string());

        let params: Vec<String> = self
            .parameters
            .iter()
            .map(|p| format!("{} {}", p.param_type.display(type_db), p.name))
            .collect();

        format!("{} {}({})", return_ty, self.name, params.join(", "))
    }

    pub fn end_address(&self) -> u64 {
        self.address + self.size as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PrimitiveType, Type};

    #[test]
    fn test_function_creation() {
        let func = FunctionEntry::new(0x1000, "main".to_string(), 100);
        assert_eq!(func.address, 0x1000);
        assert_eq!(func.name, "main");
        assert_eq!(func.size, 100);
        assert_eq!(func.end_address(), 0x1064);
    }

    #[test]
    fn test_function_with_signature() {
        let func = FunctionEntry::new(0x1000, "add".to_string(), 50).with_signature(
            Type::Primitive(PrimitiveType::I32),
            vec![
                FunctionParameter {
                    name: "a".to_string(),
                    param_type: Type::Primitive(PrimitiveType::I32),
                    location: ParameterLocation::Unknown,
                },
                FunctionParameter {
                    name: "b".to_string(),
                    param_type: Type::Primitive(PrimitiveType::I32),
                    location: ParameterLocation::Unknown,
                },
            ],
        );

        assert_eq!(func.parameters.len(), 2);
        assert!(func.return_type.is_some());
    }

    #[test]
    fn test_bincode_roundtrip() {
        let func = FunctionEntry::new(0x401000, "x".to_string(), 10);
        let bytes = bincode::serialize(&func).unwrap();
        let back: FunctionEntry = bincode::deserialize(&bytes).unwrap_or_else(|e| {
            panic!(
                "roundtrip failed: {} (bytes: {:?})",
                e,
                &bytes[..bytes.len().min(48)]
            )
        });
        assert_eq!(back.address, 0x401000);
    }
}
