//! Type printer for C-like syntax

use crate::{Type, TypeDatabase, Result};

/// Print a type in C-like syntax
pub fn print_type(db: &TypeDatabase, ty: &Type) -> String {
    match ty {
        Type::Void => "void".to_string(),
        Type::Bool => "bool".to_string(),
        Type::Char => "char".to_string(),
        Type::Int { bits, signed } => match (bits, signed) {
            (8, true) => "int8_t".to_string(),
            (8, false) => "uint8_t".to_string(),
            (16, true) => "int16_t".to_string(),
            (16, false) => "uint16_t".to_string(),
            (32, true) => "int32_t".to_string(),
            (32, false) => "uint32_t".to_string(),
            (64, true) => "int64_t".to_string(),
            (64, false) => "uint64_t".to_string(),
            _ => format!("{}{}", if *signed { "int" } else { "uint" }, bits),
        },
        Type::Float { bits } => match bits {
            32 => "float".to_string(),
            64 => "double".to_string(),
            _ => format!("float{}", bits),
        },
        Type::Pointer(inner) => format!("{}*", print_type(db, inner)),
        Type::Array(inner, len) => format!("{}[{}]", print_type(db, inner), len),
        Type::Struct(name) => format!("struct {}", name),
        Type::Union(name) => format!("union {}", name),
        Type::Enum(name) => format!("enum {}", name),
        Type::Typedef(name) => name.clone(),
        Type::Function(func) => {
            let params: Vec<String> = func.parameters.iter().map(|p| print_type(db, p)).collect();
            let params_str = if params.is_empty() {
                "void".to_string()
            } else {
                params.join(", ")
            };
            let variadic = if func.variadic { ", ..." } else { "" };
            format!("{}(*)({}{})", print_type(db, &func.return_type), params_str, variadic)
        }
        Type::Unknown => "unknown".to_string(),
    }
}

/// Print a struct definition in C-like syntax
pub fn print_struct_def(db: &TypeDatabase, struct_def: &crate::StructDef) -> Result<String> {
    let mut lines = Vec::new();

    if let Some(comment) = &struct_def.comment {
        lines.push(format!("/* {} */", comment));
    }

    lines.push(format!("struct {} {{", struct_def.name));

    for field in &struct_def.fields {
        let type_str = print_type(db, &field.ty);
        let mut line = format!("    {} {}", type_str, field.name);

        // Check if it's an array
        if let Type::Array(_, len) = &field.ty {
            line = format!("    {} {}[{}]", print_type(db, field.ty.pointee().unwrap_or(&Type::Unknown)), field.name, len);
        }

        if let Some(comment) = &field.comment {
            line.push_str(&format!("; /* {} */", comment));
        } else {
            line.push(';');
        }

        lines.push(line);
    }

    lines.push("};".to_string());

    Ok(lines.join("\n"))
}

/// Print an enum definition in C-like syntax
pub fn print_enum_def(_db: &TypeDatabase, enum_def: &crate::EnumDef) -> Result<String> {
    let mut lines = Vec::new();

    if let Some(comment) = &enum_def.comment {
        lines.push(format!("/* {} */", comment));
    }

    lines.push(format!("enum {} {{", enum_def.name));

    for (i, variant) in enum_def.variants.iter().enumerate() {
        let mut line = format!("    {} = {}", variant.name, variant.value);

        if let Some(comment) = &variant.comment {
            line.push_str(&format!(", /* {} */", comment));
        } else if i < enum_def.variants.len() - 1 {
            line.push(',');
        }

        lines.push(line);
    }

    lines.push("};".to_string());

    Ok(lines.join("\n"))
}

/// Print a typedef in C-like syntax
pub fn print_typedef_def(db: &TypeDatabase, typedef_def: &crate::TypedefDef) -> Result<String> {
    let base_str = print_type(db, &typedef_def.base_type);
    Ok(format!("typedef {} {};", base_str, typedef_def.name))
}

/// Print a function signature
pub fn print_function_signature(
    db: &TypeDatabase,
    name: &str,
    func_type: &crate::FunctionType,
) -> String {
    let ret = print_type(db, &func_type.return_type);
    let params: Vec<String> = func_type.parameters.iter().map(|p| print_type(db, p)).collect();
    let params_str = if params.is_empty() {
        "void".to_string()
    } else {
        params.join(", ")
    };
    let variadic = if func_type.variadic { ", ..." } else { "" };

    format!("{} {}({}{})", ret, name, params_str, variadic)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StructBuilder;

    #[test]
    fn test_print_primitive() {
        let db = TypeDatabase::new();
        assert_eq!(print_type(&db, &Type::i32()), "int32_t");
        assert_eq!(print_type(&db, &Type::u64()), "uint64_t");
        assert_eq!(print_type(&db, &Type::f64()), "double");
    }

    #[test]
    fn test_print_pointer() {
        let db = TypeDatabase::new();
        let ptr = Type::pointer(Type::i32());
        assert_eq!(print_type(&db, &ptr), "int32_t*");
    }

    #[test]
    fn test_print_array() {
        let db = TypeDatabase::new();
        let arr = Type::array(Type::u8(), 10);
        assert_eq!(print_type(&db, &arr), "uint8_t[10]");
    }

    #[test]
    fn test_print_struct_def() {
        let db = TypeDatabase::new();
        let s = StructBuilder::new("Point")
            .add_field("x", Type::i32())
            .add_field("y", Type::i32())
            .build();

        let output = print_struct_def(&db, &s).unwrap();
        assert!(output.contains("struct Point {"));
        assert!(output.contains("int32_t x;"));
        assert!(output.contains("int32_t y;"));
    }
}
