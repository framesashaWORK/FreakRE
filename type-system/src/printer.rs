//! Type printer for C-like syntax

use crate::{Type, TypeDatabase, Result};

/// Print a type in C-like syntax.
///
/// Without a name the result is an abstract declarator, e.g. a pointer to
/// an array prints as `uint32_t (*)[3]` and an array of arrays as
/// `uint32_t[2][3]`.
pub fn print_type(db: &TypeDatabase, ty: &Type) -> String {
    format_declaration(db, ty, "")
}

/// Build a C declaration for `ty` around the declarator `decl`
/// (a variable name for definitions, "" for abstract declarators).
///
/// Handles pointer/array precedence correctly:
/// - pointer to array:  `uint32_t (*x)[3]`
/// - array of arrays:   `uint32_t x[2][3]`
fn format_declaration(db: &TypeDatabase, ty: &Type, decl: &str) -> String {
    match ty {
        Type::Pointer(inner) => {
            let star_decl = format!("*{}", decl);
            // '*' binds tighter than a following '[]'/'()' suffix, so a
            // pointer to an array/function needs parentheses.
            let owned = match inner.as_ref() {
                Type::Array(_, _) | Type::Function(_) => format!("({})", star_decl),
                _ => star_decl,
            };
            format_declaration(db, inner, &owned)
        }
        Type::Array(inner, len) => {
            let indexed = format!("{}[{}]", decl, len);
            format_declaration(db, inner, &indexed)
        }
        Type::Function(func) => {
            let params: Vec<String> = func.parameters.iter().map(|p| print_type(db, p)).collect();
            let params_str = if params.is_empty() {
                "void".to_string()
            } else {
                params.join(", ")
            };
            let variadic = if func.variadic { ", ..." } else { "" };
            // A bare function type denotes a function pointer in this crate.
            let decl = if decl.is_empty() { "(*)" } else { decl };
            let with_params = format!("{}({}{})", decl, params_str, variadic);
            format_declaration(db, &func.return_type, &with_params)
        }
        other => combine(print_simple_type(db, other), decl),
    }
}

/// Attach a declarator to a base type string with conventional spacing.
fn combine(base: String, decl: &str) -> String {
    if decl.is_empty() {
        return base;
    }
    let stars = decl.len() - decl.trim_start_matches('*').len();
    if stars > 0 {
        let rest = &decl[stars..];
        if rest.is_empty() {
            return format!("{}{}", base, &decl[..stars]);
        }
        return format!("{}{} {}", base, &decl[..stars], rest);
    }
    if decl.starts_with('[') {
        // Abstract array declarator stays glued to the base type.
        return format!("{}{}", base, decl);
    }
    format!("{} {}", base, decl)
}

/// Print a non-compound type (base of a declaration).
fn print_simple_type(db: &TypeDatabase, ty: &Type) -> String {
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
        Type::Struct(name) => format!("struct {}", name),
        Type::Union(name) => format!("union {}", name),
        Type::Enum(name) => format!("enum {}", name),
        Type::Typedef(name) => name.clone(),
        Type::Unknown => "unknown".to_string(),
        // Compound types are handled by format_declaration before this is
        // reached; route them back defensively instead of mis-printing.
        _ => format_declaration(db, ty, ""),
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
        // Declarator-based rendering keeps arrays/pointers valid:
        // `uint32_t data[3]`, `uint32_t x[2][3]`, `uint32_t (*rows)[3]`.
        let mut line = format!("    {}", format_declaration(db, &field.ty, &field.name));

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

    #[test]
    fn test_print_pointer_to_array() {
        let db = TypeDatabase::new();

        // Abstract form (cast style).
        let ty = Type::pointer(Type::array(Type::u32(), 3));
        assert_eq!(print_type(&db, &ty), "uint32_t (*)[3]");

        // Named field form.
        let s = StructBuilder::new("Grid")
            .add_field("rows", Type::pointer(Type::array(Type::u32(), 3)))
            .build();
        let output = print_struct_def(&db, &s).unwrap();
        assert!(output.contains("uint32_t (*rows)[3];"), "got:\n{}", output);
    }

    #[test]
    fn test_print_array_of_arrays() {
        let db = TypeDatabase::new();

        // Array(Array(u32, 3), 2) == two rows of three uint32_t.
        let ty = Type::array(Type::array(Type::u32(), 3), 2);
        assert_eq!(print_type(&db, &ty), "uint32_t[2][3]");

        let s = StructBuilder::new("Matrix")
            .add_field("matrix", Type::array(Type::array(Type::u32(), 3), 2))
            .build();
        let output = print_struct_def(&db, &s).unwrap();
        assert!(output.contains("uint32_t matrix[2][3];"), "got:\n{}", output);
    }

    #[test]
    fn test_print_nested_pointer_to_array() {
        let db = TypeDatabase::new();

        // ptr -> ptr -> array of 3
        let ty = Type::pointer(Type::pointer(Type::array(Type::u32(), 3)));
        assert_eq!(print_type(&db, &ty), "uint32_t (**)[3]");
    }

    #[test]
    fn test_print_pointer_and_function_still_valid() {
        let db = TypeDatabase::new();

        assert_eq!(print_type(&db, &Type::pointer(Type::i32())), "int32_t*");
        assert_eq!(
            print_type(&db, &Type::pointer(Type::pointer(Type::i32()))),
            "int32_t**"
        );

        let func = crate::FunctionType::new(Type::i32(), vec![Type::u8()]);
        assert_eq!(
            print_type(&db, &Type::Function(func.clone())),
            "int32_t (*)(uint8_t)"
        );
        assert_eq!(
            print_type(&db, &Type::pointer(Type::Function(func))),
            "int32_t (*)(uint8_t)"
        );
    }
}
