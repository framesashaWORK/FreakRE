//! Type layout calculations (size, alignment, field offsets)

use crate::database::{Result, TypeError};
use crate::{Type, TypeDatabase};

/// Calculate the size of a type in bytes
pub fn size_of(db: &TypeDatabase, ty: &Type) -> Result<usize> {
    size_of_inner(db, ty, 0)
}

fn size_of_inner(db: &TypeDatabase, ty: &Type, depth: usize) -> Result<usize> {
    const MAX_LAYOUT_DEPTH: usize = 64;
    if depth > MAX_LAYOUT_DEPTH {
        return Err(TypeError::CircularReference(format!(
            "size_of exceeded max depth {}: possible circular struct/union",
            MAX_LAYOUT_DEPTH
        )));
    }

    match ty {
        Type::Void => Ok(0),
        Type::Bool => Ok(1),
        Type::Char => Ok(1),
        Type::Int { bits, .. } => Ok((*bits as usize).div_ceil(8)),
        Type::Float { bits } => Ok((*bits as usize).div_ceil(8)),
        Type::Pointer(_) => Ok(8), // Assume 64-bit pointers
        Type::Array(inner, len) => {
            let elem_size = size_of_inner(db, inner, depth + 1)?;
            elem_size.checked_mul(*len).ok_or_else(|| {
                TypeError::Invalid(format!(
                    "array size overflow: {} elements x {} bytes",
                    len, elem_size
                ))
            })
        }
        Type::Struct(name) => {
            if let Some(s) = db.get_struct(name) {
                let mut offset = 0;
                for field in &s.fields {
                    let field_size = size_of_inner(db, &field.ty, depth + 1)?;
                    let align = align_of_inner(db, &field.ty, depth + 1)?;
                    if !s.packed {
                        offset = align_up(offset, align);
                    }
                    offset += field_size;
                }
                if !s.packed {
                    let total_align = align_of_inner(db, ty, depth + 1)?;
                    offset = align_up(offset, total_align);
                }
                Ok(offset)
            } else {
                Err(TypeError::NotFound(name.clone()))
            }
        }
        Type::Union(name) => {
            if let Some(u) = db.get_union(name) {
                let mut max_size = 0;
                for field in &u.fields {
                    let field_size = size_of_inner(db, &field.ty, depth + 1)?;
                    max_size = max_size.max(field_size);
                }
                let total_align = align_of_inner(db, ty, depth + 1)?;
                Ok(align_up(max_size, total_align))
            } else {
                Err(TypeError::NotFound(name.clone()))
            }
        }
        Type::Enum(name) => {
            if let Some(e) = db.get_enum(name) {
                size_of_inner(db, &e.base_type, depth + 1)
            } else {
                Err(TypeError::NotFound(name.clone()))
            }
        }
        Type::Typedef(name) => {
            if let Some(td) = db.get_typedef(name) {
                size_of_inner(db, &td.base_type, depth + 1)
            } else {
                Err(TypeError::NotFound(name.clone()))
            }
        }
        Type::Function(_) => Ok(8), // Function pointers are pointer-sized
        Type::Unknown => Err(TypeError::Invalid(
            "Cannot calculate size of unknown type".into(),
        )),
    }
}

/// Calculate the alignment of a type
pub fn align_of(db: &TypeDatabase, ty: &Type) -> Result<usize> {
    align_of_inner(db, ty, 0)
}

fn align_of_inner(db: &TypeDatabase, ty: &Type, depth: usize) -> Result<usize> {
    const MAX_LAYOUT_DEPTH: usize = 64;
    if depth > MAX_LAYOUT_DEPTH {
        return Err(TypeError::CircularReference(format!(
            "align_of exceeded max depth {}: possible circular struct/union",
            MAX_LAYOUT_DEPTH
        )));
    }

    match ty {
        Type::Void => Ok(1),
        Type::Bool => Ok(1),
        Type::Char => Ok(1),
        Type::Int { bits, .. } => Ok((*bits as usize).div_ceil(8)),
        Type::Float { bits } => Ok((*bits as usize).div_ceil(8)),
        Type::Pointer(_) => Ok(8),
        Type::Array(inner, _) => align_of_inner(db, inner, depth + 1),
        Type::Struct(name) => {
            if let Some(s) = db.get_struct(name) {
                if s.packed {
                    Ok(1)
                } else {
                    let mut max_align = 1;
                    for field in &s.fields {
                        let field_align = align_of_inner(db, &field.ty, depth + 1)?;
                        max_align = max_align.max(field_align);
                    }
                    Ok(max_align)
                }
            } else {
                Err(TypeError::NotFound(name.clone()))
            }
        }
        Type::Union(name) => {
            if let Some(u) = db.get_union(name) {
                let mut max_align = 1;
                for field in &u.fields {
                    let field_align = align_of_inner(db, &field.ty, depth + 1)?;
                    max_align = max_align.max(field_align);
                }
                Ok(max_align)
            } else {
                Err(TypeError::NotFound(name.clone()))
            }
        }
        Type::Enum(name) => {
            if let Some(e) = db.get_enum(name) {
                align_of_inner(db, &e.base_type, depth + 1)
            } else {
                Err(TypeError::NotFound(name.clone()))
            }
        }
        Type::Typedef(name) => {
            if let Some(td) = db.get_typedef(name) {
                align_of_inner(db, &td.base_type, depth + 1)
            } else {
                Err(TypeError::NotFound(name.clone()))
            }
        }
        Type::Function(_) => Ok(8),
        Type::Unknown => Err(TypeError::Invalid(
            "Cannot calculate alignment of unknown type".into(),
        )),
    }
}

/// Align an offset up to the given alignment
fn align_up(offset: usize, align: usize) -> usize {
    if align == 0 {
        offset
    } else {
        (offset + align - 1) & !(align - 1)
    }
}

/// Calculate field offsets for a struct
pub fn calculate_field_offsets(
    db: &TypeDatabase,
    struct_name: &str,
) -> Result<Vec<(String, usize, usize)>> {
    let s = db
        .get_struct(struct_name)
        .ok_or_else(|| TypeError::NotFound(struct_name.to_string()))?;

    let mut result = Vec::new();
    let mut offset = 0;

    for field in &s.fields {
        let field_size = size_of(db, &field.ty)?;
        let field_align = align_of(db, &field.ty)?;

        if !s.packed {
            offset = align_up(offset, field_align);
        }

        result.push((field.name.clone(), offset, field_size));
        offset += field_size;
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StructBuilder;

    #[test]
    fn test_primitive_sizes() {
        let db = TypeDatabase::new();
        assert_eq!(size_of(&db, &Type::u8()).unwrap(), 1);
        assert_eq!(size_of(&db, &Type::u16()).unwrap(), 2);
        assert_eq!(size_of(&db, &Type::u32()).unwrap(), 4);
        assert_eq!(size_of(&db, &Type::u64()).unwrap(), 8);
    }

    #[test]
    fn test_struct_size() {
        let mut db = TypeDatabase::new();
        let s = StructBuilder::new("Point")
            .add_field("x", Type::i32())
            .add_field("y", Type::i32())
            .build();
        db.add_struct(s).unwrap();

        assert_eq!(size_of(&db, &Type::struct_type("Point")).unwrap(), 8);
    }

    #[test]
    fn test_struct_alignment() {
        let mut db = TypeDatabase::new();
        let s = StructBuilder::new("Mixed")
            .add_field("a", Type::u8())
            .add_field("b", Type::u32())
            .add_field("c", Type::u8())
            .build();
        db.add_struct(s).unwrap();

        // Should be 12 bytes due to alignment padding
        assert_eq!(size_of(&db, &Type::struct_type("Mixed")).unwrap(), 12);
    }

    #[test]
    fn test_array_size() {
        let db = TypeDatabase::new();
        let arr = Type::array(Type::i32(), 10);
        assert_eq!(size_of(&db, &arr).unwrap(), 40);
    }

    #[test]
    fn test_array_size_overflow_returns_error() {
        let db = TypeDatabase::new();

        // 2-byte elements * usize::MAX overflows on any platform.
        let arr = Type::array(Type::u16(), usize::MAX);
        match size_of(&db, &arr) {
            Err(TypeError::Invalid(msg)) => assert!(msg.contains("overflow")),
            other => panic!("expected Invalid overflow error, got {:?}", other),
        }

        // Nested overflow must also be caught.
        let nested = Type::array(Type::array(Type::u8(), usize::MAX), usize::MAX);
        assert!(size_of(&db, &nested).is_err());
    }
}
