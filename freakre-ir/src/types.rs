//! IR type system — defines the types used in IR values and operations.

use serde::{Deserialize, Serialize};

/// IR type descriptor.
///
/// All values in the IR have an associated type. This is essential for
/// type propagation analysis and correct IR semantics.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Ty {
    /// Boolean (1-bit).
    Bool,
    /// Unsigned integer of N bits (1..=128).
    UInt(u32),
    /// Signed integer of N bits (1..=128).
    Int(u32),
    /// IEEE 754 floating-point (32 or 64 bit).
    Float(u32),
    /// Pointer to an address space (with pointed-to type).
    Ptr(Box<Ty>),
    /// Array of N elements of a given type.
    Array(u32, Box<Ty>),
    /// Structure with named fields.
    Struct(Vec<(String, Ty)>),
    /// Unknown / unresolved type (for type inference).
    Unknown,
    /// Void — no value (used for function returns and side-effects).
    Void,
}

impl Ty {
    /// Size of this type in bits, or None if unknown / variable.
    pub fn size_bits(&self) -> Option<u32> {
        match self {
            Ty::Bool => Some(1),
            Ty::UInt(n) | Ty::Int(n) | Ty::Float(n) => Some(*n),
            Ty::Ptr(_) => Some(64), // Assume 64-bit pointers
            Ty::Array(n, inner) => inner.size_bits().map(|s| s * n),
            Ty::Struct(fields) => {
                let mut total = 0u32;
                for (_, ty) in fields {
                    total += ty.size_bits()?;
                }
                Some(total)
            }
            Ty::Unknown | Ty::Void => None,
        }
    }

    /// Size of this type in bytes, rounded up.
    pub fn size_bytes(&self) -> Option<u32> {
        self.size_bits().map(|b| b.div_ceil(8))
    }

    /// Whether this is an integer type (signed or unsigned).
    pub fn is_integer(&self) -> bool {
        matches!(self, Ty::UInt(_) | Ty::Int(_))
    }

    /// Whether this is a floating-point type.
    pub fn is_float(&self) -> bool {
        matches!(self, Ty::Float(_))
    }

    /// Whether this type is a pointer.
    pub fn is_pointer(&self) -> bool {
        matches!(self, Ty::Ptr(_))
    }

    /// Whether this is a signed integer type.
    pub fn is_signed(&self) -> bool {
        matches!(self, Ty::Int(_))
    }

    /// Common type widths for machine code analysis.
    pub fn i8() -> Self { Ty::Int(8) }
    pub fn i16() -> Self { Ty::Int(16) }
    pub fn i32() -> Self { Ty::Int(32) }
    pub fn i64() -> Self { Ty::Int(64) }
    pub fn u8() -> Self { Ty::UInt(8) }
    pub fn u16() -> Self { Ty::UInt(16) }
    pub fn u32() -> Self { Ty::UInt(32) }
    pub fn u64() -> Self { Ty::UInt(64) }
    pub fn f32() -> Self { Ty::Float(32) }
    pub fn f64() -> Self { Ty::Float(64) }
    pub fn ptr() -> Self { Ty::Ptr(Box::new(Ty::UInt(8))) }

    /// Widen / narrow this integer type to a new bit width.
    pub fn resize(&self, new_bits: u32) -> Self {
        match self {
            Ty::Int(_) => Ty::Int(new_bits),
            Ty::UInt(_) => Ty::UInt(new_bits),
            other => other.clone(),
        }
    }
}

impl std::fmt::Display for Ty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ty::Bool => write!(f, "bool"),
            Ty::UInt(n) => write!(f, "u{}", n),
            Ty::Int(n) => write!(f, "i{}", n),
            Ty::Float(n) => write!(f, "f{}", n),
            Ty::Ptr(inner) => write!(f, "ptr<{}>", inner),
            Ty::Array(n, inner) => write!(f, "[{} x {}]", n, inner),
            Ty::Struct(fields) => {
                write!(f, "{{")?;
                for (i, (name, ty)) in fields.iter().enumerate() {
                    if i > 0 { write!(f, ", ")?; }
                    write!(f, "{}: {}", name, ty)?;
                }
                write!(f, "}}")
            }
            Ty::Unknown => write!(f, "?"),
            Ty::Void => write!(f, "void"),
        }
    }
}

impl PartialOrd for Ty {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Ty {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering::*;
        match (self, other) {
            (Ty::Bool, Ty::Bool) => Equal,
            (Ty::Bool, _) => Less,
            (_, Ty::Bool) => Greater,
            (Ty::UInt(a), Ty::UInt(b)) => a.cmp(b),
            (Ty::UInt(_), _) => Less,
            (_, Ty::UInt(_)) => Greater,
            (Ty::Int(a), Ty::Int(b)) => a.cmp(b),
            (Ty::Int(_), _) => Less,
            (_, Ty::Int(_)) => Greater,
            (Ty::Float(a), Ty::Float(b)) => a.cmp(b),
            (Ty::Float(_), _) => Less,
            (_, Ty::Float(_)) => Greater,
            (Ty::Ptr(a), Ty::Ptr(b)) => a.cmp(b),
            (Ty::Ptr(_), _) => Less,
            (_, Ty::Ptr(_)) => Greater,
            (Ty::Array(a, ba), Ty::Array(b, bb)) => a.cmp(b).then(ba.cmp(bb)),
            (Ty::Array(..), _) => Less,
            (_, Ty::Array(..)) => Greater,
            (Ty::Struct(a), Ty::Struct(b)) => a.cmp(b),
            (Ty::Struct(..), _) => Less,
            (_, Ty::Struct(..)) => Greater,
            (Ty::Unknown, Ty::Unknown) => Equal,
            (Ty::Unknown, _) => Less,
            (_, Ty::Unknown) => Greater,
            (Ty::Void, Ty::Void) => Equal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_bits() {
        assert_eq!(Ty::Bool.size_bits(), Some(1));
        assert_eq!(Ty::i32().size_bits(), Some(32));
        assert_eq!(Ty::i64().size_bits(), Some(64));
        assert_eq!(Ty::Ptr(Box::new(Ty::u8())).size_bits(), Some(64));
    }

    #[test]
    fn test_size_bytes() {
        assert_eq!(Ty::i8().size_bytes(), Some(1));
        assert_eq!(Ty::i32().size_bytes(), Some(4));
        assert_eq!(Ty::i64().size_bytes(), Some(8));
    }

    #[test]
    fn test_type_queries() {
        assert!(Ty::i32().is_integer());
        assert!(Ty::u64().is_integer());
        assert!(!Ty::Bool.is_integer());
        assert!(Ty::f64().is_float());
        assert!(Ty::ptr().is_pointer());
        assert!(Ty::i32().is_signed());
        assert!(!Ty::u32().is_signed());
    }

    #[test]
    fn test_resize() {
        assert_eq!(Ty::i32().resize(64), Ty::i64());
        assert_eq!(Ty::u32().resize(8), Ty::u8());
    }
}
