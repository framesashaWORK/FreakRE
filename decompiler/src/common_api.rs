//! Well-known C runtime / platform API signatures.
//!
//! A small built-in database of common library functions (libc, Win32 CRT,
//! a few POSIX) used to (a) keep recovered call sites recognisable and (b)
//! provide parameter counts and types when the printing pipeline is extended
//! to carry signature information per `Stmt::Call`.
//!
//! This is intentionally dependency-free and lives inside the decompiler
//! crate so it can be seeded into [`crate::call_naming::SignatureMap`] via
//! [`crate::call_naming::SignatureMap::from_common_runtime`].

use freakre_ir::Ty;

/// A lightweight library function signature.
#[derive(Debug, Clone)]
pub struct ApiSignature {
    /// Return type.
    pub return_type: Ty,
    /// (name, type) pairs for the parameters.
    pub params: Vec<(String, Ty)>,
}

fn ptr_void() -> Ty {
    Ty::Ptr(Box::new(Ty::Void))
}

fn ptr_u8() -> Ty {
    Ty::Ptr(Box::new(Ty::u8()))
}

/// Look up a built-in signature by exact function name.
pub fn lookup_common_api(name: &str) -> Option<ApiSignature> {
    let sig = match name {
        // ─── libc memory / string ──────────────────────────────────────
        "memcpy" => ApiSignature {
            return_type: ptr_void(),
            params: vec![
                ("dst".into(), ptr_void()),
                ("src".into(), ptr_void()),
                ("n".into(), Ty::u64()),
            ],
        },
        "memmove" => ApiSignature {
            return_type: ptr_void(),
            params: vec![
                ("dst".into(), ptr_void()),
                ("src".into(), ptr_void()),
                ("n".into(), Ty::u64()),
            ],
        },
        "memset" => ApiSignature {
            return_type: ptr_void(),
            params: vec![
                ("dst".into(), ptr_void()),
                ("c".into(), Ty::i32()),
                ("n".into(), Ty::u64()),
            ],
        },
        "memcmp" => ApiSignature {
            return_type: Ty::i32(),
            params: vec![
                ("a".into(), ptr_void()),
                ("b".into(), ptr_void()),
                ("n".into(), Ty::u64()),
            ],
        },
        "strlen" => ApiSignature {
            return_type: Ty::u64(),
            params: vec![("s".into(), ptr_u8())],
        },
        "strcpy" | "strncpy" => ApiSignature {
            return_type: ptr_u8(),
            params: vec![("dst".into(), ptr_u8()), ("src".into(), ptr_u8())],
        },
        "strcmp" | "strncmp" => ApiSignature {
            return_type: Ty::i32(),
            params: vec![("a".into(), ptr_u8()), ("b".into(), ptr_u8())],
        },
        // ─── libc stdio ─────────────────────────────────────────────────
        "printf" => ApiSignature {
            return_type: Ty::i32(),
            params: vec![("fmt".into(), ptr_u8())],
        },
        "sprintf" => ApiSignature {
            return_type: Ty::i32(),
            params: vec![("buf".into(), ptr_u8()), ("fmt".into(), ptr_u8())],
        },
        "fprintf" => ApiSignature {
            return_type: Ty::i32(),
            params: vec![("stream".into(), ptr_void()), ("fmt".into(), ptr_u8())],
        },
        // ─── libc stdlib ────────────────────────────────────────────────
        "malloc" => ApiSignature {
            return_type: ptr_void(),
            params: vec![("size".into(), Ty::u64())],
        },
        "calloc" => ApiSignature {
            return_type: ptr_void(),
            params: vec![("nmemb".into(), Ty::u64()), ("size".into(), Ty::u64())],
        },
        "realloc" => ApiSignature {
            return_type: ptr_void(),
            params: vec![("ptr".into(), ptr_void()), ("size".into(), Ty::u64())],
        },
        "free" => ApiSignature {
            return_type: Ty::Void,
            params: vec![("ptr".into(), ptr_void())],
        },
        "exit" => ApiSignature {
            return_type: Ty::Void,
            params: vec![("code".into(), Ty::i32())],
        },
        "atoi" => ApiSignature {
            return_type: Ty::i32(),
            params: vec![("s".into(), ptr_u8())],
        },
        // ─── Win32 CRT / API (common) ───────────────────────────────────
        "GetProcAddress" => ApiSignature {
            return_type: ptr_void(),
            params: vec![("hmod".into(), ptr_void()), ("name".into(), ptr_u8())],
        },
        "LoadLibraryA" | "LoadLibraryW" => ApiSignature {
            return_type: ptr_void(),
            params: vec![("name".into(), ptr_u8())],
        },
        "VirtualAlloc" => ApiSignature {
            return_type: ptr_void(),
            params: vec![
                ("addr".into(), ptr_void()),
                ("size".into(), Ty::u64()),
                ("ty".into(), Ty::u32()),
                ("prot".into(), Ty::u32()),
            ],
        },
        _ => return None,
    };
    Some(sig)
}

/// Exact names present in [`lookup_common_api`], as a const list so it can be
/// seeded into a [`crate::call_naming::SignatureMap`] cheaply.
pub const COMMON_API_NAMES: &[&str] = &[
    "memcpy",
    "memmove",
    "memset",
    "memcmp",
    "strlen",
    "strcpy",
    "strncpy",
    "strcmp",
    "strncmp",
    "printf",
    "sprintf",
    "fprintf",
    "malloc",
    "calloc",
    "realloc",
    "free",
    "exit",
    "atoi",
    "GetProcAddress",
    "LoadLibraryA",
    "LoadLibraryW",
    "VirtualAlloc",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_apis_resolve() {
        assert!(lookup_common_api("memcpy").is_some());
        assert!(lookup_common_api("printf").is_some());
        assert!(lookup_common_api("VirtualAlloc").is_some());
        assert_eq!(lookup_common_api("memcpy").unwrap().params.len(), 3);
        assert!(lookup_common_api("not_a_real_fn").is_none());
    }

    #[test]
    fn names_list_covers_lookup() {
        for &name in COMMON_API_NAMES {
            assert!(
                lookup_common_api(name).is_some(),
                "missing entry for {name}"
            );
        }
    }
}
