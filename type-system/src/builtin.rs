//! Built-in types for Windows, POSIX, and common libraries

use crate::{TypeDatabase, TypedefDef, EnumDef, StructBuilder, Type};

/// Register all built-in types
pub fn register_all(db: &mut TypeDatabase) {
    register_windows_types(db);
    register_posix_types(db);
    register_common_structs(db);
}

/// Windows-specific types
fn register_windows_types(db: &mut TypeDatabase) {
    // Basic Windows types
    let _ = db.add_typedef(TypedefDef::new("BYTE", Type::u8()));
    let _ = db.add_typedef(TypedefDef::new("WORD", Type::u16()));
    let _ = db.add_typedef(TypedefDef::new("DWORD", Type::u32()));
    let _ = db.add_typedef(TypedefDef::new("QWORD", Type::u64()));
    let _ = db.add_typedef(TypedefDef::new("BOOL", Type::i32()));
    let _ = db.add_typedef(TypedefDef::new("CHAR", Type::char()));
    let _ = db.add_typedef(TypedefDef::new("WCHAR", Type::u16()));
    let _ = db.add_typedef(TypedefDef::new("INT", Type::i32()));
    let _ = db.add_typedef(TypedefDef::new("UINT", Type::u32()));
    let _ = db.add_typedef(TypedefDef::new("LONG", Type::i32()));
    let _ = db.add_typedef(TypedefDef::new("ULONG", Type::u32()));
    let _ = db.add_typedef(TypedefDef::new("LONGLONG", Type::i64()));
    let _ = db.add_typedef(TypedefDef::new("ULONGLONG", Type::u64()));
    let _ = db.add_typedef(TypedefDef::new("FLOAT", Type::f32()));
    let _ = db.add_typedef(TypedefDef::new("DOUBLE", Type::f64()));

    // Pointer types (64-bit)
    let _ = db.add_typedef(TypedefDef::new("HANDLE", Type::pointer(Type::void())));
    let _ = db.add_typedef(TypedefDef::new("HWND", Type::pointer(Type::void())));
    let _ = db.add_typedef(TypedefDef::new("HMODULE", Type::pointer(Type::void())));
    let _ = db.add_typedef(TypedefDef::new("HINSTANCE", Type::pointer(Type::void())));
    let _ = db.add_typedef(TypedefDef::new("HKEY", Type::pointer(Type::void())));
    let _ = db.add_typedef(TypedefDef::new("HDC", Type::pointer(Type::void())));
    let _ = db.add_typedef(TypedefDef::new("HBITMAP", Type::pointer(Type::void())));
    let _ = db.add_typedef(TypedefDef::new("HICON", Type::pointer(Type::void())));
    let _ = db.add_typedef(TypedefDef::new("HCURSOR", Type::pointer(Type::void())));
    let _ = db.add_typedef(TypedefDef::new("HMENU", Type::pointer(Type::void())));

    // String types
    let _ = db.add_typedef(TypedefDef::new("LPSTR", Type::pointer(Type::char())));
    let _ = db.add_typedef(TypedefDef::new("LPCSTR", Type::pointer(Type::char())));
    let _ = db.add_typedef(TypedefDef::new("LPWSTR", Type::pointer(Type::u16())));
    let _ = db.add_typedef(TypedefDef::new("LPCWSTR", Type::pointer(Type::u16())));
    let _ = db.add_typedef(TypedefDef::new("LPTSTR", Type::pointer(Type::char())));
    let _ = db.add_typedef(TypedefDef::new("LPCTSTR", Type::pointer(Type::char())));

    // Pointer-sized integers
    let _ = db.add_typedef(TypedefDef::new("SIZE_T", Type::u64()));
    let _ = db.add_typedef(TypedefDef::new("SSIZE_T", Type::i64()));
    let _ = db.add_typedef(TypedefDef::new("UINT_PTR", Type::u64()));
    let _ = db.add_typedef(TypedefDef::new("INT_PTR", Type::i64()));
    let _ = db.add_typedef(TypedefDef::new("ULONG_PTR", Type::u64()));
    let _ = db.add_typedef(TypedefDef::new("LONG_PTR", Type::i64()));
    let _ = db.add_typedef(TypedefDef::new("DWORD_PTR", Type::u64()));

    // Common enumerations
    let mut error_codes = EnumDef::new("ERROR_CODE", Type::u32());
    error_codes.add_variant("ERROR_SUCCESS", 0);
    error_codes.add_variant("ERROR_INVALID_FUNCTION", 1);
    error_codes.add_variant("ERROR_FILE_NOT_FOUND", 2);
    error_codes.add_variant("ERROR_PATH_NOT_FOUND", 3);
    error_codes.add_variant("ERROR_ACCESS_DENIED", 5);
    error_codes.add_variant("ERROR_INVALID_HANDLE", 6);
    error_codes.add_variant("ERROR_NOT_ENOUGH_MEMORY", 8);
    error_codes.add_variant("ERROR_INVALID_PARAMETER", 87);
    let _ = db.add_enum(error_codes);
}

/// POSIX-specific types
fn register_posix_types(db: &mut TypeDatabase) {
    let _ = db.add_typedef(TypedefDef::new("pid_t", Type::i32()));
    let _ = db.add_typedef(TypedefDef::new("uid_t", Type::u32()));
    let _ = db.add_typedef(TypedefDef::new("gid_t", Type::u32()));
    let _ = db.add_typedef(TypedefDef::new("size_t", Type::u64()));
    let _ = db.add_typedef(TypedefDef::new("ssize_t", Type::i64()));
    let _ = db.add_typedef(TypedefDef::new("off_t", Type::i64()));
    let _ = db.add_typedef(TypedefDef::new("time_t", Type::i64()));
    let _ = db.add_typedef(TypedefDef::new("mode_t", Type::u32()));
    let _ = db.add_typedef(TypedefDef::new("dev_t", Type::u64()));
    let _ = db.add_typedef(TypedefDef::new("ino_t", Type::u64()));
    let _ = db.add_typedef(TypedefDef::new("nlink_t", Type::u64()));
    let _ = db.add_typedef(TypedefDef::new("blksize_t", Type::i64()));
    let _ = db.add_typedef(TypedefDef::new("blkcnt_t", Type::i64()));

    // Errno values
    let mut errno = EnumDef::new("errno_t", Type::i32());
    errno.add_variant("EPERM", 1);
    errno.add_variant("ENOENT", 2);
    errno.add_variant("ESRCH", 3);
    errno.add_variant("EINTR", 4);
    errno.add_variant("EIO", 5);
    errno.add_variant("ENXIO", 6);
    errno.add_variant("E2BIG", 7);
    errno.add_variant("ENOEXEC", 8);
    errno.add_variant("EBADF", 9);
    errno.add_variant("ECHILD", 10);
    errno.add_variant("EAGAIN", 11);
    errno.add_variant("ENOMEM", 12);
    errno.add_variant("EACCES", 13);
    errno.add_variant("EFAULT", 14);
    let _ = db.add_enum(errno);
}

/// Common structures
fn register_common_structs(db: &mut TypeDatabase) {
    // Windows POINT
    let point = StructBuilder::new("POINT")
        .add_field("x", Type::i32())
        .add_field("y", Type::i32())
        .build();
    let _ = db.add_struct(point);

    // Windows RECT
    let rect = StructBuilder::new("RECT")
        .add_field("left", Type::i32())
        .add_field("top", Type::i32())
        .add_field("right", Type::i32())
        .add_field("bottom", Type::i32())
        .build();
    let _ = db.add_struct(rect);

    // Windows SIZE
    let size = StructBuilder::new("SIZE")
        .add_field("cx", Type::i32())
        .add_field("cy", Type::i32())
        .build();
    let _ = db.add_struct(size);

    // Windows FILETIME
    let filetime = StructBuilder::new("FILETIME")
        .add_field("dwLowDateTime", Type::u32())
        .add_field("dwHighDateTime", Type::u32())
        .build();
    let _ = db.add_struct(filetime);

    // Windows SYSTEMTIME
    let systime = StructBuilder::new("SYSTEMTIME")
        .add_field("wYear", Type::u16())
        .add_field("wMonth", Type::u16())
        .add_field("wDayOfWeek", Type::u16())
        .add_field("wDay", Type::u16())
        .add_field("wHour", Type::u16())
        .add_field("wMinute", Type::u16())
        .add_field("wSecond", Type::u16())
        .add_field("wMilliseconds", Type::u16())
        .build();
    let _ = db.add_struct(systime);

    // Windows GUID
    let guid = StructBuilder::new("GUID")
        .add_field("Data1", Type::u32())
        .add_field("Data2", Type::u16())
        .add_field("Data3", Type::u16())
        .add_field("Data4", Type::array(Type::u8(), 8))
        .build();
    let _ = db.add_struct(guid);
}
