// build.rs — Attempts to find and link Capstone disassembly engine.
//
// Strategy:
// 1. Try pkg-config first (system-installed libcapstone)
// 2. If not found, set CAPSTONE_AVAILABLE=false and rely on fallback LDE
//
// When CAPSTONE_AVAILABLE is set, the `capstone` feature is activated and
// raw FFI bindings in `capstone_bindings.rs` become available.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CAPSTONE_LIB_DIR");
    println!("cargo:rerun-if-env-changed=CAPSTONE_INCLUDE_DIR");

    // Strategy 1: User-specified paths
    if let Ok(lib_dir) = std::env::var("CAPSTONE_LIB_DIR") {
        println!("cargo:rustc-link-search=native={}", lib_dir);
        println!("cargo:rustc-link-lib=capstone");
        println!("cargo:rustc-cfg=capstone_available");
        if let Ok(inc_dir) = std::env::var("CAPSTONE_INCLUDE_DIR") {
            println!("cargo:include={}", inc_dir);
        }
        return;
    }

    // Strategy 2: pkg-config
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(lib) = pkg_config::Config::new()
            .atleast_version("4.0")
            .probe("capstone")
        {
            println!("cargo:rustc-cfg=capstone_available");
            for path in &lib.include_paths {
                println!("cargo:include={}", path.display());
            }
            return;
        }
    }

    // Strategy 3: Try common Windows paths for Capstone
    #[cfg(target_os = "windows")]
    {
        // Check common installation directories for capstone.lib
        let search_dirs = [
            std::env::var("CAPSTONE_LIB_DIR").ok(),
            Some("C:\\capstone\\lib".to_string()),
            Some("C:\\Program Files\\capstone\\lib".to_string()),
            std::env::var("VCPKG_ROOT").ok().map(|v| format!("{}\\installed\\x64-windows\\lib", v)),
        ];

        for dir in search_dirs.iter().filter_map(|d| d.as_ref()) {
            let lib_path = std::path::Path::new(dir).join("capstone.lib");
            let dll_path = std::path::Path::new(dir).join("capstone.dll");
            if lib_path.exists() || dll_path.exists() {
                println!("cargo:rustc-link-search=native={}", dir);
                println!("cargo:rustc-link-lib=capstone");
                println!("cargo:rustc-cfg=capstone_available");
                return;
            }
        }

        // Capstone not found on Windows — fall through to LDE fallback
        eprintln!("cargo:warning=Capstone not found on Windows — using built-in LDE for x86/x64 only");
        eprintln!("cargo:warning=Set CAPSTONE_LIB_DIR to enable multi-arch disassembly");
    }

    // Fallback: Capstone not available, will use built-in LDE
    eprintln!("cargo:warning=Capstone not found — using built-in LDE for x86/x64 only");
    eprintln!("cargo:warning=Set CAPSTONE_LIB_DIR and CAPSTONE_INCLUDE_DIR for multi-arch support");
}
