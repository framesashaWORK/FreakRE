// build.rs — Probes for system libcapstone and emits `cfg(capstone_available)`.
// Hand-written FFI in `src/capstone_bindings.rs` is the single source of
// truth (no bindgen: faster builds, no libclang requirement, stable layout
// checked at runtime against the linked library).
//
// Strategy:
// 1. User-specified CAPSTONE_LIB_DIR / CAPSTONE_INCLUDE_DIR
// 2. pkg-config (Linux/macOS)
// 3. Common Windows paths (vcpkg, manual install)
// 4. Fallback: built-in LDE (x86/x64 only)

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CAPSTONE_LIB_DIR");
    println!("cargo:rerun-if-env-changed=CAPSTONE_INCLUDE_DIR");

    let mut found = false;

    // Strategy 1: User-specified paths
    if let Ok(lib_dir) = std::env::var("CAPSTONE_LIB_DIR") {
        println!("cargo:rustc-link-search=native={}", lib_dir);
        println!("cargo:rustc-link-lib=capstone");
        found = true;
    }

    // Strategy 2: pkg-config (non-Windows)
    #[cfg(not(target_os = "windows"))]
    if !found {
        if pkg_config::Config::new()
            .atleast_version("4.0")
            .probe("capstone")
            .is_ok()
        {
            found = true;
        }
    }

    // Strategy 3: Common Windows paths
    #[cfg(target_os = "windows")]
    if !found {
        let mut search_dirs: Vec<String> = Vec::new();
        if let Ok(v) = std::env::var("VCPKG_ROOT") {
            search_dirs.push(format!("{}\\installed\\x64-windows\\lib", v));
        }
        search_dirs.push("C:\\capstone\\lib".to_string());
        search_dirs.push("C:\\Program Files\\capstone\\lib".to_string());
        search_dirs.push("C:\\vcpkg\\installed\\x64-windows\\lib".to_string());

        for dir in &search_dirs {
            let lib_path = std::path::PathBuf::from(dir).join("capstone.lib");
            let dll_path = std::path::PathBuf::from(dir).join("capstone.dll");
            if lib_path.exists() || dll_path.exists() {
                println!("cargo:rustc-link-search=native={}", dir);
                println!("cargo:rustc-link-lib=capstone");
                found = true;
                break;
            }
        }
    }

    if found {
        println!("cargo:rustc-cfg=capstone_available");
    } else {
        eprintln!("cargo:warning=Capstone not found - LIMITED DISASSEMBLY MODE (built-in LDE, x86/x64 only)");
        eprintln!("cargo:warning=Install Capstone or set CAPSTONE_LIB_DIR for full multi-arch support");
    }
}
