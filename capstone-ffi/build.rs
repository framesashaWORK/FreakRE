// build.rs — Finds Capstone and generates safe FFI bindings via bindgen.
//
// Strategy:
// 1. User-specified CAPSTONE_LIB_DIR / CAPSTONE_INCLUDE_DIR
// 2. pkg-config (Linux/macOS)
// 3. Common Windows paths (vcpkg, manual install)
// 4. Fallback: built-in LDE (x86/x64 only, limited)
//
// When Capstone is found, bindgen generates type-safe bindings automatically.
// No hand-written #[repr(C)] structs needed.

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CAPSTONE_LIB_DIR");
    println!("cargo:rerun-if-env-changed=CAPSTONE_INCLUDE_DIR");

    let mut include_dir: Option<PathBuf> = None;
    let mut found = false;

    // Strategy 1: User-specified paths
    if let Ok(lib_dir) = std::env::var("CAPSTONE_LIB_DIR") {
        println!("cargo:rustc-link-search=native={}", lib_dir);
        println!("cargo:rustc-link-lib=capstone");
        if let Ok(inc_dir) = std::env::var("CAPSTONE_INCLUDE_DIR") {
            include_dir = Some(PathBuf::from(&inc_dir));
        }
        found = true;
    }

    // Strategy 2: pkg-config (non-Windows)
    #[cfg(not(target_os = "windows"))]
    if !found {
        if let Ok(lib) = pkg_config::Config::new()
            .atleast_version("4.0")
            .probe("capstone")
        {
            if let Some(path) = lib.include_paths.first() {
                include_dir = Some(path.clone());
            }
            found = true;
        }
    }

    // Strategy 3: Common Windows paths
    #[cfg(target_os = "windows")]
    if !found {
        let search_dirs = [
            std::env::var("CAPSTONE_LIB_DIR").ok(),
            Some("C:\\capstone\\lib".to_string()),
            Some("C:\\Program Files\\capstone\\lib".to_string()),
            std::env::var("VCPKG_ROOT").ok().map(|v| format!("{}\\installed\\x64-windows\\lib", v)),
        ];

        for dir in search_dirs.iter().filter_map(|d| d.as_ref()) {
            let lib_path = PathBuf::from(dir).join("capstone.lib");
            let dll_path = PathBuf::from(dir).join("capstone.dll");
            if lib_path.exists() || dll_path.exists() {
                println!("cargo:rustc-link-search=native={}", dir);
                println!("cargo:rustc-link-lib=capstone");
                // Include dir is typically ../include relative to lib
                let inc = PathBuf::from(dir).parent().map(|p| p.join("include"));
                if let Some(ref inc_path) = inc {
                    if inc_path.exists() {
                        include_dir = Some(inc_path.clone());
                    }
                }
                found = true;
                break;
            }
        }
    }

    if found {
        println!("cargo:rustc-cfg=capstone_available");

        // Generate bindings via bindgen if include dir is available
        if let Some(ref inc_dir) = include_dir {
            let header = inc_dir.join("capstone").join("capstone.h");
            if header.exists() {
                let out_path = PathBuf::from(std::env::var("OUT_DIR").unwrap());
                let bindings = bindgen::Builder::default()
                    .header(header.to_str().unwrap())
                    .allowlist_function("cs_.*")
                    .allowlist_type("cs_.*")
                    .allowlist_type("csh")
                    .allowlist_var("CS_.*")
                    .derive_debug(true)
                    .derive_default(true)
                    .generate()
                    .expect("Failed to generate Capstone bindings via bindgen");

                bindings
                    .write_to_file(out_path.join("bindings.rs"))
                    .expect("Failed to write generated bindings");

                println!("cargo:rustc-cfg=capstone_bindgen");
                eprintln!("cargo:warning=Generated Capstone bindings via bindgen");
            } else {
                eprintln!("cargo:warning=capstone.h not found at {:?}, using manual FFI", header);
            }
        }
    } else {
        eprintln!("cargo:warning=⚠️  Capstone not found — LIMITED DISASSEMBLY MODE (built-in LDE, x86/x64 only)");
        eprintln!("cargo:warning=Install Capstone or set CAPSTONE_LIB_DIR for full multi-arch support");
    }
}
