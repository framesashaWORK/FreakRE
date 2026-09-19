use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: pyc-decompile <file.c>");
        std::process::exit(1);
    }

    let path = &args[1];
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to read file: {}", e);
            std::process::exit(1);
        }
    };

    let report = match pyc_parser::analyze_python(&data) {
        Some(r) => r,
        None => {
            eprintln!("Not a Python bytecode file (.pyc)");
            std::process::exit(1);
        }
    };

    println!("=== Python Bytecode Analysis ===");
    println!("Kind: {:?}", report.kind);
    if let Some(version) = report.python_version {
        println!("Python Version: {}", version);
    }
    if let Some(path) = report.source_path {
        println!("Source path: {}", path);
    }

    println!("\n=== Strings Found ===");
    for s in report.suspicious_strings.iter().take(10) {
        println!("  \"{}\"", s);
    }

    println!("\n=== Imports ===");
    for imp in report.imports.iter().take(15) {
        println!("  {}", imp);
    }

    println!("\n=== High-Risk Imports ===");
    for imp in report.high_risk_imports.iter() {
        println!("  [!] {}", imp);
    }
}
