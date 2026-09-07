use std::{env, fs, path::PathBuf};

use pe_parser::PeFile;

const MAX_SEED_SIZE: u64 = 16 * 1024 * 1024;

fn seed(name: &'static str, mut data: Vec<u8>) -> (&'static str, Vec<u8>) {
    if data.len() >= 2 {
        data[0] = b'M';
        data[1] = b'Z';
    }
    (name, data)
}

fn malformed_seeds() -> Vec<(&'static str, Vec<u8>)> {
    let mut seeds = vec![
        seed("empty", Vec::new()),
        seed("mz-truncated", vec![0x4d, 0x5a, 0, 0]),
        seed("mz-offset-zero", vec![0x4d, 0x5a, 0, 0, 0, 0, 0, 0]),
        seed("pe-signature", vec![0x50, 0x45, 0, 0]),
        seed("mz-pe-at-zero", vec![0x4d, 0x5a, 0x50, 0x45, 0, 0]),
        seed("high-entropy-short", (0..=255).collect()),
    ];

    let mut oversized_offset = vec![0u8; 128];
    oversized_offset[0..2].copy_from_slice(b"MZ");
    oversized_offset[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
    seeds.push(("oversized-e_lfanew", oversized_offset));

    let mut truncated_nt = vec![0u8; 0x40 + 4];
    truncated_nt[0..2].copy_from_slice(b"MZ");
    truncated_nt[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    truncated_nt[0x40..0x44].copy_from_slice(b"PE\0\0");
    seeds.push(("truncated-nt-headers", truncated_nt));
    seeds
}

fn valid_pe_seed() -> (&'static str, Vec<u8>) {
    let mut data = vec![0u8; 2048];
    data[0..2].copy_from_slice(b"MZ");
    data[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    data[0x80..0x84].copy_from_slice(b"PE\0\0");
    data[0x84..0x86].copy_from_slice(&0x14Cu16.to_le_bytes());
    data[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    data[0x94..0x96].copy_from_slice(&224u16.to_le_bytes());
    data[0x98..0x9a].copy_from_slice(&0x10Bu16.to_le_bytes());
    data[0x98 + 92..0x98 + 96].copy_from_slice(&16u32.to_le_bytes());
    let section = 0x98 + 224;
    data[section..section + 5].copy_from_slice(b".text");
    data[section + 8..section + 12].copy_from_slice(&0x200u32.to_le_bytes());
    data[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    data[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
    data[section + 20..section + 24].copy_from_slice(&0x400u32.to_le_bytes());
    data[section + 36..section + 40].copy_from_slice(&0x60000020u32.to_le_bytes());
    data[0x400] = 0xC3;
    ("valid-minimal-pe32", data)
}

fn exercise_pe(data: &[u8]) {
    let Ok(pe) = PeFile::parse(data) else {
        return;
    };

    let _ = pe.rva_to_offset(0);
    let _ = pe.text_section_data();
    let _ = pe.import_directory();
    let _ = pe.iat_directory();
    let _ = pe.resource_directory();
    let _ = pe.tls_directory();
    let _ = pe.delay_import_directory();
    let _ = pe.bound_import_directory();
    let _ = pe.com_descriptor_directory();
    let _ = pe.debug_directory();
    let _ = pe.security_directory();
    let _ = pe.base_reloc_directory();
    let _ = pe.base_relocations();
    let _ = pe.runtime_functions();
    let _ = pe.relocation_count();
    let _ = pe.has_valid_relocs();
    let _ = pe.dll_characteristics_flags();
    let _ = pe.is_dotnet();
    let _ = pe.dotnet_info();
    let _ = pe.tls_callbacks();
    let _ = pe.delay_imports();
    let _ = pe.rich_header();
    let _ = pe.overlay_data();
    let _ = pe.exports();
    let _ = pe.export_names();
}

fn collect_file_seeds(paths: &[PathBuf]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut seeds = Vec::new();
    for path in paths {
        if !path.is_file() {
            continue;
        }
        let metadata = fs::metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
        if metadata.len() > MAX_SEED_SIZE {
            return Err(format!(
                "{} is larger than the {} MiB smoke limit",
                path.display(),
                MAX_SEED_SIZE / (1024 * 1024)
            ));
        }
        let data = fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
        seeds.push((path.display().to_string(), data));
    }
    Ok(seeds)
}

fn main() {
    let arguments: Vec<PathBuf> = env::args_os().skip(1).map(PathBuf::from).collect();
    let paths = if arguments.is_empty() {
        [
            PathBuf::from("corpus/seeds"),
            PathBuf::from("corpus/generated-pe"),
        ]
        .into_iter()
        .filter(|path| path.is_dir())
        .collect()
    } else {
        arguments
    };

    let mut seeds = collect_file_seeds(&paths).expect("failed to read smoke seed");
    if seeds.is_empty() {
        seeds = malformed_seeds()
            .into_iter()
            .map(|(name, data)| (name.to_owned(), data))
            .collect();
        let (name, data) = valid_pe_seed();
        seeds.push((name.to_owned(), data));
    }

    let mut parsed = 0;
    for (name, data) in &seeds {
        if PeFile::parse(data).is_ok() {
            parsed += 1;
            exercise_pe(data);
        }
        println!("smoke: {name} ({} bytes)", data.len());
    }
    println!("checked {} bounded PE seeds; exercised {} parsed inputs", seeds.len(), parsed);
}
