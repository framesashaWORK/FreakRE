#![no_main]

use libfuzzer_sys::fuzz_target;
use std::path::PathBuf;

fuzz_target!(|data: &[u8]| {
    // Fuzz project-db deserialization — untrusted bytes must never panic.
    //
    // Primary path: bincode-deserialize FunctionEntry from raw bytes (this is
    // what happens when loading records from an on-disk sled database).
    if let Ok(func) = project_db::decode_function_entry(data) {
        // Round-trip a successfully decoded entry through a temporary sled DB
        // to also exercise serialize/store/load paths with hostile values.
        let db_path: PathBuf =
            std::env::temp_dir().join(format!("freakre_fuzzdb_{}", std::process::id()));

        if let Ok(mut db) = project_db::ProjectDatabase::create(
            &db_path,
            PathBuf::from("fuzz_target"),
            String::new(),
            "x86_64".to_string(),
            "raw".to_string(),
        ) {
            let _ = db.add_function(func.clone());
            let _ = db.get_function(func.address);
            let _ = db.list_functions();
            let _ = db.flush();
            drop(db);
        }

        // Cleanup of the temporary per-process database directory
        let _ = std::fs::remove_dir_all(&db_path);
    }
});
