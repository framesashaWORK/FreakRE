//! Shared helpers for system plugins.
//!
//! Every plugin annotation goes through these helpers so that automated
//! analysis never clobbers user-authored labels or comments:
//!
//! * Labels are only written into "free" slots (empty or the auto-generated
//!   `sub_<ADDR>` default).
//! * Comments are append-style: lines tagged with a plugin-specific marker
//!   (e.g. `[ENTROPY]`) are owned by the plugins and refreshed in place, but
//!   all other lines — user comments and other plugins' lines — are kept.

use project_db::ProjectDatabase;

/// True when the label slot is effectively unused and safe to auto-name:
/// empty, or still carrying the auto-generated `sub_<ADDR>` default name.
pub fn label_slot_free(existing: &str) -> bool {
    existing.is_empty() || existing.starts_with("sub_")
}

/// Query-then-set: writes `label` at `address` only when the slot is free
/// (empty or default `sub_` name). Returns `true` if the label was written.
pub fn set_label_if_free(db: &mut ProjectDatabase, address: u64, label: String) -> bool {
    let existing = db.get_label(address).ok().flatten().unwrap_or_default();
    if !label_slot_free(&existing) {
        return false;
    }
    db.set_label(address, label).is_ok()
}

/// Append-style comment update keyed by `tag` (e.g. `"[ENTROPY]"`).
///
/// Existing lines starting with `tag` are replaced by `line`; every other
/// line is preserved verbatim. Idempotent across re-runs: writing the same
/// tagged line twice leaves the comment unchanged.
pub fn upsert_tagged_comment(db: &mut ProjectDatabase, address: u64, tag: &str, line: &str) {
    let existing = db.get_comment(address).ok().flatten();
    let new_comment = match existing {
        None => line.to_string(),
        Some(text) => {
            // Drop stale lines owned by this tag, keep everything else.
            let mut kept: Vec<&str> = text
                .lines()
                .filter(|l| !l.trim_start().starts_with(tag))
                .collect();
            if !kept.iter().any(|&l| l.trim() == line) {
                kept.push(line);
            }
            kept.join("\n")
        }
    };
    let _ = db.set_comment(address, new_comment);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_db(name: &str) -> ProjectDatabase {
        let dir = std::env::temp_dir().join(format!(
            "freakre_sys_plugins_test_{}_{}",
            name,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        ProjectDatabase::create(
            &dir,
            PathBuf::from("test.bin"),
            "deadbeef".into(),
            "x86".into(),
            "pe".into(),
        )
        .expect("failed to create test db")
    }

    #[test]
    fn test_label_slot_free() {
        assert!(label_slot_free(""));
        assert!(label_slot_free("sub_140001000"));
        assert!(!label_slot_free("main"));
        assert!(!label_slot_free("thunk_140001000"));
    }

    #[test]
    fn test_set_label_if_free_never_clobbers_user_label() {
        let mut db = temp_db("label");
        db.set_label(0x1000, "my_func".into()).unwrap();

        let written = set_label_if_free(&mut db, 0x1000, "aes_sbox (AES S-Box)".into());
        assert!(!written);
        assert_eq!(db.get_label(0x1000).unwrap().unwrap(), "my_func");

        // Free slot gets written.
        assert!(set_label_if_free(&mut db, 0x2000, "sha256_h (SHA-256 Init)".into()));
        assert_eq!(db.get_label(0x2000).unwrap().unwrap(), "sha256_h (SHA-256 Init)");

        // Default sub_ name is treated as free.
        db.set_label(0x3000, "sub_3000".into()).unwrap();
        assert!(set_label_if_free(&mut db, 0x3000, "md5_init (MD5 IV)".into()));
        assert_eq!(db.get_label(0x3000).unwrap().unwrap(), "md5_init (MD5 IV)");
    }

    #[test]
    fn test_upsert_tagged_comment_preserves_user_text() {
        let mut db = temp_db("comment");
        db.set_comment(0x1000, "user note".into()).unwrap();

        upsert_tagged_comment(&mut db, 0x1000, "[ENTROPY]", "[ENTROPY] High entropy region");
        let c = db.get_comment(0x1000).unwrap().unwrap();
        assert!(c.contains("user note"));
        assert!(c.contains("[ENTROPY] High entropy region"));

        // Refreshing our own tag replaces only our line.
        upsert_tagged_comment(&mut db, 0x1000, "[ENTROPY]", "[ENTROPY] Low entropy/padding");
        let c = db.get_comment(0x1000).unwrap().unwrap();
        assert!(c.contains("user note"));
        assert!(!c.contains("High entropy"));
        assert!(c.contains("[ENTROPY] Low entropy/padding"));

        // Other plugins' tags are untouched.
        upsert_tagged_comment(&mut db, 0x1000, "[URL]", "[URL] String: \"http://x\"");
        let c = db.get_comment(0x1000).unwrap().unwrap();
        assert!(c.contains("[ENTROPY] Low entropy/padding"));
        assert!(c.contains("[URL] String: \"http://x\""));
        assert!(c.contains("user note"));
    }

    #[test]
    fn test_upsert_tagged_comment_idempotent_and_creates() {
        let mut db = temp_db("idem");
        // Creates when slot empty.
        upsert_tagged_comment(&mut db, 0x42, "[class:", "[class: leaf]");
        assert_eq!(db.get_comment(0x42).unwrap().unwrap(), "[class: leaf]");
        // Same line again → unchanged (no duplication).
        upsert_tagged_comment(&mut db, 0x42, "[class:", "[class: leaf]");
        assert_eq!(db.get_comment(0x42).unwrap().unwrap(), "[class: leaf]");
    }
}
