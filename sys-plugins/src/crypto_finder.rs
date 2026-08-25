//! # Crypto Constants Finder Plugin
//!
//! Scans binary code for known cryptographic constants (AES S-box, SHA-256 K,
//! MD5 init vectors, DES tables, CRC32 polynomials, etc.) and labels functions
//! that contain them.

use plugins::{Plugin, PluginContext, PluginMetadata, MenuItem};
use crate::util;

const CRYPTO_CONSTANTS: &[(&[u8], &str, &str)] = &[
    (&[0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
       0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76], "aes_sbox", "AES S-Box"),
    (&[0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
       0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB], "aes_inv_sbox", "AES Inv S-Box"),
    (&[0x6A, 0x09, 0xE6, 0x67, 0xBB, 0x67, 0xAE, 0x85,
       0x3C, 0x6E, 0xF3, 0x72, 0xA5, 0x4F, 0xF5, 0x3A], "sha256_h", "SHA-256 Init"),
    (&[0x42, 0x8A, 0x2F, 0x98, 0x71, 0x37, 0x44, 0x91,
       0xB5, 0xC0, 0xFB, 0xCF, 0xE9, 0xB5, 0xDB, 0xA5], "sha256_k", "SHA-256 K"),
    (&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
       0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10], "md5_init", "MD5 IV"),
    (&[0xED, 0xB8, 0x83, 0x20], "crc32_poly", "CRC32 Poly"),
    (&[0x0E, 0x04, 0x0D, 0x01, 0x02, 0x0F, 0x0B, 0x08,
       0x03, 0x0A, 0x06, 0x0C, 0x05, 0x09, 0x00, 0x07], "des_sbox1", "DES S-Box 1"),
    (&[0x78, 0xA4, 0x6D, 0x24, 0x13, 0x72, 0xAE, 0xD6,
       0x14, 0xB7, 0x4C, 0xCC, 0x99, 0x3B, 0xA1, 0x3D], "blowfish_p", "Blowfish P"),
    (&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
       0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F], "rc4_perm", "RC4 Init Perm"),
    (b"expand 32-byte k", "chacha20_const", "ChaCha20 Const"),
    (b"expand 16-byte k", "salsa20_const", "Salsa20 Const"),
    (&[0x70, 0x82, 0x2C, 0xEC, 0xB3, 0x27, 0xC0, 0xE5,
       0xE4, 0x85, 0x57, 0x35, 0xEA, 0x0C, 0xAE, 0x41], "camellia_sbox", "Camellia S-Box"),
    (&[0x18, 0x23, 0xC6, 0xE8, 0x87, 0xB8, 0x01, 0x4F,
       0x36, 0xA6, 0xD2, 0xF5, 0x79, 0x6F, 0x91, 0x52], "whirlpool_sbox", "Whirlpool S-Box"),
];

pub struct CryptoFinderPlugin;
impl Default for CryptoFinderPlugin { fn default() -> Self { Self } }

impl Plugin for CryptoFinderPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "Crypto Constants Finder".into(),
            version: "1.0.0".into(),
            author: Some("FreakRE Team".into()),
            description: "Scans for AES, SHA-256, MD5, DES, CRC32, Blowfish, RC4, ChaCha20 constants.".into(),
            license: Some("MIT".into()),
            homepage: None,
        }
    }
    fn menu_items(&self) -> Vec<MenuItem> {
        vec![MenuItem::new("Analyze/Crypto Constants", "Find Crypto Constants").with_shortcut("Ctrl+Shift+C")]
    }
    fn on_menu_item(&mut self, ctx: &mut PluginContext, path: &str) {
        if path == "Analyze/Crypto Constants" { self.analyze(ctx); }
    }
    fn analyze(&mut self, ctx: &mut PluginContext) {
        ctx.println("[CryptoFinder] Scanning for crypto constants...");
        let functions = match ctx.db.list_functions() {
            Ok(f) => f, Err(e) => { ctx.println(&format!("Error: {}", e)); return; }
        };
        let mut total = 0usize;
        for func in &functions {
            let code = match &func.code_bytes { Some(b) => b.as_slice(), None => continue };
            for (pattern, label, name) in CRYPTO_CONSTANTS {
                if code.len() < pattern.len() { continue; }
                for off in 0..=code.len() - pattern.len() {
                    if &code[off..off + pattern.len()] == *pattern {
                        let addr = func.address + off as u64;
                        // Never clobber: only auto-label free slots (empty or sub_ name).
                        util::set_label_if_free(
                            &mut ctx.db,
                            func.address,
                            format!("{} ({})", label, name),
                        );
                        // Append-style comment refresh; preserves user text.
                        util::upsert_tagged_comment(
                            &mut ctx.db,
                            addr,
                            "Crypto:",
                            &format!("Crypto: {} (+0x{:X})", name, off),
                        );
                        ctx.println(&format!("  ✓ {} at 0x{:X} in func 0x{:X}", name, addr, func.address));
                        total += 1;
                        break;
                    }
                }
            }
        }
        ctx.println(&format!("[CryptoFinder] Done. Found {} crypto refs in {} functions.", total, functions.len()));
    }
}
