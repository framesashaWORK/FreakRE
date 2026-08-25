//! freakre-hash: Audit-friendly cryptographic hash implementations.
//! Zero external dependencies, no_std compatible.

pub mod md5;
pub mod sha1;
pub mod sha256;
pub mod crc32;
pub mod murmur3;

/// Common trait for all hash implementations.
pub trait Hasher {
    type Output: AsRef<[u8]> + Clone;
    fn new() -> Self;
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> Self::Output;
}

// ── Convenience one-shot functions ───────────────────────────────

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = sha256::Sha256::new();
    h.update(data);
    h.finalize()
}

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = sha1::Sha1::new();
    h.update(data);
    h.finalize()
}

pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut h = md5::Md5::new();
    h.update(data);
    h.finalize()
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut h = crc32::Crc32::new();
    h.update(data);
    h.finalize()
}

pub fn murmur3_32(data: &[u8], seed: u32) -> u32 {
    murmur3::murmur3_32(data, seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"");
        assert_eq!(
            hex(&hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_abc() {
        let hash = sha256(b"abc");
        assert_eq!(
            hex(&hash),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_md5_empty() {
        let hash = md5(b"");
        assert_eq!(hex(&hash), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_md5_abc() {
        let hash = md5(b"abc");
        assert_eq!(hex(&hash), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn test_sha1_abc() {
        let hash = sha1(b"abc");
        assert_eq!(hex(&hash), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn test_crc32() {
        assert_eq!(crc32(b""), 0x00000000);
        assert_eq!(crc32(b"123456789"), 0xcbf43926);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
