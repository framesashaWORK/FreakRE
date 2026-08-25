//! CRC32 implementation (ISO 3309 / ITU-T V.42). Polynomial 0xEDB88320.

const TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut crc = i;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i as usize] = crc;
        i += 1;
    }
    table
};

pub struct Crc32 {
    state: u32,
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32 {
    pub fn new() -> Self {
        Self { state: 0xFFFFFFFF }
    }

    pub fn update(&mut self, data: &[u8]) {
        for &byte in data {
            let index = ((self.state ^ byte as u32) & 0xFF) as usize;
            self.state = (self.state >> 8) ^ TABLE[index];
        }
    }

    pub fn finalize(self) -> u32 {
        self.state ^ 0xFFFFFFFF
    }
}

/// One-shot CRC32.
pub fn crc32(data: &[u8]) -> u32 {
    let mut h = Crc32::new();
    h.update(data);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_known_vectors() {
        assert_eq!(crc32(b""), 0x00000000);
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
        assert_eq!(crc32(b"The quick brown fox jumps over the lazy dog"), 0x414FA339);
    }
}
