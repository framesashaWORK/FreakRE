//! SHA-1 implementation per FIPS 180-4.

use crate::Hasher;

pub struct Sha1 {
    h: [u32; 5],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Hasher for Sha1 {
    type Output = [u8; 20];

    fn new() -> Self {
        Self {
            h: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.total_len += data.len() as u64;
        let mut offset = 0;

        if self.buf_len > 0 {
            let space = 64 - self.buf_len;
            let take = data.len().min(space);
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            offset += take;
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }

        while offset + 64 <= data.len() {
            self.compress(&data[offset..offset + 64]);
            offset += 64;
        }

        let remaining = data.len() - offset;
        if remaining > 0 {
            self.buf[..remaining].copy_from_slice(&data[offset..]);
            self.buf_len = remaining;
        }
    }

    fn finalize(mut self) -> [u8; 20] {
        let bit_len = self.total_len * 8;
        self.update(&[0x80]);
        while self.buf_len != 56 {
            self.update(&[0x00]);
        }
        self.update(&bit_len.to_be_bytes());

        let mut out = [0u8; 20];
        for (i, &h) in self.h.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&h.to_be_bytes());
        }
        out
    }
}

impl Sha1 {
    #[inline]
    fn compress(&mut self, block: &[u8]) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let [mut a, mut b, mut c, mut d, mut e] = self.h;

        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
    }
}
