//! Sparse paged guest memory with written-region tracking.

use std::collections::{BTreeMap, HashMap};

/// Page size for the sparse memory backing store.
pub const PAGE_SIZE: usize = 4096;

/// Outcome of a guest memory write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemStatus {
    /// Write committed.
    Ok,
    /// Allocating pages for this write would exceed the memory budget.
    /// Bytes in already-allocated pages may have been committed.
    OutOfBudget,
}

impl MemStatus {
    /// Map onto the executor's budget taxonomy.
    ///
    /// Returns `None` for a successful write (no budget was consumed beyond
    /// the limit) instead of panicking — the old `unreachable!` arm was a
    /// public-API footgun.
    pub fn budget_kind(self) -> Option<crate::exec::BudgetKind> {
        match self {
            MemStatus::Ok => None,
            MemStatus::OutOfBudget => Some(crate::exec::BudgetKind::Memory),
        }
    }
}

/// A contiguous region of memory that received at least one guest store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemRegion {
    pub start: u64,
    pub len: u64,
}

impl std::fmt::Display for MemRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[0x{:X}..0x{:X}) ({} B)",
            self.start,
            self.start + self.len,
            self.len
        )
    }
}

/// Sparse little-endian guest memory backed by 4 KiB pages.
///
/// Untouched memory reads as zeros. Every successful write is folded into
/// a merged interval list so [`Memory::written_regions`] can summarise
/// where the guest has been storing data (unpacker payload dumps, etc.).
#[derive(Debug, Clone)]
pub struct Memory {
    pages: HashMap<u64, Box<[u8; PAGE_SIZE]>>,
    max_pages: usize,
    regions: BTreeMap<u64, u64>, // start (inclusive) -> end (exclusive)
}

impl Memory {
    /// Create memory whose runtime page allocations are capped at
    /// `max_bytes` (rounded down to whole pages).
    pub fn new(max_bytes: u64) -> Self {
        let max_pages = (max_bytes / PAGE_SIZE as u64).min(usize::MAX as u64) as usize;
        Memory {
            pages: HashMap::new(),
            max_pages,
            regions: BTreeMap::new(),
        }
    }

    /// Seed memory with a caller-provided image.
    ///
    /// Image pages bypass the runtime budget (they are caller-provided)
    /// but still count towards [`Memory::usage_bytes`].
    pub fn load_image(&mut self, base: u64, data: &[u8]) {
        self.forced_write(base, data);
    }

    fn ensure_page_runtime(&mut self, key: u64) -> Option<()> {
        if !self.pages.contains_key(&key) {
            if self.pages.len() >= self.max_pages {
                return None;
            }
            self.pages.insert(key, Box::new([0u8; PAGE_SIZE]));
        }
        Some(())
    }

    fn ensure_page_forced(&mut self, key: u64) {
        self.pages
            .entry(key)
            .or_insert_with(|| Box::new([0u8; PAGE_SIZE]));
    }

    fn write_inner(&mut self, addr: u64, data: &[u8]) -> MemStatus {
        for (i, byte) in data.iter().enumerate() {
            let a = addr.wrapping_add(i as u64);
            let key = a / PAGE_SIZE as u64;
            if self.ensure_page_runtime(key).is_none() {
                return MemStatus::OutOfBudget;
            }
            let off = (a % PAGE_SIZE as u64) as usize;
            self.pages.get_mut(&key).unwrap()[off] = *byte;
        }
        if !data.is_empty() {
            self.note_region(addr, addr.wrapping_add(data.len() as u64));
        }
        MemStatus::Ok
    }

    fn forced_write(&mut self, addr: u64, data: &[u8]) {
        for (i, byte) in data.iter().enumerate() {
            let a = addr.wrapping_add(i as u64);
            let key = a / PAGE_SIZE as u64;
            self.ensure_page_forced(key);
            let off = (a % PAGE_SIZE as u64) as usize;
            self.pages.get_mut(&key).unwrap()[off] = *byte;
        }
        if !data.is_empty() {
            self.note_region(addr, addr.wrapping_add(data.len() as u64));
        }
    }

    /// Guest store. Honours the memory budget.
    pub fn write_bytes(&mut self, addr: u64, data: &[u8]) -> MemStatus {
        self.write_inner(addr, data)
    }

    /// Read `out.len()` bytes little-endian-friendly (zeros when unmapped).
    pub fn read_bytes(&self, addr: u64, out: &mut [u8]) {
        for (i, slot) in out.iter_mut().enumerate() {
            let a = addr.wrapping_add(i as u64);
            let key = a / PAGE_SIZE as u64;
            *slot = match self.pages.get(&key) {
                Some(p) => p[(a % PAGE_SIZE as u64) as usize],
                None => 0,
            };
        }
    }

    /// Read up to 8 bytes as a little-endian integer (zeros when unmapped).
    pub fn read_le(&self, addr: u64, size: u32) -> u64 {
        let size = (size as usize).min(8);
        let mut buf = [0u8; 8];
        self.read_bytes(addr, &mut buf[..size]);
        u64::from_le_bytes(buf)
    }

    /// Total bytes currently resident in pages.
    pub fn usage_bytes(&self) -> u64 {
        self.pages.len() as u64 * PAGE_SIZE as u64
    }

    /// Number of allocated pages.
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    /// Merged summary of every region ever successfully written.
    pub fn written_regions(&self) -> Vec<MemRegion> {
        self.regions
            .iter()
            .map(|(&s, &e)| MemRegion {
                start: s,
                len: e - s,
            })
            .collect()
    }

    fn note_region(&mut self, start: u64, end: u64) {
        if end < start {
            // Wrapping write (e.g., rsp near 0) — treat as two regions or ignore the wrap part
            // For now, just handle the non-wrapping prefix and suffix separately
            self.note_region(start, u64::MAX);
            if end > 0 {
                self.note_region(0, end);
            }
            return;
        }
        let mut s = start;
        let mut e = end;
        if let Some((&k, &v)) = self.regions.range(..=s).next_back() {
            if v >= s {
                s = k;
                e = e.max(v);
            }
        }
        while let Some((&k, &v)) = self.regions.range(..=e).next_back() {
            if v < s {
                break;
            }
            self.regions.remove(&k);
            s = s.min(k);
            e = e.max(v);
        }
        self.regions.insert(s, e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_fill_and_roundtrip() {
        let mut m = Memory::new(1 << 20);
        assert_eq!(m.read_le(0xDEAD_0000, 8), 0);
        m.write_bytes(0x1000, &[1, 2, 3, 4, 5, 6, 7, 8]).assert_ok();
        assert_eq!(m.read_le(0x1000, 8), 0x0807_0605_0403_0201);
        assert_eq!(m.read_le(0x1004, 4), 0x0807_0605);
    }

    #[test]
    fn cross_page_write() {
        let mut m = Memory::new(1 << 20);
        let a = 0x1FF8;
        m.write_bytes(a, &[0xAA; 16]).assert_ok();
        let mut buf = [0u8; 16];
        m.read_bytes(a, &mut buf);
        assert!(buf.iter().all(|&b| b == 0xAA));
        assert_eq!(m.page_count(), 2);
    }

    #[test]
    fn budget_enforced() {
        let mut m = Memory::new(PAGE_SIZE as u64);
        assert_eq!(m.write_bytes(0x0, &[1; 8]), MemStatus::Ok);
        assert_eq!(
            m.write_bytes(PAGE_SIZE as u64 * 10, &[2; 8]),
            MemStatus::OutOfBudget
        );
    }

    #[test]
    fn regions_merge() {
        let mut m = Memory::new(1 << 20);
        m.write_bytes(0x100, &[0; 4]).assert_ok();
        m.write_bytes(0x104, &[0; 4]).assert_ok();
        m.write_bytes(0x120, &[0; 8]).assert_ok();
        m.write_bytes(0xF0, &[0; 8]).assert_ok();
        let rs = m.written_regions();
        assert_eq!(
            rs,
            vec![
                MemRegion {
                    start: 0xF0,
                    len: 8
                },
                MemRegion {
                    start: 0x100,
                    len: 8
                },
                MemRegion {
                    start: 0x120,
                    len: 8
                },
            ]
        );
    }

    #[test]
    fn image_bypasses_budget_but_counts_usage() {
        let mut m = Memory::new(0);
        m.load_image(0x400000, &[0x90; 16]);
        assert_eq!(m.usage_bytes(), PAGE_SIZE as u64);
        assert_eq!(m.write_bytes(0x800000, &[1]), MemStatus::OutOfBudget);
    }

    trait AssertOk {
        fn assert_ok(&self);
    }
    impl AssertOk for MemStatus {
        fn assert_ok(&self) {
            assert_eq!(*self, MemStatus::Ok);
        }
    }
}
