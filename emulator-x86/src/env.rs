//! Environment hooks: guest memory-mapped I/O and syscall stubbing.

/// Records one guest syscall handled by the environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallRecord {
    pub number: Option<i64>,
    pub args: Vec<u64>,
    pub result: i64,
}

/// Environment contract for the emulator.
///
/// All methods have defaults so an analysis only overrides what it needs:
///
/// - [`EmuEnv::mem_read`]: return `Some(bytes)` to service a guest load
///   externally (device memory, shadow pages). `None` falls through to the
///   emulator's internal sparse memory, which reads zeros when unmapped.
/// - [`EmuEnv::mem_write`]: observe guest stores (I/O trace). Stores are
///   always also committed to internal memory.
/// - [`EmuEnv::syscall`]: handle a `SYSCALL` IR instruction; the returned
///   value lands in RAX. The default logs and returns 0.
pub trait EmuEnv {
    fn mem_read(&mut self, _addr: u64, _size: u32) -> Option<Vec<u8>> {
        None
    }

    fn mem_write(&mut self, _addr: u64, _data: &[u8]) {}

    fn syscall(&mut self, _number: Option<i64>, _args: &[u64]) -> i64 {
        0
    }
}

/// Do-nothing / logging environment for pure-computation payloads
/// (unpacker stubs, XOR decoders).
///
/// Reads fall through to internal memory (zeros when unmapped), writes are
/// tracked by the emulator's memory model, syscalls are logged with result 0.
#[derive(Debug, Clone, Default)]
pub struct DefaultEnv {
    pub syscalls: Vec<SyscallRecord>,
    pub external_writes: Vec<(u64, usize)>,
}

impl DefaultEnv {
    pub fn new() -> Self {
        Self::default()
    }
}

impl EmuEnv for DefaultEnv {
    fn mem_write(&mut self, addr: u64, data: &[u8]) {
        self.external_writes.push((addr, data.len()));
    }

    fn syscall(&mut self, number: Option<i64>, args: &[u64]) -> i64 {
        let rec = SyscallRecord {
            number,
            args: args.to_vec(),
            result: 0,
        };
        self.syscalls.push(rec);
        0
    }
}
