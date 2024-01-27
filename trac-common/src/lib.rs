#![no_std]

#![allow(non_camel_case_types)]

pub enum RSSMember {
    MM_FILEPAGES,	/* Resident file mapping pages */
	MM_ANONPAGES,	/* Resident anonymous pages */
	MM_SWAPENTS,	/* Anonymous swap entries */
	MM_SHMEMPAGES,	/* Resident shared memory pages */
    MM_TOTAL
}

pub struct ProcessPerfCounterEntry {
    pub prev_counter: u64,
    pub proc_counter: u64,
}
#[derive(Debug, Copy, Clone)]
pub struct NettraceSample {
	pub bytes: u64,
	pub count: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NettraceSample{ }

#[derive(Debug, Copy, Clone)]
pub struct DiskIOPSSample {
    pub iops: u64,
    pub bytes: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DiskIOPSSample{ }
#[repr(C)]
pub struct kmem_rss_stat_args {
    pub _unused: u64,
    pub mm_id: u32,
    pub curr: u32,
    pub member: i32,
    pub _unused2: u32,
    pub size: i64
}

#[repr(C)]
pub struct block_block_io_start_args {
    pub _unused: u64,
    pub dev: u32,
    pub sector: u64,
    pub nr_sector: u32,
    pub bytes: u32,
    pub rwbs: [char; 8],
    pub comm: [char; 16],
    pub cmd: [char; 4],
}

pub struct RSSStatSample {
    pub previous: [i64; 4],
}

pub static START_TIME_KEY: u64 = 0;
pub static SAMEPLE_RATE_KEY: u64 = 1;
pub static PID_KEY: u64 = 2;
pub static MS_IN_NS: u64 = 1000000;

pub static ETH_P_IP: u16 = (0x0800 as u16).to_be();
pub static ETH_P_IPV6: u16 = (0x86DD as u16).to_be();
pub static IPPROTO_TCP: u32 = 6;
pub static IPPROTO_UDP: u32 = 17;
