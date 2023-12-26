use std::time::Instant;

use aya::Bpf;
use aya::maps::{MapData, Array, HashMap};
use aya::programs::TracePoint;
use trac_common::*;

use crate::helpers::boot_time_get_ns;
use crate::typedefs::Resource;

struct DiskSample {
    timestamp: u64,
    iops: u64,
    bytes: u64,
}

impl DiskSample {
    pub fn stringify(&self) -> String {
        format!("{},{},{}", self.timestamp, self.iops, self.bytes)
    }
}

pub struct Disk<'a> {
    start_time: Instant,
    bpf: &'a mut Bpf,
    pid: &'a u64,
}

impl <'a>Disk<'a> {
    pub fn new(bpf: &'a mut Bpf, pid: &'a u64) -> Self {
        Disk { start_time: Instant::now(), bpf, pid }
    }
}

impl <'a>Resource for Disk<'a> {
    fn trace_start(&mut self) {
        let program_tracepoint: &mut TracePoint = self.bpf.program_mut("observe_disk").unwrap().try_into().unwrap();
        program_tracepoint.load().unwrap();
        program_tracepoint.attach("block", "block_io_start").unwrap();

        let mut settings_map = HashMap::try_from(self.bpf.map_mut("SETTINGS_MAP").unwrap()).unwrap() as HashMap<&mut MapData, u64, u64>;
        match boot_time_get_ns() {
            Ok(boot_time) => {
                let _ = settings_map.insert(START_TIME_KEY, boot_time, 0);
                let _ = settings_map.insert(SAMEPLE_RATE_KEY, 500, 0);
                let _ = settings_map.insert(PID_KEY, self.pid, 0);
            },
            Err(_) => {
                panic!("failed to get boot time nanoseconds");
            }
        }
        self.start_time = Instant::now();
    }

    fn to_csv_lines(&mut self) -> Vec<String> {
        let disk_iops_map = Array::try_from(self.bpf.map_mut("DISK_IOPS_MAP").unwrap()).unwrap() as Array<&mut MapData, DiskIOPSSample>;
        let num_buckets = (Instant::now().duration_since(self.start_time).as_millis() / 500) as u32;
        let mut ret: Vec<String> = Vec::new();
        
        ret.push(String::from("timestamp,iops,bytes"));
        for i in 0..num_buckets {
            let k: DiskIOPSSample = disk_iops_map.get(&i, 0).unwrap();
            ret.push(DiskSample{
                timestamp: i as u64,
                iops: k.iops,
                bytes: k.bytes,
            }.stringify())
        }

        ret
    }
}
