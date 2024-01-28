use std::time::Instant;

use aya::util::nr_cpus;
use aya::Bpf;
use aya::maps::{ HashMap, MapData, PerCpuArray};
use aya::programs::TracePoint;
use log::error;
use trac_common::*;

use crate::helpers::boot_time_get_ns;
use crate::typedefs::Resource;


struct MemSample {
    timestamp: u64,
    core: usize,
    filepages: i64,
    anonpages: i64,
    swapents: i64,
    shmempages: i64,
    total: i64,
}

impl MemSample {
    pub fn stringify(&self) -> String {
        format!("{},{},{},{},{},{},{}", self.timestamp, self.core, self.filepages, self.anonpages, self.swapents, self.shmempages, self.total)
    }
}

pub struct Mem<'a> {
    start_time: Instant,
    bpf: &'a mut Bpf,
    pid: &'a u64,
    sample_rate: u64,
}

impl <'a>Mem<'a> {
    pub fn new(bpf: &'a mut Bpf, pid: &'a u64, sample_rate: u64) -> Self {
        Mem { start_time: Instant::now(), bpf, pid, sample_rate }
    }
}

impl <'a>Resource for Mem<'a> {
    fn trace_start(&mut self) {
        let program_tracepoint: &mut TracePoint = self.bpf.program_mut("observe_memory").unwrap().try_into().unwrap();
        program_tracepoint.load().unwrap();
        program_tracepoint.attach("kmem", "rss_stat").unwrap();

        let mut settings_map = HashMap::try_from(self.bpf.map_mut("SETTINGS_MAP").unwrap()).unwrap() as HashMap<&mut MapData, u64, u64>;
        match boot_time_get_ns() {
            Ok(boot_time) => {
                let _ = settings_map.insert(START_TIME_KEY, boot_time, 0);
                let _ = settings_map.insert(SAMEPLE_RATE_KEY, self.sample_rate, 0);
                let _ = settings_map.insert(PID_KEY, self.pid, 0);
            },
            Err(_) => {
                panic!("failed to get boot time nanoseconds");
            }
        }

        self.start_time = Instant::now();
    }

    fn to_csv_lines(&mut self) -> Vec<String> {
        let rss_stat_map = PerCpuArray::try_from(self.bpf.map_mut("RSS_STAT_MAP").unwrap()).unwrap() as PerCpuArray<&mut MapData, [i64; 4]>;
        let num_cores = nr_cpus().unwrap();
        let mut cur = vec![[0,0,0,0]; num_cores];
        let num_buckets = (Instant::now().duration_since(self.start_time).as_millis() / self.sample_rate as u128) as u32;
        let mut ret: Vec<String> = Vec::new();
        
        ret.push(String::from("timestamp,core,filepages,anonpages,swapents,shmempages,total"));
        for i in 0..num_buckets {
            let val = rss_stat_map.get(&i, 0).unwrap();
            for (core, core_val) in val.iter().enumerate() {
                for (cur_index, k) in core_val.iter().enumerate() {
                    cur[core][cur_index] += k;
                }
                ret.push(MemSample{
                    timestamp: (i+1) as u64 * self.sample_rate,
                    core: core,
                    filepages: cur[core][RSSMember::MM_FILEPAGES as usize],
                    anonpages: cur[core][RSSMember::MM_ANONPAGES as usize],
                    swapents: cur[core][RSSMember::MM_SWAPENTS as usize],
                    shmempages: cur[core][RSSMember::MM_SHMEMPAGES as usize],
                    total: cur[core][0] + cur[core][1] + cur[core][2] + cur[core][3],
                }.stringify())
            }
            
        }

        let rss_last_shmem_map = HashMap::try_from(self.bpf.map_mut("RSS_LAST_SHMEM_MAP").unwrap()).unwrap() as HashMap<&mut MapData, u32, SHMEM_STAT>;
        for k in rss_last_shmem_map.keys() {
            let key = k.unwrap();
            let value = rss_last_shmem_map.get(&key, 0).unwrap();
            error!("{}, {}", key, value.counter);
        }

        ret
    }
}
