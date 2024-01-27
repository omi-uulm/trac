use std::time::Instant;

use aya::Bpf;
use aya::maps::{MapData, Array, HashMap};
use aya::programs::TracePoint;
use trac_common::*;

use crate::helpers::boot_time_get_ns;
use crate::typedefs::Resource;

struct MemSample {
    timestamp: u64,
    filepages: u64,
    anonpages: u64,
    swapents: u64,
    shmempages: u64,
    total: u64,
}

impl MemSample {
    pub fn stringify(&self) -> String {
        format!("{},{},{},{},{},{}", self.timestamp, self.filepages, self.anonpages, self.swapents, self.shmempages, self.total)
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
        let rss_stat_map = Array::try_from(self.bpf.map_mut("RSS_STAT_MAP").unwrap()).unwrap() as Array<&mut MapData, RSSStat>;
        let mut cur: [u64; 5] = [0,0,0,0,0];
        let num_buckets = (Instant::now().duration_since(self.start_time).as_millis() / self.sample_rate as u128) as u32;
        let mut ret: Vec<String> = Vec::new();
        

        ret.push(String::from("timestamp,filepages,anonpages,swapents,shmempages,total"));
        for i in 0..num_buckets {
            let val: RSSStat = rss_stat_map.get(&i, 0).unwrap();
            for (i, k) in val.iter().enumerate() {
                if k.touched == 0xDEADBEEF {
                    cur[i] = k.bytes;
                }
            }

            ret.push(MemSample{
                timestamp: (i+1) as u64 * self.sample_rate,
                filepages: cur[RSSMemberEnum::MM_FILEPAGES as usize],
                anonpages: cur[RSSMemberEnum::MM_ANONPAGES as usize],
                swapents: cur[RSSMemberEnum::MM_SWAPENTS as usize],
                shmempages: cur[RSSMemberEnum::MM_SHMEMPAGES as usize],
                total: cur.iter().sum(),
            }.stringify())
        }

        ret
    }
}
