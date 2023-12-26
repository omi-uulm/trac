use std::time::Instant;

use aya::Bpf;
use aya::maps::{MapData, Array, HashMap};
use aya::programs::TracePoint;
use trac_common::*;

use crate::helpers::boot_time_get_ns;
use crate::typedefs::Resource;


struct MemSample {
    timestamp: u64,
    filepages: i64,
    anonpages: i64,
    swapents: i64,
    shmempages: i64,
    total: i64,
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
}

impl <'a>Mem<'a> {
    pub fn new(bpf: &'a mut Bpf, pid: &'a u64) -> Self {
        Mem { start_time: Instant::now(), bpf, pid }
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
        let rss_stat_map = Array::try_from(self.bpf.map_mut("RSS_STAT_MAP").unwrap()).unwrap() as Array<&mut MapData, [i64;5]>;
        let mut cur: [i64; 5] = [0,0,0,0,0];
        let num_buckets = (Instant::now().duration_since(self.start_time).as_millis() / 500) as u32;
        let mut ret: Vec<String> = Vec::new();
        
        ret.push(String::from("timestamp,filepages,anonpages,swapents,shmempages,total"));
        for i in 0..num_buckets {
            let val = rss_stat_map.get(&i, 0).unwrap();
            for (i, k) in val.iter().enumerate() {
                cur[i] += k;
            }

            ret.push(MemSample{
                timestamp: i as u64,
                filepages: cur[0],
                anonpages: cur[1],
                swapents: cur[2],
                shmempages: cur[3],
                total: cur[4],
            }.stringify())
        }

        ret
    }
}
