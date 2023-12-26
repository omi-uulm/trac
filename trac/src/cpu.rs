use std::time::Instant;

use aya::{maps::{MapData, Array, HashMap}, Bpf, programs::{SamplePolicy, PerfTypeId, PerfEvent, perf_event::{ perf_hw_id, PerfEventScope }}, util::online_cpus};
use trac_common::*;

use crate::helpers::boot_time_get_ns;
use crate::typedefs::Resource;


struct CPUSample {
    timestamp: u64,
    cycles: u64,
}

impl CPUSample {
    pub fn stringify(&self) -> String {
        format!("{},{}", self.timestamp, self.cycles)
    }
}

pub struct CPU<'a> {
    start_time: Instant,
    bpf: &'a mut Bpf,
    pid: &'a u64,
    sample_rate: u64,
}

impl <'a>CPU<'a> {
    pub fn new(bpf: &'a mut Bpf, pid: &'a u64, sample_rate: u64) -> Self {
        CPU { start_time: Instant::now(), bpf, pid, sample_rate }
    }
}

impl <'a>Resource for CPU<'a> {
    fn trace_start(&mut self) {
        let program_perf: &mut PerfEvent = self.bpf.program_mut("observe_cpu_clock").unwrap().try_into().unwrap();
        program_perf.load().unwrap();
        for cpu in online_cpus().unwrap() {
            program_perf.attach(
                PerfTypeId::Hardware,
                perf_hw_id::PERF_COUNT_HW_CPU_CYCLES as u64,
                PerfEventScope::AllProcessesOneCpu { cpu },
                SamplePolicy::Frequency(1000),
            ).unwrap();
        }

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
        let cycles_map: Array<&mut MapData, u64> = Array::try_from(self.bpf.map_mut("TOTAL_CYCLES_MAP").unwrap()).unwrap() as Array<&mut MapData, u64>;
        let num_buckets = (Instant::now().duration_since(self.start_time).as_millis() / self.sample_rate as u128) as u32;
        let mut ret: Vec<String> = Vec::new();
        
        ret.push(String::from("timestamp,cycles"));
        for i in 0..num_buckets {
            let k = cycles_map.get(&i, 0).unwrap();
            ret.push(CPUSample{
                timestamp: (i+1) as u64 * self.sample_rate,
                cycles: k,
            }.stringify())
        }

        ret
    }
}
