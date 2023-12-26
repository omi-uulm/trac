use std::time::Instant;

use aya::Bpf;
use aya::maps::{MapData, Array, HashMap};
use aya::programs::{XdpFlags, Xdp};
use trac_common::*;

use crate::helpers::boot_time_get_ns;
use crate::typedefs::Resource;


struct NetSample {
    timestamp: u64,
    count: u64,
    bytes: u64,
}

impl NetSample {
    pub fn stringify(&self) -> String {
        format!("{},{},{}", self.timestamp, self.count, self.bytes)
    }
}

pub struct Net<'a> {
    start_time: Instant,
    bpf: &'a mut Bpf,
    iface: &'a String,
    sample_rate: u64,
}

impl <'a>Net<'a> {
    pub fn new(bpf: &'a mut Bpf, iface: &'a String, sample_rate: u64) -> Self {
        Net { start_time: Instant::now(), bpf, iface, sample_rate }
    }
}

impl <'a>Resource for Net<'a> {
    fn trace_start(&mut self) {
        let program_xdp: &mut Xdp = self.bpf.program_mut("observe_iface").unwrap().try_into().unwrap();
        program_xdp.load().unwrap();
        program_xdp.attach(self.iface, XdpFlags::default()).unwrap();

        let mut settings_map = HashMap::try_from(self.bpf.map_mut("SETTINGS_MAP").unwrap()).unwrap() as HashMap<&mut MapData, u64, u64>;
        match boot_time_get_ns() {
            Ok(boot_time) => {
                let _ = settings_map.insert(START_TIME_KEY, boot_time, 0);
                let _ = settings_map.insert(SAMEPLE_RATE_KEY, self.sample_rate, 0);
            },
            Err(_) => {
                panic!("failed to get boot time nanoseconds");
            }
        }

        self.start_time = Instant::now();
    }

    fn to_csv_lines(&mut self) -> Vec<String> {
        let nettrace_map = Array::try_from(self.bpf.map_mut("NETTRACE_MAP").unwrap()).unwrap() as Array<&mut MapData, NettraceSample>;
        let num_buckets = (Instant::now().duration_since(self.start_time).as_millis() / self.sample_rate as u128) as u32;
        let mut ret: Vec<String> = Vec::new();

        ret.push(String::from("timestamp,count,bytes"));
        for i in 0..num_buckets {
            let k = nettrace_map.get(&i, 0).unwrap();
            ret.push(NetSample{
                timestamp: (i+1) as u64 * self.sample_rate,
                count: k.count,
                bytes: k.bytes,
            }.stringify())
        }

        ret
    }
}
