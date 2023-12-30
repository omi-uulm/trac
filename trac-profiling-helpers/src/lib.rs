#![allow(unused_variables)]

use aya::Bpf;


#[cfg(feature = "profiling")]
#[derive(Debug, Copy, Clone)]
pub struct ProfilingEntry {
    pub count: u64,
    pub inner_nanosecs: u64,
    pub outer_nanosecs: u64,
}

#[cfg(feature = "profiling")]
unsafe impl aya::Pod for ProfilingEntry{ }

#[cfg(feature = "profiling")]
pub fn print_profiling_csv(bpf: &mut Bpf) {
    let state_map: aya::maps::Array<&mut aya::maps::MapData, u64> = aya::maps::Array::try_from(bpf.map_mut("BPF_PROFILING_STATE_MAP").unwrap()).unwrap().into();
    let key: u32 = 1;
    let num_buckets: u32 = state_map.get(&key, 0).unwrap() as u32;
    
    let data_map: aya::maps::Array<&mut aya::maps::MapData, ProfilingEntry> = aya::maps::Array::try_from(bpf.map_mut("BPF_PROFILING_MAP").unwrap()).unwrap().into();

    println!("timestamp,ebpf_nanos,ebpf_with_profiling_nanos,count");
    for i in 0..num_buckets {
        let k: ProfilingEntry = data_map.get(&i, 0).unwrap();
        println!("{},{},{},{}", (i+1) * 1000, k.inner_nanosecs, 2 * k.outer_nanosecs - k.inner_nanosecs, k.count);
    }
}
#[cfg(not(feature = "profiling"))]
pub fn print_profiling_csv(bpf: &mut Bpf) {}
