use aya::maps::{Array, MapData, HashMap};
use aya::programs::perf_event::{perf_hw_id, PerfEventScope};
use aya::programs::{PerfEvent, PerfTypeId, SamplePolicy, TracePoint};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use libc::__c_anonymous_ptrace_syscall_info_entry;
use log::{debug, info, warn};
use tokio::signal;
use std::{
    env::args,
    borrow::BorrowMut,
    time::Instant,
    fs::read_to_string,
};
use scanf::sscanf;

static START_TIME_KEY: u64 = 0;
static SAMEPLE_RATE_KEY: u64 = 1;
static PID_KEY: u64 = 2;

pub fn boot_time_get_ns() -> Result<u64, u64> {
    let result = match read_to_string("/proc/uptime") {
        Ok(line) => { 
            info!("{}", line);
            let mut boot_time_ns = 0.0;
            sscanf!(&line, "{} {}", boot_time_ns);
            info!("{}", boot_time_ns);
            (boot_time_ns * 1000000000.0) as u64
            // match sscanf!(line, "{f32} {f32}") {
            //     Ok(ret) => {
            //         info!("{}", ret.0);
            //         Ok((ret.0 * 1000000000.0) as u64)
            //     },
            //     Err(_) => Err(0),
            // }
        },
        Err(_) => 0,
    };
    Ok(result)
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // TODO: temporary, replace by a config file later
    let args: Vec<String> = args().collect();
    let pid = &args[1];
    let pid: u64 = pid.parse().unwrap();


    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/trac"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/trac"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // let program: &mut TracePoint = bpf.program_mut("trac").unwrap().try_into()?;
    // program.load()?;
    // program.attach("sched", "sched_switch")?;

    let program_perf: &mut PerfEvent = bpf.program_mut("observe_cpu_clock").unwrap().try_into()?;
    program_perf.load()?;
    for cpu in online_cpus()? {
        program_perf.attach(
            PerfTypeId::Hardware,
            perf_hw_id::PERF_COUNT_HW_CPU_CYCLES as u64,
            PerfEventScope::AllProcessesOneCpu { cpu },
            SamplePolicy::Frequency(1000),
        )?;
    }

    let mut settings_map = HashMap::try_from(bpf.map_mut("SETTINGS_MAP").unwrap())? as HashMap<&mut MapData, u64, u64>;
    match boot_time_get_ns() {
        Ok(boot_time) => {
            settings_map.insert(START_TIME_KEY, boot_time, 0);
            // TODO: replace 500 by sample rate
            settings_map.insert(SAMEPLE_RATE_KEY, 500, 0);
            settings_map.insert(PID_KEY, pid, 0);
        },
        Err(_) => {
            panic!("failed to get boot time nanoseconds");
        }
    }

    let cycles_map = Array::try_from(bpf.map_mut("TOTAL_CYCLES_MAP").unwrap())? as Array<&mut MapData, u64>;
    let start_time = Instant::now();

    
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");


    // TODO: replace 500 by sample rate
    let num_buckets = (Instant::now().duration_since(start_time).as_millis() / 500) as u32;


    for i in 0..num_buckets {
        let k = cycles_map.get(&i, 0)?;
        info!("{k}");
    }


    


    Ok(())
}
