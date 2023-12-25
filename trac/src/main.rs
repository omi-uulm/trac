use aya::maps::{Array, MapData, HashMap};
use aya::programs::perf_event::{perf_hw_id, PerfEventScope};
use aya::programs::{PerfEvent, PerfTypeId, SamplePolicy, TracePoint, Xdp, XdpFlags, Program};
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
};
use clap::{ Parser, Subcommand };
use trac_common::*;

mod helpers;
use helpers::boot_time_get_ns;


#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[clap(short, default_value = "test", global = true)]
    test: String,

    #[command(subcommand)]
    command: Option<Commands>,
}
#[derive(Subcommand)]
enum Commands {
    Net {
        #[clap(short, long, default_value = "eth0")]
        iface: String,
    },
    CPU {
        #[clap(short, long)]
        pid: u64,
    },
    Mem {
        #[clap(short, long)]
        pid: u64,
    },
}

fn init() -> Bpf {
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
    )).unwrap();
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/trac"
    )).unwrap();
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    return bpf
}

async fn handle_cpu(pid: &u64, bpf: &mut Bpf) {
    let program_perf: &mut PerfEvent = bpf.program_mut("observe_cpu_clock").unwrap().try_into().unwrap();
    program_perf.load().unwrap();
    for cpu in online_cpus().unwrap() {
        program_perf.attach(
            PerfTypeId::Hardware,
            perf_hw_id::PERF_COUNT_HW_CPU_CYCLES as u64,
            PerfEventScope::AllProcessesOneCpu { cpu },
            SamplePolicy::Frequency(1000),
        ).unwrap();
    }
    let mut settings_map = HashMap::try_from(bpf.map_mut("SETTINGS_MAP").unwrap()).unwrap() as HashMap<&mut MapData, u64, u64>;
    match boot_time_get_ns() {
        Ok(boot_time) => {
            settings_map.insert(START_TIME_KEY, boot_time, 0);
            settings_map.insert(SAMEPLE_RATE_KEY, 500, 0);
            settings_map.insert(PID_KEY, pid, 0);
        },
        Err(_) => {
            panic!("failed to get boot time nanoseconds");
        }
    }

    let cycles_map = Array::try_from(bpf.map_mut("TOTAL_CYCLES_MAP").unwrap()).unwrap() as Array<&mut MapData, u64>;
    let start_time = Instant::now();
    
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await.unwrap();
    info!("Exiting...");
    
    let num_buckets = (Instant::now().duration_since(start_time).as_millis() / 500) as u32;
    for i in 0..num_buckets {
        let k = cycles_map.get(&i, 0).unwrap();
        info!("{k}");
    }
}

async fn handle_mem(pid: &u64, bpf: &mut Bpf) {
    let program_tracepoint: &mut TracePoint = bpf.program_mut("observe_memory").unwrap().try_into().unwrap();
    program_tracepoint.load().unwrap();
    program_tracepoint.attach("kmem", "rss_stat").unwrap();


    let mut settings_map = HashMap::try_from(bpf.map_mut("SETTINGS_MAP").unwrap()).unwrap() as HashMap<&mut MapData, u64, u64>;
    match boot_time_get_ns() {
        Ok(boot_time) => {
            settings_map.insert(START_TIME_KEY, boot_time, 0);
            settings_map.insert(SAMEPLE_RATE_KEY, 500, 0);
            settings_map.insert(PID_KEY, pid, 0);
        },
        Err(_) => {
            panic!("failed to get boot time nanoseconds");
        }
    }

    let rss_stat_map = Array::try_from(bpf.map_mut("RSS_STAT_MAP").unwrap()).unwrap() as Array<&mut MapData, i64>;
    let start_time = Instant::now();
    
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await.unwrap();
    info!("Exiting...");

    let mut cur: i64 = 0;
    let num_buckets = (Instant::now().duration_since(start_time).as_millis() / 500) as u32;
    for i in 0..num_buckets {
        let k = rss_stat_map.get(&i, 0).unwrap();
        cur += k;
        info!("{cur}");
    }
}

async fn handle_net(iface: &String, bpf: &mut Bpf) {
    let program_xdp: &mut Xdp = bpf.program_mut("observe_iface").unwrap().try_into().unwrap();
    program_xdp.load().unwrap();
    program_xdp.attach(&iface, XdpFlags::default()).unwrap();

    let mut settings_map = HashMap::try_from(bpf.map_mut("SETTINGS_MAP").unwrap()).unwrap() as HashMap<&mut MapData, u64, u64>;
    match boot_time_get_ns() {
        Ok(boot_time) => {
            settings_map.insert(START_TIME_KEY, boot_time, 0);
            settings_map.insert(SAMEPLE_RATE_KEY, 500, 0);
        },
        Err(_) => {
            panic!("failed to get boot time nanoseconds");
        }
    }

    let nettrace_map = Array::try_from(bpf.map_mut("NETTRACE_MAP").unwrap()).unwrap() as Array<&mut MapData, NettraceSample>;
    let start_time: Instant = Instant::now();

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await.unwrap();
    info!("Exiting...");

    let num_buckets = (Instant::now().duration_since(start_time).as_millis() / 500) as u32;
    for i in 0..num_buckets {
        let k = nettrace_map.get(&i, 0).unwrap();
        info!("{}", k.bytes);
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let mut bpf = init();

    let cli = Cli::parse();

    match &cli.command {
        Some( Commands::CPU { pid }) => {
            handle_cpu(&pid, &mut bpf).await;
        }
        Some(Commands::Net { iface }) => {
            handle_net(&iface, &mut bpf).await;
        }
        Some(Commands::Mem { pid }) => {
            handle_mem(&pid, &mut bpf).await;
        }
        None => {
            println!("Default subcommand");
        }
    }

    Ok(())
}
