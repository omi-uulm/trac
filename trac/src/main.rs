use aya::maps::{Array, MapData, HashMap};
use aya::programs::perf_event::{perf_hw_id, PerfEventScope};
use aya::programs::{PerfEvent, PerfTypeId, SamplePolicy, TracePoint, Xdp, XdpFlags, Program};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use libc::__c_anonymous_ptrace_syscall_info_entry;
use log::{debug, info, warn};
use tokio::signal;
use std::thread::sleep;
use std::time::Duration;
use std::{
    env::args,
    borrow::BorrowMut,
    time::Instant,
};
use clap::{ Parser, Subcommand };
use trac_common::*;

mod helpers;
use helpers::boot_time_get_ns;

use crate::helpers::get_rss_member_name;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[clap(short, long, global = true, default_value = "0", required = false)]
    timeout: i64,

    #[command(subcommand)]
    command: Option<Commands>,
}
impl Cli {
    async fn timeout_or_ctrl_c(&self) {
        if self.timeout <= 0 {
            info!("Waiting for Ctrl-C...");
            signal::ctrl_c().await.unwrap();
            info!("Exiting...");
        } else {
            sleep(Duration::from_secs(self.timeout as u64))
        }
    }
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
    Dsk {
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

fn handle_cpu(pid: &u64, bpf: &mut Bpf) -> Instant {
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

    Instant::now()
}

fn print_cpu(start_time: Instant, bpf: &mut Bpf) {
    let cycles_map: Array<&mut MapData, u64> = Array::try_from(bpf.map_mut("TOTAL_CYCLES_MAP").unwrap()).unwrap() as Array<&mut MapData, u64>;
    println!("timestamp,cycles");
    let num_buckets = (Instant::now().duration_since(start_time).as_millis() / 500) as u32;
    for i in 0..num_buckets {
        let k = cycles_map.get(&i, 0).unwrap();
        println!("{},{}", i, k);
    }
}

fn handle_disk(pid: &u64, bpf: &mut Bpf) -> Instant {    
    let program_tracepoint: &mut TracePoint = bpf.program_mut("observe_disk").unwrap().try_into().unwrap();
    program_tracepoint.load().unwrap();
    program_tracepoint.attach("block", "block_io_start").unwrap();

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
    Instant::now()

}

fn print_disk(start_time: Instant, bpf: &mut Bpf) {
    let disk_iops_map = Array::try_from(bpf.map_mut("DISK_IOPS_MAP").unwrap()).unwrap() as Array<&mut MapData, DiskIOPSSample>;
    println!("timestamp,iops,bytes");
    let num_buckets = (Instant::now().duration_since(start_time).as_millis() / 500) as u32;
    for i in 0..num_buckets {
        let k = disk_iops_map.get(&i, 0).unwrap();
        println!("{},{},{}", i, k.iops, k.bytes);
    }
}

fn handle_mem(pid: &u64, bpf: &mut Bpf) -> Instant {
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

    Instant::now()
}

fn print_mem(start_time: Instant, bpf: &mut Bpf) {
    let rss_stat_map = Array::try_from(bpf.map_mut("RSS_STAT_MAP").unwrap()).unwrap() as Array<&mut MapData, [i64;5]>;
    println!("timestamp,{},{},{},{},{}", get_rss_member_name(0), get_rss_member_name(1), get_rss_member_name(2), get_rss_member_name(3), get_rss_member_name(4));
    let mut cur: [i64; 5] = [0,0,0,0,0];
    let num_buckets = (Instant::now().duration_since(start_time).as_millis() / 500) as u32;
    for i in 0..num_buckets {
        let val = rss_stat_map.get(&i, 0).unwrap();
        for (i, k) in val.iter().enumerate() {
            cur[i] += k;
        }
        println!("{},{},{},{},{},{}", i, cur[0], cur[1], cur[2], cur[3], cur[4]);
    }
}

fn handle_net(iface: &String, bpf: &mut Bpf) -> Instant {
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

    Instant::now()
}

fn print_net(start_time: Instant, bpf: &mut Bpf) {
    let nettrace_map = Array::try_from(bpf.map_mut("NETTRACE_MAP").unwrap()).unwrap() as Array<&mut MapData, NettraceSample>;
    println!("timestamp,count,bytes");
    let num_buckets = (Instant::now().duration_since(start_time).as_millis() / 500) as u32;
    for i in 0..num_buckets {
        let k = nettrace_map.get(&i, 0).unwrap();
        println!("{},{},{}", i, k.count, k.bytes);
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let mut bpf = init();

    let cli = Cli::parse();

    match &cli.command {
        Some( Commands::CPU { pid }) => {
            let start_time = handle_cpu(&pid, &mut bpf);
            cli.timeout_or_ctrl_c().await;
            print_cpu(start_time, &mut bpf);
        }
        Some(Commands::Net { iface }) => {
            let start_time = handle_net(&iface, &mut bpf);
            cli.timeout_or_ctrl_c().await;
            print_net(start_time, &mut bpf);
        }
        Some(Commands::Mem { pid }) => {
            let start_time = handle_mem(&pid, &mut bpf);
            cli.timeout_or_ctrl_c().await;
            print_mem(start_time, &mut bpf);
        }
        Some(Commands::Dsk { pid}) => {
            let start_time = handle_disk(&pid, &mut bpf);
            cli.timeout_or_ctrl_c().await;
            print_disk(start_time, &mut bpf);
        }
        None => {
            println!("Default subcommand");
        }
    }

    Ok(())
}
