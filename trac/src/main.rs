use aya::{ include_bytes_aligned, Bpf };
use indicatif::{ProgressBar, ProgressStyle};
// use aya_log::BpfLogger;
use log::{ debug, info };
use tokio::signal;
use typedefs::Resource;
use std::{ thread::sleep, time::Duration, collections::HashMap };
use clap::{ Parser, Subcommand };

mod helpers;
mod typedefs;
mod cpu;
mod disk;
mod mem;
mod net;
use trac_profiling_helpers::print_profiling_csv;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[clap(short, long, global = true, default_value = "0", required = false, help = "Trace duration seconds. A value less or equal to 0 means running forever.")]
    duration: i64,

    #[clap(short, long, global = true, default_value = "1000", required = false, help = "Sampling rate in milliseconds. This resolution also applies to the time buckets in the CSV output.")]
    sample_rate: u64,

    #[clap(long, global = true, default_value = "false", required = false, help = "Display progress bar")]
    progress: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}
impl Cli {
    async fn duration_or_ctrl_c(&self) {
        if self.duration <= 0 {
            info!("Waiting for Ctrl-C...");
            signal::ctrl_c().await.unwrap();
            info!("Exiting...");
        } else {
            if self.progress {
                let bar = ProgressBar::new(self.duration as u64);
                bar.set_style(ProgressStyle::with_template("[{elapsed}/{duration}] {wide_bar}")
                    .unwrap());
                for _ in 0..self.duration {
                    sleep(Duration::from_secs(1));
                    bar.inc(1);
                }
            } else {
                sleep(Duration::from_secs(self.duration as u64));
            }
        }
    }
}


#[derive(Subcommand)]
enum Commands {
    Net {
        #[clap(short, long, default_value = "eth0", help = "Interface name")]
        iface: String,
    },
    CPU {
        #[clap(short, long, help = "PID tree to be traced")]
        pid: u64,
    },
    Mem {
        #[clap(short, long, help = "PID tree to be traced")]
        pid: u64,
    },
    Dsk {
        #[clap(short, long, help = "PID tree to be traced")]
        pid: u64,
    },
}

fn init() ->  HashMap<&'static str, &'static [u8]> {
    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let mut bpf_objects: HashMap<&str, &[u8]> = HashMap::new();

    #[cfg(debug_assertions)] {
        bpf_objects.insert("cpu", include_bytes_aligned!("../../target/bpfel-unknown-none/debug/trac-cpu"));
        bpf_objects.insert("mem", include_bytes_aligned!("../../target/bpfel-unknown-none/debug/trac-mem"));
        bpf_objects.insert("disk", include_bytes_aligned!("../../target/bpfel-unknown-none/debug/trac-disk"));
        bpf_objects.insert("net", include_bytes_aligned!("../../target/bpfel-unknown-none/debug/trac-net"));
    }
    #[cfg(not(debug_assertions))]
    {
        bpf_objects.insert("cpu", include_bytes_aligned!("../../target/bpfel-unknown-none/release/trac-cpu"));
        bpf_objects.insert("mem", include_bytes_aligned!("../../target/bpfel-unknown-none/release/trac-mem"));
        bpf_objects.insert("disk", include_bytes_aligned!("../../target/bpfel-unknown-none/release/trac-disk"));
        bpf_objects.insert("net", include_bytes_aligned!("../../target/bpfel-unknown-none/release/trac-net"));
    }

    bpf_objects
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();
    let bpf_objects = init();
    let mut bpf: Bpf;

    let mut tracer: Box<dyn Resource> = match &cli.command {
        Some(Commands::CPU { pid }) => {
            bpf = Bpf::load(bpf_objects.get("cpu").unwrap()).unwrap();
            Box::new(cpu::CPU::new(&mut bpf, pid, cli.sample_rate))
        },
        Some(Commands::Net { iface }) => {
            bpf = Bpf::load(bpf_objects.get("net").unwrap()).unwrap();
            Box::new(net::Net::new(&mut bpf, iface, cli.sample_rate))
        },
        Some(Commands::Mem { pid }) => {
            bpf = Bpf::load(bpf_objects.get("mem").unwrap()).unwrap();
            Box::new(mem::Mem::new(&mut bpf, pid, cli.sample_rate))
        },
        Some(Commands::Dsk { pid}) => {
            bpf = Bpf::load(bpf_objects.get("disk").unwrap()).unwrap();
            Box::new(disk::Disk::new(&mut bpf, pid, cli.sample_rate))
        },
        None => {
            return Err(anyhow::Error::msg("subcommand"))
        }
    };

    tracer.trace_start();
    cli.duration_or_ctrl_c().await;
    for line in tracer.to_csv_lines() {
        println!("{line}")
    }

    std::mem::drop(tracer);

    print_profiling_csv(&mut bpf);

    Ok(())
}
