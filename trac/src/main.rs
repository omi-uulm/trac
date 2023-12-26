use aya::{ include_bytes_aligned, Bpf };
// use aya_log::BpfLogger;
use log::{ debug, info };
use tokio::signal;
use typedefs::Resource;
use std::{ thread::sleep, time::Duration };
use clap::{ Parser, Subcommand };

mod helpers;
mod typedefs;
mod cpu;
mod disk;
mod mem;
mod net;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[clap(short, long, global = true, default_value = "0", required = false, help = "Trace duration seconds. A value less or equal to 0 means running forever.")]
    duration: i64,

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
            sleep(Duration::from_secs(self.duration as u64))
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

fn init() -> Bpf {
    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    #[cfg(debug_assertions)]
    let bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/trac"
    )).unwrap();
    #[cfg(not(debug_assertions))]
    let bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/trac"
    )).unwrap();
    // if let Err(e) = BpfLogger::init(&mut bpf) {
    //     // This can happen if you remove all log statements from your eBPF program.
    //     warn!("failed to initialize eBPF logger: {}", e);
    // }
    return bpf
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let mut bpf = init();

    let cli = Cli::parse();

    let mut tracer: Box<dyn Resource> = match &cli.command {
        Some( Commands::CPU { pid }) => Box::new(cpu::CPU::new(&mut bpf, pid)),
        Some(Commands::Net { iface }) => Box::new(net::Net::new(&mut bpf, iface)),
        Some(Commands::Mem { pid }) => Box::new(mem::Mem::new(&mut bpf, pid)),
        Some(Commands::Dsk { pid}) => Box::new(disk::Disk::new(&mut bpf, pid)),
        None => {
            return Err(anyhow::Error::msg("subcommand"))
        }
    };

    tracer.trace_start();
    cli.duration_or_ctrl_c().await;
    for line in tracer.to_csv_lines() {
        println!("{line}")
    }

    Ok(())
}
