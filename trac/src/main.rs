use aya::programs::perf_event::{perf_hw_id, PerfEventScope};
use aya::programs::{PerfEvent, PerfTypeId, SamplePolicy, TracePoint};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{debug, info, warn};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
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
            SamplePolicy::Frequency(10000),
        )?;
    }
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
