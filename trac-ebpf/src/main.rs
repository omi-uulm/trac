#![no_std]
#![no_main]

use aya_bpf::{
    macros::{tracepoint, perf_event},
    programs::{TracePointContext, PerfEventContext},
    BpfContext
};
use aya_log_ebpf::info;

#[perf_event]
pub fn observe_cpu_clock(ctx: PerfEventContext) -> u32 {
    match try_observe_cpu_clock(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_observe_cpu_clock(ctx: PerfEventContext) -> Result<u32, u32> {
    let pid = ctx.pid() as i32;
    if pid == 90911 {
        info!(&ctx, "pid: {}", pid);
    }
    // info!(&ctx, "tracepoint cpu called");
    
    Ok(0)
}

#[tracepoint]
pub fn trac(ctx: TracePointContext) -> u32 {
    match try_trac(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_trac(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "tracepoint sched_switch called");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
