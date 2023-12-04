#![no_std]
#![no_main]

mod vmlinux;

use core::{panic, ptr::null, default};
use aya_bpf::{
    helpers::{bpf_perf_event_read, bpf_get_smp_processor_id, bpf_get_current_comm, bpf_get_current_task, bpf_get_current_task_btf},
    macros::{perf_event, tracepoint},
    programs::{perf_event, PerfEventContext, TracePointContext},
    BpfContext,
};
use aya_log_ebpf::{info};
use vmlinux::task_struct;

#[perf_event]
pub fn observe_cpu_clock(ctx: PerfEventContext) -> u32 {
    match try_observe_cpu_clock(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_observe_cpu_clock(ctx: PerfEventContext) -> Result<u32, u32> {
    let pid = ctx.pid() as i32;
    let cpu = unsafe { bpf_get_smp_processor_id() };
    let prog_name =  bpf_get_current_comm().map_err(|e| e as u32)?;
    let prog_name = unsafe {core::str::from_utf8_unchecked(&prog_name)};

    let mut task = unsafe { bpf_get_current_task_btf() as *mut task_struct };

    for _ in 1..8 {
        match unsafe { (*task).pid } {
            0 => break,
            1 => break,
            6307 => {
                info!(&ctx, "pid: {}", pid);
                info!(&ctx, "cpu: {}", cpu);
                info!(&ctx, "prog_name: {}", prog_name);
                break;
            }
            _ => {}
        }
        
        if unsafe { (*task).parent }.is_null() {
            break;
        } else {
            task = unsafe { (*task).parent };
        }
    }

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
