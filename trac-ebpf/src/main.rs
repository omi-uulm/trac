#![no_std]
#![no_main]

mod vmlinux;
mod bpf_perf_event_data;

use core::{panic, ptr::{null, null_mut}, default, mem::size_of};
use aya_bpf::{
    helpers::{bpf_get_smp_processor_id, bpf_perf_prog_read_value, bpf_get_current_comm, bpf_get_current_task, bpf_get_current_task_btf, bpf_perf_event_output, bpf_perf_event_read},
    macros::{perf_event, tracepoint},
    programs::{ perf_event, PerfEventContext, TracePointContext},
    BpfContext, bindings::bpf_perf_event_value,
};
use aya_log_ebpf::{info};
use vmlinux::{task_struct};

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

    let mut task: *mut task_struct = unsafe { bpf_get_current_task_btf() as *mut task_struct };

    let mut ev: *mut bpf_perf_event_data::bpf_perf_event_data = unsafe { ctx.as_ptr() as *mut bpf_perf_event_data::bpf_perf_event_data };

    let mut v = bpf_perf_event_value {
        counter: 0,
        enabled: 0,
        running: 0,
    };
    let mut value = core::ptr::addr_of_mut!(v);

    unsafe { bpf_perf_prog_read_value(ev as *mut aya_bpf::bindings::bpf_perf_event_data, value, core::mem::size_of::<bpf_perf_event_value>() as u32); }

    for _ in 1..8 {
        match unsafe { (*task).pid } {
            0 => break,
            1 => break,
            10202 => {
                info!(&ctx, "pid: {}", pid);
                info!(&ctx, "cpu: {}", cpu);
                info!(&ctx, "prog_name: {}", prog_name);
                info!(&ctx, "valuee: {}", unsafe { (*value).counter });
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
