#![no_std]
#![no_main]

mod task;
mod perf_event;

use aya_bpf::{
    helpers::{bpf_perf_prog_read_value, bpf_get_current_task_btf },
    macros::{ perf_event, map },
    bindings::{ bpf_perf_event_value, bpf_perf_event_data },
    programs::PerfEventContext,
    BpfContext,
    maps::{ PerCpuHashMap, Array },
};
use core::{ptr::addr_of_mut, mem::size_of};
use task::task_struct;
use perf_event::bpf_perf_event_data as native_bpf_perf_event_data;
use trac_profiling_macros::{ profiling, profiling_maps_def };
use trac_common::*;
use trac_ebpf::bpf_defaults;

#[map]
static PROC_MAP: PerCpuHashMap<u64, ProcessPerfCounterEntry> = PerCpuHashMap::with_max_entries(1024, 0);

#[map]
static TOTAL_CYCLES_MAP: Array<u64> = Array::with_max_entries(262144, 0);

profiling_maps_def!();

bpf_defaults!();

#[perf_event]
#[profiling]
pub fn observe_cpu_clock(ctx: PerfEventContext) -> u32 {
    match try_observe_cpu_clock(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_observe_cpu_clock(ctx: PerfEventContext) -> Result<u32, u32> {
    let mut task: *mut task_struct = unsafe { bpf_get_current_task_btf() as *mut task_struct };
    let read_value_ctx: *mut native_bpf_perf_event_data = ctx.as_ptr() as *mut native_bpf_perf_event_data;
    let mut value = bpf_perf_event_value { counter: 0, enabled: 0, running: 0 };
    let value_ptr = addr_of_mut!(value);

    unsafe { bpf_perf_prog_read_value(read_value_ctx as *mut bpf_perf_event_data, value_ptr, size_of::<bpf_perf_event_value>() as u32); };

    let watch_pid: u64 = match unsafe { SETTINGS_MAP.get(&PID_KEY) } {
        None => 0,
        Some(p) => *p,
    };

    for _ in 1..8 {
        let cur_pid = unsafe { (*task).pid } as u64;
        match cur_pid {
            0 => break,
            1 => break,
            w if w == watch_pid => {
                let counter = value.counter;
                let mut proc_entry = ProcessPerfCounterEntry{prev_counter: counter, proc_counter: 0};
                let mut additional_cycles: u64 = 0;
                let current_bucket = get_current_bucket();

                match unsafe { PROC_MAP.get(&cur_pid) } {
                    None => {},
                    Some(i) => {
                        additional_cycles = counter - i.prev_counter;
                        proc_entry.proc_counter = i.proc_counter + additional_cycles;
                        proc_entry.prev_counter = counter;
                    }
                }
                let _ = PROC_MAP.insert(&cur_pid, &proc_entry, 0);

                match TOTAL_CYCLES_MAP.get_ptr_mut(current_bucket) {
                    None => {},
                    Some(i) => {
                        unsafe { *i += additional_cycles };
                    }
                }

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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
