#![no_std]
#![no_main]

mod task;
mod perf_event;

use aya_bpf::{
    helpers::{ bpf_get_smp_processor_id, bpf_perf_prog_read_value, bpf_get_current_comm, bpf_get_current_task_btf, bpf_ktime_get_tai_ns, bpf_ktime_get_boot_ns },
    macros::{ perf_event, tracepoint, map },
    bindings::{ bpf_perf_event_value, bpf_perf_event_data },
    programs::{ PerfEventContext, TracePointContext },
    BpfContext,
    maps::{ PerCpuHashMap, Array, HashMap },
};
use aya_log_ebpf::info;
use core::{
    str::from_utf8_unchecked,
    ptr::addr_of_mut,
};
use task::task_struct;
use perf_event::bpf_perf_event_data as native_bpf_perf_event_data;

pub struct ProcessPerfCounterEntry {
    pub prev_counter: u64,
    pub proc_counter: u64,
}

static START_TIME_KEY: u64 = 0;
static SAMEPLE_RATE_KEY: u64 = 1;
static MS_IN_NS: u64 = 1000000;

#[map]
static SETTINGS_MAP: HashMap<u64, u64> = HashMap::with_max_entries(2, 0);

#[map]
static PROC_MAP: PerCpuHashMap<u64, ProcessPerfCounterEntry> = PerCpuHashMap::with_max_entries(1024, 0);

#[map]
static TOTAL_CYCLES_MAP: Array<u64> = Array::with_max_entries(262144, 0);

#[perf_event]
pub fn observe_cpu_clock(ctx: PerfEventContext) -> u32 {
    match try_observe_cpu_clock(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn get_current_bucket() -> u32 {
    let mut current_bucket = 0;
    let timestamp = unsafe { bpf_ktime_get_boot_ns() };

    match unsafe { SETTINGS_MAP.get(&START_TIME_KEY) } {
        None => {
            match SETTINGS_MAP.insert(&START_TIME_KEY, &timestamp, 0) {
                Ok(_) => {},
                Err(_) => { return current_bucket }
            }
        },
        Some(i) => {
            // TODO: replace 500 by sample rate
            current_bucket = ((timestamp - i) / MS_IN_NS / 500) as u32;
        }
    }

    current_bucket
}

fn try_observe_cpu_clock(ctx: PerfEventContext) -> Result<u32, u32> {
    // let cpu = unsafe { bpf_get_smp_processor_id() };
    // let prog_name =  bpf_get_current_comm().map_err(|e| e as u32)?;
    // let prog_name = unsafe { from_utf8_unchecked(&prog_name) };
    let mut task: *mut task_struct = unsafe { bpf_get_current_task_btf() as *mut task_struct };
    let read_value_ctx: *mut native_bpf_perf_event_data = ctx.as_ptr() as *mut native_bpf_perf_event_data;
    let mut value = bpf_perf_event_value { counter: 0, enabled: 0, running: 0 };
    let value_ptr = addr_of_mut!(value);

    unsafe { bpf_perf_prog_read_value(read_value_ctx as *mut bpf_perf_event_data, value_ptr, core::mem::size_of::<bpf_perf_event_value>() as u32); }

    for _ in 1..8 {
        let cur_pid = unsafe { (*task).pid } as u64;
        match cur_pid {
            0 => break,
            1 => break,
            10202 => {
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

                // info!(&ctx, "prog_name: {}", prog_name);
                // info!(&ctx, "pid: {}", cur_pid);
                // info!(&ctx, "cpu: {}", cpu);
                // info!(&ctx, "valuee: {}", proc_entry.proc_counter);
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
