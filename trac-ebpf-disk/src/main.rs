#![no_std]
#![no_main]

mod task;

use aya_bpf::{
    helpers::bpf_get_current_task_btf,
    macros::{ tracepoint, map },
    programs::TracePointContext,
    BpfContext,
    maps::Array,
};
use task::task_struct;
use trac_profiling_macros::{ profiling, profiling_maps_def };
use trac_common::*;
use trac_ebpf::bpf_defaults;

#[map]
static DISK_IOPS_MAP: Array<DiskIOPSSample> = Array::with_max_entries(262144, 0);

profiling_maps_def!();

bpf_defaults!();

#[tracepoint]
#[profiling]
pub fn observe_disk(ctx: TracePointContext) -> u32 {
    match try_observe_disk(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_observe_disk(ctx: TracePointContext) -> Result<u32, u32> {
    let mut task: *mut task_struct = unsafe { bpf_get_current_task_btf() as *mut task_struct };
    let readable_ctx: *mut block_block_io_start_args = ctx.as_ptr() as *mut block_block_io_start_args;
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
                let current_bucket = get_current_bucket();

                match DISK_IOPS_MAP.get_ptr_mut(current_bucket) {
                    None => {},
                    Some(i) => {
                        unsafe { (*i).iops += 1 };
                        unsafe { (*i).bytes += (*readable_ctx).bytes as u64 };
                    }
                }
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
