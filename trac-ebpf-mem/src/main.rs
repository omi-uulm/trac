#![no_std]
#![no_main]

mod task;

use aya_bpf::{
    helpers::bpf_get_current_task_btf,
    macros::{ tracepoint, map },
    programs::TracePointContext,
    BpfContext,
    maps::{ Array, PerCpuHashMap },
};
use task::task_struct;
use trac_profiling_macros::{ profiling, profiling_maps_def };
use trac_common::*;
use trac_ebpf::bpf_defaults;

#[map]
static RSS_LAST_STATE_MAP: PerCpuHashMap<i32, RSSStatSample> = PerCpuHashMap::with_max_entries(100, 0);

#[map]
static RSS_STAT_MAP: Array<[i64; 4]> = Array::with_max_entries(262144, 0);

profiling_maps_def!();

bpf_defaults!();

#[tracepoint]
#[profiling]
pub fn observe_memory(ctx: TracePointContext) -> u32 {
    match try_observe_memory(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_observe_memory(ctx: TracePointContext) -> Result<u32, u32> {
    let mut task: *mut task_struct = unsafe { bpf_get_current_task_btf() as *mut task_struct };
    let pid = unsafe { (*task).pid };
    let readable_ctx: *mut kmem_rss_stat_args = ctx.as_ptr() as *mut kmem_rss_stat_args;
    let mtype = unsafe { (*readable_ctx).member } as usize;
    let size = unsafe { (*readable_ctx).size };
    let current_bucket = get_current_bucket();
    
    if mtype > 3 || size <= 0 {
        return Err(0);
    }

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
                match RSS_LAST_STATE_MAP.get_ptr_mut(&pid) {
                    None => {
                        let mut value = RSSStatSample{ previous: [0,0,0,0] };
                        value.previous[mtype] = size as u64;
                        _ = RSS_LAST_STATE_MAP.insert(&pid, &value, 0);
                    }
                    Some(state) => {
                        let diff = size - unsafe { (*state).previous[mtype] } as i64;
                        unsafe { (*state).previous[mtype] = size as u64 };

                        match RSS_STAT_MAP.get_ptr_mut(current_bucket) {
                            None => {}
                            Some(stat) => {
                                unsafe { (*stat)[mtype] += diff; }
                            }
                        }

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
