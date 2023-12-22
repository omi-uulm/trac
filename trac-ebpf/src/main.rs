#![no_std]
#![no_main]

mod task;
mod perf_event;
mod net;

use aya_bpf::{
    helpers::{bpf_perf_prog_read_value, bpf_get_current_task_btf, bpf_ktime_get_boot_ns },
    macros::{ perf_event, tracepoint, map, xdp },
    bindings::{ bpf_perf_event_value, bpf_perf_event_data, xdp_action::{XDP_PASS, XDP_ABORTED} },
    programs::{ PerfEventContext, TracePointContext, XdpContext },
    BpfContext,
    maps::{ PerCpuHashMap, Array, HashMap },
};
use aya_log_ebpf::info;
use core::{ptr::addr_of_mut, mem::size_of};
use task::task_struct;
use perf_event::bpf_perf_event_data as native_bpf_perf_event_data;
use net::{xdp_md, ethhdr, iphdr, ipv6hdr, tcphdr, udphdr};

pub struct ProcessPerfCounterEntry {
    pub prev_counter: u64,
    pub proc_counter: u64,
}

pub struct NettraceSample {
	pub bytes: u64,
	pub count: u64,
}

static START_TIME_KEY: u64 = 0;
static SAMEPLE_RATE_KEY: u64 = 1;
static PID_KEY: u64 = 2;
static MS_IN_NS: u64 = 1000000;

static ETH_P_IP: u16 = (0x0800 as u16).to_be();
static ETH_P_IPV6: u16 = (0x86DD as u16).to_be();
static IPPROTO_TCP: u32 = 6;
static IPPROTO_UDP: u32 = 17;

#[map]
static SETTINGS_MAP: HashMap<u64, u64> = HashMap::with_max_entries(3, 0);

#[map]
static PROC_MAP: PerCpuHashMap<u64, ProcessPerfCounterEntry> = PerCpuHashMap::with_max_entries(1024, 0);

#[map]
static TOTAL_CYCLES_MAP: Array<u64> = Array::with_max_entries(262144, 0);

#[map]
static NETTRACE_MAP: Array<NettraceSample> = Array::with_max_entries(262144, 0);

#[perf_event]
pub fn observe_cpu_clock(ctx: PerfEventContext) -> u32 {
    match try_observe_cpu_clock(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn get_sample_rate() -> u64 {
    return match unsafe { SETTINGS_MAP.get(&SAMEPLE_RATE_KEY) } {
        None => 500,
        Some(i) => *i,
    }
}

fn get_current_bucket() -> u32 {
    let timestamp = unsafe { bpf_ktime_get_boot_ns() };

    match unsafe { SETTINGS_MAP.get(&START_TIME_KEY) } {
        None => 0,
        Some(i) => {
            // TODO: replace 500 by sample rate
            ((timestamp - i) / MS_IN_NS / get_sample_rate()) as u32
        }
    }
}

fn try_observe_cpu_clock(ctx: PerfEventContext) -> Result<u32, u32> {
    // let cpu = unsafe { bpf_get_smp_processor_id() };
    // let prog_name =  bpf_get_current_comm().map_err(|e| e as u32)?;
    // let prog_name = unsafe { from_utf8_unchecked(&prog_name) };
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

fn try_get_payload_size(ctx: XdpContext) -> u32 {
    let native_ctx = ctx.as_ptr() as *const xdp_md;
    let data_start = unsafe { (*native_ctx).data } as u64;
    let data_end = unsafe { (*native_ctx).data_end } as u64;
    let total = data_end - data_start;
    let mut hdr_len: u32;
    let mut h_proto: u32;
    let eth = data_start as *const ethhdr;

    hdr_len = size_of::<ethhdr>() as u32;

    if data_start + hdr_len as u64 > data_end {
        return 0;
    }

    h_proto = unsafe { (*eth).h_proto } as u32;
    if h_proto == ETH_P_IP as u32 {
        if data_start + hdr_len as u64 + size_of::<iphdr>() as u64 > data_end {
            h_proto = 0;
        } else {
            let iph = (data_start + hdr_len as u64) as *const iphdr;
            h_proto = unsafe { (*iph).protocol } as u32;
        }
    } else if h_proto == ETH_P_IPV6 as u32 {
        if data_start + hdr_len as u64 + size_of::<ipv6hdr>() as u64 > data_end {
            h_proto = 0;
        } else {
            let iph = (data_start + hdr_len as u64) as *const ipv6hdr;
            h_proto = unsafe { (*iph).nexthdr } as u32;
        }
    } else {
        return 0;
    }

    if h_proto == IPPROTO_TCP {
        let tcph: *const tcphdr;

        if data_start + hdr_len as u64 + size_of::<tcphdr>() as u64 > data_end {
            return 0;
        }

        tcph = (data_start + hdr_len as u64) as *const tcphdr;
        let doff = unsafe { (*tcph).doff() } as u64;
        if doff > 10 || data_start + hdr_len as u64 + doff * 4 > data_end {
            return 0;
        }

        hdr_len += (doff * 4) as u32;

        if hdr_len as u64 > total || hdr_len > 100 {
            return 0;
        }
    } else if h_proto == IPPROTO_UDP {
        if data_start + hdr_len as u64 + size_of::<udphdr>() as u64 > data_end {
            return 0;
        }

        hdr_len += size_of::<udphdr>() as u32;
    } else {
        return 0
    }

    return total as u32 - hdr_len;
}

#[xdp]
pub fn observe_iface(ctx: XdpContext) -> u32 {
    match unsafe { try_observe_iface(ctx) } {
        Ok(ret) => ret,
        Err(_) => XDP_ABORTED,
    }
}

unsafe fn try_observe_iface(ctx: XdpContext) -> Result<u32, u32> {
    let bucket = get_current_bucket();

    let pkt_len = try_get_payload_size(ctx);

    if pkt_len == 0 {
        return Err(XDP_PASS);
    }

    match NETTRACE_MAP.get_ptr_mut(bucket) {
        None => {},
        Some(i) => {
            (*i).bytes += pkt_len as u64;
            (*i).count += 1;
        },
    };

    Ok(XDP_PASS)
}


#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
