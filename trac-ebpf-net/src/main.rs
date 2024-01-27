#![no_std]
#![no_main]

mod net;

use aya_bpf::{
    macros::{ map, xdp },
    bindings::xdp_action::XDP_PASS,
    programs::XdpContext,
    BpfContext,
    maps::Array,
};
use core::mem::size_of;
use net::{xdp_md, ethhdr, iphdr, ipv6hdr, tcphdr, udphdr};
use trac_profiling_macros::{ profiling, profiling_maps_def };
use trac_common::*;
use trac_ebpf::bpf_defaults;

#[map]
static NETTRACE_MAP: Array<NettraceSample> = Array::with_max_entries(262144, 0);

profiling_maps_def!();

bpf_defaults!();

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
#[profiling]
pub fn observe_iface(ctx: XdpContext) -> u32 {
    match unsafe { try_observe_iface(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
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
