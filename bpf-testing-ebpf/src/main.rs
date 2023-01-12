#![no_std]
#![no_main]

use core::mem;

use bindings::arphdr;
use memoffset::offset_of;

use aya_bpf::{
    bindings::{TC_ACT_PIPE, BPF_F_NO_PREALLOC},
    helpers::bpf_redirect,
    macros::{classifier, map, sock_ops},
    maps::{Array, HashMap},
    programs::{SockOpsContext, TcContext},
};
use aya_log_ebpf::info;

use crate::bindings::{ethhdr, iphdr, udphdr};

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;

#[map(name = "tc_target_ifindex")]
static mut TGT_IFINDEX: Array<u32> = Array::with_max_entries(1, 0);

#[map(name = "arp_entries")]
static mut ARP_MAP: HashMap<u32, [u8; 6]> = HashMap::with_max_entries(1024, BPF_F_NO_PREALLOC);

#[map(name = "arp_self")]
static ARP_SELF: HashMap<u32, bool> = HashMap::with_max_entries(1024, BPF_F_NO_PREALLOC);

#[classifier(name = "tap_egress")]
pub fn tap_egress_classifier(_ctx: TcContext) -> i32 {
    TC_ACT_PIPE
}

#[classifier(name = "phys_ingress")]
pub fn phys_ingress_classifier(ctx: TcContext) -> i32 {
    // Optimize later on by not cloning
    // unsafe { bpf_redirect(0, 0); }

    // Clone & send SKB to the TAP device for our app to forward.
    if let Some(&ifindex) = unsafe { TGT_IFINDEX.get(0) } {
        match handle_pkt(ctx, ifindex) {
            Ok(e) => e,
            Err(e) => e,
        }
    } else {
        TC_ACT_PIPE
    }
}

const ETH_P_IP: u16 = 0x0800;
const ETH_P_ARP: u16 = 0x0806;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const ARP_HDR_LEN: usize = mem::size_of::<arphdr>();

const VCMP_PORT: u16 = 2426;

fn handle_ipv4(ctx: TcContext, ifindex: u32) -> Result<i32, i32> {
    let iph: iphdr = ctx.load(ETH_HDR_LEN).map_err(|_| TC_ACT_PIPE)?;
    let ihl = 4 * (iph.ihl() as usize);

    let spt = u16::from_be(
        ctx.load(ETH_HDR_LEN + ihl + offset_of!(udphdr, source))
            .map_err(|_| TC_ACT_PIPE)?,
    );
    let dpt = u16::from_be(
        ctx.load(ETH_HDR_LEN + ihl + offset_of!(udphdr, dest))
            .map_err(|_| TC_ACT_PIPE)?,
    );

    if spt == VCMP_PORT || dpt == VCMP_PORT {
        Ok(unsafe { bpf_redirect(ifindex, 0).try_into().unwrap() })
    } else {
        Err(TC_ACT_PIPE)
    }
}

const ARP_HLN_ETH: usize = 6;
const ARP_HRD_ETH: u16 = 1;
const ARP_PRO_IP: u16 = ETH_P_IP;
const ARP_PLN_IP: usize = 4;
const ARP_OP_REQ: u16 = 1;

// https://datatracker.ietf.org/doc/html/rfc826
// we sniff neighbor MAC<->IP bindings from ingress ARP traffic
// local MAC should come from static Map
fn handle_arp(ctx: TcContext) -> Result<i32, i32> {
    let hrd = u16::from_be(
        ctx.load(ETH_HDR_LEN + offset_of!(arphdr, ar_hrd))
            .map_err(|_| TC_ACT_PIPE)?,
    );
    let pro = u16::from_be(
        ctx.load(ETH_HDR_LEN + offset_of!(arphdr, ar_pro))
            .map_err(|_| TC_ACT_PIPE)?,
    );
    let hln = u8::from_be(
        ctx.load(ETH_HDR_LEN + offset_of!(arphdr, ar_hln))
            .map_err(|_| TC_ACT_PIPE)?,
    );
    let pln = u8::from_be(
        ctx.load(ETH_HDR_LEN + offset_of!(arphdr, ar_pln))
            .map_err(|_| TC_ACT_PIPE)?,
    );
    let op = u16::from_be(
        ctx.load(ETH_HDR_LEN + offset_of!(arphdr, ar_op))
            .map_err(|_| TC_ACT_PIPE)?,
    );

    if hrd == ARP_HRD_ETH && pro == ARP_PRO_IP && usize::from(hln) == ARP_HLN_ETH && usize::from(pln) == ARP_PLN_IP {
        let mut merge_flag = false;

        let mut sha = [0u8; ARP_HLN_ETH];
        ctx.load_bytes(ETH_HDR_LEN + ARP_HDR_LEN, &mut sha[..]).map_err(|_| TC_ACT_PIPE)?;

        let spa = u32::from_be(ctx.load(ETH_HDR_LEN + ARP_HDR_LEN + ARP_HLN_ETH as usize).map_err(|_| TC_ACT_PIPE)?);

        // if spa in translation table
        if unsafe { ARP_MAP.get(&spa) }.is_some() {
            // update translation table for this spa w/ the sha
            let _ = unsafe { ARP_MAP.insert(&spa, &sha, 0) };
            merge_flag = true;
        }

        let tpa = u32::from_be(ctx.load(ETH_HDR_LEN + ARP_HDR_LEN + ARP_HLN_ETH as usize + ARP_PLN_IP + ARP_HLN_ETH as usize).map_err(|_| TC_ACT_PIPE)?);
        // if tpa is us
        if unsafe { ARP_SELF.get(&tpa) }.is_some() {
            if !merge_flag {
                // add spa => sha to translation table
                let _ = unsafe { ARP_MAP.insert(&spa, &sha, 0) };
            }

            // is the op a request?
            if op == ARP_OP_REQ {
                // swap hardware & protocol fields (sender <-> target)
                // insert local hardware & protocol addresses into sender fields
                // set op to reply
                // swap MAC hdr source & destination addresses
                // insert local hardware address into MAC hdr source field
                // redirect back out the same interface it was received on
            }
        }
    }

    Ok(TC_ACT_PIPE)
}

fn handle_pkt(ctx: TcContext, ifindex: u32) -> Result<i32, i32> {
    let h_proto = u16::from_be(
        ctx.load(offset_of!(ethhdr, h_proto))
            .map_err(|_| TC_ACT_PIPE)?,
    );
    match h_proto {
        ETH_P_IP => handle_ipv4(ctx, ifindex),
        ETH_P_ARP => handle_arp(ctx),
        _ => Err(TC_ACT_PIPE),
    }
}

/* Below is the sock-ops sample */

#[sock_ops(name = "bpf_testing")]
pub fn bpf_testing(ctx: SockOpsContext) -> u32 {
    match try_bpf_testing(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_bpf_testing(ctx: SockOpsContext) -> Result<u32, u32> {
    info!(&ctx, "received TCP connection");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
