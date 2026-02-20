#![no_std]
#![no_main]

mod collector;
mod blocker;
mod table;
mod parser;
mod syn_cookie;

use core::mem::size_of;

use aya_ebpf::{
    bindings::xdp_action,
    macros::xdp,
    macros::classifier,
    programs::XdpContext,
};
use aya_ebpf::bindings::{TC_ACT_OK, TC_ACT_UNSPEC, TC_ACT_SHOT};
use aya_ebpf::programs::TcContext;
use network_types::eth::EthHdr;
use network_types::ip::{Ipv4Hdr, IpProto};
use crate::parser::{parse_packet, PacketInfo};
use crate::table::{update_session, SessionUpdateParams};

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match unsafe { try_xdp_firewall(ctx) } {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match unsafe { try_tc_egress(ctx) } {
        Ok(tc_action) => tc_action,
        Err(_) => TC_ACT_UNSPEC as i32,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

unsafe fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let pkt: PacketInfo = match parse_packet(&ctx) {
        Ok(packet) => packet,
        Err(_) => return Ok(xdp_action::XDP_PASS),
    };

    if pkt.flags == 0x0002 {
        return syn_cookie::send_syn_cookie(&ctx);
    }

    if blocker::is_blocked(pkt.src_ip) {
        return Ok(xdp_action::XDP_DROP);
    }

    let params = SessionUpdateParams::from(&pkt);
    update_session(&params);

    collector::submit_event(&params);

    Ok(xdp_action::XDP_PASS)
}

unsafe fn try_tc_egress(ctx: TcContext) -> Result<i32, ()> {
    // TC 負責補齊TX資料
    let pkt: PacketInfo = match parse_packet(&ctx) {
        Ok(packet) => packet,
        Err(_) => return Ok(TC_ACT_OK),
    };

    if blocker::is_blocked(pkt.dst_ip) {
        return Ok(TC_ACT_SHOT);
    }

    let params = SessionUpdateParams::from(&pkt);

    update_session(&params);

    Ok(TC_ACT_OK)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
