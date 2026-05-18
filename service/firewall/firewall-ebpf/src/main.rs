#![no_std]
#![no_main]

mod blocker;
mod collector;
mod parser;
mod scorer;
mod syn_cookie;
mod table;

use core::mem::size_of;

use crate::parser::{parse_packet, PacketInfo};
use crate::table::{update_session, SessionUpdateParams};
use aya_ebpf::bindings::xdp_action::XDP_PASS;
use aya_ebpf::bindings::{TC_ACT_OK, TC_ACT_SHOT, TC_ACT_UNSPEC};
use aya_ebpf::programs::TcContext;
use aya_ebpf::{bindings::xdp_action, macros::classifier, macros::xdp, programs::XdpContext};
use firewall_common::constants::{TCP_FLAG_ACK, TCP_FLAG_SYN};
use firewall_common::protocol::L4Info;
use firewall_common::session::SessionKey;

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

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let pkt: PacketInfo = parse_packet(&ctx)?;

    if let L4Info::Tcp(tcp) = pkt.l4_info {
        if tcp.flags == TCP_FLAG_SYN {
            return Ok(syn_cookie::send_syn_cookie(&ctx)?);
        } else if tcp.flags == TCP_FLAG_ACK {
            let cookie = syn_cookie::calculate_cookie(
                pkt.src_ip,
                pkt.dst_ip,
                tcp.src_port,
                tcp.dst_port,
                pkt.proto,
            );

            if cookie != tcp.ack_seq + 1 {
                return Ok(xdp_action::XDP_DROP);
            }
        }
    }

    if blocker::is_blocked(pkt.src_ip) {
        return Ok(xdp_action::XDP_DROP);
    }

    let params = SessionUpdateParams::from(&pkt);
    let session = update_session(&params);

    let mut score = 0i32;
    if let Some(session_value) = session {
        let key = SessionKey::from(&params);
        if let Some(result) = scorer::score_session(session_value, key) {
            score = result.score;

            if result.action == xdp_action::XDP_DROP {
                return Ok(xdp_action::XDP_DROP);
            }
        }
    }

    collector::submit_event(&params, score);

    Ok(xdp_action::XDP_PASS)
}

#[inline(never)]
unsafe fn try_tc_egress(ctx: TcContext) -> Result<i32, ()> {
    // TC 負責補齊TX資料
    let pkt: PacketInfo = match parse_packet(&ctx) {
        Ok(packet) => packet,
        Err(_) => return Ok(TC_ACT_OK as i32),
    };

    if blocker::is_blocked(pkt.dst_ip) {
        return Ok(TC_ACT_SHOT as i32);
    }

    // 直接構建參數以避免驗證器問題
    let (src_port, dst_port, flag) = match pkt.l4_info {
        L4Info::Tcp(tcp) => (tcp.src_port, tcp.dst_port, tcp.flags),
        L4Info::Udp(udp) => (udp.src_port, udp.dst_port, 0),
        L4Info::Icmp(icmp) => (icmp.icmp_id, icmp.icmp_seq, 0),
        L4Info::Unknown => (0, 0, 0),
    };

    let params = SessionUpdateParams {
        src_ip: pkt.src_ip,
        dst_ip: pkt.dst_ip,
        src_port,
        dst_port,
        proto: pkt.proto,
        len: pkt.len as u64,
        payload_len: pkt.payload_len,
        flag,
    };

    update_session(&params);

    Ok(TC_ACT_OK as i32)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
