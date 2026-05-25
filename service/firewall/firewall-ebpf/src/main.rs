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
use aya_ebpf::bindings::{TC_ACT_OK, TC_ACT_SHOT};
use aya_ebpf::programs::TcContext;
use aya_ebpf::{bindings::xdp_action, macros::classifier, macros::xdp, programs::XdpContext};
use firewall_common::constants::{TCP_FLAG_ACK, TCP_FLAG_SYN};
use firewall_common::protocol::L4Info;
use firewall_common::session::SessionKey;

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    unsafe { tc_egress_impl(&ctx) }
}

// Body lives in a separate function so register allocation isolates each
// match arm (same pattern try_xdp_firewall uses). Returning i32 instead of
// Result<i32, ()> avoids the "aggregate returns are not supported" rejection
// previously seen with #[inline(never)] on Result-returning helpers.
unsafe fn tc_egress_impl(ctx: &TcContext) -> i32 {
    let pkt: PacketInfo = match parse_packet(ctx) {
        Ok(p) => p,
        Err(_) => return TC_ACT_OK as i32,
    };

    if blocker::is_blocked(pkt.dst_ip) {
        return TC_ACT_SHOT as i32;
    }

    if matches!(pkt.l4_info, L4Info::Unknown) {
        return TC_ACT_OK as i32;
    }

    let params = SessionUpdateParams::from(&pkt);
    update_session(&params);

    TC_ACT_OK as i32
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

    if blocker::is_blocked(pkt.src_ip) {
        return Ok(xdp_action::XDP_DROP);
    }

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

            // Client's ACK seq must equal cookie + 1 (wrapping).
            if tcp.ack_seq.wrapping_sub(1) != cookie {
                return Ok(xdp_action::XDP_DROP);
            }
        }
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


#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
