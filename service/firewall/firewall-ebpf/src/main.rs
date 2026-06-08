#![no_std]
#![no_main]

mod blocker;
mod collector;
mod parser;
mod scorer;
mod syn_cookie;
mod table;

use crate::parser::{parse_packet, PacketInfo};
use crate::table::{update_session, SessionUpdateParams};
use aya_ebpf::bindings::{TC_ACT_OK, TC_ACT_SHOT};
use aya_ebpf::programs::TcContext;
use aya_ebpf::{bindings::xdp_action, macros::classifier, macros::xdp, programs::XdpContext};
use firewall_common::constants::{TCP_FLAG_ACK, TCP_FLAG_SYN};
use firewall_common::model::ScoreResult;
use firewall_common::protocol::L4Info;
use firewall_common::session::SessionValue;

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
    let mut pkt = PacketInfo::default();
    // Bounds + length are read here (concrete context, inlined) and passed as
    // scalars; see parse_packet for why they must not be derived inside it.
    // For TC, total_len is the skb length, which differs from data_end - data.
    let total_len = ctx.len() as u64;
    if !parse_packet(ctx.data(), ctx.data_end(), total_len, &mut pkt) {
        return TC_ACT_OK as i32;
    }

    if blocker::is_blocked(pkt.dst_ip) {
        return TC_ACT_SHOT as i32;
    }

    if matches!(pkt.l4_info, L4Info::Unknown) {
        return TC_ACT_OK as i32;
    }

    let params = SessionUpdateParams::from(&pkt);
    let mut session_value = SessionValue::default();
    update_session(&params, &mut session_value);

    TC_ACT_OK as i32
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let mut pkt = PacketInfo::default();
    // Bounds + length are read here (concrete context, inlined) and passed as
    // scalars; see parse_packet for why they must not be derived inside it.
    let start = ctx.data();
    let end = ctx.data_end();
    let total_len = (end - start) as u64;
    if !parse_packet(start, end, total_len, &mut pkt) {
        // Preserve prior `?` semantics: parse failure → Err → XDP_ABORTED.
        return Err(());
    }

    if blocker::is_blocked(pkt.src_ip) {
        return Ok(xdp_action::XDP_DROP);
    }

    // SYN-cookie fast path is IPv4-only: send_syn_cookie rewrites an IPv4
    // header in place and XDP_TX's it, so it must not run for IPv6 packets.
    // IPv6 TCP falls through to normal session tracking.
    if let L4Info::Tcp(tcp) = pkt.l4_info {
        if !pkt.is_ipv6 {
            if tcp.flags == TCP_FLAG_SYN {
                return Ok(syn_cookie::send_syn_cookie(&ctx)?);
            } else if tcp.flags == TCP_FLAG_ACK {
                // Cookie hashes the 32-bit IPv4 address; recover it from the
                // IPv4-mapped key (last 4 bytes are the address, network order).
                let src32 = u32::from_be_bytes([
                    pkt.src_ip[12],
                    pkt.src_ip[13],
                    pkt.src_ip[14],
                    pkt.src_ip[15],
                ]);
                let dst32 = u32::from_be_bytes([
                    pkt.dst_ip[12],
                    pkt.dst_ip[13],
                    pkt.dst_ip[14],
                    pkt.dst_ip[15],
                ]);
                let cookie = syn_cookie::calculate_cookie(
                    src32,
                    dst32,
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
    }

    let params = SessionUpdateParams::from(&pkt);
    let mut session_value = SessionValue::default();

    let mut score = 0i32;
    if update_session(&params, &mut session_value) {
        let mut result = ScoreResult {
            score: 0,
            action: 0,
        };
        if scorer::score_session(&session_value, pkt.proto, &mut result) {
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
