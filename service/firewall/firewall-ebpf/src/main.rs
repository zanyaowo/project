#![no_std]
#![no_main]

use core::mem::size_of;
use core::ptr::addr_of_mut;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::RingBuf,
    programs::XdpContext,
};

use aya_log_ebpf::info;
use firewall_common::PacketLog;
use network_types::eth::EthHdr;
use network_types::ip::Ipv4Hdr;

#[map]
static mut PACKET_LOG: RingBuf = RingBuf::with_byte_size(4096, 0);

const ETH_P_IP: u16 = 0x0800;

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match unsafe { try_xdp_firewall(ctx) } {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = size_of::<T>();

    // 使用 wrapping_add 避免 Debug 模式下的溢位檢查 panic
    if start.wrapping_add(offset).wrapping_add(len) > end {
        return Err(());
    }

    Ok((start.wrapping_add(offset)) as *const T)
}

unsafe fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    info!(&ctx, "receive a packet");
    let eth_hdr: *const EthHdr = ptr_at(&ctx, 0)?;

    if u16::from_be((*eth_hdr).ether_type) == ETH_P_IP {
        let ipv4_hdr: *const Ipv4Hdr = ptr_at(&ctx, size_of::<EthHdr>())?;

        info!(&ctx, "IPv4 packet detected");

        // 使用 addr_of_mut! 避免直接對 static mut 建立參考 (Rust 2024 安全性)
        if let Some(mut events) = (*addr_of_mut!(PACKET_LOG)).reserve::<PacketLog>(0) {
            let event = events.as_mut_ptr();
            (*event).ip_addr = u32::from_be_bytes((*ipv4_hdr).src_addr);
            // 修正: 使用 wrapping_sub 避免減法溢位檢查 panic
            (*event).len = (ctx.data_end().wrapping_sub(ctx.data())) as u32;
            (*event).action = xdp_action::XDP_PASS; 

            events.submit(0);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
