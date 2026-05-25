use aya_ebpf::maps::Array;
use aya_ebpf::programs::XdpContext;
use aya_ebpf::{bindings::xdp_action, macros::map};
use core::mem;
use network_types::eth::EthHdr;
use network_types::ip::Ipv4Hdr;
use network_types::tcp::TcpHdr;

const ETH_HDR_LEN: usize = mem::size_of::<EthHdr>();
const IP_HDR_LEN: usize = mem::size_of::<Ipv4Hdr>();
const TCP_HDR_LEN: usize = mem::size_of::<TcpHdr>();


#[map]
static mut SECRET_KEY: Array<u32> = Array::with_max_entries(1, 0);

#[inline(always)]
pub fn calculate_cookie(src: u32, dst: u32, sport: u16, dport: u16, proto: u8) -> u32 {
    let secret = unsafe { SECRET_KEY.get(0).unwrap_or(&0) };
    // Jenkins-like Hash / MurmurHash3 Mixer
    let mut h = *secret;
    h = h.wrapping_add(src);
    h = h.wrapping_add(dst);
    h = h.wrapping_add(((sport as u32) << 16) | (dport as u32));
    h = h.wrapping_add(proto as u32);

    // Mixer function for better bit distribution
    h ^= h >> 16;
    h = h.wrapping_mul(0x85ebca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2ae35);
    h ^= h >> 16;
    h
}

// RFC1624: Incremental Internet Checksum
// 用於更新 TCP checksum 而無需重新計算整個封包
// Formula: HC' = ~(C + (-m) + m') = ~(~HC + ~m + m')
fn update_checksum(old_csum: u16, old_val: u32, new_val: u32) -> u16 {
    let mut sum = !old_csum as u32;

    sum = sum.wrapping_add(!(old_val >> 16) as u16 as u32);
    sum = sum.wrapping_add(!(old_val & 0xFFFF) as u16 as u32);

    sum = sum.wrapping_add((new_val >> 16) as u16 as u32);
    sum = sum.wrapping_add((new_val & 0xFFFF) as u16 as u32);

    // Two folds suffice: max initial sum is 5×0xFFFF, fold 1 ≤ 0x10003, fold 2 ≤ 0xFFFF.
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);

    !(sum as u16)
}

#[inline(always)]
pub fn send_syn_cookie(ctx: &XdpContext) -> Result<u32, ()> {
    let data_end = ctx.data_end();
    let data = ctx.data();

    if data + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN > data_end {
        return Err(());
    }

    let eth = unsafe { &mut *(data as *mut EthHdr) };
    let ip = unsafe { &mut *((data + ETH_HDR_LEN) as *mut Ipv4Hdr) };
    let tcp = unsafe { &mut *((data + ETH_HDR_LEN + IP_HDR_LEN) as *mut TcpHdr) };

    let src_ip = u32::from_be_bytes(ip.src_addr);
    let dst_ip = u32::from_be_bytes(ip.dst_addr);
    let src_port = u16::from_be_bytes(tcp.source);
    let dst_port = u16::from_be_bytes(tcp.dest);
    let proto = ip.proto as u8;
    let seq = u32::from_be_bytes(tcp.seq);

    let cookie = calculate_cookie(src_ip, dst_ip, src_port, dst_port, proto);

    // 地址交換之後XDP_TX
    let tmp_mac = eth.src_addr;
    eth.src_addr = eth.dst_addr;
    eth.dst_addr = tmp_mac;

    let tmp_ip = ip.src_addr;
    ip.src_addr = ip.dst_addr;
    ip.dst_addr = tmp_ip;

    let tmp_port = tcp.source;
    tcp.source = tcp.dest;
    tcp.dest = tmp_port;

    // Capture the actual 16-bit data-offset+flags word BEFORE modifying the flags.
    // TCP offset 12–13: [doff<<4 | reserved, flags_byte].
    // Using the real word (not a zero-extended flags constant) is correct per RFC 1624
    // even though the result is mathematically identical when doff is unchanged.
    let doff_flags_off = ETH_HDR_LEN + IP_HDR_LEN + 12;
    let old_doff_flags: u32 = unsafe {
        let hi = *((data + doff_flags_off) as *const u8) as u32;
        let lo = *((data + doff_flags_off + 1) as *const u8) as u32;
        (hi << 8) | lo
    };

    tcp.set_syn(1);
    tcp.set_ack(1);

    tcp.ack_seq = u32::to_be_bytes(seq + 1);
    tcp.seq = u32::to_be_bytes(cookie);

    let new_doff_flags: u32 = unsafe {
        let hi = *((data + doff_flags_off) as *const u8) as u32;
        let lo = *((data + doff_flags_off + 1) as *const u8) as u32;
        (hi << 8) | lo
    };

    let mut csum = u16::from_be_bytes(tcp.check);
    csum = update_checksum(csum, seq, cookie);
    csum = update_checksum(csum, 0, seq + 1);
    csum = update_checksum(csum, old_doff_flags, new_doff_flags);

    tcp.check = u16::to_be_bytes(csum);

    Ok(xdp_action::XDP_TX)
}
