use core::mem::size_of;
use aya_ebpf::programs::{TcContext, XdpContext};
use network_types::eth::EthHdr;
use network_types::icmp::IcmpHdr;
use network_types::ip::{Ipv4Hdr, IpProto, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;
use firewall_common::{IcmpInfo, L4Packet, TcpInfo, UdpInfo};
use crate::syn_cookie::calculate_cookie;
const ETH_IPV4: u16 = 0x0800;
const ETH_IPV6: u16 = 0x86DD;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMP_V6: u8 = 58;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

pub struct PacketInfo {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub len: u64,
    pub flags: u8,
    pub payload_len: u64,

    pub icmp_type: u8,
    pub icmp_code: u8,
}

pub trait PacketContext {
    fn len(&self) -> u32;
    fn data_start(&self) -> usize;
    fn data_end(&self) -> usize;
}

impl PacketContext for XdpContext {
    fn len(&self) -> u32 {
        (self.data_end() - self.data()) as u32
    }

    fn data_start(&self) -> usize {
        self.data()
    }

    fn data_end(&self) -> usize {
        self.data_end()
    }
}

impl PacketContext for TcContext {
    fn len(&self) -> u32 {
        self.len()
    }

    fn data_start(&self) -> usize {
        self.data()
    }

    fn data_end(&self) -> usize {
        self.data_end()
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(start: usize, end: usize, offset: usize) -> Result<*const T, ()> {
    let len = size_of::<T>();

    if start.wrapping_add(offset).wrapping_add(len) > end {
        return Err(());
    }

    Ok((start.wrapping_add(offset)) as *const T)
}

pub unsafe fn parse_eth<C: PacketContext>(ctx: &C) -> Result<(u16, usize), ()> {
    let eth_hdr: *const EthHdr = ptr_at(ctx.data_start(), ctx.data_end(), 0)?;
    let eth_type = u16::from_be((*eth_hdr).ether_type);
    Ok((eth_type, size_of::<EthHdr>()))
}

pub unsafe fn parse_ipv4<C: PacketContext>(ctx: &C, offset: usize) -> Result<(Ipv4Hdr, usize), ()> {
    let ipv4_hdr: *const Ipv4Hdr = ptr_at(ctx.data_start(), ctx.data_end(), offset)?;
    Ok((*ipv4_hdr, offset + size_of::<Ipv4Hdr>()))
}

pub unsafe fn parse_ipv6<C: PacketContext>(ctx: &C, offset: usize) -> Result<(Ipv6Hdr, usize), ()> {
    let hdr: *const Ipv6Hdr = ptr_at(ctx.data_start(), ctx.data_end(), offset)?;
    Ok((*hdr, offset + size_of::<Ipv6Hdr>()))
}

pub unsafe fn parse_l4<C: PacketContext>(ctx: &C, offset: usize, proto: u8) -> Result<L4Packet, ()> {
    match proto {
        IPPROTO_TCP => {
            let tcp_hdr: *const TcpHdr = ptr_at(ctx.data_start(), ctx.data_end(), offset)?;
            let src_port = u16::from_be_bytes((*tcp_hdr).source);
            let dst_port = u16::from_be_bytes((*tcp_hdr).dest);
            let flag_ptr: *const u8 = ptr_at(ctx.data_start(), ctx.data_end(), offset + 13)?;
            let flags: u8 = *flag_ptr;

            let offset_byte: u8 = *ptr_at(ctx.data_start(), ctx.data_end(), offset + 12)?;
            let data_offset = (offset_byte & 0xF0) >> 4;
            let header_len = (data_offset as usize) * 4;

            Ok(L4Packet::Tcp(TcpInfo{src_port, dst_port, flags, header_len: header_len as u64, padding: [0; 3] }))
        }
        IPPROTO_UDP => {
            let udp_hdr: *const UdpHdr = ptr_at(ctx.data_start(), ctx.data_end(), offset)?;
            let src_port = u16::from_be_bytes((*udp_hdr).src);
            let dst_port = u16::from_be_bytes((*udp_hdr).dst);
            let header_len = (size_of::<UdpHdr>()) as u64;

            Ok(L4Packet::Udp(UdpInfo{src_port, dst_port, header_len, padding: [0; 4] }))
        }
        IPPROTO_ICMP | IPPROTO_ICMP_V6 => {
            let icmp_hdr: *const IcmpHdr = ptr_at(ctx.data_start(), ctx.data_end(), offset)?;
            let icmp_type = (*icmp_hdr).type_;
            let icmp_code = (*icmp_hdr).code;
            let mut icmp_id = 0;
            let mut icmp_seq = 0;

            if icmp_type == 8 || icmp_type == 0 {
                 if let Ok(id_ptr) = ptr_at::<u16>(ctx.data_start(), ctx.data_end(), offset + 4) {
                     icmp_id = u16::from_be(*id_ptr);
                 }
                 if let Ok(seq_ptr) = ptr_at::<u16>(ctx.data_start(), ctx.data_end(), offset + 6) {
                     icmp_seq = u16::from_be(*seq_ptr);
                 }
            }

            Ok(L4Packet::Icmp(IcmpInfo{icmp_type, icmp_code, icmp_id, icmp_seq, padding: [0; 2], header_len: (size_of::<IcmpHdr>()) as u64}))
        }
        _ => Err(()),
    }
}

pub unsafe fn parse_packet<C: PacketContext>(ctx: &C) -> Result<PacketInfo, ()> {
    let (eth_type, l3_offset) = parse_eth(ctx)?;
    let mut ip_header_len = 0;

    let (src_ip, dst_ip, proto, l4_offset) = match eth_type {
        ETH_IPV4 => {
            let (ipv4_hdr, l4_offset): (Ipv4Hdr, usize) = parse_ipv4(ctx, l3_offset)?;
            let src_ip = u32::from_be_bytes(ipv4_hdr.src_addr);
            let dst_ip = u32::from_be_bytes(ipv4_hdr.dst_addr);
            ip_header_len = ((ipv4_hdr.vihl & 0x0F) as usize) * 4;

            let proto_u8 = match ipv4_hdr.proto {
                IpProto::Tcp => IPPROTO_TCP,
                IpProto::Udp => IPPROTO_UDP,
                IpProto::Icmp => IPPROTO_ICMP,
                _ => 0,
            };

            (src_ip, dst_ip, proto_u8, l4_offset)
        },
        ETH_IPV6 => {
             return Err(());
        },
        _ => return Err(()),
    };

    let l4_packet = parse_l4(ctx, l4_offset, proto).unwrap_or(L4Packet::Unknown);

    let (src_port, dst_port, flags, l4_header_len, icmp_type, icmp_code) = match l4_packet {
        L4Packet::Tcp(t) => (t.src_port, t.dst_port, t.flags, t.header_len as usize, 0, 0),
        L4Packet::Udp(u) => (u.src_port, u.dst_port, 0, u.header_len as usize, 0, 0),
        L4Packet::Icmp(i) => (i.icmp_id, i.icmp_seq, 0, i.header_len as usize, i.icmp_type, i.icmp_code),
        _ => (0, 0, 0, 0, 0, 0),
    };

    let total_len = ctx.len() as u64;

    let header_len = (l3_offset + ip_header_len + l4_header_len) as u64;
    let payload_len = if total_len > header_len {
        total_len - header_len
    } else {
        0
    };

    let packet = PacketInfo {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto,
        len: total_len,
        payload_len,
        flags,
        icmp_type,
        icmp_code,
    };

    Ok(packet)
}
