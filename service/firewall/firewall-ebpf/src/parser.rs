use core::mem::size_of;
use aya_ebpf::programs::{TcContext, XdpContext};
use network_types::eth::EthHdr;
use network_types::icmp::IcmpHdr;
use network_types::ip::{Ipv4Hdr, IpProto, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;
use firewall_common::constants::{IPPROTO_ICMP, IPPROTO_ICMP_V6, IPPROTO_TCP, IPPROTO_UDP ,ETH_IPV4, ETH_IPV6};
use firewall_common::protocol::{IcmpInfo, L4Info, TcpInfo, UdpInfo};
pub struct PacketInfo {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub proto: u8,
    pub len: u16,
    pub payload_len: u64,
    pub l4_info: L4Info,
    pub padding: [u8; 5]
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

    Ok(start.wrapping_add(offset) as *const T)
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

pub unsafe fn parse_tcp<C: PacketContext>(ctx: &C, offset: usize) -> Result<TcpInfo, ()> {
    let tcp_hdr: *const TcpHdr = ptr_at(ctx.data_start(), ctx.data_end(), offset)?;
    let src_port = u16::from_be_bytes((*tcp_hdr).source);
    let dst_port = u16::from_be_bytes((*tcp_hdr).dest);
    let flag_ptr: *const u8 = ptr_at(ctx.data_start(), ctx.data_end(), offset + 13)?;
    let flags: u8 = *flag_ptr;
    let seq = u32::from_be_bytes((*tcp_hdr).seq);
    let ack_seq = u32::from_be_bytes((*tcp_hdr).ack_seq);
    let windows = u16::from_be_bytes((*tcp_hdr).window);

    let offset_byte: u8 = *ptr_at(ctx.data_start(), ctx.data_end(), offset + 12)?;
    let data_offset = (offset_byte & 0xF0) >> 4;
    let header_len = (data_offset * 4) as u8;

    Ok(TcpInfo{
        src_port,
        dst_port,
        flags,
        seq,
        ack_seq,
        windows,
        header_len,
    })
}

pub unsafe fn parse_udp<C: PacketContext>(ctx: &C, offset: usize) -> Result<UdpInfo, ()>{
    let udp_hdr: *const UdpHdr = ptr_at(ctx.data_start(), ctx.data_end(), offset)?;
    let src_port = u16::from_be_bytes((*udp_hdr).src);
    let dst_port = u16::from_be_bytes((*udp_hdr).dst);

    let header_len = size_of::<UdpHdr>() as u8;

    Ok(UdpInfo{src_port, dst_port, header_len, padding: [0; 3] })
}

pub unsafe fn parse_icmp<C: PacketContext>(ctx: &C, offset: usize) -> Result<IcmpInfo, ()>{
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

    Ok(IcmpInfo{icmp_type, icmp_code, icmp_id, icmp_seq, header_len: 8, padding: [0; 1]})
}

pub unsafe fn parse_packet<C: PacketContext>(ctx: &C) -> Result<PacketInfo, ()> {
    let (eth_type, l3_offset) = parse_eth(ctx)?;
    let mut ip_header_len = 0;
    let mut ip_total_len = 0;

    let (src_ip, dst_ip, proto, l4_offset) = match eth_type {
        ETH_IPV4 => {
            let (ipv4_hdr, l4_offset): (Ipv4Hdr, usize) = parse_ipv4(ctx, l3_offset)?;
            let src_ip = u32::from_be_bytes(ipv4_hdr.src_addr);
            let dst_ip = u32::from_be_bytes(ipv4_hdr.dst_addr);
            ip_header_len = ((ipv4_hdr.vihl & 0x0F) as usize) * 4;
            ip_total_len = u16::from_be_bytes(ipv4_hdr.tot_len);

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

    let l4_info = match proto {
        IPPROTO_TCP => {
            let tcp = parse_tcp(ctx, l4_offset)?;
            L4Info::Tcp(tcp)
        }
        IPPROTO_UDP => {
            let udp = parse_udp(ctx, l4_offset)?;
            L4Info::Udp(udp)
        }
        IPPROTO_ICMP | IPPROTO_ICMP_V6 => {
            let icmp = parse_icmp(ctx, l4_offset)?;
            L4Info::Icmp(icmp)
        }
        _ => L4Info::Unknown,
    };

    let l4_header_len = match &l4_info {
        L4Info::Tcp(tcp) => tcp.header_len as usize,
        L4Info::Udp(udp) => udp.header_len as usize,
        L4Info::Icmp(icmp) => icmp.header_len as usize,
        _ => 0,
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
        proto,
        len: ip_total_len,
        payload_len,
        l4_info,
        padding: [0; 5],
    };

    Ok(packet)
}
