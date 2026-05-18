use core::prelude::rust_2024::*;

#[repr(C)]
#[derive(Copy, Clone)]
pub enum L4Info {
    Tcp(TcpInfo),
    Udp(UdpInfo),
    Icmp(IcmpInfo),
    Unknown,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct TcpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: u8,
    pub seq: u32,
    pub ack_seq: u32,
    pub windows: u16,
    pub header_len: u8,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct UdpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub header_len: u8,
    pub padding: [u8; 3],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct IcmpInfo {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub icmp_id: u16,
    pub icmp_seq: u16,
    pub header_len: u8,
    pub padding: [u8; 1],
}
