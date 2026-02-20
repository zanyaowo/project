#![no_std]

#[derive(Copy, Clone)]
pub struct ModelFeature {
    pub duration: u64, // 持續時間
    pub orig_bytes: u64, // 發送端位元組
    pub resp_bytes: u64,
    pub orig_pkts: u64,
    pub resp_pkts: u64,
    pub orig_ip_bytes: u64,
    pub resp_ip_bytes: u64,
    pub history_len: u64,
    pub bytes_sum: u64,
    pub pkts_sum: u64,
    pub bytes_ratio: u64,
    pub pkts_ratio: u64,
    pub bps_approx: u64,
    pub proto_h: u8, // 協定雜湊值 (mod 16)
    pub service_h: u8, // 服務雜湊值 (mod 128)
    pub _padding: [u8; 6], // 補齊 8 bytes 對齊 (2 bytes u8 + 6 bytes padding = 8 bytes)
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SessionEvent{
    pub key: SessionKey,
    pub timestamp: u64,
    pub len: u16,
    pub flag: u8,
    pub padding: [u8; 5],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SessionEvent {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SessionKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub _padding: [u8; 3], // 補齊 4 bytes 對齊
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SessionKey {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SessionValue {
    // 累積總流量
    pub orig_bytes: u64,
    pub resp_bytes: u64,

    // 累積數量
    pub orig_pkts: u64,
    pub resp_pkts: u64,

    // 累積流量（network layer）
    pub orig_ip_bytes: u64,
    pub resp_ip_bytes: u64,

    // 時間
    pub start_ts: u64,
    pub last_seen_ts: u64,

    // 連線狀態和padding
    pub flag: u8,
    pub is_close: bool,
    pub _padding: [u8; 6], // 補齊 8 bytes 對齊
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SessionValue {}

#[repr(C)]
#[derive(Copy, Clone)]
pub enum L4Packet{
    Tcp(TcpInfo),
    Udp(UdpInfo),
    Icmp(IcmpInfo),
    Unknown,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct TcpInfo{
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: u8,
    pub header_len: u64,
    pub padding: [u8; 3],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct UdpInfo{
    pub src_port: u16,
    pub dst_port: u16,
    pub header_len: u64,
    pub padding: [u8; 4],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct IcmpInfo {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub icmp_id: u16,
    pub icmp_seq: u16,
    pub header_len: u64,
    pub padding: [u8; 2],
}
