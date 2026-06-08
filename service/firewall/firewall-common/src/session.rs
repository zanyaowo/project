#[repr(C)]
#[derive(Copy, Clone)]
pub struct SessionEvent {
    pub key: SessionKey,
    pub timestamp: u64,
    pub len: u16,
    pub flag: u8,
    pub score: i32,
    pub padding: [u8; 1],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SessionEvent {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SessionKey {
    // Addresses are stored as 16-byte IPv6 form. IPv4 flows use the
    // IPv4-mapped representation (::ffff:a.b.c.d) so a single key type
    // serves both stacks. See `ipv4_mapped` / `key_bytes_to_ip`.
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub _padding: [u8; 3],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SessionKey {}

/// Build the IPv4-mapped IPv6 address `::ffff:a.b.c.d` from 4 raw IPv4 bytes
/// (network byte order). Lets IPv4 flows share the 16-byte key/blocklist
/// types with native IPv6 flows.
#[inline(always)]
pub const fn ipv4_mapped(addr: [u8; 4]) -> [u8; 16] {
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, addr[0], addr[1], addr[2], addr[3],
    ]
}

/// Convert a userspace `IpAddr` into the 16-byte key form used by the
/// kernel maps (IPv4 → IPv4-mapped, IPv6 → raw octets).
#[cfg(feature = "user")]
pub fn ip_to_key_bytes(ip: std::net::IpAddr) -> [u8; 16] {
    match ip {
        std::net::IpAddr::V4(v4) => ipv4_mapped(v4.octets()),
        std::net::IpAddr::V6(v6) => v6.octets(),
    }
}

/// Inverse of [`ip_to_key_bytes`]: an IPv4-mapped key decodes back to an
/// `IpAddr::V4`, anything else to `IpAddr::V6`.
#[cfg(feature = "user")]
pub fn key_bytes_to_ip(bytes: [u8; 16]) -> std::net::IpAddr {
    let v6 = std::net::Ipv6Addr::from(bytes);
    match v6.to_ipv4_mapped() {
        Some(v4) => std::net::IpAddr::V4(v4),
        None => std::net::IpAddr::V6(v6),
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SessionValue {
    // 累積總流量
    pub orig_bytes: u64,
    pub resp_bytes: u64,

    // 累積數量
    pub orig_pkts: u64,
    pub resp_pkts: u64,

    // 時間
    pub start_ts: u64,
    pub last_seen_ts: u64,

    // 封包資訊
    pub pkt_sum_sq: u64,
    pub max_pkt_len: u32,

    // 連線狀態和padding
    pub score: i32,
    pub flag: u8,
    pub is_close: bool,
    pub _padding: [u8; 6],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SessionValue {}
