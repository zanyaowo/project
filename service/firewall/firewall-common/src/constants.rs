// protocol
pub const TCP_FLAG_FIN: u8 = 0x01;
pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_RST: u8 = 0x04;
pub const TCP_FLAG_ACK: u8 = 0x10;
pub const ETH_IPV4: u16 = 0x0800;
pub const ETH_IPV6: u16 = 0x86DD;
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_ICMP_V6: u8 = 58;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

// eBPF Map size
core::include!(core::concat!(env!("OUT_DIR"), "/map_sizes.rs"));
