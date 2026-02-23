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