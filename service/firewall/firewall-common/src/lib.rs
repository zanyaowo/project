#![no_std]
use core::prelude::rust_2024::*;

pub mod session;
pub mod constants;

pub mod protocol;
pub mod model;

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



