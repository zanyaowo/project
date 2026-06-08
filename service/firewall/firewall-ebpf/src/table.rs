use crate::PacketInfo;
use aya_ebpf::{helpers::bpf_ktime_get_ns, macros::map, maps::LruPerCpuHashMap};
use firewall_common::constants::{SESSION_TABLE_SIZE, TCP_FLAG_FIN, TCP_FLAG_RST};
use firewall_common::protocol::L4Info;
use firewall_common::session::{SessionKey, SessionValue};

// Not `static mut`: aya map types provide interior mutability (their methods take
// `&self`), so a plain `static` avoids the Rust 2024 "shared reference to mutable
// static" hazard. The `unsafe` blocks below remain — they cover the raw-pointer
// deref from `get_ptr_mut`, not the map access itself.
#[map]
pub static SESSIONS: LruPerCpuHashMap<SessionKey, SessionValue> =
    LruPerCpuHashMap::with_max_entries(SESSION_TABLE_SIZE, 0);

pub struct SessionUpdateParams {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub len: u64,
    pub payload_len: u64,
    pub flag: u8,
}

impl From<&PacketInfo> for SessionUpdateParams {
    fn from(packet: &PacketInfo) -> Self {
        let src_ip = packet.src_ip;
        let dst_ip = packet.dst_ip;
        let proto = packet.proto;
        let (src_port, dst_port, flag) = match packet.l4_info {
            L4Info::Tcp(tcp) => (tcp.src_port, tcp.dst_port, tcp.flags),
            L4Info::Udp(udp) => (udp.src_port, udp.dst_port, 0),
            L4Info::Icmp(icmp) => (icmp.icmp_id, icmp.icmp_seq, 0),
            L4Info::Unknown => (0, 0, 0),
        };

        SessionUpdateParams {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto,
            len: packet.len as u64,
            payload_len: packet.payload_len,
            flag,
        }
    }
}

impl From<&SessionUpdateParams> for SessionKey {
    fn from(params: &SessionUpdateParams) -> Self {
        SessionKey {
            src_ip: params.src_ip,
            dst_ip: params.dst_ip,
            src_port: params.src_port,
            dst_port: params.dst_port,
            proto: params.proto,
            _padding: [0; 3],
        }
    }
}

fn is_connection_closed(flag: u8) -> bool {
    if (flag & TCP_FLAG_RST != 0) || (flag & TCP_FLAG_FIN != 0) {
        return true;
    };
    false
}

// 更新 session。結果寫入 `out`，回傳 `true` 表示有產生 SessionValue。
//
// 回傳 scalar（bool）而非 `Option<SessionValue>`：這讓本函式維持為真正的
// BPF-to-BPF call、擁有自己的 stack frame，兩個 40-byte SessionKey 與
// new SessionValue 不再堆到 XDP caller 的 frame 上（位址改成 16-byte 後
// 撞上 BPF 512-byte stack 上限）。aggregate return 在此 toolchain 不被支援，
// 故用 `&mut out` out-param + scalar return（同 tc_egress_impl 的 scalar 模式）。
#[inline(never)]
pub fn update_session(params: &SessionUpdateParams, out: &mut SessionValue) -> bool {
    let fwd_key = SessionKey {
        src_ip: params.src_ip,
        dst_ip: params.dst_ip,
        src_port: params.src_port,
        dst_port: params.dst_port,
        proto: params.proto,
        _padding: [0; 3],
    };

    unsafe {
        if let Some(session) = SESSIONS.get_ptr_mut(&fwd_key) {
            (*session).orig_pkts += 1;
            (*session).orig_bytes += params.payload_len;
            // Clamp len to u16 max before squaring: 65535^2 ≈ 4.3B fits in u32, never
            // overflows u64 here, and avoids any 128-bit intrinsic (__multi3-free).
            let sq = params.len.min(65535) * params.len.min(65535);
            (*session).pkt_sum_sq = (*session).pkt_sum_sq.saturating_add(sq);
            (*session).last_seen_ts = bpf_ktime_get_ns();
            (*session).flag = params.flag;
            (*session).is_close = is_connection_closed(params.flag);

            if (*session).max_pkt_len < params.len as u32 {
                (*session).max_pkt_len = params.len as u32;
            }

            *out = *session;
            return true;
        }

        // rev_key 只在 reverse/new 路徑建立，避免兩個 40-byte key 同時 live。
        let rev_key = SessionKey {
            src_ip: params.dst_ip,
            dst_ip: params.src_ip,
            src_port: params.dst_port,
            dst_port: params.src_port,
            proto: params.proto,
            _padding: [0; 3],
        };

        if let Some(session) = SESSIONS.get_ptr_mut(&rev_key) {
            (*session).resp_pkts += 1;
            (*session).resp_bytes += params.payload_len;
            let sq = params.len.min(65535) * params.len.min(65535);
            (*session).pkt_sum_sq = (*session).pkt_sum_sq.saturating_add(sq);
            (*session).last_seen_ts = bpf_ktime_get_ns();
            (*session).flag = params.flag;
            (*session).is_close = is_connection_closed(params.flag);

            if (*session).max_pkt_len < params.len as u32 {
                (*session).max_pkt_len = params.len as u32;
            }

            *out = *session;
            return true;
        }

        let is_close = is_connection_closed(params.flag);

        let new_session = SessionValue {
            orig_bytes: params.payload_len,
            orig_pkts: 1,
            resp_bytes: 0,
            resp_pkts: 0,
            pkt_sum_sq: params.len.min(65535) * params.len.min(65535),
            max_pkt_len: params.len as u32,
            start_ts: bpf_ktime_get_ns(),
            last_seen_ts: bpf_ktime_get_ns(),
            flag: params.flag,
            is_close,
            _padding: [0; 6],
            score: 0,
        };
        let _ = SESSIONS.insert(&fwd_key, &new_session, 0);

        *out = new_session;
        true
    }
}
