use aya_ebpf::{
    maps::LruPerCpuHashMap,
    macros::map,
    helpers::bpf_ktime_get_ns
};
use firewall_common::constants::{SESSION_TABLE_SIZE, TCP_FLAG_FIN, TCP_FLAG_RST};
use firewall_common::protocol::L4Info;
use firewall_common::session::{SessionKey, SessionValue};
use crate::PacketInfo;

#[map]
pub static mut SESSIONS: LruPerCpuHashMap<SessionKey, SessionValue> = LruPerCpuHashMap::with_max_entries(SESSION_TABLE_SIZE, 0);

pub struct SessionUpdateParams {
    pub src_ip: u32,
    pub dst_ip: u32,
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

        SessionUpdateParams{
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

fn is_connection_closed(flag: u8) -> bool{
    if (flag & TCP_FLAG_RST != 0) || (flag & TCP_FLAG_FIN != 0){
        return true;
    };
    false
}

//更新session
#[inline(always)]
pub fn update_session(params: &SessionUpdateParams) -> bool {
    let fwd_key = SessionKey{
        src_ip: params.src_ip,
        dst_ip: params.dst_ip,
        src_port: params.src_port,
        dst_port: params.dst_port,
        proto: params.proto,
        _padding: [0; 3],
    };

    let rev_key = SessionKey{
        src_ip: params.dst_ip,
        dst_ip: params.src_ip,
        src_port: params.dst_port,
        dst_port: params.src_port,
        proto: params.proto,
        _padding: [0; 3],
    };

    unsafe{
        if let Some(session) = SESSIONS.get_ptr_mut(&fwd_key){
            (*session).orig_pkts += 1;
            (*session).orig_bytes += params.payload_len;
            (*session).orig_ip_bytes += params.len;
            (*session).last_seen_ts = bpf_ktime_get_ns();
            (*session).flag = params.flag;

            (*session).is_close = is_connection_closed(params.flag);
            true
        }else if let Some(session) = SESSIONS.get_ptr_mut(&rev_key){
            (*session).resp_pkts += 1;
            (*session).resp_bytes += params.payload_len;
            (*session).resp_ip_bytes += params.len;
            (*session).last_seen_ts = bpf_ktime_get_ns();
            (*session).flag = params.flag;

            (*session).is_close = is_connection_closed(params.flag);
            true
        }else {
            let mut is_close = false;
            is_close = is_connection_closed(params.flag);

            let new_session = SessionValue {
                orig_bytes: params.payload_len,
                orig_pkts: 1,
                orig_ip_bytes: params.len,
                resp_bytes: 0,
                resp_pkts: 0,
                resp_ip_bytes: 0,
                start_ts: bpf_ktime_get_ns(),
                last_seen_ts: bpf_ktime_get_ns(),
                flag: params.flag,
                is_close,
                _padding: [0; 6],
            };
            SESSIONS.insert(&fwd_key, &new_session, 0);
            true
        }
    }
}
