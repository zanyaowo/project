use aya_ebpf::{
    maps::LruPerCpuHashMap,
    macros::map,
    helpers::bpf_ktime_get_ns
};
use firewall_common::{SessionKey, SessionValue};
use crate::PacketInfo;

const SESSION_MAP_SIZE: u32 = 2048;

#[map]
pub static mut SESSIONS: LruPerCpuHashMap<SessionKey, SessionValue> = LruPerCpuHashMap::with_max_entries(SESSION_MAP_SIZE, 0);

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
        SessionUpdateParams{
            src_ip: packet.src_ip,
            dst_ip: packet.dst_ip,
            src_port: packet.src_port,
            dst_port: packet.dst_port,
            proto: packet.proto,
            len: packet.len,
            payload_len: packet.payload_len,
            flag: packet.flags,
        }
    }
}

//更新session
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

            if (params.flag & 0x04 != 0) || (params.flag & 0x01 != 0){
                (*session).is_close = true;
            }
            true
        }else if let Some(session) = SESSIONS.get_ptr_mut(&rev_key){
            (*session).resp_pkts += 1;
            (*session).resp_bytes += params.payload_len;
            (*session).resp_ip_bytes += params.len;
            (*session).last_seen_ts = bpf_ktime_get_ns();
            (*session).flag = params.flag;

            if (params.flag & 0x04 != 0) || (params.flag & 0x01 != 0){
                (*session).is_close = true;
            }
            true
        }else {
            let mut is_close = false;
            if (params.flag & 0x04 != 0) || (params.flag & 0x01 != 0){
                is_close = true;
            }

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
