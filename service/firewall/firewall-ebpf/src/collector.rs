use core::ptr::addr_of_mut;
use aya_ebpf::{
    macros::map,
    maps::RingBuf,
    programs::XdpContext,
    helpers::bpf_ktime_get_ns
};
use network_types::ip::{IpProto, Ipv4Hdr};
use firewall_common::{SessionEvent, SessionKey, SessionValue};
use crate::table::{SessionUpdateParams, SESSIONS};

#[map]
static mut EVENTS_POOL: RingBuf = RingBuf::with_byte_size(4096, 0);

// Updated signature to take raw values instead of Ipv4Hdr struct
// This avoids the need to reconstruct the struct in main.rs
pub fn submit_event(
    session_update_params: &SessionUpdateParams
) {
    let key: SessionKey = SessionKey {
        src_ip: session_update_params.src_ip,
        dst_ip: session_update_params.dst_ip,
        src_port: session_update_params.src_port,
        dst_port: session_update_params.dst_port,
        proto: session_update_params.proto,
        _padding: [0; 3],
    };

    unsafe {
        let current_time = bpf_ktime_get_ns();

        if let Some(mut events) = EVENTS_POOL.reserve::<SessionEvent>(0) {
            let event = events.as_mut_ptr();
            (*event).key = key;
            (*event).timestamp = current_time;
            (*event).len = session_update_params.len as u16;
            (*event).flag = session_update_params.flag;
            events.submit(0);
        }
    }
}
