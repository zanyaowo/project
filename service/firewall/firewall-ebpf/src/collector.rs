use aya_ebpf::{
    macros::map,
    maps::RingBuf,
    helpers::bpf_ktime_get_ns
};
use aya_ebpf::maps::{PerCpuArray};
use firewall_common::constants::EVENT_RING_BUF_SIZE;
use firewall_common::session::{SessionEvent, SessionKey};
use crate::table::SessionUpdateParams;

#[map]
static mut EVENTS_POOL: RingBuf = RingBuf::with_byte_size(EVENT_RING_BUF_SIZE, 0);

#[map]
static mut DROP_EVENTS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

// Updated signature to take raw values instead of Ipv4Hdr struct
// This avoids the need to reconstruct the struct in main.rs
pub fn submit_event(
    session_update_params: &SessionUpdateParams,
    score: i32
) {
    let key: SessionKey = SessionKey::from(session_update_params);

    unsafe {
        let current_time = bpf_ktime_get_ns();

        if let Some(mut events) = EVENTS_POOL.reserve::<SessionEvent>(0) {
            let event = events.as_mut_ptr();
            (*event).key = key;
            (*event).timestamp = current_time;
            (*event).len = session_update_params.len as u16;
            (*event).flag = session_update_params.flag;
            (*event).score = score;
            events.submit(0);
        }else{
            if let Some(mut counter) = DROP_EVENTS.get_ptr_mut(0) {
                *counter+=1;
            }
        }
    }
}
