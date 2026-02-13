use core::ptr::addr_of_mut;
use aya_ebpf::{
    macros::map,
    maps::RingBuf,
    programs::XdpContext,
    helpers::bpf_ktime_get_ns
};
use network_types::ip::{IpProto, Ipv4Hdr};
use firewall_common::{RawFeature, SessionKey, SessionValue};
use crate::table::SESSIONS;

#[map]
static mut PACKET_POOL: RingBuf = RingBuf::with_byte_size(4096, 0);

pub fn submit_feature(ctx: &XdpContext, ip_hdr: Ipv4Hdr, src_port: u16, dst_port: u16) {
    let src_ip: u32 = u32::from_be_bytes(ip_hdr.src_addr);
    let dst_ip: u32 = u32::from_be_bytes(ip_hdr.dst_addr);
    let proto_h: IpProto = ip_hdr.proto;
    let service_h = ip_hdr.tos;

    let key: SessionKey = SessionKey {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto: proto_h as u8,
        _padding: [0; 3],
    };

    unsafe {
        let session_info = SESSIONS.get(&key);
        let current_time = bpf_ktime_get_ns();

        if let Some(mut events) = PACKET_POOL.reserve::<RawFeature>(0) {
            let event = events.as_mut_ptr();

            (*event).src_ip = src_ip;
            (*event).dst_ip = dst_ip;
            (*event).src_port = src_port;
            (*event).dst_port = dst_port;
            (*event).proto = proto_h as u8;
            (*event).service_h = service_h;
            (*event).current_ts = current_time;
            (*event)._padding1 = [0; 2];

            if let Some(session) = session_info {
                (*event).orig_bytes = (*session).orig_bytes;
                (*event).resp_bytes = (*session).resp_bytes;
                (*event).orig_pkts = (*session).orig_pkts;
                (*event).resp_pkts = (*session).resp_pkts;
                (*event).start_ts = (*session).start_ts;
            } else {
                (*event).orig_bytes = 0;
                (*event).resp_bytes = 0;
                (*event).orig_pkts = 0;
                (*event).resp_pkts = 0;
                (*event).start_ts = current_time;
            }

            events.submit(0);
        }
    }
}
