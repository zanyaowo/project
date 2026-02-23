use aya::maps::{MapData, PerCpuHashMap, RingBuf};
use firewall_common::session::{SessionEvent, SessionKey, SessionValue};
use firewall_common::ModelFeature;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use tokio::io::unix::AsyncFd;
use std::ops::Deref;

pub struct Logger<'a> {
    ring_buf: RingBuf<&'a mut MapData>,
    session_table: PerCpuHashMap<&'a mut MapData, SessionKey, SessionValue>,
}

impl<'a> Logger<'a> {
    pub fn new(
        ring_buf: RingBuf<&'a mut MapData>,
        session_table: PerCpuHashMap<&'a mut MapData, SessionKey, SessionValue>
    ) -> anyhow::Result<Self> {
        Ok(Self { ring_buf, session_table })
    }

    pub async fn start(&mut self) -> anyhow::Result<()> {
        let mut async_fd = AsyncFd::new(self.ring_buf.as_raw_fd())?;

        loop {
            let mut guard = async_fd.readable().await?;

            while let Some(raw_event) = self.ring_buf.next() {
                let data: &[u8] = raw_event.deref();
                let event: SessionEvent = unsafe { (data.as_ptr() as *const SessionEvent).read_unaligned() };
                let session_key = event.key;

                // Lookup the specific session in the Per-CPU Map
                if let Ok(values) = self.session_table.get(&session_key, 0) {

                    let start_ts = values.iter().map(|v| v.start_ts).filter(|&t| t > 0).min().unwrap_or(0);
                    let last_seen_ts = values.iter().map(|v| v.last_seen_ts).max().unwrap_or(0);
                    let duration_ns = last_seen_ts.saturating_sub(start_ts);
                    let duration_sec = duration_ns as f64 / 1_000_000_000.0;

                    let orig_bytes: u64 = values.iter().map(|v| v.orig_bytes).sum();
                    let resp_bytes: u64 = values.iter().map(|v| v.resp_bytes).sum();
                    let bytes_sum = orig_bytes + resp_bytes;
                    
                    let orig_pkts: u64 = values.iter().map(|v| v.orig_pkts).sum();
                    let resp_pkts: u64 = values.iter().map(|v| v.resp_pkts).sum();
                    let pkts_sum = orig_pkts + resp_pkts;

                    let bytes_ratio = if resp_bytes > 0 {
                        orig_bytes as f64 / resp_bytes as f64
                    } else {
                        orig_bytes as f64
                    };

                    let pkts_ratio = if resp_pkts > 0 {
                        orig_pkts as f64 / resp_pkts as f64
                    } else {
                        orig_pkts as f64
                    };

                    let bps_approx = if duration_sec > 0.0 {
                        bytes_sum as f64 / duration_sec
                    } else {
                        bytes_sum as f64
                    };

                    log::info!(
                        "Log: Src={}:{}, Dst={}:{}, Proto={}, Bytes={}, Dur={:.4}s",
                        Ipv4Addr::from(session_key.src_ip), session_key.src_port,
                        Ipv4Addr::from(session_key.dst_ip), session_key.dst_port,
                        session_key.proto,
                        bytes_sum,
                        duration_sec
                    );

                    let _model_feature = ModelFeature {
                        duration: duration_ns,
                        orig_bytes,
                        resp_bytes,
                        orig_pkts,
                        resp_pkts,
                        orig_ip_bytes: values.iter().map(|v| v.orig_ip_bytes).sum(),
                        resp_ip_bytes: values.iter().map(|v| v.resp_ip_bytes).sum(),
                        history_len: 0, 
                        bytes_sum,
                        pkts_sum,
                        bytes_ratio: (bytes_ratio * 1000.0) as u64,
                        pkts_ratio: (pkts_ratio * 1000.0) as u64,
                        bps_approx: bps_approx as u64,
                        proto_h: session_key.proto % 16,
                        service_h: 0,
                        _padding: [0; 6],
                    };
                }
            }
            guard.clear_ready();
        }
    }
}