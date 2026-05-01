use aya::maps::{MapData, PerCpuHashMap, RingBuf};
use firewall_common::session::{SessionEvent, SessionKey, SessionValue};
use firewall_common::ModelFeature;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use tokio::io::unix::AsyncFd;
use std::ops::Deref;
use std::sync::Arc;
use crate::lib::config::Config;

struct SessionSummary {
    orig_bytes: u64,
    resp_bytes: u64,
    orig_pkts: u64,
    resp_pkts: u64,
    orig_ip_bytes: u64,
    resp_ip_bytes: u64,
    start_ts: u64,
    last_seen_ts: u64,
}

pub struct Logger<'a> {
    ring_buf: RingBuf<&'a mut MapData>,
    session_table: PerCpuHashMap<&'a mut MapData, SessionKey, SessionValue>,
    config: Arc<Config>,
}

impl<'a> Logger<'a> {
    pub fn new(
        ring_buf: RingBuf<&'a mut MapData>,
        session_table: PerCpuHashMap<&'a mut MapData, SessionKey, SessionValue>,
        config: Arc<Config>
    ) -> anyhow::Result<Self> {
        Ok(Self { ring_buf, session_table, config })
    }

    fn aggregate_per_cpu(values: &[SessionValue]) -> SessionSummary {
        SessionSummary {
            orig_bytes: values.iter().map(|v| v.orig_bytes).sum(),
            resp_bytes: values.iter().map(|v| v.resp_bytes).sum(),
            orig_pkts: values.iter().map(|v| v.orig_pkts).sum(),
            resp_pkts: values.iter().map(|v| v.resp_pkts).sum(),
            orig_ip_bytes: values.iter().map(|v| v.orig_ip_bytes).sum(),
            resp_ip_bytes: values.iter().map(|v| v.resp_ip_bytes).sum(),
            start_ts: values.iter().map(|v| v.start_ts).filter(|&t| t > 0).min().unwrap_or(0),
            last_seen_ts: values.iter().map(|v| v.last_seen_ts).max().unwrap_or(0),
        }
    }

    fn build_feature(key: &SessionKey, summary: &SessionSummary) -> ModelFeature {
        let duration_ns = summary.last_seen_ts.saturating_sub(summary.start_ts);
        let duration_sec = duration_ns as f64 / 1_000_000_000.0;
        let bytes_sum = summary.orig_bytes + summary.resp_bytes;
        let pkts_sum = summary.orig_pkts + summary.resp_pkts;

        let bytes_ratio = if summary.resp_bytes > 0 {
            summary.orig_bytes as f64 / summary.resp_bytes as f64
        } else {
            summary.orig_bytes as f64
        };

        let pkts_ratio = if summary.resp_pkts > 0 {
            summary.orig_pkts as f64 / summary.resp_pkts as f64
        } else {
            summary.orig_pkts as f64
        };

        let bps_approx = if duration_sec > 0.0 {
            bytes_sum as f64 / duration_sec
        } else {
            bytes_sum as f64
        };

        ModelFeature {
            duration: duration_ns,
            orig_bytes: summary.orig_bytes,
            resp_bytes: summary.resp_bytes,
            orig_pkts: summary.orig_pkts,
            resp_pkts: summary.resp_pkts,
            orig_ip_bytes: summary.orig_ip_bytes,
            resp_ip_bytes: summary.resp_ip_bytes,
            history_len: 0,
            bytes_sum,
            pkts_sum,
            bytes_ratio: (bytes_ratio * 1000.0) as u64,
            pkts_ratio: (pkts_ratio * 1000.0) as u64,
            bps_approx: bps_approx as u64,
            proto_h: key.proto % 16,
            service_h: 0,
            _padding: [0; 6],
        }
    }

    pub async fn start(&mut self) -> anyhow::Result<()> {
        let mut async_fd = AsyncFd::new(self.ring_buf.as_raw_fd())?;

        loop {
            let mut guard = async_fd.readable().await?;

            while let Some(raw_event) = self.ring_buf.next() {
                let data: &[u8] = raw_event.deref();
                if data.len() < std::mem::size_of::<SessionEvent>() {
                    log::warn!("Invalid event size: {} bytes, expected {}",
                        data.len(), std::mem::size_of::<SessionEvent>());
                    continue;
                }

                // SAFETY: 已驗證 data 大小足夠容納 SessionEvent
                let event: SessionEvent = unsafe { (data.as_ptr() as *const SessionEvent).read_unaligned() };
                let session_key = event.key;

                let values = match self.session_table.get(&session_key, 0) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let summary = Self::aggregate_per_cpu(&values);
                let _feature = Self::build_feature(&session_key, &summary);

                log::info!(
                    "Log: Src={}:{}, Dst={}:{}, Proto={}, Bytes={}, Dur={:.4}s",
                    Ipv4Addr::from(session_key.src_ip), session_key.src_port,
                    Ipv4Addr::from(session_key.dst_ip), session_key.dst_port,
                    session_key.proto,
                    _feature.bytes_sum,
                    _feature.duration as f64 / 1_000_000_000.0
                );
            }
            guard.clear_ready();
        }
    }
}
