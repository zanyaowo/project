use crate::lib::config::Config;
use aya::maps::{MapData, PerCpuHashMap, RingBuf};
use firewall_common::session::{SessionEvent, SessionKey, SessionValue};
use std::net::Ipv4Addr;
use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;

struct SessionSummary {
    orig_bytes: u64,
    resp_bytes: u64,
    orig_pkts: u64,
    resp_pkts: u64,
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
        config: Arc<Config>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            ring_buf,
            session_table,
            config,
        })
    }

    fn aggregate_per_cpu(values: &[SessionValue]) -> SessionSummary {
        SessionSummary {
            orig_bytes: values.iter().map(|v| v.orig_bytes).sum(),
            resp_bytes: values.iter().map(|v| v.resp_bytes).sum(),
            orig_pkts: values.iter().map(|v| v.orig_pkts).sum(),
            resp_pkts: values.iter().map(|v| v.resp_pkts).sum(),
            start_ts: values
                .iter()
                .map(|v| v.start_ts)
                .filter(|&t| t > 0)
                .min()
                .unwrap_or(0),
            last_seen_ts: values.iter().map(|v| v.last_seen_ts).max().unwrap_or(0),
        }
    }

    pub async fn start(&mut self) -> anyhow::Result<()> {
        let mut async_fd = AsyncFd::new(self.ring_buf.as_raw_fd())?;

        loop {
            let mut guard = async_fd.readable().await?;

            while let Some(raw_event) = self.ring_buf.next() {
                let data: &[u8] = raw_event.deref();
                if data.len() < std::mem::size_of::<SessionEvent>() {
                    log::warn!(
                        "Invalid event size: {} bytes, expected {}",
                        data.len(),
                        std::mem::size_of::<SessionEvent>()
                    );
                    continue;
                }

                // SAFETY: 已驗證 data 大小足夠容納 SessionEvent
                let event: SessionEvent =
                    unsafe { (data.as_ptr() as *const SessionEvent).read_unaligned() };
                let session_key = event.key;

                let values = match self.session_table.get(&session_key, 0) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let summary = Self::aggregate_per_cpu(&values);
                let bytes_sum = summary.orig_bytes + summary.resp_bytes;
                let duration_ns = summary.last_seen_ts.saturating_sub(summary.start_ts);

                log::info!(
                    "Log: Src={}:{}, Dst={}:{}, Proto={}, Bytes={}, Dur={:.4}s",
                    Ipv4Addr::from(session_key.src_ip),
                    session_key.src_port,
                    Ipv4Addr::from(session_key.dst_ip),
                    session_key.dst_port,
                    session_key.proto,
                    bytes_sum,
                    duration_ns as f64 / 1_000_000_000.0
                );
            }
            guard.clear_ready();
        }
    }
}
