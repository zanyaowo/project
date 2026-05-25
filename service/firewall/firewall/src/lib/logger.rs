use crate::lib::config::Config;
use aya::maps::{MapData, PerCpuArray, PerCpuHashMap, RingBuf};
use firewall_common::session::{SessionEvent, SessionKey, SessionValue};
use std::net::Ipv4Addr;
use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::time::{interval, Duration};

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
    drop_events: PerCpuArray<&'a mut MapData, u64>,
    config: Arc<Config>,
}

impl<'a> Logger<'a> {
    pub fn new(
        ring_buf: RingBuf<&'a mut MapData>,
        session_table: PerCpuHashMap<&'a mut MapData, SessionKey, SessionValue>,
        drop_events: PerCpuArray<&'a mut MapData, u64>,
        config: Arc<Config>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            ring_buf,
            session_table,
            drop_events,
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

    fn log_metrics(&self, events_processed: u64) {
        let session_count = self.session_table.iter().count();

        let drop_count: u64 = self
            .drop_events
            .get(&0, 0)
            .map(|vals| vals.iter().sum())
            .unwrap_or(0);

        let drop_rate = if events_processed + drop_count > 0 {
            drop_count as f64 / (events_processed + drop_count) as f64
        } else {
            0.0
        };

        log::info!(
            "metrics: sessions={} events={} ring_drops={} drop_rate={:.3}",
            session_count,
            events_processed,
            drop_count,
            drop_rate,
        );
    }

    pub async fn start(&mut self) -> anyhow::Result<()> {
        let mut async_fd = AsyncFd::new(self.ring_buf.as_raw_fd())?;
        let mut metrics_ticker = interval(Duration::from_secs(60));
        let mut events_processed: u64 = 0;

        loop {
            tokio::select! {
                _ = metrics_ticker.tick() => {
                    self.log_metrics(events_processed);
                }
                readable = async_fd.readable() => {
                    let mut guard = readable?;

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

                        if self.config.log.enable_session_log {
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

                        events_processed += 1;
                    }
                    guard.clear_ready();
                }
            }
        }
    }
}
