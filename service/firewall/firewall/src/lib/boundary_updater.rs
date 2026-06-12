//! Score-stream calibration layer (dual-sketch + gated update).
//!
//! Consumes `StatsEvent` from the kernel ring buffer and maintains two
//! per-feature sketches:
//!   * `S_ref`  — only samples that passed the kernel BENIGN gate
//!     (`STATS_FLAG_BENIGN_GATE`); produces the published bucket boundaries.
//!   * `S_live` — all sampled flows; reflects the current distribution.
//!
//! A gate compares `divergence(S_ref, S_live)` against the high-risk-bucket
//! hit-rate trend to decide whether an observed drift is normal business
//! growth (update reference boundaries) or attack poisoning (freeze them).
//!
//! Note on monotonicity: the current model is 1-bit per feature
//! (`BUCKET_COUNT == 2`), so there is a single boundary per feature and no
//! cross-quantile ordering constraint. A monotonicity projection only
//! becomes relevant if `BUCKET_COUNT > 2`; it is intentionally omitted here
//! rather than shipped as dead code.

use crate::lib::config::Config;
use crate::lib::model_loader::{update_score_threshold, write_boundary_version};
use aya::maps::{Array, MapData, RingBuf};
use firewall_common::model::{
    BoundaryMeta, ModelConfig, QuantileBound, StatsEvent, FEATURE_COUNT, FEATURE_COUNT_USIZE,
    STATS_FLAG_BENIGN_GATE,
};
use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;

/// Fixed denominator used when encoding a ratio-typed boundary back into a
/// `QuantileBound`. Must stay integer (kernel datapath avoids floats).
const RATIO_SCALE: u64 = 1_000_000;

/// Feature indices 0 and 1 are absolute-valued in the kernel comparison
/// (`proto`, per-packet mean length); 2..5 are ratios (numer/denom).
fn is_absolute_feature(i: usize) -> bool {
    i <= 1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateState {
    /// Normal drift: update reference boundaries (EMA) and publish.
    Normal,
    /// Ambiguous: update the live sketch only, do not touch reference.
    Uncertain,
    /// Suspected attack poisoning: freeze reference boundaries.
    AttackFreeze,
}

// ---------------------------------------------------------------------------
// Pure logic (host-testable, no eBPF / no IO)
// ---------------------------------------------------------------------------

/// p-quantile of `numer/denom` ratios via batch sort. `q` in [0, 1].
pub fn batch_quantile(values: &[(u32, u32)], q: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut ratios: Vec<f64> = values
        .iter()
        .map(|(n, d)| *n as f64 / (*d as f64 + 1.0))
        .collect();
    ratios.sort_by(f64::total_cmp);
    let idx = ((q * (ratios.len() - 1) as f64) as usize).min(ratios.len() - 1);
    ratios[idx]
}

/// p-quantile of an i32 score batch.
pub fn score_quantile(scores: &[i32], q: f64) -> f64 {
    if scores.is_empty() {
        return 0.0;
    }
    let mut s = scores.to_vec();
    s.sort_unstable();
    let idx = ((q * (s.len() - 1) as f64) as usize).min(s.len() - 1);
    s[idx] as f64
}

pub fn ema(current: f64, new_sample: f64, alpha: f64) -> f64 {
    alpha * new_sample + (1.0 - alpha) * current
}

pub fn drift_ratio(current: f64, new_val: f64) -> f64 {
    (new_val - current).abs() / (current.abs() + 1e-9)
}

/// Mean normalized absolute difference between reference and live quantiles.
pub fn divergence(q_ref: &[f64], q_live: &[f64]) -> f64 {
    if q_ref.is_empty() || q_ref.len() != q_live.len() {
        return 0.0;
    }
    let sum: f64 = q_ref
        .iter()
        .zip(q_live)
        .map(|(r, l)| (l - r).abs() / (r.abs() + 1e-9))
        .sum();
    sum / q_ref.len() as f64
}

/// Gate decision. `high_risk_jump` is true when the high-risk-bucket hit
/// rate spiked relative to its trend (set by the caller).
pub fn decide_gate(divergence: f64, high_risk_jump: bool, div_threshold: f64) -> GateState {
    if divergence > div_threshold {
        if high_risk_jump {
            GateState::AttackFreeze
        } else {
            GateState::Normal
        }
    } else {
        GateState::Uncertain
    }
}

/// Encode a per-feature boundary value back into the kernel `QuantileBound`
/// representation, matching scorer.rs comparison semantics.
pub fn encode_bound(feature_index: usize, value: f64) -> QuantileBound {
    if is_absolute_feature(feature_index) {
        QuantileBound {
            value: value.max(0.0).round() as u64,
            numer: 0,
            denom: 0,
        }
    } else {
        QuantileBound {
            value: 0,
            numer: (value.max(0.0) * RATIO_SCALE as f64).round() as u64,
            denom: RATIO_SCALE,
        }
    }
}

/// Decode a kernel `QuantileBound` back to a scalar value for drift maths.
pub fn decode_bound(feature_index: usize, b: &QuantileBound) -> f64 {
    if is_absolute_feature(feature_index) {
        b.value as f64
    } else if b.denom == 0 {
        0.0
    } else {
        b.numer as f64 / b.denom as f64
    }
}

// ---------------------------------------------------------------------------
// Stateful updater
// ---------------------------------------------------------------------------

pub struct BoundaryUpdater<'a> {
    ring_buf: RingBuf<&'a mut MapData>,
    bounds_map: Array<&'a mut MapData, QuantileBound>,
    meta_map: Array<&'a mut MapData, BoundaryMeta>,
    config_map: Array<&'a mut MapData, ModelConfig>,
    config: Arc<Config>,

    ref_batch: [Vec<(u32, u32)>; FEATURE_COUNT_USIZE],
    live_batch: [Vec<(u32, u32)>; FEATURE_COUNT_USIZE],
    ref_score: Vec<i32>,
    live_score: Vec<i32>,

    current_bounds: [f64; FEATURE_COUNT_USIZE],
    current_threshold: f64,
    high_risk_rate_ewma: f64,
}

impl<'a> BoundaryUpdater<'a> {
    pub fn new(
        ring_buf: RingBuf<&'a mut MapData>,
        bounds_map: Array<&'a mut MapData, QuantileBound>,
        meta_map: Array<&'a mut MapData, BoundaryMeta>,
        config_map: Array<&'a mut MapData, ModelConfig>,
        config: Arc<Config>,
    ) -> Self {
        Self {
            ring_buf,
            bounds_map,
            meta_map,
            config_map,
            config,
            ref_batch: Default::default(),
            live_batch: Default::default(),
            ref_score: Vec::new(),
            live_score: Vec::new(),
            current_bounds: [0.0; FEATURE_COUNT_USIZE],
            current_threshold: 0.0,
            high_risk_rate_ewma: 0.0,
        }
    }

    /// Seed `current_bounds`/`current_threshold` from the maps the loader
    /// already populated, so the first batch computes meaningful drift.
    fn seed(&mut self) {
        for i in 0..FEATURE_COUNT_USIZE {
            if let Ok(b) = self.bounds_map.get(&(i as u32), 0) {
                self.current_bounds[i] = decode_bound(i, &b);
            }
        }
        if let Ok(cfg) = self.config_map.get(&0u32, 0) {
            self.current_threshold = cfg.threshold as f64;
        }
    }

    fn ingest(&mut self, ev: &StatsEvent) {
        let benign = ev.flags & STATS_FLAG_BENIGN_GATE != 0;
        for i in 0..FEATURE_COUNT_USIZE {
            self.live_batch[i].push((ev.numer[i], ev.denom[i]));
            if benign {
                self.ref_batch[i].push((ev.numer[i], ev.denom[i]));
            }
        }
        self.live_score.push(ev.score);
        if benign {
            self.ref_score.push(ev.score);
        }
    }

    fn batch_ready(&self) -> bool {
        let n = self.config.adaptive.batch_size;
        self.live_batch[0].len() >= n && self.ref_batch[0].len() >= n.max(1)
    }

    fn clear_batches(&mut self) {
        for i in 0..FEATURE_COUNT_USIZE {
            self.ref_batch[i].clear();
            self.live_batch[i].clear();
        }
        self.ref_score.clear();
        self.live_score.clear();
    }

    /// Process one full batch: compute quantiles, run the gate, and publish
    /// boundary / threshold updates only when the gate says `Normal`.
    /// Returns the gate decision (for logging / tests).
    fn process_batch(&mut self) -> anyhow::Result<GateState> {
        let ac = self.config.adaptive.clone();

        let q_ref: Vec<f64> = (0..FEATURE_COUNT_USIZE)
            .map(|i| batch_quantile(&self.ref_batch[i], 0.5))
            .collect();
        let q_live: Vec<f64> = (0..FEATURE_COUNT_USIZE)
            .map(|i| batch_quantile(&self.live_batch[i], 0.5))
            .collect();

        let div = divergence(&q_ref, &q_live);

        // High-risk-bucket hit rate from the live batch.
        let total = self.live_score.len().max(1) as f64;
        let high = self
            .live_score
            .iter()
            .filter(|&&s| s as f64 >= self.current_threshold)
            .count() as f64;
        let batch_high_rate = high / total;
        let high_risk_jump = self.high_risk_rate_ewma > 1e-6
            && batch_high_rate > self.high_risk_rate_ewma * ac.high_risk_rate_jump;
        self.high_risk_rate_ewma = ema(self.high_risk_rate_ewma, batch_high_rate, ac.ewma_alpha);

        let state = decide_gate(div, high_risk_jump, ac.divergence_threshold);

        if state == GateState::Normal {
            // Path A: per-feature EMA toward reference p50, gated by minor drift.
            let mut new_bounds = [QuantileBound {
                value: 0,
                numer: 0,
                denom: 0,
            }; FEATURE_COUNT_USIZE];
            let mut any_major = false;
            for i in 0..FEATURE_COUNT_USIZE {
                let cur = self.current_bounds[i];
                let target = q_ref[i];
                let dr = drift_ratio(cur, target);
                let next = if dr > ac.minor_drift_ratio {
                    ema(cur, target, ac.ewma_alpha)
                } else {
                    cur
                };
                if dr > ac.major_drift_ratio {
                    any_major = true;
                }
                self.current_bounds[i] = next;
                new_bounds[i] = encode_bound(i, next);
            }

            if any_major {
                log::warn!(
                    "boundary_updater: major drift (>{:.2}) — recommend Python retrain",
                    ac.major_drift_ratio
                );
            }

            let ttl_ns = ac.boundary_ttl_secs.saturating_mul(1_000_000_000);
            let t0 = std::time::Instant::now();
            write_boundary_version(
                &mut self.bounds_map,
                &mut self.meta_map,
                &new_bounds[..FEATURE_COUNT as usize],
                ttl_ns,
            )?;
            // Table 2 / 8.A-5: syscall cost of the double-buffered bank write
            // + version flip, sampled per published batch.
            log::info!(
                "boundary_updater: map_update_latency_us={:.1}",
                t0.elapsed().as_secs_f64() * 1e6
            );

            // Path B: threshold tracks BENIGN-only p85 (drift-gated).
            let p85 = score_quantile(&self.ref_score, 0.85);
            if drift_ratio(self.current_threshold, p85) > ac.score_drift_ratio {
                self.current_threshold = ema(self.current_threshold, p85, ac.ewma_alpha);
                update_score_threshold(
                    &mut self.config_map,
                    self.current_threshold.round() as i32,
                )?;
            }

            log::info!(
                "boundary_updater: Normal — published boundaries (div={:.3})",
                div
            );
        } else {
            log::warn!(
                "boundary_updater: {:?} — reference frozen (div={:.3}, high_jump={})",
                state,
                div,
                high_risk_jump
            );
        }

        Ok(state)
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        if !self.config.adaptive.enabled {
            log::info!("boundary_updater: disabled by config");
            return Ok(());
        }
        self.seed();

        let async_fd = AsyncFd::new(self.ring_buf.as_raw_fd())?;
        loop {
            let mut guard = async_fd.readable().await?;

            loop {
                // Decode into an owned StatsEvent, dropping `raw` at end of
                // the match arm so `self.ring_buf` is released before any
                // `&mut self` call below.
                let ev: StatsEvent = match self.ring_buf.next() {
                    None => break,
                    Some(raw) => {
                        let data: &[u8] = raw.deref();
                        if data.len() < std::mem::size_of::<StatsEvent>() {
                            continue; // raw dropped here
                        }
                        // SAFETY: size checked; StatsEvent is repr(C) + Pod.
                        unsafe { (data.as_ptr() as *const StatsEvent).read_unaligned() }
                        // raw dropped here
                    }
                };

                self.ingest(&ev);

                if self.batch_ready() {
                    if let Err(e) = self.process_batch() {
                        log::error!("boundary_updater: batch failed: {e}");
                    }
                    self.clear_batches();
                }
            }
            guard.clear_ready();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantile_basic() {
        let v: Vec<(u32, u32)> = (1..=100).map(|n| (n, 0)).collect();
        let p50 = batch_quantile(&v, 0.5);
        assert!((p50 - 50.0).abs() < 2.0, "p50 was {p50}");
        assert_eq!(batch_quantile(&[], 0.5), 0.0);
    }

    #[test]
    fn score_quantile_p85() {
        let s: Vec<i32> = (0..100).collect();
        assert!((score_quantile(&s, 0.85) - 85.0).abs() < 2.0);
    }

    #[test]
    fn ema_converges_toward_sample() {
        let mut x = 0.0;
        for _ in 0..200 {
            x = ema(x, 10.0, 0.2);
        }
        assert!((x - 10.0).abs() < 0.1);
    }

    #[test]
    fn drift_ratio_handles_zero_current() {
        assert!(drift_ratio(0.0, 5.0) > 1.0);
        assert!(drift_ratio(100.0, 100.0) < 1e-6);
    }

    #[test]
    fn divergence_zero_when_identical() {
        let a = vec![1.0, 2.0, 3.0];
        assert!(divergence(&a, &a) < 1e-9);
        let b = vec![2.0, 4.0, 6.0];
        assert!(divergence(&a, &b) > 0.4);
    }

    #[test]
    fn gate_state_machine() {
        // small divergence => Uncertain regardless of jump
        assert_eq!(decide_gate(0.1, true, 0.3), GateState::Uncertain);
        assert_eq!(decide_gate(0.1, false, 0.3), GateState::Uncertain);
        // large divergence + no jump => Normal (business growth)
        assert_eq!(decide_gate(0.5, false, 0.3), GateState::Normal);
        // large divergence + jump => AttackFreeze (poisoning)
        assert_eq!(decide_gate(0.5, true, 0.3), GateState::AttackFreeze);
    }

    #[test]
    fn bound_encode_decode_roundtrip() {
        // absolute feature (protocol-like)
        let b0 = encode_bound(0, 6.0);
        assert_eq!(b0.value, 6);
        assert!((decode_bound(0, &b0) - 6.0).abs() < 1e-9);
        // ratio feature
        let b3 = encode_bound(3, 1.5);
        assert_eq!(b3.denom, RATIO_SCALE);
        assert!((decode_bound(3, &b3) - 1.5).abs() < 1e-6);
    }

    #[test]
    fn stats_event_decode_from_bytes() {
        let ev = StatsEvent {
            numer: [6, 1500, 9, 10, 42],
            denom: [1, 10, 100, 5, 7],
            score: 1234,
            flags: STATS_FLAG_BENIGN_GATE,
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &ev as *const StatsEvent as *const u8,
                std::mem::size_of::<StatsEvent>(),
            )
        };
        assert_eq!(bytes.len(), 48, "StatsEvent must stay 48 bytes");
        let back: StatsEvent = unsafe { (bytes.as_ptr() as *const StatsEvent).read_unaligned() };
        assert_eq!(back.numer, ev.numer);
        assert_eq!(back.denom, ev.denom);
        assert_eq!(back.score, 1234);
        assert!(back.flags & STATS_FLAG_BENIGN_GATE != 0);
    }
}
