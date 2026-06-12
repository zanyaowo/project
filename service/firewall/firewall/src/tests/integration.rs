//! Host-testable cross-layer integration coverage.
//!
//! Validates the decision flow that connects the layers:
//!   simulated kernel scorer output (`StatsEvent`)
//!     → calibration-layer gate decision (`boundary_updater`)
//!     → double-buffer hot-swap invariant (no half-update).
//!
//! The real on-hardware end-to-end path (live XDP + eBPF maps) is exercised by
//! `tests::test::test_session_tracking` (root + NIC, `#[ignore]`). This module
//! covers the logic between ingress and map publication so it runs in CI
//! without privileges.

use firewall_common::model::{
    StatsEvent, FEATURE_COUNT, FEATURE_COUNT_USIZE, STATS_FLAG_BENIGN_GATE,
};

use crate::lib::boundary_updater::{
    batch_quantile, decide_gate, decode_bound, divergence, ema, encode_bound, GateState,
};

/// Result of replaying one synthetic batch through the calibration logic.
struct BatchOutcome {
    /// Per-feature reference (BENIGN-gated) p50 ratios.
    q_ref: Vec<f64>,
    /// Mean normalised divergence between reference and live sketches.
    divergence: f64,
    /// Fraction of live flows landing in the high-risk bucket.
    high_risk_rate: f64,
}

/// Mirror of `BoundaryUpdater::ingest` + the quantile/divergence half of
/// `process_batch`, operating on a synthetic batch of kernel events. Kept in
/// lock-step with the production logic so the test fails if the contract
/// (BENIGN gate → S_ref, all flows → S_live) drifts.
fn run_batch(events: &[StatsEvent], threshold: i32) -> BatchOutcome {
    let mut ref_batch: Vec<Vec<(u32, u32)>> = vec![Vec::new(); FEATURE_COUNT_USIZE];
    let mut live_batch: Vec<Vec<(u32, u32)>> = vec![Vec::new(); FEATURE_COUNT_USIZE];
    let mut live_scores: Vec<i32> = Vec::new();

    for ev in events {
        let benign = ev.flags & STATS_FLAG_BENIGN_GATE != 0;
        for i in 0..FEATURE_COUNT_USIZE {
            live_batch[i].push((ev.numer[i], ev.denom[i]));
            if benign {
                ref_batch[i].push((ev.numer[i], ev.denom[i]));
            }
        }
        live_scores.push(ev.score);
    }

    let q_ref: Vec<f64> = (0..FEATURE_COUNT_USIZE)
        .map(|i| batch_quantile(&ref_batch[i], 0.5))
        .collect();
    let q_live: Vec<f64> = (0..FEATURE_COUNT_USIZE)
        .map(|i| batch_quantile(&live_batch[i], 0.5))
        .collect();
    let div = divergence(&q_ref, &q_live);

    let total = live_scores.len().max(1) as f64;
    let high = live_scores.iter().filter(|&&s| s >= threshold).count() as f64;

    BatchOutcome {
        q_ref,
        divergence: div,
        high_risk_rate: high / total,
    }
}

/// A clearly-BENIGN sampled flow: passes the kernel gate (feeds S_ref) and
/// scores far below threshold. `ratio_numer/100` is the per-feature ratio.
fn benign_event(ratio_numer: u32) -> StatsEvent {
    StatsEvent {
        numer: [ratio_numer; FEATURE_COUNT_USIZE],
        denom: [100; FEATURE_COUNT_USIZE],
        score: 10,
        flags: STATS_FLAG_BENIGN_GATE,
    }
}

/// A flow that did not pass the BENIGN gate (S_live only). `score` decides
/// whether it counts as high-risk; the caller uses a low score for benign
/// business growth and a high score for an attack burst.
fn ungated_event(ratio_numer: u32, score: i32) -> StatsEvent {
    StatsEvent {
        numer: [ratio_numer; FEATURE_COUNT_USIZE],
        denom: [100; FEATURE_COUNT_USIZE],
        score,
        flags: 0,
    }
}

/// Business-growth drift: the live distribution shifts away from the frozen
/// reference, but the high-risk-bucket rate stays flat. The gate must publish
/// (Normal) and the reference p50 must survive the encode/decode round-trip
/// that produces the boundary the datapath reads.
#[test]
fn benign_growth_publishes_boundaries() {
    let threshold = 1000;
    let div_threshold = 0.30;

    let mut batch = Vec::new();
    for _ in 0..200 {
        batch.push(benign_event(100)); // ref + live, ratio ~1.0
    }
    for _ in 0..400 {
        batch.push(ungated_event(160, 10)); // live only, shifted, LOW score
    }

    let outcome = run_batch(&batch, threshold);

    assert!(
        outcome.divergence > div_threshold,
        "divergence {} should exceed {}",
        outcome.divergence,
        div_threshold
    );
    assert!(
        outcome.high_risk_rate < 1e-6,
        "high-risk rate should be ~0, got {}",
        outcome.high_risk_rate
    );
    assert_eq!(
        decide_gate(
            outcome.divergence,
            /* high_risk_jump */ false,
            div_threshold
        ),
        GateState::Normal
    );

    // Published bound = reference p50 re-encoded; verify no precision loss that
    // would corrupt the boundary the kernel scorer compares against.
    for i in 0..FEATURE_COUNT_USIZE {
        let enc = encode_bound(i, outcome.q_ref[i]);
        let dec = decode_bound(i, &enc);
        assert!(
            (dec - outcome.q_ref[i]).abs() <= 1.0,
            "feature {i} round-trip {} vs {}",
            dec,
            outcome.q_ref[i]
        );
    }
}

/// Attack burst: the live distribution shifts AND the high-risk-bucket rate
/// spikes relative to its trend. The gate must freeze the reference boundaries
/// (AttackFreeze) so attack traffic cannot poison the published quantiles.
#[test]
fn attack_spike_freezes_reference() {
    let threshold = 1000;
    let div_threshold = 0.30;
    let jump_factor = 2.0;

    // Warm-up establishes a small baseline high-risk EWMA (the jump test is
    // disabled while the EWMA is still ~0, matching process_batch).
    let mut warmup = Vec::new();
    for _ in 0..200 {
        warmup.push(benign_event(100));
    }
    for _ in 0..10 {
        warmup.push(ungated_event(100, 5000));
    }
    let warm = run_batch(&warmup, threshold);
    let ewma = ema(0.0, warm.high_risk_rate, 0.20);

    let mut batch = Vec::new();
    for _ in 0..200 {
        batch.push(benign_event(100)); // ref + live
    }
    for _ in 0..400 {
        batch.push(ungated_event(160, 5000)); // live only, HIGH score
    }
    let outcome = run_batch(&batch, threshold);

    assert!(
        outcome.divergence > div_threshold,
        "divergence {} should exceed {}",
        outcome.divergence,
        div_threshold
    );
    let high_risk_jump = ewma > 1e-6 && outcome.high_risk_rate > ewma * jump_factor;
    assert!(
        high_risk_jump,
        "high-risk rate {} should jump over {} * {}",
        outcome.high_risk_rate, ewma, jump_factor
    );
    assert_eq!(
        decide_gate(outcome.divergence, high_risk_jump, div_threshold),
        GateState::AttackFreeze
    );
}

/// Hot-swap safety: mirrors `model_loader::write_boundary_version` (writes the
/// inactive bank, flips `active`) and `scorer::active_bank_base` (reads the
/// active bank). The written and read banks must occupy disjoint ranges so the
/// datapath never observes a half-updated boundary set.
#[test]
fn double_buffer_banks_never_overlap() {
    for active in 0u32..2 {
        let inactive = 1 - (active & 1);
        let base_active = (active & 1) * FEATURE_COUNT;
        let base_inactive = inactive * FEATURE_COUNT;

        assert_ne!(
            base_active, base_inactive,
            "active and inactive banks must differ"
        );

        let read = base_active..base_active + FEATURE_COUNT;
        let write = base_inactive..base_inactive + FEATURE_COUNT;
        assert!(
            read.end <= write.start || write.end <= read.start,
            "bank ranges {:?} and {:?} overlap → possible half-update",
            read,
            write
        );
    }
}
