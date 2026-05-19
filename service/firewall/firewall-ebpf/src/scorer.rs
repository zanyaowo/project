use aya_ebpf::bindings::xdp_action::XDP_PASS;
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, PerCpuArray, RingBuf};

use firewall_common::constants::{
    BOUNDARY_META_SIZE, MODEL_CONFIG_SIZE, QUANTILE_BOUND_SIZE, SCORE_TABLE_SIZE,
    STATS_RING_BUF_SIZE, STATS_SAMPLE_SHIFT,
};
use firewall_common::model::*;
use firewall_common::session::{SessionKey, SessionValue};

// QUANTILE_BOUNDS holds BOUNDARY_BANK_COUNT banks laid out contiguously:
// bank `b` occupies entries [b*FEATURE_COUNT .. (b+1)*FEATURE_COUNT).
#[map]
static mut QUANTILE_BOUNDS: Array<QuantileBound> = Array::with_max_entries(QUANTILE_BOUND_SIZE, 0);

#[map]
static mut SCORE_TABLE: Array<i32> = Array::with_max_entries(SCORE_TABLE_SIZE, 0);

#[map]
static mut MODEL_CONFIG: Array<ModelConfig> = Array::with_max_entries(MODEL_CONFIG_SIZE, 0);

// Versioned metadata for double-buffered boundary banks.
#[map]
static mut BOUNDARY_META: Array<BoundaryMeta> = Array::with_max_entries(BOUNDARY_META_SIZE, 0);

// Raw feature samples for the userspace calibration layer.
#[map]
static mut STATS_RING_BUF: RingBuf = RingBuf::with_byte_size(STATS_RING_BUF_SIZE, 0);

// Per-CPU sampling counter (avoids flooding the ring buffer).
#[map]
static mut STATS_SAMPLE_CTR: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
fn sat_u32(v: u64) -> u32 {
    if v > u32::MAX as u64 {
        u32::MAX
    } else {
        v as u32
    }
}

/// Resolve the active boundary bank base offset.
/// Falls back to bank 0 when meta is missing or the version has expired (TTL).
#[inline(always)]
fn active_bank_base() -> u32 {
    let meta = unsafe { BOUNDARY_META.get(0) };
    match meta {
        Some(m) => {
            let now = unsafe { bpf_ktime_get_ns() };
            let expired = m.expiry_ns != 0 && now > m.expiry_ns;
            // Mask to {0,1}: only two banks exist (double buffering).
            let bank = if expired { 0 } else { m.active & 1 };
            bank.saturating_mul(FEATURE_COUNT)
        }
        None => 0,
    }
}

pub fn score_session(session_value: SessionValue, session_key: SessionKey) -> Option<ScoreResult> {
    let config = unsafe { MODEL_CONFIG.get(0)? };

    if config.enabled == 0 {
        return None;
    }

    let total_pkts = session_value
        .orig_pkts
        .saturating_add(session_value.resp_pkts);
    let total_bytes = session_value
        .orig_bytes
        .saturating_add(session_value.resp_bytes);
    let total_bytes_squared = total_bytes.saturating_mul(total_bytes);

    let val_denom: [u64; 5] = {
        [
            1u64,
            total_pkts,
            session_value.orig_bytes,
            session_value.resp_pkts,
            total_bytes_squared,
        ]
    };

    let max_shape = (session_value.max_pkt_len as u64).saturating_mul(session_value.orig_pkts);
    let cv_numer = session_value
        .pkt_sum_sq
        .saturating_mul(total_pkts)
        .saturating_sub(total_bytes_squared);

    let val_numer: [u64; 5] = {
        [
            session_key.proto as u64,
            total_bytes,
            max_shape,
            session_value.orig_pkts,
            cv_numer,
        ]
    };

    // Read the active bank once for the whole flow (RCU-like: no half-update).
    let bank_base = active_bank_base();

    let mut index: u32 = 0x00;

    for feature_index in 0..FEATURE_COUNT {
        let bound = unsafe { QUANTILE_BOUNDS.get(bank_base + feature_index)? };

        let i = feature_index as usize;
        let bit = if feature_index == FEAT_PROTOCOL {
            if val_numer[i] > bound.value {
                1u32
            } else {
                0u32
            }
        } else if feature_index == FEAT_PACKET_LEN_MEAN {
            if val_numer[i] > bound.value.saturating_mul(val_denom[i]) {
                1u32
            } else {
                0u32
            }
        } else {
            let lhs = val_numer[i].saturating_mul(bound.denom);
            let rhs = bound.numer.saturating_mul(val_denom[i]);
            if lhs > rhs {
                1u32
            } else {
                0u32
            }
        };

        index |= bit << feature_index;
    }

    let score = unsafe { SCORE_TABLE.get(index)? };

    let action = if *score >= config.threshold {
        config.action
    } else {
        XDP_PASS
    };

    // ---- Calibration-layer sampling: emit raw feature values ----
    // Sample 1 of (1<<STATS_SAMPLE_SHIFT) flows per CPU to bound ring pressure.
    let do_sample = unsafe {
        if let Some(ctr) = STATS_SAMPLE_CTR.get_ptr_mut(0) {
            *ctr = (*ctr).wrapping_add(1);
            (*ctr & ((1u64 << STATS_SAMPLE_SHIFT) - 1)) == 0
        } else {
            false
        }
    };

    if do_sample {
        // S_ref eligibility: clearly BENIGN (score*2 < threshold).
        let benign = (*score as i64).saturating_mul(2) < config.threshold as i64;
        let flags = if benign { STATS_FLAG_BENIGN_GATE } else { 0 };

        unsafe {
            if let Some(mut slot) = STATS_RING_BUF.reserve::<StatsEvent>(0) {
                let evt = slot.as_mut_ptr();
                (*evt).numer = [
                    sat_u32(val_numer[0]),
                    sat_u32(val_numer[1]),
                    sat_u32(val_numer[2]),
                    sat_u32(val_numer[3]),
                    sat_u32(val_numer[4]),
                ];
                (*evt).denom = [
                    sat_u32(val_denom[0]),
                    sat_u32(val_denom[1]),
                    sat_u32(val_denom[2]),
                    sat_u32(val_denom[3]),
                    sat_u32(val_denom[4]),
                ];
                (*evt).score = *score;
                (*evt).flags = flags;
                slot.submit(0);
            }
        }
    }

    Some(ScoreResult {
        score: *score,
        action,
    })
}
