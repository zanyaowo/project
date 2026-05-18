use aya_ebpf::bindings::xdp_action::XDP_PASS;
use aya_ebpf::macros::map;
use aya_ebpf::maps::Array;

use firewall_common::constants::{MODEL_CONFIG_SIZE, QUANTILE_BOUND_SIZE, SCORE_TABLE_SIZE};
use firewall_common::model::*;
use firewall_common::session::{SessionKey, SessionValue};

// TODO 撰寫map定義以及kernel推論函數

#[map]
static mut QUANTILE_BOUNDS: Array<QuantileBound> = Array::with_max_entries(QUANTILE_BOUND_SIZE, 0);

#[map]
static mut SCORE_TABLE: Array<i32> = Array::with_max_entries(SCORE_TABLE_SIZE, 0);

#[map]
static mut MODEL_CONFIG: Array<ModelConfig> = Array::with_max_entries(MODEL_CONFIG_SIZE, 0);

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

    let mut index: u32 = 0x00;

    for feature_index in 0..FEATURE_COUNT {
        let bound = unsafe { QUANTILE_BOUNDS.get(feature_index)? };

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

    Some(ScoreResult {
        score: *score,
        action,
    })
}
