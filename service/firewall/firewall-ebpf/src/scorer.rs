
use aya_ebpf::maps::Array;
use aya_ebpf::macros::map;

use firewall_common::model::*;
use firewall_common::session::{SessionKey, SessionValue };
use firewall_common::constants::*;

// TODO 撰寫map定義以及kernel推論函數

#[map]
static mut QUANTILE_BOUNDS: Array<QuantileBound> = Array::with_max_entries(QUANTILE_BOUND_SIZE, 0);

#[map]
static mut MODEL_WEIGHTS: Array<ModelWeight> = Array::with_max_entries(MODEL_WEIGHT_SIZE, 0);

#[map]
static mut MODEL_CONFIG: Array<ModelConfig> = Array::with_max_entries(MODEL_CONFIG_SIZE, 0);

pub fn score_session(session_value: SessionValue, session_key: SessionKey) -> Option<i32> {
    let config = unsafe { MODEL_CONFIG.get(0)? };

    if config.enabled == 0 {
        return None;
    }

    let total_pkts = session_value.orig_pkts + session_value.resp_pkts;
    let total_bytes = session_value.orig_bytes + session_value.resp_bytes;
    let total_bytes_squared = total_bytes * total_bytes;

    let val_demon: [u64; 5] = {
        [
            1u64,
            total_pkts,
            session_value.orig_bytes,
            session_value.resp_pkts,
            total_bytes_squared
        ]
    };

    let min_shape = session_value.min_pkt_len as u64 * session_value.orig_pkts;
    let cv_numer = session_value.pkt_sum_sq.saturating_mul(total_pkts).saturating_sub(total_bytes_squared);

    let val_numer: [u64; 5] = {
        [
            session_key.proto as u64,
            total_bytes,
            min_shape,
            session_value.orig_pkts,
            cv_numer,
        ]
    };

    let score = 0;

    for feature_index in 0..FEATURE_COUNT {
        let bucket_count = BUCKET_COUNT;
        for bucket_index in 0..bucket_count {
            let quantile_bucket = unsafe { QUANTILE_BOUNDS.get(bucket_index)? };
            // val_numer / val_denom <= bucket_numer / bucket_denom => val_numer * bucket_denom <= bucket_numer * val_denom
            if val_numer.get(feature_index) * quantile_bucket[bucket_index].denom <=  quantile_bucket[bucket_index].numer * val_numer[feature_index]{

            }else if{

            }

        }
    }

    Some(session_value.score)

}