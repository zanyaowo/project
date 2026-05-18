use aya::maps::{Array, MapData};
use firewall_common::model::{ModelConfig, QuantileBound, FEATURE_COUNT, SCORE_TABLE_SIZE};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct QuantileBoundEntry {
    name: String,
    #[serde(rename = "type")]
    type_: String,
    value: Option<u64>,
    numer: Option<u64>,
    denom: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ModelFile {
    version: u32,
    feature_order: Vec<String>,
    threshold_cmp: String,
    score_scale: u32,
    length_unit: String,
    threshold: i32,
    quantile_bounds: Vec<QuantileBoundEntry>,
    score_table: Vec<i32>,
}

const CONTRACT_VERSION: u32 = 1;
const SCORE_SCALE: u32 = 10_000;
const LENGTH_UNIT: &str = "packet_len";
const THRESHOLD_CMP: &str = ">=";
const CANONICAL_FEATURE_ORDER: [&str; 5] = [
    "protocol",
    "pkt_len_mean",
    "fwd_max_q",
    "sym_ratio",
    "pkt_cv_sq",
];

fn validate_model_contract(model_file: &ModelFile) -> anyhow::Result<()> {
    if model_file.version != CONTRACT_VERSION {
        anyhow::bail!(
            "distilled model version must be {}, got {}",
            CONTRACT_VERSION,
            model_file.version
        );
    }
    if !model_file
        .feature_order
        .iter()
        .map(String::as_str)
        .eq(CANONICAL_FEATURE_ORDER.iter().copied())
    {
        anyhow::bail!(
            "feature_order must be {:?}, got {:?}",
            CANONICAL_FEATURE_ORDER,
            model_file.feature_order
        );
    }
    if model_file.threshold_cmp != THRESHOLD_CMP {
        anyhow::bail!(
            "threshold_cmp must be {:?}, got {:?}",
            THRESHOLD_CMP,
            model_file.threshold_cmp
        );
    }
    if model_file.score_scale != SCORE_SCALE {
        anyhow::bail!(
            "score_scale must be {}, got {}",
            SCORE_SCALE,
            model_file.score_scale
        );
    }
    if model_file.length_unit != LENGTH_UNIT {
        anyhow::bail!(
            "length_unit must be {:?}, got {:?}",
            LENGTH_UNIT,
            model_file.length_unit
        );
    }
    if model_file.quantile_bounds.len() != FEATURE_COUNT as usize {
        anyhow::bail!(
            "quantile_bounds must contain exactly {} entries, got {}",
            FEATURE_COUNT,
            model_file.quantile_bounds.len()
        );
    }
    if model_file.score_table.len() != SCORE_TABLE_SIZE as usize {
        anyhow::bail!(
            "score_table must contain exactly {} entries, got {}",
            SCORE_TABLE_SIZE,
            model_file.score_table.len()
        );
    }

    for (i, entry) in model_file.quantile_bounds.iter().enumerate() {
        let expected_name = CANONICAL_FEATURE_ORDER[i];
        if entry.name != expected_name {
            anyhow::bail!(
                "quantile_bounds[{}].name must be {:?}, got {:?}",
                i,
                expected_name,
                entry.name
            );
        }

        let expected_type = if i <= 1 { "absolute" } else { "ratio" };
        if entry.type_ != expected_type {
            anyhow::bail!(
                "quantile_bounds[{}].type must be {:?}, got {:?}",
                i,
                expected_type,
                entry.type_
            );
        }

        match expected_type {
            "absolute" => {
                if entry.value.is_none() {
                    anyhow::bail!("absolute bound {:?} must contain value", entry.name);
                }
            }
            "ratio" => {
                if entry.numer.is_none() || entry.denom.is_none() {
                    anyhow::bail!("ratio bound {:?} must contain numer and denom", entry.name);
                }
                if entry.denom == Some(0) {
                    anyhow::bail!("ratio bound {:?} denom must be non-zero", entry.name);
                }
            }
            _ => unreachable!(),
        }
    }

    Ok(())
}

pub fn load_model(
    config_map: &mut Array<&mut MapData, ModelConfig>,
    bounds_map: &mut Array<&mut MapData, QuantileBound>,
    score_map: &mut Array<&mut MapData, i32>,
    model_path: &str,
    action: &str,
) -> anyhow::Result<()> {
    let contents = std::fs::read_to_string(model_path)?;
    let model_file: ModelFile = serde_json::from_str(&contents)?;
    validate_model_contract(&model_file)?;

    let disabled = ModelConfig {
        enabled: 0,
        feature_count: FEATURE_COUNT,
        threshold: 0,
        action: 0,
    };
    config_map.set(0, disabled, 0)?;

    for (i, entry) in model_file.quantile_bounds.iter().enumerate() {
        let bound = match entry.type_.as_str() {
            "absolute" => QuantileBound {
                value: entry.value.unwrap_or(0),
                numer: 0,
                denom: 0,
            },
            "ratio" => QuantileBound {
                value: 0,
                numer: entry.numer.unwrap_or(0),
                denom: entry.denom.unwrap_or(1),
            },
            _ => anyhow::bail!("unknown quantile bound type: {}", entry.type_),
        };

        bounds_map.set(i as u32, bound, 0)?;
    }

    for (i, score) in model_file.score_table.iter().enumerate() {
        score_map.set(i as u32, *score, 0)?;
    }

    let action_val: u32 = match action {
        "drop" => 1,
        _ => 0,
    };

    let enabled = ModelConfig {
        enabled: 1,
        feature_count: FEATURE_COUNT,
        threshold: model_file.threshold,
        action: action_val,
    };

    config_map.set(0, enabled, 0)?;

    Ok(())
}
