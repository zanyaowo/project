use aya::maps::{Array, MapData};
use serde::Deserialize;
use firewall_common::model::{ModelConfig, QuantileBound, FEATURE_COUNT};

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
    threshold: i32,
    quantile_bounds: Vec<QuantileBoundEntry>,
    score_table: Vec<i32>,
}


pub fn load_model(
    config_map: &mut Array<&mut MapData, ModelConfig>,
    bounds_map: &mut Array<&mut MapData, QuantileBound>,
    score_map: &mut Array<&mut MapData, i32>,
    model_path: &str,
    action: &str
) -> anyhow::Result<()> {
    let contents = std::fs::read_to_string(model_path)?;
    let model_file: ModelFile = serde_json::from_str(&contents)?;

    let disabled = ModelConfig{
        enabled: 0,
        feature_count: FEATURE_COUNT,
        threshold: 0,
        action: 0,
    };
    config_map.set(0, disabled, 0)?;

    for (i , entry) in model_file.quantile_bounds.iter().enumerate() {
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
            _ => anyhow::bail!("unknown quantile bound type: {}", entry.type_)
        };

        bounds_map.set(i as u32, bound, 0)?;
    }

    for (i, score) in model_file.score_table.iter().enumerate() {
        score_map.set(i as u32, *score, 0)?;
    }

    let action_val: u32 = match action { "drop" => 1, _ => 0 };

    let enabled = ModelConfig{
        enabled: 1,
        feature_count: FEATURE_COUNT,
        threshold: model_file.threshold,
        action: action_val,
    };

    config_map.set(0, enabled, 0)?;

    Ok(())
}