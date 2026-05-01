use aya::include_bytes_aligned;
use aya::maps::{PerCpuHashMap, RingBuf, Array};
use std::sync::Arc;
use log::warn;
use crate::lib::config::Config;
use crate::lib::controller::FirewallController;
use crate::lib::logger::Logger;
use crate::lib::model_loader::load_model;

mod lib;
mod tests;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {

    let config: Config = Config::from_file("config.toml")
        .unwrap_or_else(|e| {
            warn!("Failed to load config: {}", e);
            Config::default()
        }
        );
    let config = Arc::new(config);

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(&config.log.log_level)
    ).init();

    let bytecode = include_bytes_aligned!(env!("FIREWALL_BPF"));
    let mut controller = FirewallController::load(bytecode, config.clone())?;

    let iface = config.network.interface.as_str();

    if config.network.enable_xdp {
        controller.attach_xdp(&iface)?;
    }

    if config.network.enable_tc {
        controller.attach_tc(&iface)?;
    }

    let mut session_map_data = None;
    let mut event_map_data = None;
    let mut score_table_data = None;
    let mut quantile_table_data = None;
    let mut model_config_data = None;

    for (name, map) in controller.maps_mut() {
        match name {
            "SESSIONS" => session_map_data = Some(map),
            "EVENTS_POOL" => event_map_data = Some(map),
            "SCORE_TABLE" => score_table_data = Some(map),
            "QUANTILE_BOUNDS" => quantile_table_data = Some(map),
            "MODEL_CONFIG" => model_config_data = Some(map),
            _ => {}
        }
    }

    let session_map = session_map_data.ok_or_else(|| anyhow::anyhow!("SESSIONS map not found"))?;
    let event_map = event_map_data.ok_or_else(|| anyhow::anyhow!("EVENTS_POOL map not found"))?;
    let score_map = score_table_data.ok_or_else(|| anyhow::anyhow!("SCORE_TABLE map not found"))?;
    let quantile_bounds_map = quantile_table_data.ok_or_else(|| anyhow::anyhow!("QUANTILE_BOUNDS map not found"))?;
    let model_config_map = model_config_data.ok_or_else(|| anyhow::anyhow!("MODEL_CONFIG map not found"))?;

    let session_table = PerCpuHashMap::try_from(session_map)?;
    let event_ring_buf = RingBuf::try_from(event_map)?;
    let mut score_table = Array::try_from(score_map)?;
    let mut quantile_bounds_table = Array::try_from(quantile_bounds_map)?;
    let mut model_config_table = Array::try_from(model_config_map)?;

    if config.model.enabled{
        load_model(
            &mut model_config_table,
            &mut quantile_bounds_table,
            &mut score_table,
            &config.model.model_file,
            &config.model.action,
        )?;
    }

    let mut logger = Logger::new(event_ring_buf, session_table, config.clone())?;
    logger.start().await?;
    
    Ok(())
}