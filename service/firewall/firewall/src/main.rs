use crate::lib::boundary_updater::BoundaryUpdater;
use crate::lib::config::Config;
use crate::lib::controller::FirewallController;
use crate::lib::logger::Logger;
use crate::lib::model_loader::load_model;
use aya::include_bytes_aligned;
use aya::maps::{Array, PerCpuHashMap, RingBuf};
use firewall_common::model::BoundaryMeta;
use log::warn;
use std::sync::Arc;

mod lib;
mod tests;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let config: Config = Config::from_file("config.toml").unwrap_or_else(|e| {
        warn!("Failed to load config: {}", e);
        Config::default()
    });
    let config = Arc::new(config);

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(&config.log.log_level),
    )
    .init();

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
    let mut stats_ring_data = None;
    let mut boundary_meta_data = None;

    for (name, map) in controller.maps_mut() {
        match name {
            "SESSIONS" => session_map_data = Some(map),
            "EVENTS_POOL" => event_map_data = Some(map),
            "SCORE_TABLE" => score_table_data = Some(map),
            "QUANTILE_BOUNDS" => quantile_table_data = Some(map),
            "MODEL_CONFIG" => model_config_data = Some(map),
            "STATS_RING_BUF" => stats_ring_data = Some(map),
            "BOUNDARY_META" => boundary_meta_data = Some(map),
            _ => {}
        }
    }

    let session_map = session_map_data.ok_or_else(|| anyhow::anyhow!("SESSIONS map not found"))?;
    let event_map = event_map_data.ok_or_else(|| anyhow::anyhow!("EVENTS_POOL map not found"))?;
    let score_map = score_table_data.ok_or_else(|| anyhow::anyhow!("SCORE_TABLE map not found"))?;
    let quantile_bounds_map =
        quantile_table_data.ok_or_else(|| anyhow::anyhow!("QUANTILE_BOUNDS map not found"))?;
    let model_config_map =
        model_config_data.ok_or_else(|| anyhow::anyhow!("MODEL_CONFIG map not found"))?;
    let stats_ring_map =
        stats_ring_data.ok_or_else(|| anyhow::anyhow!("STATS_RING_BUF map not found"))?;
    let boundary_meta_map =
        boundary_meta_data.ok_or_else(|| anyhow::anyhow!("BOUNDARY_META map not found"))?;

    let session_table = PerCpuHashMap::try_from(session_map)?;
    let event_ring_buf = RingBuf::try_from(event_map)?;
    let mut score_table = Array::try_from(score_map)?;
    let mut quantile_bounds_table = Array::try_from(quantile_bounds_map)?;
    let mut model_config_table = Array::try_from(model_config_map)?;
    let stats_ring_buf = RingBuf::try_from(stats_ring_map)?;
    let boundary_meta_table: Array<_, BoundaryMeta> = Array::try_from(boundary_meta_map)?;

    if config.model.enabled {
        load_model(
            &mut model_config_table,
            &mut quantile_bounds_table,
            &mut score_table,
            &config.model.model_file,
            &config.model.action,
        )?;
    }

    let mut logger = Logger::new(event_ring_buf, session_table, config.clone())?;
    let mut updater = BoundaryUpdater::new(
        stats_ring_buf,
        quantile_bounds_table,
        boundary_meta_table,
        model_config_table,
        config.clone(),
    );

    // Logger and the calibration layer run concurrently. (v1's plan to
    // spawn the updater inside controller.load() is infeasible under aya's
    // borrow model — load() cannot spawn a task borrowing maps from the
    // Ebpf it returns; concurrent run here is the correct adaptation.)
    tokio::try_join!(logger.start(), updater.run())?;

    Ok(())
}
