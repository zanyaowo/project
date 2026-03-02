use aya::include_bytes_aligned;
use aya::maps::{PerCpuHashMap, RingBuf};
use std::sync::Arc;
use log::warn;
use crate::lib::config::Config;
use crate::lib::controller::FirewallController;
use crate::lib::logger::Logger;

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
        env_logger::Env::default().default_filter_or(&config.log_config.log_level)
    ).init();

    let bytecode = include_bytes_aligned!(env!("FIREWALL_BPF"));
    let mut controller = FirewallController::load(bytecode, config.clone())?;

    let iface = config.network_config.iface.as_str();

    if config.network_config.enable_xdp {
        controller.attach_xdp(&iface)?;
    }

    if config.network_config.enable_tc {
        controller.attach_tc(&iface)?;
    }


    let mut session_map_data = None;
    let mut event_map_data = None;

    for (name, map) in controller.maps_mut() {
        match name {
            "SESSIONS" => session_map_data = Some(map),
            "EVENTS_POOL" => event_map_data = Some(map),
            _ => {}
        }
    }

    let session_map = session_map_data.ok_or_else(|| anyhow::anyhow!("SESSIONS map not found"))?;
    let event_map = event_map_data.ok_or_else(|| anyhow::anyhow!("EVENTS_POOL map not found"))?;

    let session_table = PerCpuHashMap::try_from(session_map)?;
    let event_ring_buf = RingBuf::try_from(event_map)?;

    let mut logger = Logger::new(event_ring_buf, session_table, config.clone())?;
    logger.start().await?;
    
    Ok(())
}