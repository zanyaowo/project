use aya::include_bytes_aligned;
use aya::maps::{PerCpuHashMap, RingBuf};
use firewall_common::{SessionKey, SessionValue};
use crate::lib::controller::FirewallController;
use crate::lib::logger::Logger;

mod lib;
mod tests;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let bytecode = include_bytes_aligned!(env!("FIREWALL_BPF"));
    let mut controller = FirewallController::load(bytecode)?;

    let iface = std::env::var("IFACE").unwrap_or_else(|_| "wlp3s0".to_string());
    controller.attach(&iface)?;

    let mut session_map_data = None;
    let mut event_map_data = None;

    // Split borrows: Iterate through maps to get both mutable references simultaneously
    for (name, map) in controller.maps_mut() {
        match name {
            "SESSIONS" => session_map_data = Some(map),
            "EVENTS_POOL" => event_map_data = Some(map),
            _ => {}
        }
    }

    let session_map = session_map_data.expect("SESSIONS map not found");
    let event_map = event_map_data.expect("EVENTS_POOL map not found");

    let session_table = PerCpuHashMap::try_from(session_map)?;
    let event_ring_buf = RingBuf::try_from(event_map)?;

    let mut logger = Logger::new(event_ring_buf, session_table)?;    
    logger.start().await?;
    
    Ok(())
}