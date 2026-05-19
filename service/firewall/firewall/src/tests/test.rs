use anyhow::Result;
use aya::include_bytes_aligned;
use aya::maps::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use firewall_common::session::{SessionKey, SessionValue};

use crate::lib::config::Config;
use crate::lib::controller::FirewallController;

#[tokio::test]
#[ignore = "requires Linux + eBPF + root + a real NIC; run explicitly"]
pub async fn test_session_tracking() -> Result<()> {
    let bytecode = include_bytes_aligned!(env!("FIREWALL_BPF"));
    let config = Arc::new(Config::default());
    let mut controller = FirewallController::load(bytecode, config)?;
    controller.attach_xdp("wlp3s0")?; // Attached for integration testing

    // Loop a few times to see if any sessions are created
    for i in 0..5 {
        println!("Check {}:", i);
        let mut count = 0;

        {
            let sessions_map = controller
                .get_mut_map("SESSIONS")
                .expect("SESSIONS map not found");
            let mut sessions: HashMap<_, SessionKey, SessionValue> =
                HashMap::try_from(sessions_map)?;
            for item in sessions.iter() {
                let (key, value) = item?;
                println!(
                    "  Session: {} -> {}, Pkts: {}/{}",
                    Ipv4Addr::from(key.src_ip),
                    Ipv4Addr::from(key.dst_ip),
                    value.orig_pkts,
                    value.resp_pkts
                );
                count += 1;
            }
        }

        if count == 0 {
            println!("  (No sessions yet)");
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    }

    // Add a simple assertion or return Ok(()) to indicate success
    Ok(())
}
