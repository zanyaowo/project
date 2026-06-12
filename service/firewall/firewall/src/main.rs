// `lib` below is a plain submodule of the binary, not a library target root.
// special_module_name is an early-pass lint: the item-level allow is ignored,
// it must sit at crate level.
#![allow(special_module_name)]

use crate::lib::boundary_updater::BoundaryUpdater;
use crate::lib::config::Config;
use crate::lib::controller::FirewallController;
use crate::lib::logger::Logger;
use crate::lib::model_loader::{load_model, write_boundary_version};
use aya::include_bytes_aligned;
use aya::maps::{Array, MapData, PerCpuArray, PerCpuHashMap, RingBuf};
use clap::Parser;
use firewall_common::model::{BoundaryMeta, QuantileBound, FEATURE_COUNT};
use log::warn;
use std::sync::Arc;

mod lib;
mod tests;

#[derive(Parser)]
#[command(name = "firewall", about = "eBPF-based DDoS detection firewall")]
struct Cli {
    /// Config file path
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// Override network interface from config
    #[arg(short, long)]
    iface: Option<String>,

    /// Override log level from config (trace / debug / info / warn / error)
    #[arg(short = 'L', long)]
    log_level: Option<String>,
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        use tokio::signal::unix::SignalKind;
        let mut sigterm = tokio::signal::unix::signal(SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();

    let mut config: Config = Config::from_file(&cli.config).unwrap_or_else(|e| {
        warn!("Failed to load config from {}: {}", cli.config, e);
        Config::default()
    });

    if let Some(iface) = cli.iface {
        config.network.interface = iface;
    }
    if let Some(level) = cli.log_level {
        config.log.log_level = level;
    }

    let config = Arc::new(config);

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(&config.log.log_level),
    )
    .init();

    let bytecode = include_bytes_aligned!(env!("FIREWALL_BPF"));
    let mut controller = FirewallController::load(bytecode, config.clone())?;

    let iface = config.network.interface.as_str();

    if config.network.enable_xdp {
        controller.attach_xdp(iface)?;
    }

    if config.network.enable_tc {
        controller.attach_tc(iface)?;
    }

    let mut session_map_data = None;
    let mut event_map_data = None;
    let mut score_table_data = None;
    let mut quantile_table_data = None;
    let mut model_config_data = None;
    let mut stats_ring_data = None;
    let mut boundary_meta_data = None;
    let mut drop_events_data = None;

    for (name, map) in controller.maps_mut() {
        match name {
            "SESSIONS" => session_map_data = Some(map),
            "EVENTS_POOL" => event_map_data = Some(map),
            "SCORE_TABLE" => score_table_data = Some(map),
            "QUANTILE_BOUNDS" => quantile_table_data = Some(map),
            "MODEL_CONFIG" => model_config_data = Some(map),
            "STATS_RING_BUF" => stats_ring_data = Some(map),
            "BOUNDARY_META" => boundary_meta_data = Some(map),
            "DROP_EVENTS" => drop_events_data = Some(map),
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

    let drop_events_map =
        drop_events_data.ok_or_else(|| anyhow::anyhow!("DROP_EVENTS map not found"))?;
    let session_table = PerCpuHashMap::try_from(session_map)?;
    let event_ring_buf = RingBuf::try_from(event_map)?;
    let drop_events: PerCpuArray<_, u64> = PerCpuArray::try_from(drop_events_map)?;
    let mut score_table = Array::try_from(score_map)?;
    let mut quantile_bounds_table = Array::try_from(quantile_bounds_map)?;
    let mut model_config_table = Array::try_from(model_config_map)?;
    let stats_ring_buf = RingBuf::try_from(stats_ring_map)?;
    let mut boundary_meta_table: Array<_, BoundaryMeta> = Array::try_from(boundary_meta_map)?;

    if config.model.enabled {
        load_model(
            &mut model_config_table,
            &mut quantile_bounds_table,
            &mut score_table,
            &config.model.model_file,
            &config.model.action,
        )?;
    }

    // Table 2 / 8.A-5: direct microbenchmark of the boundary map-update path
    // (double-buffered QUANTILE_BOUNDS write + BOUNDARY_META version flip).
    // The adaptive gate only publishes under benign-dominated traffic, which
    // is hard to synthesize on a loopback testbed; this hook measures the pure
    // syscall cost against the real kernel maps. Enable with
    //   FIREWALL_BENCH_MAP_UPDATE=<iterations> firewall --iface lo
    if let Ok(iters) = std::env::var("FIREWALL_BENCH_MAP_UPDATE") {
        let n: usize = iters.parse().unwrap_or(1000);
        bench_map_update(&mut quantile_bounds_table, &mut boundary_meta_table, n)?;
        return Ok(());
    }

    let mut logger = Logger::new(event_ring_buf, session_table, drop_events, config.clone())?;
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
    tokio::select! {
        res = async { tokio::try_join!(logger.start(), updater.run()) } => { res?; }
        _ = shutdown_signal() => {
            log::info!("Shutdown signal received");
        }
    }

    // Drop map borrows before touching controller for TC cleanup.
    drop(logger);
    drop(updater);

    if config.network.enable_tc {
        if let Err(e) = controller.detach_tc(iface) {
            log::warn!("TC cleanup failed (qdisc may already be gone): {e}");
        }
    }

    log::info!("Shutdown complete");
    Ok(())
}

/// Microbenchmark the boundary map-update path: `n` back-to-back
/// `write_boundary_version` calls (double-buffered bank write + version flip)
/// against the live kernel maps, reporting min/p50/p99/max in microseconds.
/// Mirrors the per-batch publish the adaptive updater performs at steady state.
fn bench_map_update(
    bounds_map: &mut Array<&mut MapData, QuantileBound>,
    meta_map: &mut Array<&mut MapData, BoundaryMeta>,
    n: usize,
) -> anyhow::Result<()> {
    let new_bounds = [QuantileBound {
        value: 1,
        numer: 1,
        denom: 1,
    }; FEATURE_COUNT as usize];

    let mut samples: Vec<f64> = Vec::with_capacity(n);
    // One untimed warm-up to fault in pages / prime the bank flip.
    write_boundary_version(bounds_map, meta_map, &new_bounds, 0)?;
    for _ in 0..n {
        let t0 = std::time::Instant::now();
        write_boundary_version(bounds_map, meta_map, &new_bounds, 0)?;
        samples.push(t0.elapsed().as_secs_f64() * 1e6);
    }

    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pct = |p: f64| samples[((samples.len() as f64 * p) as usize).min(samples.len() - 1)];
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    log::info!(
        "map_update_latency_bench: n={} min={:.2} p50={:.2} mean={:.2} p99={:.2} max={:.2} (us); \
         each call = {} QUANTILE_BOUNDS set + 1 BOUNDARY_META flip",
        n,
        samples[0],
        pct(0.50),
        mean,
        pct(0.99),
        samples[samples.len() - 1],
        FEATURE_COUNT,
    );
    Ok(())
}
