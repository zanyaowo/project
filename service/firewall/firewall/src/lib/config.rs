use firewall_common::model::ModelConfig;
use log::Level;
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::sync::Arc;

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    pub network: NetworkConfig,
    pub security: SecurityConfig,
    pub log: LogConfig,
    pub maps: MapsConfig,
    pub model: ModelSetting,
    pub adaptive: BoundaryAdaptConfig,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "lowercase")]
pub enum XdpMode {
    Native,
    Skb,
}

#[derive(Deserialize, Clone, Debug)]
pub struct NetworkConfig {
    pub interface: String,
    pub enable_xdp: bool,
    pub enable_tc: bool,
    pub xdp_mode: XdpMode,
}

#[derive(Deserialize, Clone, Debug)]
pub struct LogConfig {
    pub log_level: String,
    pub enable_session_log: bool,
}

#[derive(Deserialize, Clone, Debug)]
pub struct SecurityConfig {
    pub enable_random_secret: bool,
    pub custom_cookie: Option<u32>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct MapsConfig {
    pub block_list_size: u32,
    pub session_table_size: u32,
    pub event_ring_buffer_size: u32,
}

#[derive(Deserialize, Clone, Debug)]
pub struct ModelSetting {
    pub enabled: bool,
    pub model_file: String,
    pub action: String,
    pub hot_reload: bool,
}

#[derive(Deserialize, Clone, Debug)]
pub struct BoundaryAdaptConfig {
    pub enabled: bool,
    pub batch_size: usize,
    pub sample_shift: u32,
    pub ewma_alpha: f64,
    pub minor_drift_ratio: f64,
    pub major_drift_ratio: f64,
    pub score_drift_ratio: f64,
    pub divergence_threshold: f64,
    pub high_risk_rate_jump: f64,
    pub boundary_ttl_secs: u64,
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let contents = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    pub fn default() -> Self {
        Self {
            network: NetworkConfig {
                interface: "lo".to_string(),
                enable_tc: true,
                enable_xdp: true,
                xdp_mode: XdpMode::Skb,
            },
            security: SecurityConfig {
                enable_random_secret: true,
                custom_cookie: None,
            },

            log: LogConfig {
                log_level: Level::Info.to_string(),
                enable_session_log: false,
            },
            maps: MapsConfig {
                block_list_size: 1024,
                session_table_size: 65536,
                event_ring_buffer_size: 4096,
            },
            model: ModelSetting {
                enabled: true,
                model_file: "model.json".to_string(),
                action: "log".to_string(),
                hot_reload: false,
            },
            adaptive: BoundaryAdaptConfig {
                enabled: true,
                batch_size: 1000,
                sample_shift: 4,
                ewma_alpha: 0.20,
                minor_drift_ratio: 0.20,
                major_drift_ratio: 0.50,
                score_drift_ratio: 0.05,
                divergence_threshold: 0.30,
                high_risk_rate_jump: 2.0,
                boundary_ttl_secs: 600,
            },
        }
    }
}
