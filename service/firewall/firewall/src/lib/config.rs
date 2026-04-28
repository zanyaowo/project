use serde::Deserialize;
use std::fs;
use std::path::Path;
use log::Level;
use std::sync::Arc;
use firewall_common::model::ModelConfig;

#[derive(Deserialize, Clone, Debug)]
pub struct Config{
    pub network: NetworkConfig,
    pub security: SecurityConfig,
    pub log: LogConfig,
    pub maps: MapsConfig,
    pub model: ModelSetting
}

#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "lowercase")]
pub enum XdpMode {
    Native,
    Skb,
}

#[derive(Deserialize, Clone, Debug)]
pub struct NetworkConfig{
    pub interface: String,
    pub enable_xdp: bool,
    pub enable_tc: bool,
    pub xdp_mode: XdpMode,
}

#[derive(Deserialize, Clone, Debug)]
pub struct LogConfig{
    pub log_level: String,
    pub enable_session_log: bool,
}

#[derive(Deserialize, Clone, Debug)]
pub struct SecurityConfig{
    pub enable_random_secret: bool,
    pub custom_cookie: Option<u32>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct MapsConfig{
    pub block_list_size: u32,
    pub session_table_size: u32,
    pub event_ring_buffer_size: u32,
}

#[derive(Deserialize, Clone, Debug)]
pub struct ModelSetting{
    pub enabled: bool,
    pub model_file: String,
    pub action: String,
    pub hot_reload: bool,
}

impl Config{
    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self>{
        let contents = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    pub fn default() -> Self{
        Self{
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
            model: ModelSetting{
                enabled: true,
                model_file: "model.json".to_string(),
                action: "log".to_string(),
                hot_reload: false,
            }
        }
    }

}