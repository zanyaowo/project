use std::path::PathBuf;
use std::{env, fs};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let config_path = manifest_dir.parent().unwrap().join("firewall/config.toml");

    // 告訴 Cargo：config.toml 改變時要重新執行 build.rs
    println!("cargo:rerun-if-changed={}", config_path.display());

    let (
        block_list_size,
        session_table_size,
        event_ring_buffer_size,
        quantile_bound_size,
        score_table_size,
        model_config_size,
        stats_ring_buf_size,
    ) = if config_path.exists() {
        let contents = fs::read_to_string(&config_path).unwrap();
        parse_map_sizes(&contents)
    } else {
        // config 不存在時的預設值；stats ring buf 預設 65536 bytes（≈1365 StatsEvent@48B）
        (1024u32, 65536u32, 4096u32, 5u32, 32u32, 1u32, 65536u32)
    };

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let code = format!(
        "pub const BLOCK_LIST_SIZE: u32 = {};\n\
           pub const SESSION_TABLE_SIZE: u32 = {};\n\
           pub const EVENT_RING_BUF_SIZE: u32 = {};\n
           pub const QUANTILE_BOUND_SIZE: u32 = {};\n
           pub const SCORE_TABLE_SIZE: u32 = {};\n
           pub const MODEL_CONFIG_SIZE: u32 = {};\n
           pub const STATS_RING_BUF_SIZE: u32 = {};\n",
        block_list_size,
        session_table_size,
        event_ring_buffer_size,
        quantile_bound_size,
        score_table_size,
        model_config_size,
        stats_ring_buf_size
    );
    fs::write(out_dir.join("map_sizes.rs"), code).unwrap();
}

fn parse_map_sizes(contents: &str) -> (u32, u32, u32, u32, u32, u32) {
    let value: toml::Value = toml::from_str(&contents).unwrap();
    let maps = &value["maps"];

    (
        maps.get("block_list_size")
            .and_then(|v| v.as_integer())
            .unwrap_or(1024) as u32,
        maps.get("session_table_size")
            .and_then(|v| v.as_integer())
            .unwrap_or(65536) as u32,
        maps.get("event_ring_buffer_size")
            .and_then(|v| v.as_integer())
            .unwrap_or(4096) as u32,
        maps.get("quantile_bound_size")
            .and_then(|v| v.as_integer())
            .unwrap_or(80) as u32,
        maps.get("score_table_size")
            .and_then(|v| v.as_integer())
            .unwrap_or(32) as u32,
        maps.get("model_config_size")
            .and_then(|v| v.as_integer())
            .unwrap_or(1) as u32,
    )
}
