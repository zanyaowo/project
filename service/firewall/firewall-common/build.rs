use std::{env, fs};
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let config_path = manifest_dir.parent().unwrap().join("firewall/config.toml");

    // 告訴 Cargo：config.toml 改變時要重新執行 build.rs
    println!("cargo:rerun-if-changed={}", config_path.display());

    let (block_list_size, session_table_size, event_ring_buffer_size) =
        if config_path.exists() {
            let contents = fs::read_to_string(&config_path).unwrap();
            parse_map_sizes(&contents)
        } else {
            // config 不存在時的預設值
            (1024u32, 65536u32, 4096u32)
        };

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let code = format!(
        "pub const BLOCK_LIST_SIZE: u32 = {};\n\
           pub const SESSION_TABLE_SIZE: u32 = {};\n\
           pub const EVENT_RING_BUF_SIZE: u32 = {};\n",
        block_list_size, session_table_size, event_ring_buffer_size
    );
    fs::write(out_dir.join("map_sizes.rs"), code).unwrap();
}

fn parse_map_sizes(contents: &str) -> (u32, u32, u32) {
    let value: toml::Value = toml::from_str(&contents).unwrap();
    let maps = &value["maps"];

    (
        maps["block_list_size"].as_integer().unwrap() as u32,
        maps["session_table_size"].as_integer().unwrap() as u32,
        maps["event_ring_buffer_size"].as_integer().unwrap() as u32,
    )
}