use anyhow::Context as _;
use clap::Parser;
use std::{
    path::PathBuf,
    process::Command,
};

#[derive(Parser)]
struct Opts {
    #[clap(subcommand)]
    cmd: Cmd,
}

#[derive(Parser)]
enum Cmd {
    /// Build the eBPF program
    BuildEbpf {
        /// Build for release
        #[clap(long)]
        release: bool,
    },
    /// Build and run the userspace program
    Run {
        /// Build for release
        #[clap(long)]
        release: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();

    match opts.cmd {
        Cmd::BuildEbpf { release } => build_ebpf(release),
        Cmd::Run { release } => run(release),
    }
}

fn build_ebpf(release: bool) -> anyhow::Result<()> {
    let dir = PathBuf::from(".");
    let target = "bpfel-unknown-none";

    let mut args = vec![
        "build",
        "-Z",
        "build-std=core",
        "--package",
        "firewall-ebpf",
        "--target",
        target,
    ];
    if release {
        args.push("--release");
    }

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = Command::new(cargo)
        .current_dir(&dir)
        .args(&args)
        .status()
        .context("Failed to build eBPF program")?;

    if !status.success() {
        anyhow::bail!("Failed to build eBPF program");
    }

    Ok(())
}

fn run(release: bool) -> anyhow::Result<()> {
    // 1. 先編譯 eBPF
    build_ebpf(release)?;

    // 2. 計算 eBPF 編譯出的檔案路徑
    let profile = if release { "release" } else { "debug" };
    let bpf_path = std::env::current_dir()?
        .join("target")
        .join("bpfel-unknown-none")
        .join(profile)
        .join("firewall-ebpf");

    // 3. 執行使用者空間程式，並傳入環境變數
    let mut args = vec!["run", "--package", "firewall"];
    if release {
        args.push("--release");
    }

    // 這裡需要 sudo 權限來載入 XDP，所以通常我們會希望 cargo run 跑起來後
    // 內部程式碼去處理權限，或者直接用 sudo -E cargo xtask run
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = Command::new(cargo)
        .args(&args)
        .env("FIREWALL_BPF", bpf_path) // 設定環境變數供 env! 巨集讀取
        .status()
        .context("Failed to run userspace program")?;

    if !status.success() {
        anyhow::bail!("Failed to run userspace program");
    }

    Ok(())
}