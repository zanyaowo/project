# Userspace Firewall 改進計畫

生成日期: 2026-02-21

## 當前功能分析

### 已實現的功能

1. **eBPF 程式載入與附加** - XDP 程式載入與網路介面附加
2. **事件處理** - 透過 RingBuf 從 kernel 接收 SessionEvent
3. **Session 聚合與統計** - 跨 CPU 聚合 session 資料並計算統計指標
4. **Session 清理機制** - 定義了基於協定與時間的 session 清理邏輯 (task.rs)
5. **ModelFeature 特徵計算** - 計算機器學習模型所需的網路流量特徵

### 架構概覽

```
firewall/src/
├── main.rs           # 程式進入點、eBPF 載入、事件處理迴圈
├── lib/
│   ├── controller.rs # FirewallController - eBPF 程式管理
│   ├── logger.rs     # Logger - RingBuf 事件處理與統計計算
│   └── task.rs       # Session 清理邏輯 (未使用)
└── tests/
    └── test.rs       # Session tracking 測試
```

## 需要改進的功能

### 🔴 Critical (關鍵功能缺失)

#### 1. SECRET_KEY 初始化
**問題**: syn_cookie.rs 使用的 SECRET_KEY Map 未初始化
**影響**: SYN Cookie 功能無法正常運作，驗證邏輯會失效
**建議實作**:
```rust
// controller.rs
impl FirewallController {
    pub fn init_secret_key(&mut self) -> anyhow::Result<()> {
        use rand::Rng;
        let secret: u32 = rand::thread_rng().gen();

        let secret_map = self.bpf.map_mut("SECRET_KEY")
            .context("SECRET_KEY map not found")?;
        let mut array: Array<_, u32> = Array::try_from(secret_map)?;
        array.set(0, secret, 0)?;

        Ok(())
    }
}
```

**相關檔案**:
- `firewall-ebpf/src/syn_cookie.rs:21` - SECRET_KEY 定義
- `firewall/src/lib/controller.rs` - 需要新增初始化方法

---

#### 2. TC Egress 程式未附加
**問題**: main.rs 只附加 XDP 程式，TC egress 程式未被使用
**影響**: 無法追蹤 TX (outbound) 方向的流量，Session 資料不完整
**建議實作**:
```rust
// controller.rs
use aya::programs::{tc, SchedClassifier, TcAttachType};

impl FirewallController {
    pub fn attach_tc(&mut self, iface: &str) -> anyhow::Result<()> {
        // 建立 clsact qdisc
        tc::qdisc_add_clsact(iface)?;

        let program: &mut SchedClassifier = self.bpf
            .program_mut("tc_egress")
            .context("tc_egress program not found")?
            .try_into()?;

        program.load()?;
        program.attach(iface, TcAttachType::Egress)?;

        Ok(())
    }

    pub fn detach_tc(&mut self, iface: &str) -> anyhow::Result<()> {
        tc::qdisc_del_clsact(iface)?;
        Ok(())
    }
}
```

**相關檔案**:
- `firewall-ebpf/src/main.rs:33-39` - tc_egress 程式定義
- `firewall/src/main.rs:18` - 需要呼叫 attach_tc
- `firewall/src/lib/controller.rs` - 需要新增 TC 附加方法

---

#### 3. BLOCK_LIST 動態管理介面
**問題**: 無法在 runtime 動態新增/移除封鎖的 IP
**影響**: 必須重新編譯才能修改封鎖名單，無法即時回應安全威脅
**建議實作**:
```rust
// controller.rs
use aya::maps::HashMap;

impl FirewallController {
    pub fn block_ip(&mut self, ip: Ipv4Addr) -> anyhow::Result<()> {
        let block_map = self.bpf.map_mut("BLOCK_LIST")
            .context("BLOCK_LIST not found")?;
        let mut map: HashMap<_, u32, u8> = HashMap::try_from(block_map)?;
        map.insert(u32::from(ip), 1, 0)?;
        Ok(())
    }

    pub fn unblock_ip(&mut self, ip: Ipv4Addr) -> anyhow::Result<()> {
        let block_map = self.bpf.map_mut("BLOCK_LIST")
            .context("BLOCK_LIST not found")?;
        let mut map: HashMap<_, u32, u8> = HashMap::try_from(block_map)?;
        map.remove(&u32::from(ip))?;
        Ok(())
    }

    pub fn list_blocked_ips(&mut self) -> anyhow::Result<Vec<Ipv4Addr>> {
        let block_map = self.bpf.map_mut("BLOCK_LIST")
            .context("BLOCK_LIST not found")?;
        let map: HashMap<_, u32, u8> = HashMap::try_from(block_map)?;

        let mut ips = Vec::new();
        for item in map.iter() {
            if let Ok((ip, _)) = item {
                ips.push(Ipv4Addr::from(ip));
            }
        }
        Ok(ips)
    }
}
```

**相關檔案**:
- `firewall-ebpf/src/blocker.rs` - BLOCK_LIST 定義
- `firewall/src/lib/controller.rs` - 需要新增管理方法

---

#### 4. Graceful Shutdown
**問題**: 無 SIGINT/SIGTERM 處理，程式終止時不會清理 eBPF 程式
**影響**: eBPF 程式可能殘留在網路介面上，需要手動 `ip link set dev <iface> xdp off`
**建議實作**:
```rust
// main.rs
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // ... 初始化程式碼 ...

    // Spawn logger task
    let logger_handle = tokio::spawn(async move {
        logger.start().await
    });

    // Wait for shutdown signal
    tokio::select! {
        _ = signal::ctrl_c() => {
            log::info!("Received SIGINT, shutting down...");
        }
        _ = signal_unix::signal(signal_unix::SignalKind::terminate())? => {
            log::info!("Received SIGTERM, shutting down...");
        }
    }

    // Cleanup
    controller.detach_tc(&iface)?;
    // XDP auto-detaches on drop

    log::info!("Shutdown complete");
    Ok(())
}
```

**相關檔案**:
- `firewall/src/main.rs` - 需要新增 signal handling

---

### 🟡 Major (重要功能)

#### 5. CLI 介面
**問題**: Cargo.toml 已引入 clap dependency 但未使用
**影響**: 無法透過命令列進行操作管理
**建議實作**:
```rust
// main.rs
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "firewall")]
#[command(about = "eBPF-based firewall", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the firewall service
    Start {
        #[arg(short, long, default_value = "wlp3s0")]
        iface: String,
    },
    /// Stop the firewall service
    Stop,
    /// Show firewall status
    Status,
    /// Manage IP blocklist
    Block {
        #[command(subcommand)]
        action: BlockAction,
    },
    /// List active sessions
    Sessions {
        #[arg(short, long, default_value = "table")]
        format: String, // table, json, csv
    },
    /// Show statistics
    Stats,
}

#[derive(Subcommand)]
enum BlockAction {
    Add { ip: String },
    Remove { ip: String },
    List,
}
```

**相關檔案**:
- `firewall/src/main.rs` - 需要重構為 CLI 應用
- `firewall/Cargo.toml:15` - clap dependency 已存在

---

#### 6. Configuration 管理
**問題**: 所有設定都是硬編碼 (介面名稱、timeout 值等)
**影響**: 難以在不同環境部署，缺乏彈性
**建議實作**:
```toml
# config/firewall.toml
[firewall]
interface = "wlp3s0"
log_level = "info"

[session]
tcp_timeout = 30        # seconds
tcp_close_timeout = 5   # seconds after FIN/RST
udp_timeout = 10        # seconds
cleanup_interval = 5    # seconds

[syn_cookie]
enable = true
secret_rotation_interval = 3600  # seconds

[export]
enable_prometheus = true
prometheus_port = 9090
enable_json_log = false
json_log_path = "/var/log/firewall/sessions.jsonl"
```

```rust
// lib/config.rs
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub firewall: FirewallConfig,
    pub session: SessionConfig,
    pub syn_cookie: SynCookieConfig,
    pub export: ExportConfig,
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&content)?)
    }
}
```

**新增檔案**:
- `firewall/src/lib/config.rs` - 設定檔載入
- `firewall/config/firewall.toml` - 預設設定檔

**依賴新增**:
```toml
# Cargo.toml
serde = { version = "1", features = ["derive"] }
toml = "0.8"
```

---

#### 7. 結構化日誌
**問題**: 使用 `println!` 而非 `log` crate，不適合生產環境
**影響**: 無法控制日誌等級、格式、輸出目標
**建議改進**:
```rust
// logger.rs
use log::{info, warn, debug};

// 將這段:
println!(
    "Log: Src={}:{}, Dst={}:{}, Proto={}, Bytes={}, Dur={:.4}s",
    ...
);

// 改為:
info!(
    "session_closed src={}:{} dst={}:{} proto={} bytes={} duration={:.4}s orig_pkts={} resp_pkts={}",
    Ipv4Addr::from(session_key.src_ip), session_key.src_port,
    Ipv4Addr::from(session_key.dst_ip), session_key.dst_port,
    session_key.proto,
    bytes_sum,
    duration_sec,
    orig_pkts,
    resp_pkts
);

debug!("feature_computed bytes_ratio={:.3} pkts_ratio={:.3} bps={}",
    bytes_ratio, pkts_ratio, bps_approx);
```

**相關檔案**:
- `firewall/src/lib/logger.rs:67-74` - 需要改用 log macros

---

#### 8. Metrics 匯出
**問題**: ModelFeature 計算後未被使用
**影響**: 無法監控系統狀態、無法整合 Prometheus/Grafana
**建議實作**:
```rust
// lib/metrics.rs
use prometheus::{Registry, IntCounter, Histogram, Opts};

pub struct MetricsExporter {
    registry: Registry,
    sessions_total: IntCounter,
    sessions_active: IntGauge,
    bytes_total: IntCounter,
    packets_total: IntCounter,
    session_duration: Histogram,
}

impl MetricsExporter {
    pub fn new() -> anyhow::Result<Self> {
        let registry = Registry::new();

        let sessions_total = IntCounter::new(
            "firewall_sessions_total",
            "Total number of sessions"
        )?;
        registry.register(Box::new(sessions_total.clone()))?;

        // ... 註冊其他 metrics ...

        Ok(Self { registry, sessions_total, ... })
    }

    pub fn record_session(&self, feature: &ModelFeature) {
        self.sessions_total.inc();
        self.bytes_total.inc_by(feature.bytes_sum);
        self.packets_total.inc_by(feature.pkts_sum);
        self.session_duration.observe(feature.duration as f64 / 1e9);
    }

    pub async fn serve(self, port: u16) -> anyhow::Result<()> {
        // HTTP server for /metrics endpoint
    }
}
```

**新增檔案**:
- `firewall/src/lib/metrics.rs` - Prometheus exporter

**依賴新增**:
```toml
prometheus = "0.13"
axum = "0.7"  # for HTTP server
```

---

#### 9. Session 匯出與查詢
**問題**: 無法查看目前活躍的 sessions
**影響**: 缺乏可見性，難以診斷網路問題
**建議實作**:
```rust
// controller.rs
impl FirewallController {
    pub fn list_sessions(&mut self) -> anyhow::Result<Vec<SessionInfo>> {
        let session_map = self.bpf.map_mut("SESSIONS")
            .context("SESSIONS not found")?;
        let sessions: PerCpuHashMap<_, SessionKey, SessionValue> =
            PerCpuHashMap::try_from(session_map)?;

        let mut result = Vec::new();
        for item in sessions.iter() {
            let (key, values) = item?;

            // 聚合 per-CPU 資料
            let info = SessionInfo {
                src_ip: Ipv4Addr::from(key.src_ip),
                dst_ip: Ipv4Addr::from(key.dst_ip),
                src_port: key.src_port,
                dst_port: key.dst_port,
                proto: key.proto,
                orig_bytes: values.iter().map(|v| v.orig_bytes).sum(),
                resp_bytes: values.iter().map(|v| v.resp_bytes).sum(),
                // ...
            };
            result.push(info);
        }
        Ok(result)
    }
}

// CLI command
Commands::Sessions { format } => {
    let sessions = controller.list_sessions()?;
    match format.as_str() {
        "json" => println!("{}", serde_json::to_string_pretty(&sessions)?),
        "csv" => { /* CSV output */ },
        _ => { /* table output */ },
    }
}
```

**相關檔案**:
- `firewall/src/lib/controller.rs` - 新增查詢方法

---

### 🟢 Minor (次要功能)

#### 10. Session 清理任務未執行
**問題**: task.rs 的 `kill_old_sessions` 已實作但從未被呼叫
**影響**: Session table 會無限增長，最終耗盡記憶體
**建議修復**:
```rust
// main.rs
let cleanup_handle = tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        interval.tick().await;
        let removed = task::kill_old_sessions(&mut session_table);
        if removed > 0 {
            log::debug!("Cleaned {} old sessions", removed);
        }
    }
});
```

**相關檔案**:
- `firewall/src/lib/task.rs:6-52` - kill_old_sessions 實作
- `firewall/src/main.rs` - 需要啟動清理任務

---

#### 11. 多網路介面支援
**問題**: 只支援單一網路介面
**影響**: 無法同時監控多個介面 (如 eth0 + wlan0)
**建議實作**:
```rust
// main.rs
let ifaces: Vec<String> = env::var("IFACES")
    .unwrap_or_else(|_| "wlp3s0".to_string())
    .split(',')
    .map(|s| s.trim().to_string())
    .collect();

for iface in &ifaces {
    controller.attach(iface)?;
    controller.attach_tc(iface)?;
}
```

---

#### 12. 錯誤重試機制
**問題**: attach 失敗就直接退出，無重試邏輯
**影響**: 暫時性錯誤 (如介面尚未 up) 會導致服務無法啟動
**建議實作**:
```rust
use tokio::time::{sleep, Duration};

async fn attach_with_retry(
    controller: &mut FirewallController,
    iface: &str,
    max_retries: u32
) -> anyhow::Result<()> {
    let mut attempt = 0;
    loop {
        match controller.attach(iface) {
            Ok(_) => return Ok(()),
            Err(e) if attempt < max_retries => {
                let delay = Duration::from_secs(2u64.pow(attempt));
                warn!("Attach failed (attempt {}), retrying in {:?}: {}",
                    attempt + 1, delay, e);
                sleep(delay).await;
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}
```

---

#### 13. Health Check 端點
**問題**: 無法查詢服務狀態
**影響**: 難以整合 Kubernetes readiness/liveness probes
**建議實作**:
```rust
// lib/health.rs
use axum::{Router, Json, routing::get};
use serde::Serialize;

#[derive(Serialize)]
struct HealthStatus {
    status: String,
    attached: bool,
    interfaces: Vec<String>,
    sessions_count: u64,
}

async fn health_handler() -> Json<HealthStatus> {
    // 檢查 eBPF 程式狀態
    Json(HealthStatus {
        status: "ok".to_string(),
        attached: true,
        interfaces: vec!["wlp3s0".to_string()],
        sessions_count: 1234,
    })
}

pub async fn serve_health(port: u16) -> anyhow::Result<()> {
    let app = Router::new().route("/health", get(health_handler));
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

---

#### 14. 統計資訊儀表板
**建議實作**:
```bash
$ firewall stats
┌─────────────────────────────────────┐
│      Firewall Statistics            │
├─────────────────────────────────────┤
│ Active Sessions:        1,234       │
│ Total Sessions:        45,678       │
│ Blocked IPs:               12       │
│ Packets Processed:  9,876,543       │
│ Bytes Processed:       12.3 GB      │
│ Throughput:            1.2 MB/s     │
│ Uptime:              2d 14h 32m     │
└─────────────────────────────────────┘

Top Talkers:
  192.168.1.100:443 ← → 8.8.8.8:53     12.3 MB
  192.168.1.101:80  ← → 1.1.1.1:443     8.7 MB
  ...
```

---

#### 15. eBPF Map 檢查工具
**建議實作**:
```bash
$ firewall debug maps
Available maps:
  - SESSIONS (LruPerCpuHashMap): 1234 entries, 10240 max
  - BLOCK_LIST (HashMap): 5 entries, 1024 max
  - EVENTS_POOL (RingBuf): 262144 bytes
  - SECRET_KEY (Array): 1 entry

$ firewall debug dump SESSIONS --limit 10
SessionKey { src: 192.168.1.100:12345, dst: 8.8.8.8:443, proto: TCP }
  CPU 0: bytes=1234, pkts=10
  CPU 1: bytes=5678, pkts=45
  Total: bytes=6912, pkts=55
...
```

---

## 實作優先順序

### Phase 1: 核心功能修復 (1-2 週)
優先級最高，修復關鍵缺陷

1. ✅ SECRET_KEY 初始化
2. ✅ TC egress 附加
3. ✅ Graceful shutdown
4. ✅ Session 清理任務啟用

**交付物**: 功能完整的基礎防火牆

---

### Phase 2: CLI 與管理 (1-2 週)
提升可用性與管理能力

5. ✅ CLI 介面實作
6. ✅ BLOCK_LIST 管理 API
7. ✅ Configuration 檔案支援

**交付物**: 可用於生產環境的命令列工具

---

### Phase 3: 可觀測性 (1 週)
增強監控與除錯能力

8. ✅ 結構化日誌
9. ✅ Prometheus metrics
10. ✅ Session 查詢 API

**交付物**: 可整合 Grafana/Prometheus 的監控方案

---

### Phase 4: 增強功能 (1-2 週)
提升穩定性與易用性

11. ✅ 多介面支援
12. ✅ 錯誤重試機制
13. ✅ Health check 端點
14. ✅ 統計儀表板
15. ✅ Debug 工具

**交付物**: 企業級防火牆解決方案

---

## 相關文件

- [Code Quality Review](./code_quality_review_2026-02-21.md) - eBPF 與 common 程式碼審查
- [PacketInfo Redesign Proposal](./packetinfo_redesign_proposal.md) - 封包解析架構設計

---

## 技術參考

- [Aya Book](https://aya-rs.dev/book/) - Rust eBPF 框架文件
- [Prometheus Rust Client](https://docs.rs/prometheus/latest/prometheus/) - Metrics 匯出
- [Clap](https://docs.rs/clap/latest/clap/) - CLI 框架
- [Tokio Signal](https://docs.rs/tokio/latest/tokio/signal/) - Graceful shutdown
