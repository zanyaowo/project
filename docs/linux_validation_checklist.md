# Linux 驗證清單

> macOS 無法編譯 aya（Linux-only syscall：`SYS_bpf`, netlink, `CLOCK_BOOTTIME`）。
> 本文件列出所有需在 Linux 環境確認的項目，依優先度排序。
> 完成後在狀態欄打 `[x]` 並記錄結果。

---

## 環境前置

```bash
# 確認 kernel version >= 5.15（eBPF ring buffer + TC 需要）
uname -r

# 確認 Rust nightly（專案使用 nightly features）
rustup show

# 確認 bpf-linker 可用（eBPF 目標編譯）
cargo install bpf-linker

# 確認 xtask build 工具
cd service/firewall && cargo xtask build-ebpf
```

---

## P0 — 編譯與載入

| 狀態 | 項目 | 指令 |
|------|------|------|
| `[ ]` | firewall-common 編譯 | `cargo check --package firewall-common` |
| `[ ]` | firewall-ebpf 編譯（eBPF target）| `CARGO_TARGET_BPFEL_UNKNOWN_NONE_RUSTFLAGS="-C relocation-model=pic" cargo build --package firewall-ebpf --target bpfel-unknown-none -Z build-std=core` 或 `cargo xtask build-ebpf` |
| `[ ]` | firewall userspace 編譯 | `cargo build --package firewall` |
| `[ ]` | eBPF verifier 通過（無 insn limit / stack overflow）| 觀察 `cargo xtask run` 輸出，無 `Error: BPF_PROG_LOAD` 錯誤 |

---

## P0 — 新功能驗證（2026-05-20 新增）

### CLI 參數

| 狀態 | 項目 | 指令 / 預期 |
|------|------|------------|
| `[ ]` | `--help` 顯示正確 | `sudo ./firewall --help` → 顯示 `--config`, `--iface`, `--log-level` |
| `[ ]` | `--config` 覆蓋路徑 | `sudo ./firewall --config /tmp/test.toml` → 讀取指定 config |
| `[ ]` | `--iface` 覆蓋介面 | `sudo ./firewall --iface eth0` → 掛載至 eth0 而非 config 預設 |
| `[ ]` | `--log-level debug` 輸出 DEBUG | `sudo ./firewall -L debug` → 看到 DEBUG 級 log |

### Graceful Shutdown

| 狀態 | 項目 | 指令 / 預期 |
|------|------|------------|
| `[ ]` | SIGINT 正常退出 | 啟動後 Ctrl-C → 看到 `"Shutdown signal received"` + `"Shutdown complete"` |
| `[ ]` | SIGTERM 正常退出 | `kill -TERM <pid>` → 同上 |
| `[ ]` | XDP 程式已從介面卸載 | 退出後 `ip link show <iface>` → 無 `xdp` 標記 |
| `[ ]` | TC clsact qdisc 已清除 | `tc qdisc show dev <iface>` → 無 `clsact` |

### BLOCK_LIST 動態管理

| 狀態 | 項目 | 驗證方式 |
|------|------|---------|
| `[ ]` | `block_ip` 寫入 BPF map | 呼叫 `controller.block_ip("1.2.3.4".parse()?)` 後，用 `bpftool map dump name BLOCK_LIST` 確認 IP 存在 |
| `[ ]` | `unblock_ip` 移除 map entry | 呼叫 `unblock_ip` 後，`bpftool map dump` 確認 entry 消失 |
| `[ ]` | `list_blocked` 回傳正確 | 插入 2 個 IP → `list_blocked()` 回傳長度 == 2 |
| `[ ]` | 封鎖 IP 的封包被 XDP DROP | `hping3 -S <blocked_ip>` 無回應，`bpftool prog tracelog` 或 metrics 顯示 drop |

---

## P1 — 既有功能回歸測試

### XDP + TC 基本流程

| 狀態 | 項目 | 驗證方式 |
|------|------|---------|
| `[ ]` | XDP 程式成功 attach | `ip link show <iface>` 顯示 `xdp` |
| `[ ]` | TC egress 成功 attach | `tc filter show dev <iface> egress` 顯示 `tc_egress` |
| `[ ]` | 正常封包通過（PASS）| `ping <iface-ip>` 有回應 |
| `[ ]` | SYN cookie 驗證有效 | `hping3 -S <iface-ip>` 三次握手成功 |

### Scorer + Score Table

| 狀態 | 項目 | 驗證方式 |
|------|------|---------|
| `[ ]` | `distilled_rules.json` 載入成功 | log 中出現 `"model loaded"` 無 parse 錯誤 |
| `[ ]` | `SCORE_TABLE` BPF map 已填入 | `bpftool map dump name SCORE_TABLE` 顯示 32 個 i32 entries |
| `[ ]` | `QUANTILE_BOUNDS` 已填入（double-buffer）| `bpftool map dump name QUANTILE_BOUNDS` 顯示 10 entries（5 features × 2 banks）|
| `[ ]` | `active_bank_base()` 讀取正確 bank | 修改 `BOUNDARY_META.active = 1` → scorer 用 bank 1 的 bounds（可透過 log 或 bpftool 確認）|

### Boundary Updater（Adaptive Calibration）

| 狀態 | 項目 | 驗證方式 |
|------|------|---------|
| `[ ]` | `STATS_RING_BUF` 有資料流入 | `bpftool map dump name STATS_RING_BUF`（或觀察 boundary_updater log）|
| `[ ]` | `StatsEvent.flags` BENIGN gate 正確 | 低風險流量 flags bit0 == 1；高風險流量 bit0 == 0 |
| `[ ]` | 批次達 `batch_size` 後觸發 `process_batch` | log 出現 `"boundary_updater: Normal"` 或 `"boundary_updater: Uncertain"` |
| `[ ]` | GateState 在高風險暴增時切換 AttackFreeze | 發送大量模擬攻擊封包 → log 出現 `"boundary_updater: AttackFreeze"` |
| `[ ]` | Normal 狀態下 boundary 版本遞增 | `bpftool map dump name BOUNDARY_META` → `version` 欄位增加 |
| `[ ]` | TTL 到期後回退 bank 0 | 設定 `boundary_ttl_secs = 5` → 5 秒後 scorer 回退 bank 0 |

---

## P2 — 單元測試 / cargo test

| 狀態 | 項目 | 指令 |
|------|------|------|
| `[ ]` | boundary_updater 內建 unit tests | `cargo test --package firewall` → 8 個測試全過（quantile, ema, drift_ratio, divergence, gate_state, encode_decode, stats_event_size, etc.）|
| `[ ]` | `StatsEvent` 大小仍為 48 bytes | `stats_event_decode_from_bytes` 測試中 `assert_eq!(bytes.len(), 48)` |
| `[ ]` | session tracking tests | `cargo test --package firewall -- session` |

---

## P2 — 實驗腳本（需資料路徑）

| 狀態 | 項目 | 指令 |
|------|------|------|
| `[ ]` | 確認資料路徑 `service/model/dataset/parquet_clean/` 存在 | `ls service/model/dataset/parquet_clean/` |
| `[ ]` | Run 30 N-sweep 可執行 | `uv run --project service/model python -m service.model.experiments.run30_n_sweep` |
| `[ ]` | Run 30 輸出結果記錄 | 將輸出貼入 `docs/2_decision/quantile_bucket_strategy_log.md` Run 30 段落 |

---

## 驗證環境記錄（填寫後存檔）

| 項目 | 值 |
|------|---|
| Linux kernel | |
| Distribution | |
| Rust toolchain | |
| 網路介面 | |
| 驗證日期 | |
| 驗證人 | |
