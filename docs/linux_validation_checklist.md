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
| `[x]` | firewall-common 編譯 | `cargo check --package firewall-common` |
| `[x]` | firewall-ebpf 編譯（eBPF target）| `cargo xtask build-ebpf`（debug + release 均通過，2026-05-22） |
| `[x]` | firewall userspace 編譯 | `cargo build --package firewall`（需先 build-ebpf，FIREWALL_BPF 有值） |
| `[x]` | eBPF verifier 通過（無 insn limit / stack overflow）| 2026-05-23 通過。修補：(1) `tc_egress` 拆 helper、(2) `update_checksum` while 改 2-fold、(3) `wrapping_mul` 取代 `saturating_mul`。詳見 `docs/_crosscut/issues/ebpf_verifier_pitfalls.md` |

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
| `[x]` | SIGINT 正常退出 | 2026-05-23 確認（Ctrl-C 觸發 `Shutdown signal received` + `Shutdown complete`）|
| `[x]` | SIGTERM 正常退出 | 2026-05-23 確認（`sudo pkill -TERM firewall` 觸發 graceful shutdown） |
| `[x]` | XDP 程式已從介面卸載 | 2026-05-23 確認（`ip link show wlp3s0` 無 `xdp` 標記） |
| `[x]` | TC clsact qdisc 已清除 | 2026-05-23 確認（修補：`detach_tc` 改用 `tc qdisc del dev <iface> clsact` 系統指令，aya 0.13.1 沒提供等效 API） |

### BLOCK_LIST 動態管理

| 狀態 | 項目 | 驗證方式 |
|------|------|---------|
| `[ ]` | `block_ip` 寫入 BPF map | 呼叫 `controller.block_ip("1.2.3.4".parse()?)` 後，用 `bpftool map dump name BLOCK_LIST` 確認 IP 存在 |
| `[ ]` | `unblock_ip` 移除 map entry | 呼叫 `unblock_ip` 後，`bpftool map dump` 確認 entry 消失 |
| `[ ]` | `list_blocked` 回傳正確 | 插入 2 個 IP → `list_blocked()` 回傳長度 == 2 |
| `[ ]` | 封鎖 IP 的封包被 XDP DROP | `hping3 -S <blocked_ip>` 無回應，`bpftool prog tracelog` 或 metrics 顯示 drop |

---

## On-hardware 驗證 runbook（`scripts/validate_runtime.sh`，2026-06-07）

> 自動化上述 P0/P1 手動項目。**前提：firewall 必須先在另一終端啟動**（maps 已載入、XDP/TC 已 attach）；腳本只檢查 live maps 與打流量，不負責啟動 firewall。需 `root` + `bpftool`；打流量需 `hping3`。

```bash
# 終端 1：啟動 firewall（前景，持續運行）
make run-firewall IFACE=<iface>

# 終端 2：依序驗證
make verify-load      IFACE=<iface>            # P0：XDP/TC attach + 6 個 map 載入、SCORE_TABLE=32、QUANTILE_BOUNDS=10
make verify-packets   IFACE=<iface>            # P1：ping/hping3 → SESSIONS 成長、dump SCORE_TABLE/DROP_EVENTS
make verify-boundary  IFACE=<iface>            # P1：SYN flood → 觀察 firewall log 'AttackFreeze' + BOUNDARY_META.version 凍結
make verify-blocklist IFACE=<iface> IP=1.2.3.4 # 寫 IPv4-mapped key 進 BLOCK_LIST → hping3 → DROP_EVENTS 遞增 → 自動清除 entry
```

**逐項對應：**

| 子指令 | 對應 checklist 項目 | 通過判準 |
|--------|--------------------|---------|
| `verify-load` | P0 attach / 各 map 載入 / SCORE_TABLE 32-entry / QUANTILE_BOUNDS 10-entry | XDP+TC PASS、5 map 全 loaded |
| `verify-packets` | P1 正常封包通過、SCORE_TABLE 填入 | SESSIONS 數量成長 |
| `verify-boundary` | P1 GateState AttackFreeze、version 遞增/凍結 | flood 時 log 出現 `AttackFreeze`、version 停止遞增 |
| `verify-blocklist` | P0 封鎖 IP 封包被 DROP | DROP_EVENTS 遞增（單機 spoofed source 需配合 tracelog 確認） |

> 注意：`verify-boundary` / `verify-blocklist` 的最終判定需人工觀察 firewall 終端 log 與 `bpftool prog tracelog`；單機環境下 spoofed-source 封包不一定真的回流經 XDP ingress，雙機拓樸最可靠。

---

## P1 — 既有功能回歸測試

### XDP + TC 基本流程

| 狀態 | 項目 | 驗證方式 |
|------|------|---------|
| `[x]` | XDP 程式成功 attach | 2026-05-23 確認（程式啟動無錯誤，wlp3s0 SKB mode） |
| `[x]` | TC egress 成功 attach | 2026-05-23 確認（程式啟動無錯誤） |
| `[ ]` | 正常封包通過（PASS）| `ping <iface-ip>` 有回應（待實際測） |
| `[ ]` | SYN cookie 驗證有效 | `hping3 -S <iface-ip>` 三次握手成功（待實際測） |

### Scorer + Score Table

| 狀態 | 項目 | 驗證方式 |
|------|------|---------|
| `[x]` | `model.json` 載入成功 | 2026-05-23 contract 驗證通過（CIC-only 重新產出 via `distill_export_cic_only.py`，threshold=7073）|
| `[ ]` | `SCORE_TABLE` BPF map 已填入 | `bpftool map dump name SCORE_TABLE` 顯示 32 個 i32 entries |
| `[ ]` | `QUANTILE_BOUNDS` 已填入（double-buffer）| `bpftool map dump name QUANTILE_BOUNDS` 顯示 10 entries（5 features × 2 banks）|
| `[ ]` | `active_bank_base()` 讀取正確 bank | 修改 `BOUNDARY_META.active = 1` → scorer 用 bank 1 的 bounds（可透過 log 或 bpftool 確認）|

### Boundary Updater（Adaptive Calibration）

| 狀態 | 項目 | 驗證方式 |
|------|------|---------|
| `[ ]` | `STATS_RING_BUF` 有資料流入 | bpftool map dump name STATS_RING_BUF（或觀察 boundary_updater log）|
| `[ ]` | `StatsEvent.flags` BENIGN gate 正確 | 低風險流量 flags bit0 == 1；高風險流量 bit0 == 0 |
| `[ ]` | 批次達 `batch_size` 後觸發 `process_batch` | log 出現 `"boundary_updater: Normal"` 或 `"boundary_updater: Uncertain"` |
| `[ ]` | GateState 在高風險暴增時切換 AttackFreeze | 發送大量模擬攻擊封包 → log 出現 `"boundary_updater: AttackFreeze"` |
| `[ ]` | Normal 狀態下 boundary 版本遞增 | `bpftool map dump name BOUNDARY_META` → `version` 欄位增加 |
| `[ ]` | TTL 到期後回退 bank 0 | 設定 `boundary_ttl_secs = 5` → 5 秒後 scorer 回退 bank 0 |

---

## P2 — 單元測試 / cargo test

| 狀態 | 項目 | 指令 |
|------|------|------|
| `[x]` | boundary_updater 內建 unit tests | `cargo test --package firewall` → 8 passed（quantile, ema, drift_ratio, divergence, gate_state, encode_decode, stats_event_size, score_quantile），2026-05-22 |
| `[x]` | `StatsEvent` 大小仍為 48 bytes | `stats_event_decode_from_bytes` 通過 |
| `[x]` | session tracking tests | `cargo test --package firewall -- session`（test 存在，標記 `#[ignore]` 需 root + NIC；測試基礎建設確認，2026-05-23） |

---

## P2 — 實驗腳本（需資料路徑）

| 狀態 | 項目 | 指令 |
|------|------|------|
| `[x]` | 確認資料路徑 `service/model/dataset/parquet_clean/` 存在 | `ls service/model/dataset/parquet_clean/`（2026-05-23 確認） |
| `[x]` | Run 30 N-sweep 可執行 | `uv run --project service/model python -m service.model.experiments.run30_n_sweep`（成功，2026-05-23） |
| `[x]` | Run 30 輸出結果記錄 | 貼入 `docs/2_decision/quantile_bucket_strategy_log.md` Run 30 段落（2026-05-23） |

---

## 運行里程碑

### 2026-05-23 — 首次端對端成功啟動 ✅

**狀態：** firewall 可在 wlp3s0 介面成功啟動、attach XDP + TC、載入 model、Logger 持續讀取 ring buffer。

**過程關鍵修補（依時序）：**

1. **eBPF verifier — `aggregate returns are not supported`** → `try_tc_egress` 改 `#[inline(always)]`（後改為直接展開到 entry function）
2. **eBPF verifier — `last insn is not an exit or jmp`** → `tc_egress` 拆成 `tc_egress_impl(&ctx) -> i32` helper，回傳 scalar 避免 sret convention
3. **eBPF verifier — `BPF program is too large` (1M insns)** → `syn_cookie.rs::update_checksum` 的 `while` 改成兩次 unrolled fold
4. **eBPF verifier — `R9 !read_ok` / `R7 !read_ok`** → multi-arm match join point register 未初始化；改用 helper function 隔離 register allocation
5. **`__multi3` undefined** → `scorer.rs` / `table.rs` 的 `saturating_mul` 全換成 `wrapping_mul`
6. **aya 0.13.1 API** → `Array::get` 需要 `&u32`、`tc::qdisc_del_clsact` → `qdisc_detach_program`
7. **model.json 不符 contract** → `distill_export_cic_only.py` 用 CIC BENIGN 重新產出（30000 samples，IF n_estimators=200，threshold=7073）

**完整技術細節：** `docs/_crosscut/issues/ebpf_verifier_pitfalls.md`、`docs/_crosscut/learning/ebpf_debugging_guide.md`

**已確認功能：**
- ✅ eBPF 程式通過 verifier
- ✅ XDP 程式 attach 到 wlp3s0（SKB mode）
- ✅ TC egress 程式 attach
- ✅ Model JSON 載入成功（contract 驗證通過）
- ✅ Logger 持續從 EVENTS_POOL ring buffer 讀取事件
- ✅ Boundary Updater task 同時運行
- ℹ️  AYA_LOGS warning 為預期行為（我們未定義 perf event array）

---

### 2026-06-07 — release verifier load 實機複驗（loopback）✅ / debug build verifier reject ⚠️

**環境：** kernel 6.12.90-1-MANJARO，以預建 artifact 直接 load（未重編；nightly + bpf-linker 缺，現有 source 有未提交修改未涵蓋）。介面用 `lo`（SKB / `xdpgeneric`）避免擾動 live `wlp3s0`。

| 項目 | 結果 |
|------|------|
| release artifact（`target/release/firewall`，05-23 build）load | ✅ verifier PASS，XDP+TC attach 到 lo |
| Logger ring buffer | ✅ 即時讀到 loopback TCP session（`127.0.0.1` 多筆） |
| SIGTERM graceful shutdown | ✅ `Shutdown complete`，lo 無 xdp / 無 tc egress filter / 無 clsact 殘留 |
| **debug artifact（`target/debug/firewall`，05-31 build）load** | ❌ **verifier REJECT**：`last insn is not an exit or jmp`（0 insns processed） |

**結論：**
- 正式 load 路徑（release）在真機 kernel verifier 通過 — §8.C 🔴 verifier-load 任務完成。
- **debug eBPF bytecode 過不了 verifier**（未最佳化，典型 debug-vs-release 差異）。影響 `make run-firewall-debug` 與 `make run-test`（integration `test_session_tracking` 走 debug bytecode 會撞同一錯）。
  - **根因確認**：workspace 與 `firewall-ebpf/Cargo.toml` **完全沒有 `[profile.*]` 設定** → dev build 為 `opt-level=0`，aya 已知陷阱（opt-level=0 的 BPF object verifier 必拒）。
  - **建議修法**（aya template 慣例，待有 nightly + bpf-linker 時套用並重編驗證）：於 eBPF 所屬 workspace `Cargo.toml` 加
    ```toml
    [profile.dev]
    opt-level = 3
    [profile.release]
    lto = true
    ```
  - 在修好前：on-hardware 一律用 release artifact（`make run-firewall` / `make run-test` 需改走 release bytecode）。
- 未跑：`verify-packets/boundary/blocklist` 的 map dump 與 flood — `bpftool` / `hping3` 未安裝且 pacman offline。

---

## 驗證環境記錄（填寫後存檔）

| 項目 | 值 |
|------|---|
| Linux kernel | 6.12.90-1-MANJARO |
| Distribution | Manjaro |
| Rust toolchain | nightly-x86_64-unknown-linux-gnu (1.97.0-nightly, 2026-05-21) |
| bpf-linker | 0.10.3（升級自 0.9.15，修 LLVM 22 相容性） |
| 網路介面 | wlp3s0（無線，XDP SKB mode）|
| 驗證日期 | 2026-05-23 |
| 驗證人 | zanya |
