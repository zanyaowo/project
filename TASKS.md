# Project Task List

> 依閉環資料流分層：感測 → 決策 → 執行 → 回饋。標記說明：`[ ]` 待辦、`[x]` 完成、`[-]` 進行中。
> 嚴重度：🔴 阻塞性 / 🟡 重要 / 🟢 次要

---

## 1. 感測層（eBPF XDP — 特徵抽取）

| 狀態 | 嚴重 | 任務 | 位置 |
|------|------|------|------|
| `[ ]` | 🔴 | 在 XDP per-flow struct 新增 `fwd_pkt_max` 欄位，追蹤前向最大封包大小（FwdMax_q 依賴此值，目前 kernel struct 缺少） | `firewall-ebpf/src/` |
| `[ ]` | 🟡 | 移除或實作 `ModelFeature` struct（`firewall-common/src/lib.rs:4-21`），目前已定義但從未使用 | `firewall-common/src/lib.rs` |
| `[ ]` | 🟢 | 實作 IPv6 封包解析（`parser.rs:157-159` 目前直接 skip） | `firewall-ebpf/src/parser.rs` |
| `[ ]` | 🟢 | 補上 `unsafe` 程式碼的 safety invariant 說明（`main.rs`, `syn_cookie.rs`, `parser.rs`, `table.rs`） | firewall-ebpf |

---

## 2. 決策層（eBPF TC scorer + ML pipeline）

| 狀態 | 嚴重 | 任務 | 位置 |
|------|------|------|------|
| `[ ]` | 🔴 | 評估 Run 29 `init_win_bit`（Init Fwd Win / Init Bwd Win 比值）是否整合進 eBPF scorer 取代 `protocol_bit`（Run 29 結論：單特徵 AUC=0.9995 for HOIC） | `firewall-ebpf/src/scorer.rs` + `distill_export.py` |
| `[ ]` | 🟡 | 執行 Run 30 N-sweep（資料就緒後）：驗證多點分位桶對 HOIC / LOIC-HTTP 的改善效果 | `service/model/experiments/run30_n_sweep.py` |
| `[ ]` | 🟡 | 根據 Run 30 結果更新 `distill_export.py`：若 N=4 variant 顯著優於 N=2，調整 contract 並重新蒸餾 `distilled_rules.json` | `pipeline/distill_export.py` |
| `[ ]` | 🟡 | 撰寫 Layer 2 Userspace 完整 IF 集成計畫文件（`docs/2_decision/layer2_integration_plan.md`，目前 CLAUDE.md / kernel_defense_architecture.md 有 3 處懸空引用） | `docs/2_decision/` |
| `[ ]` | 🟢 | 更新 `docs/_crosscut/kernel_defense_architecture.md` 的 AUC 表：補入 Run 30 結果欄 | `docs/_crosscut/kernel_defense_architecture.md` |

---

## 3. 執行層（Rust Userspace — 控制面 / 限流）

| 狀態 | 嚴重 | 任務 | 位置 |
|------|------|------|------|
| `[ ]` | 🔴 | 修復 `logger.rs:34`：RingBuf 讀取前缺少 buffer 大小驗證，可能越界 | `firewall/src/lib/logger.rs:34` |
| `[ ]` | 🔴 | 修復 `main.rs:52-53`：Per-CPU Map 查詢使用 `expect()`，CPU 不存在時 panic | `firewall/src/main.rs:52-53` |
| `[ ]` | 🔴 | 修復 `controller.rs:48-51`：`xdp_mode` 的非窮舉 match，非法值會 panic | `firewall/src/lib/controller.rs:48-51` |
| `[ ]` | 🟡 | 實作 TC egress attach（`attach_tc` / `detach_tc`）並在 `main.rs` 呼叫，使 Bwd 流量追蹤完整 | `firewall/src/lib/controller.rs` + `main.rs` |
| `[ ]` | 🟡 | 實作 `BLOCK_LIST` 動態管理（`block_ip` / `unblock_ip` / `list_blocked_ips`），讓 runtime 可修改封鎖名單 | `firewall/src/lib/controller.rs` |
| `[ ]` | 🟡 | 實作 SIGINT/SIGTERM graceful shutdown：`tokio::select!` + `controller.detach_tc()`，防止 eBPF 程式殘留介面 | `firewall/src/main.rs` |
| `[ ]` | 🟡 | 實作 CLI（`clap` 已在 Cargo.toml，但 `main.rs` 未使用）：子命令 `start` / `stop` / `status` / `block` / `sessions` / `stats` | `firewall/src/main.rs` |
| `[ ]` | 🟢 | 補齊 metrics 輸出（sessions count, drop rate, boundary version）供監控使用 | `firewall/src/lib/logger.rs` |

---

## 4. 回饋層（Boundary Adaptive Update v2）

> 依據 `docs/4_feedback/boundary_adaptive_update_plan.md`（v2 dual-sketch + gated）

| 狀態 | 嚴重 | 任務 | 位置 |
|------|------|------|------|
| `[ ]` | 🔴 | 調整 `StatsEvent`：將 `_pad` 改為 `flags: u32`，定義 `STATS_FLAG_BENIGN_GATE = 0x01` | `firewall-common/src/model.rs` |
| `[ ]` | 🔴 | 在 eBPF scorer 端計算並寫入 `flags.bit0`（`score × 2 < threshold` 為 BENIGN gate） | `firewall-ebpf/src/scorer.rs` |
| `[ ]` | 🟡 | 定義並寫入 `BoundaryMeta` struct（`version: u32`, `active: u32`, `expiry_ns: u64`）至新 BPF map | `firewall-common/src/model.rs` + kernel map |
| `[ ]` | 🟡 | 調整 `QUANTILE_BOUNDS` map 為 `2 × FEATURE_COUNT` entries（double-buffer layout），scorer 讀取時依 `BoundaryMeta.active` 選 bank | `firewall-ebpf/src/scorer.rs` |
| `[ ]` | 🟡 | 實作 userspace `BoundaryUpdater`：維護 `S_ref`（BENIGN gate 過濾）+ `S_live`（全取樣），計算 `Δ_t = quantile divergence` | `firewall/src/lib/boundary_updater.rs` |
| `[ ]` | 🟡 | 實作 `GateState` 狀態機（`Normal` / `Uncertain` / `AttackFreeze`）：依 `Δ_t` 與高風險桶命中率切換 | `firewall/src/lib/boundary_updater.rs` |
| `[ ]` | 🟡 | 實作 periodic calibration：每 N 批以 EMA 更新 reference boundary，通過 gate 後寫 inactive bank，原子切換 `BoundaryMeta.active` | `firewall/src/lib/boundary_updater.rs` |
| `[ ]` | 🟢 | 實作 `expiry_ns` TTL 回退邏輯（kernel 端：`now > expiry_ns` 時回退 bank 0） | `firewall-ebpf/src/scorer.rs` |

---

## 5. 跨層 / 整合

| 狀態 | 嚴重 | 任務 | 位置 |
|------|------|------|------|
| `[ ]` | 🟡 | 端到端整合測試：XDP 收封包 → scorer 分類 → boundary updater 更新 → 熱切換 eBPF map，驗證無 half-update | `firewall/src/tests/` |
| `[ ]` | 🟢 | 更新 `docs/claude_ref/codebase_map.md`：補充 `boundary_updater.rs` 函式清單（待實作完成後） | `docs/claude_ref/codebase_map.md` |

---

## 實驗清單

> `[x]` 已完成並記錄、`[-]` 已寫腳本待跑、`[ ]` 規劃中

| 狀態 | Run | 主題 | 腳本 | 關鍵結論 |
|------|-----|------|------|---------|
| `[x]` | 01–07 | 特徵選擇基線（80→17 特徵，AUC=0.9257） | — | 絕對值特徵跨環境 AUC 0.28 |
| `[x]` | 08–10 | 跨資料集驗證：絕對值特徵在 LOIC-HTTP 崩潰 | — | 確認需無量綱特徵 |
| `[x]` | 11–16 | 比例特徵（Shape+Sym+Pkt_CV）+ log1p | — | HOIC 仍 ≈0；比例特徵未解決 |
| `[x]` | 17 | N=2 分位桶突破（BENIGN 中位數邊界） | `run17_quantile_ratio.py` | HOIC 0.002→0.993；核心突破 |
| `[x]` | 18 | Bytes sum 特徵實驗 | `run18_bytes_sum.py` | — |
| `[x]` | 19 | Mixed BENIGN 邊界（CIC+BigFlow） | `run19_mixed_benign.py` | 解決 CIC-only overfit |
| `[x]` | 20 | 移除 Shape_q 影響評估 | `run20_no_shape.py` | AUC −0.017，損失可接受但需替代 |
| `[x]` | 21 | Shape_q 替代特徵搜尋 | `run21_shape_alternatives.py` | FwdMax_ratio 為最佳替代（+0.031） |
| `[x]` | 22 | FwdMax_q N-scan（N=2/4/8/16） | `run22_fwdmax_n_scan.py` | N=2 最優；IF-direct（非 contract 路徑） |
| `[x]` | 23 | BigFlow OOD overfit 驗證 | `run23_bigflow_overfit_check.py` | Shape_q BigFlow AUC 0.40（反轉）|
| `[x]` | 24 | Mixed BENIGN 訓練：Shape_q vs FwdMax_q | `run24_mixed_benign_shape_fwdmax.py` | Mixed 後 FwdMax_q 均勝 Shape_q |
| `[x]` | 25 | 最終特徵確立 + N-scan（FwdMax+Sym+CV+Protocol+Mean） | `run25_final_fwdmax_n_scan.py` | 最終 5 特徵方案（IF-direct，非 contract）|
| `[x]` | 26 | 完整指標（AUC-PR, TPR@FPR）| `run26_extended_metrics.py` | AUC-PR DDoS2019=0.9895；BigFlow TPR@1%=0.0148 |
| `[x]` | 27 | Boundary overfit check（CIC vs BigFlow 邊界差異）| `run27_boundary_overfit_check.py` | 兩環境分布差異 2–4×；必須 Mixed 邊界 |
| `[x]` | 28 | Contract 對照矩陣（Run25 original vs 32-entry all-binary）| `run28_contract_matrix.py` | **部署 contract HOIC=0.0001，avg=0.60**；protocol 二值化是根本原因 |
| `[x]` | 29 | HOIC 特徵替換（init_win_bit 修復 HOIC）| `run29_hoic_feature_search.py` | `init_win_bit` 單特徵 HOIC AUC=0.9995；BigFlow 無此欄位不受影響 |
| `[-]` | **30** | N-sweep 多點分位桶（N=2/4/8，全特徵含 Protocol）| `run30_n_sweep.py` | 腳本完成，等待資料路徑 |
| `[ ]` | 31 | `init_win_bit` contract 整合驗證：以 32-entry 或 64-entry 實際 score table 重跑 Run29 最佳變體 | — | 確認 init_win_bit 在 score-table 路徑（非 IF-direct）的真實 AUC |
| `[ ]` | 32 | Layer 2 完整 IF 整合實驗：userspace runtime IF 與 kernel fast-path 分流策略 | — | 需先完成 Layer 2 集成計畫文件 |
