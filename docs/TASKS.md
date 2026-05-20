# Project Task List

> 依閉環資料流分層：感測 → 決策 → 執行 → 回饋。標記說明：`[ ]` 待辦、`[x]` 完成、`[-]` 進行中。
> 嚴重度：🔴 阻塞性 / 🟡 重要 / 🟢 次要

---

## 1. 感測層（eBPF XDP — 特徵抽取）

| 狀態 | 嚴重 | 任務 | 位置 |
|------|------|------|------|
| `[x]` | 🔴 | 在 XDP per-flow struct 新增 `fwd_pkt_max` 欄位（`SessionValue.max_pkt_len: u32` 已存在） | `firewall-common/src/session.rs:46` |
| `[x]` | 🟡 | 移除 `ModelFeature` struct（已不存在於 `firewall-common/src/lib.rs`） | — |
| `[ ]` | 🟢 | 實作 IPv6 封包解析（`parser.rs:215` 目前 `ETH_IPV6 => return Err(())`） | `firewall-ebpf/src/parser.rs:215` |
| `[x]` | 🟢 | 補上 `unsafe` 程式碼的 safety invariant 說明（`parser.rs` 所有 `unsafe fn` 已有完整 SAFETY 說明）| `firewall-ebpf/src/parser.rs` |

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
| `[x]` | 🔴 | 修復 `logger.rs`：RingBuf 讀取前大小驗證（`data.len() < size_of::<SessionEvent>()` 已修） | `firewall/src/lib/logger.rs:62` |
| `[x]` | 🔴 | 修復 `main.rs`：Per-CPU Map 查詢改用 `?` 而非 `expect()`（已修） | `firewall/src/main.rs` |
| `[x]` | 🔴 | 修復 `controller.rs`：`xdp_mode` match 改為窮舉（`Native` / `Skb` 均覆蓋）| `firewall/src/lib/controller.rs:51` |
| `[x]` | 🟡 | 實作 TC egress attach（`attach_tc` 已實作）並在 `main.rs` 呼叫 | `firewall/src/lib/controller.rs:60` |
| `[x]` | 🟡 | 實作 `BLOCK_LIST` 動態管理（`block_ip` / `unblock_ip` / `list_blocked`）| `firewall/src/lib/controller.rs:80` |
| `[x]` | 🟡 | 實作 SIGINT/SIGTERM graceful shutdown（`tokio::select!` + `shutdown_signal()`）| `firewall/src/main.rs` |
| `[x]` | 🟡 | 實作 CLI（`--config` / `--iface` / `--log-level` 覆蓋）| `firewall/src/main.rs` |
| `[ ]` | 🟢 | 補齊 metrics 輸出（sessions count, drop rate, boundary version）供監控使用 | `firewall/src/lib/logger.rs` |

---

## 4. 回饋層（Boundary Adaptive Update v2）

> 依據 `docs/4_feedback/boundary_adaptive_update_plan.md`（v2 dual-sketch + gated）

| 狀態 | 嚴重 | 任務 | 位置 |
|------|------|------|------|
| `[x]` | 🔴 | 調整 `StatsEvent`：`flags: u32` 與 `STATS_FLAG_BENIGN_GATE = 0x01` 已定義 | `firewall-common/src/model.rs:45` |
| `[x]` | 🔴 | eBPF scorer 計算並寫入 `flags.bit0`（`score×2 < threshold`）已實作 | `firewall-ebpf/src/scorer.rs:158` |
| `[x]` | 🟡 | `BoundaryMeta` struct 及 `BOUNDARY_META` BPF map 已實作 | `firewall-common/src/model.rs:68` |
| `[x]` | 🟡 | `QUANTILE_BOUNDS` double-buffer layout + `active_bank_base()` 已實作 | `firewall-ebpf/src/scorer.rs:48` |
| `[x]` | 🟡 | `BoundaryUpdater` S_ref / S_live dual-sketch + `divergence()` 已實作 | `firewall/src/lib/boundary_updater.rs` |
| `[x]` | 🟡 | `GateState` 狀態機（`Normal` / `Uncertain` / `AttackFreeze`）已實作 | `firewall/src/lib/boundary_updater.rs:42` |
| `[x]` | 🟡 | Periodic calibration（EMA + `write_boundary_version` 原子切換）已實作 | `firewall/src/lib/boundary_updater.rs:233` |
| `[x]` | 🟢 | `expiry_ns` TTL 回退邏輯（`now > expiry_ns → bank 0`）已實作 | `firewall-ebpf/src/scorer.rs:53` |

---

## 5. 跨層 / 整合

| 狀態 | 嚴重 | 任務 | 位置 |
|------|------|------|------|
| `[ ]` | 🟡 | 端到端整合測試：XDP 收封包 → scorer 分類 → boundary updater 更新 → 熱切換 eBPF map，驗證無 half-update | `firewall/src/tests/` |
| `[ ]` | 🟢 | 更新 `docs/claude_ref/codebase_map.md`：補充 `boundary_updater.rs` 函式清單（待實作完成後） | `docs/claude_ref/codebase_map.md` |

---

## 實驗清單（特徵工程 Run 01–32）

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

---

## 論文實驗計畫（IEEE 2-page / WiP）

> 目標敘事：Detection works ＋ Quantile bucket is useful ＋ eBPF mapping is lightweight
> 必做 4 個（P0/P1）＋ 加分 3 個（P2/P3）。兩頁 IEEE 放 **Table 1 + Table 2 + Figure 1 + Figure 2** 即可。

---

### 必做 E1 — 偵測能力 baseline（P0）

**目標：** 證明 teacher + student 有效，分位桶蒸餾不輸 IF teacher 太多。

**交付物：** `Table 1 — Detection Performance`

| 狀態 | 方法 | 說明 |
|------|------|------|
| `[ ]` | IF + fixed threshold | Contamination 參數作為全局 threshold |
| `[ ]` | IF + static quantile bucket | N=4 bucket，邊界只用訓練集算一次（不更新）|
| `[ ]` | Student score regression | Student 直接回歸 IF anomaly score（MSE loss）|
| `[ ]` | **Student quantile bucket KD** | 你的方法：KL/CE distillation → bucket policy |
| `[ ]` | Supervised baseline（選）| LR / RF，需 attack label，作為上限參考 |

**評估指標：** Precision、Recall、F1、ROC-AUC、PR-AUC、FPR、FNR
**Dataset：** CIC-DDoS2019 + BigFlow（至少兩個，展示跨環境）

---

### 必做 E2 — Score Regression vs Quantile-Bucket Classification（P1）

**目標：** 回答 reviewer 必問：「為什麼不直接讓 student 回歸分數？」

**交付物：** 併入 Table 1 或獨立 Table 2（視頁面空間）

| 狀態 | 比較軸 | 說明 |
|------|--------|------|
| `[ ]` | Student output type | Regression（continuous score）vs Classification（bucket label）|
| `[ ]` | Loss function | MSE/MAE vs CrossEntropy vs KL divergence |
| `[ ]` | Ranking preservation | Spearman correlation（student score vs IF score）|
| `[ ]` | Top-k attack recall | 前 k% 高風險流量是否被 student 正確抓到 |

**關鍵論點：** 分位桶保留相對排序（anomaly ranking），不強迫 student 重現不穩定的絕對分數值。

---

### 必做 E3 — Static vs Streaming Bucket（drift robustness）（P1）

**目標：** 證明分位桶邊界獨立更新有價值（流量漂移下 static 邊界會退化）。

**交付物：** `Figure 2 — F1 / FNR over time under drift`

| 狀態 | 對照組 | 邊界更新方式 |
|------|--------|------------|
| `[ ]` | Static Quantile Bucket | 訓練集計算一次，不更新 |
| `[ ]` | Periodic Update Bucket | 每 T 秒以當前視窗重算 |
| `[ ]` | **Gated Streaming Bucket** | 你的方法：S_ref / S_live dual-sketch + GateState |

**Drift 場景（人工製造）：**
- 正常流量 packet rate 放大 2×（模擬業務高峰）
- 攻擊比例從 10% 增加到 50%（模擬攻擊持續）
- 切成至少 4 個 time window，折線圖呈現 F1 / FNR 變化

---

### 必做 E4 — eBPF 系統效能（P0）

**目標：** 證明這是系統論文，eBPF map lookup 遠快於 IF inference。

**交付物：** `Table 2 — System Overhead`

| 狀態 | 指標 | 說明 |
|------|------|------|
| `[ ]` | Packet throughput（pps）| 各方法能處理的最大封包率 |
| `[ ]` | CPU usage（%）| eBPF enforcement 對 CPU 的佔用 |
| `[ ]` | Map lookup latency（ns）| bucket/action 查表單次延遲 |
| `[ ]` | Map update latency（µs）| userspace 寫 BPF map 的成本 |
| `[ ]` | Mitigation latency（µs）| 從偵測到開始 DROP/RATE_LIMIT 的端到端延遲 |
| `[ ]` | Legitimate drop ratio（%）| 正常封包誤丟比例 |

**對照組：**

| 方法 | 說明 |
|------|------|
| No mitigation | 純觀察，無 enforcement |
| eBPF static blocklist | 傳統 IP 黑名單查表 |
| IF per-flow inference（userspace）| 每封包跑一次 sklearn IF |
| **eBPF bucket policy map** | 你的方法 |

**核心要證明：** `eBPF map lookup ≪ IF per-flow inference`

---

### 加分 E5 — Attack Contamination 實驗（P2）

**目標：** 展示 gated update 在 DDoS 攻擊比例高時的安全優勢。

**交付物：** `Figure 2` 的一部分，或單獨小 table

| 狀態 | 攻擊比例 ρ | Naive streaming FNR | Gated streaming FNR |
|------|-----------|:-------------------:|:-------------------:|
| `[ ]` | 10% | — | — |
| `[ ]` | 30% | — | — |
| `[ ]` | 50% | — | — |
| `[ ]` | 80% | — | — |

**關鍵論點：** Naive streaming 在 ρ 高時把攻擊流量校準為新常態（FNR 上升）；gated update 凍結 reference boundary，FNR 維持穩定。

---

### 加分 E6 — Bucket 數量 K 敏感度（P2）

**目標：** 回答「為什麼選 K=4」，同時呈現 eBPF table size 代價。

**交付物：** 小 table 或 appendix（2 頁空間不夠時可在正文提一句）

| 狀態 | K | F1 | PR-AUC | eBPF table size | 說明 |
|------|---|----|--------|-----------------|------|
| `[ ]` | 2 | — | — | 32-entry | 目前 contract |
| `[ ]` | 4 | — | — | 1024-entry | 建議目標 |
| `[ ]` | 8 | — | — | 32768-entry | 資訊上限 |
| `[ ]` | 4-bucket policy | PASS / MONITOR / RATE_LIMIT / DROP | — | 1024-entry | 語意清晰 |

**Bucket 語意建議（K=4）：**

| Bucket | 意義 | Action |
|--------|------|--------|
| 0 | Normal | PASS |
| 1 | Low risk | PASS / MONITOR |
| 2 | Suspicious | RATE_LIMIT |
| 3 | Attack-like | DROP |

---

### 加分 E7 — BPF Map 熱更新一致性（P3）

**目標：** 證明 versioned double-buffer 更新不會讓 datapath 出現 half-update。

**交付物：** 小 table（若頁面空間允許）

| 狀態 | 測試場景 | 指標 |
|------|----------|------|
| `[ ]` | 高速封包通過時持續更新 boundary map | packet loss、inconsistent decision count |
| `[ ]` | Direct update（無 versioning）vs Versioned update | inconsistent decision per 1k updates |
| `[ ]` | TTL 開啟 vs 關閉 | stale policy duration（ms）|

---

### 論文交付物總覽

```
Figure 1  架構圖（Traffic → XDP → Feature Map → IF Teacher → Bucket Policy → eBPF → Action）
Table 1   Detection Performance（E1 + E2）
Table 2   System Overhead（E4）
Figure 2  Drift / Contamination robustness over time（E3 + E5）
```

**最小可行版（時間不夠時）：** Table 1 + Table 2 + 一張折線圖 = 兩頁站得住。

**論文敘事（最終目標）：**
> Quantile-bucket distillation preserves most of the Isolation Forest teacher's detection performance while reducing datapath decision cost to eBPF map lookups. Compared with fixed-threshold and score-regression baselines, streaming quantile-bucket calibration improves robustness under traffic drift. Gated updates further reduce attack-induced boundary contamination during DDoS bursts.
