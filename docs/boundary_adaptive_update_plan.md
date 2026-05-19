# eBPF 分位桶邊界自適應更新計畫（v2：dual-sketch + gated update）

**狀態：** 設計修訂完成，待實作
**依據：** Run 27–29 實驗結論 + kernel_defense_architecture.md Layer 設計 + 設計回饋（gated update / dual sketch / versioned eBPF map）
**v1 → v2 變更摘要：** 由單路徑「偵測 drift → 更新」改為「reference / live 雙草圖 + gate 判斷後才更新 reference 邊界」，並把 eBPF 熱更新具體化為 versioned + double-buffering + fixed-point + TTL。

---

## 1. 背景與動機

### 問題

`QUANTILE_BOUNDS` 與 `SCORE_TABLE` 在部署後是靜態的，由 Python ML pipeline 離線產出，Rust loader 一次性寫入。當部署環境的流量統計偏離訓練 BENIGN 分布時（Run 27 確認 CIC 2019 與 BigFlow 差異達 2–4×），性能退化而沒有自動修正機制。

### 核心設計原則（保守版敘述）

> 利用串流分位數草圖作為 Isolation Forest anomaly score 的輕量校準層，將高成本的 teacher retraining 與低成本的 score-to-policy mapping update 解耦；並透過 gated update、dual sketch 與 versioned eBPF map，避免「正常流量漂移」與「DDoS 攻擊污染」被混為一談。

形式化：

```
x  --f_T-->  s  --g_t-->  b  --h-->  action
   (IF teacher)  (分位桶校準)  (策略)
```

- `f_T`（Isolation Forest）：特徵 → 異常分數。重建需重新取樣與建樹，**更新成本高、頻率低**（Python 離線、小時/天/手動）。
- `g_t`（分位桶 / score→bucket mapping）：異常分數 → 風險桶。僅依賴**分數流的統計分布**，可高頻、低成本校準。

本系統的獨立更新點是 `g_t`，**不是** `f_T`。因此這是 *score calibration / policy mapping update*，不是 teacher model retraining——這個用詞比「模型自適應」精確，也比較不會被挑戰。

### A 與 B 追蹤不同層次的漂移

| 路徑 | 追蹤對象 | 輸出 | 解決的問題 |
|------|----------|------|-----------|
| **A** | 原始特徵分佈（每特徵一個草圖）| QUANTILE_BOUNDS | 輸入環境漂移（封包大小上升、協定比例改變）|
| **B** | IF anomaly score 分佈（一個草圖）| MODEL_CONFIG.threshold | 決策閾值漂移（正常流量分數整體偏移）|

| 漂移類型 | A 能偵測 | B 能偵測 |
|---------|:--------:|:--------:|
| 正常流量封包大小上升 | ✅ | ⚠️ 間接 |
| 攻擊手法改變 | ❌ | ✅ |
| 業務高峰期流量改變 | ✅ | ✅ |
| IF 模型老化 | ❌ | ✅ |

---

## 2. 量化器選型（保守敘述，避免過度設計）

本實作**不引入 DDSketch / t-digest / GK 等外部 sketch crate**，使用每批 `BATCH_SIZE` 筆的 batch sort 取分位數即可滿足需求（kernel 不算中位數，分位數一律在 userspace 算）。串流分位數文獻僅作為背景框架，不作為實作主線：

| 類別 | 代表文獻 | 特性（保守敘述） | 是否進實作 |
|------|----------|------------------|:----------:|
| 經典 streaming quantile | GK 2001 | single-pass、rank-error bound `O((1/ε)·log(εN))` | 否 |
| Tail quantile 工程實作 | t-digest 2019 | 小 sketch、對偏態/尾端分位有良好工程表現；需遵守 centroid size constraint 與 scale function | 否 |
| 相對誤差 / mergeable | DDSketch 2019 (PVLDB) | relative-error guarantee、fully mergeable、Datadog 大規模使用 | 否 |
| Concept drift trigger | ADWIN 2007 | adaptive windowing，監控 scalar stream 的統計變化（如 mean shift），非完整分布檢定 | 觸發訊號之一（選用） |

說明：不宣稱任一方法「最強」。各方法分別適合 relative error / tail quantile / concept drift trigger。ADWIN 若採用，只作為 score stream 的觸發訊號之一，完整分布變化以 reference/live 草圖的 quantile divergence 補足（見 §4）。

---

## 3. 架構設計（v2：dual-sketch + gate）

### 分層資料流

```
【Isolation Forest Teacher：低頻更新】
  features → anomaly score s ∈ fixed-point；Python 離線/手動，產出 SCORE_TABLE（不在線上改）

        ↓ kernel 每筆流量：5-bit index → SCORE_TABLE → score

【eBPF kernel (scorer.rs)：取樣輸出 StatsEvent】
  - 對「取樣後的流量」寫入 STATS_RING_BUF: StatsEvent{ numer[5], denom[5], score, flags }
  - flags bit0 = passed_benign_gate（score × 2 < threshold，明確 BENIGN）

        ↓ STATS_RING_BUF

【Score Calibration Layer (boundary_updater.rs)：高頻校準】
  state:
    S_ref  : 只接收 flags.passed_benign_gate == 1 的樣本（低風險、可信）
    S_live : 接收所有取樣樣本（反映當前分布）
    boundary version v、current boundaries B_v

        ↓

【Drift / Attack Gate】
  signals:
    - quantile divergence  Δ_t = (1/K) Σ |Q_live(τ_i) − Q_ref(τ_i)|
    - 高風險桶命中率（bit==1 比例）
    - DROP 率 / legitimate drop feedback
    - (選用) ADWIN on score stream
  decision:
    normal drift     → 以 EMA 緩慢更新 reference 邊界 → 寫 eBPF
    suspected attack  → 凍結 reference 邊界，只更新 mitigation policy（不寫 boundary）
    uncertain         → 只更新 S_live，不動 reference、不寫 eBPF

        ↓

【Boundary Recalibration】
  B_raw = { Q_ref(τ1..τK) }
  B_new = EMA(B_old, B_raw, α)
  B_new = monotonicity_check(B_new)   # 寫入前確保非遞減

        ↓

【eBPF Map Hot Update（versioned + double-buffer + fixed-point + TTL）】
  寫 inactive buffer → 更新 version/expiry → 原子切換 active index

        ↓

【XDP / TC Enforcement】
  packet → feature/risk mapping → bucket → action
```

### 為何要 dual sketch（這是 v2 最重要的安全性邏輯）

v1 的單路徑「偵測到 drift 就更新」在 DDoS 場景有風險：攻擊高峰把分數分布整體右移，若直接校準，等於把攻擊流量「校準成新常態」（attack adaptation），降低防禦靈敏度。

v2 原則：

> **偵測到 drift 不代表要更新分位桶；要先判斷 drift 是正常業務變化還是攻擊污染。攻擊造成的分布偏移應該被隔離，而不是被校準成新常態。**

- `S_ref`：只吃通過 kernel BENIGN gate（`score × 2 < threshold`）的低風險樣本，產生穩定的 bucket boundary。
- `S_live`：吃所有取樣樣本，反映當前分布，用於偵測偏移。
- `Δ_t = D(S_ref, S_live)`：判斷是「正常漂移」還是「攻擊污染」的核心指標。

### Gate 決策表

| 情況 | 不建議（v1 行為） | v2 行為 |
|------|------------------|---------|
| 桶 3 / 高風險桶命中率暴增 | 直接提高異常邊界 | 進入 attack mode，**凍結** reference boundary |
| DROP 率暴增 | 直接降低靈敏度 | 檢查 legitimate drop / allowlist / service health，不自動放寬 |
| 分數分布右移、Δ_t 上升但高風險桶**未**同步暴增 | 立即更新 | 視為正常漂移，EMA 緩慢更新 reference |
| Δ_t 上升 **且** 高風險桶命中率同步暴增 | 接受新分布 | 攻擊污染，凍結 reference，只更新 S_live 與 mitigation policy |

---

## 4. 更新時機（四類）

| 更新類型 | 觸發條件 | 是否更新 reference boundary | 是否寫 eBPF map |
|----------|----------|:--------------------------:|:--------------:|
| Per-sample sketch update | 每筆取樣 score | 只進 S_live；S_ref 僅在 gate 通過時 | 否 |
| Periodic calibration | 每 N 批（≈1–5 分鐘） | 是，使用 EMA | 是 |
| Drift-triggered calibration | Δ_t / (選用) ADWIN 超過門檻 | 視 gate 結果 | 視 gate 結果 |
| Attack-mode freeze | 高風險桶暴增、DROP 率暴增、service degradation | 否 | 只更新 mitigation policy |

---

## 5. 新增 / 修改的資料結構

### `StatsEvent`（firewall-common/src/model.rs，已存在，調整 `_pad → flags`）

```rust
#[repr(C)]
#[derive(Copy, Clone)]
pub struct StatsEvent {
    pub numer: [u32; FEATURE_COUNT_USIZE], // 各特徵分子（u64 飽和截斷至 u32）
    pub denom: [u32; FEATURE_COUNT_USIZE], // 各特徵分母
    pub score: i32,
    pub flags: u32,                        // 原 _pad；bit0 = passed_benign_gate
}
// 仍為 48 bytes；#[cfg(feature="user")] unsafe impl aya::Pod
```

`flags` 常數（firewall-common/src/model.rs）：

```rust
pub const STATS_FLAG_BENIGN_GATE: u32 = 0x01; // score×2 < threshold（明確 BENIGN）
```

各特徵 numer/denom 對應（與現有 scorer.rs `val_numer/val_denom` 一致）：

| feat | 特徵 | numer | denom |
|-----|------|-------|-------|
| 0 | PROTOCOL | proto as u32 | 1 |
| 1 | PKT_LEN_MEAN | total_bytes | total_pkts |
| 2 | FWD_MAX_Q | max_pkt × orig_pkts (sat u32) | orig_bytes |
| 3 | SYM_RATIO | orig_pkts | resp_pkts |
| 4 | PKT_CV_SQ | cv_numer (sat u32) | total_bytes² (sat u32) |

### `BoundaryMeta`（versioned 雙緩衝中繼資料）

`QuantileBound` 本已是整數（kernel 無浮點），不需額外 fixed-point。版本/緩衝中繼以獨立小 map 表示：

```rust
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct BoundaryMeta {
    pub version: u32,    // 每次發布遞增
    pub active: u32,     // 目前生效 bank（0 或 1）
    pub expiry_ns: u64,  // TTL（CLOCK_MONOTONIC ns）；0 = 不過期
}
```

**Double buffering（over 既有 QuantileBound layout）**：`QUANTILE_BOUNDS` 配置 `2 × FEATURE_COUNT` entries，bank `b` 佔 `[b*FEATURE_COUNT .. (b+1)*FEATURE_COUNT)`。userspace 寫入 inactive bank 全部 entries 後，以**單一 `BOUNDARY_META.set(0, …)`** 原子翻轉 `active`。datapath 在 `score_session()` 開頭讀一次 `BOUNDARY_META`，整筆流量用同一 bank（RCU-like，無半更新）；若 `expiry_ns != 0 && now > expiry_ns` 則回退 bank 0（保守預設）。

---

## 6. 修改清單（v2）

### firewall-common

| 檔案 | 改動 |
|------|------|
| `src/model.rs` | `StatsEvent._pad → flags`；新增 `STATS_FLAG_BENIGN_GATE`、`BoundaryConfig`、`unsafe impl aya::Pod`（user feature）|
| `src/constants.rs` | 新增 `STATS_SAMPLE_SHIFT`（1<<N 取 1）、`STATS_BATCH_SIZE`（1000）、`BOUNDARY_BANK_COUNT`（2）|
| `build.rs` | **修 bug**：`parse_map_sizes` 回傳 8-tuple 並解析 `stats_ring_buf_size`；新增 `boundary_meta_size`（=1）；`quantile_bound_size` 預設改 10（2 bank × 5）|

### firewall-ebpf

| 檔案 | 改動 |
|------|------|
| `src/scorer.rs` | 新增 `STATS_RING_BUF`、`BOUNDARY_META`、`STATS_SAMPLE_CTR`（PerCpuArray）map；`score_session()` 開頭讀 `BOUNDARY_META` 決定 bank base（含 TTL 回退）；末端 per-CPU 取樣輸出 `StatsEvent`，設 `flags`（`score×2<threshold` → `STATS_FLAG_BENIGN_GATE`）；`QUANTILE_BOUNDS` index 改 `bank_base + feature_index` |
| `src/main.rs` | 確認新 map 自動掛載（aya `#[map]`）|

### firewall（userspace）

| 檔案 | 改動 |
|------|------|
| `src/lib/mod.rs` | 新增 `pub mod boundary_updater;` |
| `src/lib/boundary_updater.rs` | **新檔**：dual-sketch buffers、batch-sort 量化器、EMA、divergence、gate 狀態機、versioned/double-buffer 寫入、`#[cfg(test)]` 純邏輯測試（見 §7）|
| `src/lib/model_loader.rs` | 新增 `write_boundary_version()`（寫 inactive bank + 翻轉 `BOUNDARY_META.active`，含 CLOCK_MONOTONIC TTL）、`update_score_threshold()` |
| `src/lib/config.rs` | 新增 `BoundaryAdaptConfig` sub-struct + `Config.adaptive` + default |
| `src/lib/mod.rs` | 新增 `pub mod boundary_updater;` |
| `src/main.rs` | 收 `STATS_RING_BUF`、`BOUNDARY_META` map；load_model 後將 STATS_RING_BUF + QUANTILE_BOUNDS + BOUNDARY_META + MODEL_CONFIG 交給 `BoundaryUpdater`，與 `logger.start()` 以 `tokio::try_join!` 併發（**v1 寫「controller.load() 內 spawn」在 aya 借用模型下不可行——改在 main 併發**）|

---

## 7. boundary_updater.rs 詳細設計

### 量化器（無外部 crate）

```rust
fn batch_quantile(values: &[(u32, u32)], q: f64) -> f64 {
    let mut ratios: Vec<f64> = values.iter()
        .map(|(n, d)| *n as f64 / (*d as f64 + 1.0))
        .collect();
    ratios.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = ((q * (ratios.len() - 1) as f64) as usize).min(ratios.len().saturating_sub(1));
    ratios[idx]
}
```

### EMA / drift / divergence

```rust
fn ema(current: f64, new_sample: f64, alpha: f64) -> f64 {
    alpha * new_sample + (1.0 - alpha) * current
}
fn drift_ratio(current: f64, new_val: f64) -> f64 {
    (new_val - current).abs() / (current.abs() + 1e-9)
}
// Δ_t：多個 τ 上 live 與 ref 分位數的平均絕對差（正規化）
fn divergence(q_ref: &[f64], q_live: &[f64]) -> f64 {
    q_ref.iter().zip(q_live)
        .map(|(r, l)| (l - r).abs() / (r.abs() + 1e-9))
        .sum::<f64>() / q_ref.len() as f64
}
```

> Monotonicity 投影（多分位非遞減修正）在目前 1-bit/feature（`BUCKET_COUNT == 2`，每特徵單一邊界）設計下無意義，**刻意不實作**，避免 dead code；待 `BUCKET_COUNT > 2`（同一變數多個 quantile bucket）時才需要。

### Task 結構與 gate 狀態機

```rust
pub enum GateState { Normal, Uncertain, AttackFreeze }

pub struct BoundaryUpdater {
    ref_batch:  [Vec<(u32, u32)>; FEATURE_COUNT_USIZE], // S_ref：僅 gate 通過樣本
    live_batch: [Vec<(u32, u32)>; FEATURE_COUNT_USIZE], // S_live：所有取樣樣本
    ref_score:  Vec<i32>,
    live_score: Vec<i32>,
    current_bounds: [f64; FEATURE_COUNT_USIZE],
    current_threshold: f64,
    boundary_version: u32,
    high_risk_rate_ewma: f64, // 高風險桶命中率 EWMA，attack 判定用
    state: GateState,
    config: BoundaryAdaptConfig,
}
```

Gate 判定（每批結束時）：

```
Δ = divergence(Q_ref, Q_live)
high_risk = 高風險桶命中率（由 score / bit 統計）
if Δ > div_threshold && high_risk_jump:           state = AttackFreeze   # 凍結 ref，不寫 eBPF
elif Δ > div_threshold && !high_risk_jump:         state = Normal         # 正常漂移，EMA 更新 ref
else:                                              state = Uncertain      # 只更新 S_live
```

只有 `Normal` 會：EMA 更新 `current_bounds` → `monotonic_fix` → 轉 fixed-point → `write_boundary_version()`（version++、寫 inactive slot、翻轉 ACTIVE_INDEX、設 expiry）。`AttackFreeze` / `Uncertain` 不寫 boundary。

---

## 8. config.toml 新增欄位

```toml
[adaptive]
enabled = true
batch_size = 1000          # 每批多少筆才計算分位數
sample_shift = 4           # kernel 取樣率：1<<4 取 1（降 ring buffer 壓力）
ewma_alpha = 0.20          # EMA 平滑係數
minor_drift_ratio = 0.20   # Path A：邊界漂移 > 20% 才考慮更新
major_drift_ratio = 0.50   # > 50% 觸發重訓練通知
score_drift_ratio = 0.05   # Path B：score p85 漂移 > 5% 才更新 threshold
divergence_threshold = 0.30 # Δ_t 超過視為顯著偏移
high_risk_rate_jump = 2.0  # 高風險桶命中率 EWMA 倍數，判定 attack
boundary_ttl_secs = 600    # eBPF boundary 版本 TTL，逾時回退
```

---

## 9. 驗證方式

**重要**：`firewall` userspace crate 依賴 aya（Linux-only syscalls），整個 crate 在 macOS **無法編譯**。下表「unit test」指 `boundary_updater.rs` 內 `#[cfg(test)] mod tests` 的純邏輯測試——它們不需 eBPF runtime，但仍需 crate 能編譯，故須在 **Linux 上 `cargo test`** 執行（非 macOS host）。

| 測試 | 方式 | 執行環境 |
|------|------|---------|
| StatsEvent 編解碼（含 flags、48 bytes 不變） | unit test | Linux `cargo test` |
| batch_quantile / score_quantile / ema / drift_ratio / divergence | unit test | Linux `cargo test` |
| gate 狀態機（decide_gate 各組合） | unit test | Linux `cargo test` |
| encode_bound / decode_bound round-trip（absolute vs ratio） | unit test | Linux `cargo test` |
| Ring buffer 端到端 | 整合測試：注入 mock StatsEvent → 確認 Normal 才更新、AttackFreeze 不更新 | 需 Linux + eBPF |
| eBPF verifier | `cargo xtask build` + verifier 檢查（無 unbounded loop）| 需 Linux |
| double-buffer 原子切換 | datapath 讀 BOUNDARY_META.active 一致性 | 需 Linux + eBPF |
| Python 蒸餾相容 | `distill_export.py` 輸出 JSON 格式不變 | Python（任意平台）|

> 註：實作以 double-buffer over 既有 `QuantileBound`（兩 bank）+ `BoundaryMeta{version,active,expiry_ns}` 取代 v2 草案的 fixed-point `BoundaryConfig`。理由：保留已驗證的 scorer absolute/ratio 比較數學，`QuantileBound` 本已是整數運算（kernel 無浮點），故 fixed-point 轉換非必要，且風險更低。

---

## 10. 不做的事

- **不在 kernel 計算中位數 / sketch**：只收集 raw numer/denom + flags，分位數由 userspace batch-sort 計算。
- **不引入 DDSketch / t-digest / GK crate**：避免過度設計；文獻僅作背景框架。
- **不讓攻擊流量進入 reference sketch**：`STATS_FLAG_BENIGN_GATE` + gate 雙重隔離，不可省略。
- **不更新 SCORE_TABLE 的 32 個條目**：那是 IF 蒸餾結果，只有 Python 重訓練能改。
- **不對 attack-induced drift 做校準**：偵測到 drift ≠ 一定更新；攻擊污染要被隔離而非校準成新常態。
- **不嘗試在 eBPF 偵測 HOIC**：HOIC 由 Userspace IF（完整特徵）處理，符合 Layer 2 架構。
