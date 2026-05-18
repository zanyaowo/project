# eBPF 分位桶邊界自適應更新計畫

**狀態：** 設計完成，待實作  
**依據：** Run 27–29 實驗結論 + kernel_defense_architecture.md Layer 設計

---

## 背景與動機

### 問題

`QUANTILE_BOUNDS` 與 `SCORE_TABLE` 在部署後是靜態的，由 Python ML pipeline 離線產出，Rust loader 一次性寫入。當部署環境的流量統計偏離訓練 BENIGN 分布時（Run 27 確認 CIC 2019 與 BigFlow 差異達 2–4×），性能退化而沒有自動修正機制。

### 設計目標

分位桶邊界能根據觀測到的正常流量自動校準，不需要每次觸發完整 Python 重訓。Python 只在攻擊模式改變（model-level drift）時才介入。

### A 與 B 追蹤的是不同層次的漂移

| 路徑 | 追蹤對象 | 輸出 | 解決的問題 |
|------|----------|------|-----------|
| **A** | 原始特徵分佈（每特徵一個草圖）| QUANTILE_BOUNDS | 輸入環境漂移（封包大小上升、協定比例改變）|
| **B** | IF anomaly score 分佈（一個草圖）| MODEL_CONFIG.threshold | 決策閾值漂移（正常流量分數整體偏移）|

兩條路徑無法互相替代（見下表）：

| 漂移類型 | A 能偵測 | B 能偵測 |
|---------|:--------:|:--------:|
| 正常流量封包大小上升 | ✅ | ⚠️ 間接 |
| 攻擊手法改變 | ❌ | ✅ |
| 業務高峰期流量改變 | ✅ | ✅ |
| IF 模型老化 | ❌ | ✅ |

---

## 架構設計

### 資料流總覽

```
eBPF kernel (scorer.rs)
│
├─ 每筆流量：5-bit index → SCORE_TABLE → score
│
└─ score × 2 < config.threshold（明確 BENIGN）時：
    └─ 寫入 STATS_RING_BUF：StatsEvent { numer[5], denom[5], score }
                                  ↓
Rust userspace (boundary_updater.rs)
│
├─ 消費 ring buffer，累積至 BATCH_SIZE（預設 1000）筆
│
├─ 路徑 A：每個特徵計算 p50(numer/denom)
│   ├─ EWMA 平滑：new_bound = α × batch_p50 + (1−α) × current_bound（α=0.2）
│   ├─ drift 檢測：|new − current| / current > 0.20 → 更新 QUANTILE_BOUNDS
│   └─ 重大 drift > 0.50 → 標記，通知 Python 排程重訓練
│
└─ 路徑 B：計算 p85(score)
    ├─ EWMA 平滑
    ├─ drift 檢測：|new_p85 − current_threshold×0.85| / current > 0.05 → 更新 threshold
    └─ A+B 同時重大 drift → 排程 Python 完整重訓練
```

### 聯動邏輯

```
A 漂移 + B 漂移   → 環境整體改變   → 排程 Python 重訓練（全部更新）
A 穩定 + B 漂移   → 攻擊模式改變   → 調整 threshold + 告警
A 漂移 + B 穩定   → 業務成長       → 只更新 QUANTILE_BOUNDS
A 穩定 + B 穩定   → 系統正常       → 不動作
```

### 安全機制

路徑 B 的草圖**只餵入** `score × 2 < threshold` 的流量（明確 BENIGN），防止攻擊流量污染分數分佈，避免閾值被惡意推高而降低防禦靈敏度。

---

## 新增的資料結構

### `StatsEvent`（firewall-common/src/model.rs）

```rust
#[repr(C)]
#[derive(Copy, Clone)]
pub struct StatsEvent {
    pub numer: [u32; 5],  // 各特徵分子（u64 截斷，overflow 以 u32::MAX 飽和）
    pub denom: [u32; 5],  // 各特徵分母
    pub score: i32,
    pub _pad: u32,        // 對齊，共 48 bytes
}
```

**各特徵的 numer/denom 對應：**

| feat index | 特徵 | numer | denom |
|-----------|------|-------|-------|
| 0 | PROTOCOL | proto as u32 | 1 |
| 1 | PKT_LEN_MEAN | total_bytes as u32 | total_pkts as u32 |
| 2 | FWD_MAX_Q | max_pkt × orig_pkts (sat u32) | orig_bytes as u32 |
| 3 | SYM_RATIO | orig_pkts as u32 | resp_pkts as u32 |
| 4 | PKT_CV_SQ | cv_numer (sat u32) | total_bytes² (sat u32) |

---

## 修改清單

### firewall-common

| 檔案 | 改動 |
|------|------|
| `src/model.rs` | 新增 `FEATURE_COUNT_USIZE`、`StatsEvent` struct、`unsafe impl aya::Pod` |
| `src/constants.rs` | 新增 `BENIGN_STATS_FLUSH_COUNT`（預設 1000）、`STATS_BATCH_SIZE`（預設 1000）|
| `build.rs` | 新增 `stats_ring_buf_size` → 生成 `STATS_RING_BUF_SIZE`（預設 65536 bytes）|

### firewall-ebpf

| 檔案 | 改動 |
|------|------|
| `src/scorer.rs` | 新增 `STATS_RING_BUF` map 定義；在 `score_session()` 末端加 stats 收集邏輯（`if score × 2 < threshold`）|
| `src/main.rs` | 確認 `STATS_RING_BUF` 已掛載（aya 自動掛載 `#[map]` 標記的 map）|

**scorer.rs 新增邏輯（概念）：**
```rust
// 在 score_session() 取得 score 之後，返回 ScoreResult 之前
if score.saturating_mul(2) < config.threshold as i64 {
    if let Some(mut slot) = STATS_RING_BUF.reserve::<StatsEvent>(0) {
        let evt = slot.as_mut_ptr();
        (*evt).numer = [val_numer 各項 sat_as_u32];
        (*evt).denom = [val_denom 各項 sat_as_u32];
        (*evt).score = *score;
        (*evt)._pad  = 0;
        slot.submit(0);
    }
}
```

### firewall（userspace）

| 檔案 | 改動 |
|------|------|
| `src/lib/mod.rs` | 新增 `pub mod boundary_updater;` |
| `src/lib/boundary_updater.rs` | **新檔案**（見下節詳細設計）|
| `src/lib/model_loader.rs` | 新增 `update_bounds_only()` 與 `update_score_threshold()` 函式 |
| `src/lib/config.rs` | 新增 `BoundaryAdaptConfig` sub-struct（EWMA alpha、drift 閾值、batch size）|
| `src/lib/controller.rs` | `load()` 之後 spawn `boundary_updater::run()` Tokio task |

---

## boundary_updater.rs 詳細設計

### 量化器（無外部 crate）

使用 batch sort + 取分位數（不需要 DDSketch / t-digest），每批 `BATCH_SIZE` 筆：

```rust
fn batch_quantile(values: &[(u32, u32)], q: f64) -> f64 {
    let mut ratios: Vec<f64> = values.iter()
        .map(|(n, d)| *n as f64 / (*d as f64 + 1.0))
        .collect();
    ratios.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = ((q * (ratios.len() - 1) as f64) as usize).min(ratios.len() - 1);
    ratios[idx]
}
```

### EWMA 更新

```rust
fn ewma(current: f64, new_sample: f64, alpha: f64) -> f64 {
    alpha * new_sample + (1.0 - alpha) * current
}
```

### 主要 task 結構

```rust
pub struct BoundaryUpdater {
    // 路徑 A：每特徵的 numer/denom 批次緩衝
    feat_batch: [Vec<(u32, u32)>; 5],
    // 路徑 B：score 批次緩衝
    score_batch: Vec<i32>,
    // 當前已生效的邊界值（用於 drift 計算）
    current_bounds: [f64; 5],
    current_threshold: f64,
    config: BoundaryAdaptConfig,
}
```

### Drift 偵測

```rust
fn drift_ratio(current: f64, new_val: f64) -> f64 {
    (new_val - current).abs() / (current.abs() + 1e-9)
}

// Path A per feature:
//   drift_ratio > config.minor_drift  → EWMA + update QUANTILE_BOUNDS
//   drift_ratio > config.major_drift  → 也發出 major_drift 信號

// Path B score threshold:
//   drift_ratio > config.score_drift  → EWMA + update ModelConfig.threshold
```

---

## config.toml 新增欄位

```toml
[adaptive]
enabled = true
batch_size = 1000        # 累積多少筆 BENIGN 流才計算一次分位數
ewma_alpha = 0.20        # EWMA 平滑係數（0=不更新，1=完全跟隨新批次）
minor_drift_ratio = 0.20 # Path A：邊界漂移超過 20% 才更新
major_drift_ratio = 0.50 # 漂移超過 50% 觸發重訓練通知
score_drift_ratio = 0.05 # Path B：score p85 漂移超過 5% 才更新 threshold
```

---

## 驗證方式

| 測試 | 方式 |
|------|------|
| StatsEvent 編碼正確 | Unit test：填入已知 session 值，確認 numer/denom 對應特徵計算 |
| EWMA 與 drift 邏輯 | Unit test：boundary_updater 的 drift 計算與 EWMA 函式 |
| Ring buffer 端到端 | 整合測試：inject mock StatsEvent → 確認 QUANTILE_BOUNDS 在 drift > threshold 後更新 |
| eBPF verifier 通過 | `cargo xtask build` + `cargo xtask check-verifier`（無 unbounded loop）|
| Python 蒸餾相容 | 確認 `distill_export.py` 輸出 JSON 格式不變（只改 quantile_bounds 的 value/numer/denom）|

---

## 不做的事

- **不在 kernel 計算中位數**：只收集 raw numer/denom，分位數由 Rust 計算
- **不讓攻擊流量進入草圖**：`score × 2 < threshold` 是安全過濾條件，不可省略
- **不更新 SCORE_TABLE 的 32 個條目**：那是 IF 蒸餾結果，只有 Python 重訓練才能改
- **不嘗試在 eBPF 偵測 HOIC**：HOIC 由 Userspace IF（完整特徵）處理，符合 Layer 2 架構設計
