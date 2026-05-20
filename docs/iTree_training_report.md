# Isolation Forest 訓練報告

**最後更新：2026-05-03**  
**對應版本：feat/model_develope（Run 25 最終方案）**

---

## 系統概覽

Python ML pipeline 位於 `service/model/`，提供兩條推論路徑：

| 路徑 | 特徵數 | 執行位置 | 用途 |
|------|:------:|---------|------|
| **Full IF** | 25 個（`FEATURE_COLS`）| Python userspace | 邊緣案例、高精度判斷（Run 07 基準 AUC=0.9257）|
| **Distilled** | 5 個（分位桶） | eBPF kernel（+ Python 驗證）| 大流量快速過濾（Run 25 AUC 見架構文件）|

---

## 資料流

```
CICFlowMeter CSV / parquet
        ↓
   data/loader.py
   clean_and_save()          ← 預處理一次，寫入 parquet_clean/
        ↓
   parquet_clean/
   ├── train/   (03-11, 2018-11-03)   ← 訓練集
   └── test/    (01-12, 2018-12-01)   ← 驗證集（含 BigFlow）
        ↓
   pipeline/feature_select.py         ← 特徵選擇（更新 FEATURE_COLS 時執行）
        ↓
   schema.py  FEATURE_COLS            ← 唯一特徵定義來源（25 個）
        ↓
   pipeline/train.py                  ← Full IF 訓練（edge cases）
        ↓
   model_store/if_model.joblib        ← Full IF 推論用
        ↓
   pipeline/infer.py                  ← Full IF 推論

   pipeline/distill_export.py         ← Bucket IF 訓練 + 邊界計算（kernel 用）
        ↓
   model_store/distilled_rules.json   ← score_table + quantile_bounds
        ↓
   pipeline/distill.py                ← Distilled 推論（eBPF 對齊驗證）
```

**時序限制（違反即為資料洩漏）：** Train = 03-11（較早）→ Test = 01-12（較晚）。

---

## 模組說明

### schema.py — 常數唯一來源

```python
FEATURE_COLS  # 25 個訓練特徵（固定順序，與 Rust ModelFeature struct 對應）
ID_COLS       # 不可入模型的識別符（Flow ID、IP、Timestamp、Label 等）
STRING_TO_FLOAT_COLS  # ["Flow Bytes/s", "Flow Packets/s"]（需從字串 cast）
CLIP_UPPER_PERCENTILE = 0.999  # inf cap 的百分位數
```

**禁止**在其他模組硬編碼特徵名稱，一律 `from service.model.schema import FEATURE_COLS`。

**當前 25 個 FEATURE_COLS（Run 07 基準，移除 Min Packet Length）：**

| # | 特徵名稱 | # | 特徵名稱 |
|:-:|---------|:-:|---------|
| 1 | Destination Port | 14 | Flow IAT Max |
| 2 | Fwd Packet Length Mean | 15 | Flow IAT Std |
| 3 | Bwd Header Length | 16 | Flow Duration |
| 4 | Packet Length Mean | 17 | Flow Bytes/s |
| 5 | Bwd IAT Min | 18 | Fwd Header Length |
| 6 | Fwd Packet Length Min | 19 | Init_Win_bytes_forward |
| 7 | Down/Up Ratio | 20 | Init_Win_bytes_backward |
| 8 | Fwd Packet Length Max | 21 | Bwd Packets/s |
| 9 | Bwd IAT Mean | 22 | Fwd IAT Mean |
| 10 | Total Length of Fwd Packets | 23 | Total Fwd Packets |
| 11 | Flow IAT Mean | 24 | Flow IAT Min |
| 12 | Flow Packets/s | 25 | act_data_pkt_fwd |
| 13 | Protocol | | |

---

### data/cleaner.py

**公開函式：** `clean(lf: LazyFrame) → LazyFrame`

執行順序：
1. `_strip_column_names` — 欄位名稱去空白
2. `_cast_types` — `STRING_TO_FLOAT_COLS` 轉 Float64；移除 `Unnamed: 0`
3. `_cap_infinite` — inf 以非 inf 最大值的 p99.9 替換（保留高流量語意）
4. `_fill_nulls` — NaN/null 填 0.0

**使用限制：** `clean_and_save()` 產出的 `parquet_clean/` 已預處理，**不可再呼叫 clean()**。

---

### data/loader.py

| 函式 | 用途 |
|------|------|
| `_load_features_parquet(path)` | 載入單一 parquet（或 glob）為 LazyFrame |
| `csv_to_parquet()` | 批次將 `dataset/` 下 CSV 轉 parquet |
| `clean_and_save(src_dir, out_dir)` | 清洗 parquet → 寫入 `parquet_clean/` |

---

### data/sample.py — 抽樣函式（三選一，用途嚴格區分）

| 函式 | 適用場景 | 禁止用於 |
|------|---------|---------|
| `get_normal_sample_from_files(paths, n, seed)` | **IF 訓練**（BENIGN only） | 任何需要攻擊樣本的場景 |
| `get_binary_sample_from_files(paths, n_per_class, seed)` | 特徵選擇（50/50 BENIGN vs 攻擊） | IF 訓練 |
| `get_balance_sample_from_files(paths, sample_count_per_label, seed)` | 評估/測試（各 label 等量） | IF 訓練 |
| `random_sample_lazyframe(lf, n, seed)` | 從已有 LazyFrame 隨機抽樣 | — |

---

### data/features.py

`build_features(df: pd.DataFrame) → pd.DataFrame`

計算 BigFlow 等需要衍生的比率特徵（FwdMax_ratio、Sym_ratio、Pkt_CV 等）和 Protocol/Service 編碼，用於非 CICFlowMeter 格式資料的欄位對齊。

---

### pipeline/feature_select.py

| 函式 | 說明 |
|------|------|
| `variance_select(benign_df, var_threshold, corr_threshold)` | 方案 B：BENIGN variance filter + correlation filter，回傳存活特徵清單 |
| `if_auc_validate(benign_df, val_df, feature_names, ...)` | 方案 D：訓練 IF，在含攻擊驗證集上計算 AUC-ROC |
| `_numeric_matrix(df)` | 取出非 ID 數值欄位（排除 `Inbound`） |

**CLI：**
```bash
python -m service.model.pipeline.feature_select \
    --data_dir service/model/dataset/parquet_clean/train \
    --val_dir  service/model/dataset/parquet_clean/test \
    --var_threshold 1e-4 --corr_threshold 0.9 \
    --sample_n 10000 --val_sample_n 3000
```

---

### pipeline/trainer/if_.py — IsolationForestTrainer

```python
class IsolationForestTrainer(BaseTrainer):
    def fit(self, df: pl.DataFrame) -> None: ...
    # df 應為 BENIGN-only（由 train.py 用 get_normal_sample_from_files 傳入）
    # anomaly_score = -model.score_samples(X)，值越大越可疑
    # threshold = quantile(train_scores, 1 - contamination)

    def score(self, df: pl.DataFrame) -> tuple[np.ndarray, np.ndarray]: ...
    # 回傳 (anomaly_scores, is_alert)

    def bundle(self) -> dict: ...
    # 回傳 {"model_type": "if", "scaler", "model", "meta": {"feature_cols", "threshold", "contamination"}}
```

**關鍵參數：**

| 參數 | 預設值 | 說明 |
|------|:------:|------|
| `n_estimators` | 200 | 樹的數量 |
| `contamination` | 0.01 | 預期異常比例；影響 threshold 分位數（1 − contamination）|
| `seed` | 42 | 確保可重現 |

---

### pipeline/train.py — 訓練 CLI

```bash
# IF 訓練（預設）
python -m service.model.pipeline.train \
    --model_type if \
    --data_dir   service/model/dataset/parquet_clean/train \
    --sample_count 10000 \
    --n_estimators 200 \
    --contamination 0.01

# 輸出：model_store/if_model.joblib
```

**訓練流程：**
1. `get_normal_sample_from_files(paths, n=sample_count)` — BENIGN only
2. `IsolationForestTrainer.fit(df)` — StandardScaler + IsolationForest
3. `trainer.save(output)` — joblib 序列化

---

### pipeline/infer.py — Full IF 推論

```bash
python -m service.model.pipeline.infer \
    --input  service/model/dataset/parquet_clean/test/some.parquet \
    --model  service/model/model_store/if_model.joblib \
    --output alerts.parquet \
    --report                  # 若輸入有 Label 欄，印 classification report
    --sample_n 50000          # 大型檔案避免 OOM
```

**輸出欄位：** 原始欄位 + `anomaly_score`（float32）+ `is_alert`（bool），依 `anomaly_score` 降序排列，只保留 `is_alert=True`。

---

### pipeline/distill.py — 蒸餾推論（eBPF 對齊）

實現 Run 25 確立的 5 特徵分位桶 + 查表法推論，作為 eBPF kernel 的 Python 側驗證：

```python
class DistilledClassifier:
    # 從蒸餾 JSON 載入 32-entry SCORE_TABLE
    # 5 個特徵各與中位數邊界比較得 1 bit
    # 5 bits → 0–31 索引 → SCORE_TABLE[idx] >= threshold 即告警

    @classmethod
    def from_json(cls, path) -> "DistilledClassifier": ...
    def score(self, df: pl.DataFrame) -> np.ndarray: ...       # 回傳整數分數
    def predict(self, df: pl.DataFrame) -> pl.DataFrame: ...   # 附加 distill_score / is_alert
    def summary(self) -> None: ...                              # 印出 32 種組合的分數表
```

**蒸餾特徵定義：**

| 特徵鍵 | 分子欄位 | 分母欄位 | 說明 |
|--------|---------|---------|------|
| `fwd_max_q` | `Fwd Packet Length Max` | `Fwd Packet Length Mean` | 前向大小頂端離散度 |
| `sym_ratio` | `Total Fwd Packets` | `Total Bwd Packets` | 方向對稱性 |
| `pkt_cv` | `Packet Length Std` | `Packet Length Mean` | 封包大小 CV |
| `protocol` | `Protocol` | — | 協定號 |
| `pkt_len_mean` | `Packet Length Mean` | — | 平均封包大小 |

**蒸餾 JSON 格式：**
```json
{
  "threshold": 42,
  "quantile_bounds": [
    {"name": "fwd_max_q",    "type": "ratio",    "numer": 1048575, "denom": 1048576},
    {"name": "sym_ratio",    "type": "ratio",    "numer": ..., "denom": ...},
    {"name": "pkt_cv",       "type": "ratio",    "numer": ..., "denom": ...},
    {"name": "protocol",     "type": "absolute", "value": 6},
    {"name": "pkt_len_mean", "type": "absolute", "value": 100}
  ],
  "score_table": [0, 5, 10, 20, 8, 30, 40, 50, ...]
}
```

> **注意：** `quantile_bounds` 中的邊界必須以 **Mixed BENIGN**（CIC 15k + BigFlow 15k）計算；`score_table` 由 userspace 從訓練好的 IF 蒸餾（Python 端離線計算各組合的平均 IF anomaly_score）。

**CLI：**
```bash
python -m service.model.pipeline.distill \
    --rules model_store/distilled_rules.json \
    --data  dataset/parquet_clean/test/ddos.parquet \
    --sample 5000
```

---

## 完整使用範例

```bash
# ─────── 一次性前置作業 ───────
# 1. CSV → parquet
uv run --project service/model \
    python -m service.model.data.loader csv_to_parquet

# 2. 清洗 → parquet_clean/
uv run --project service/model \
    python -m service.model.data.loader clean_and_save \
        --src_dir service/model/dataset/parquet \
        --out_dir service/model/dataset/parquet_clean

# ─────── 特徵選擇（FEATURE_COLS 更新時執行）───────
# 3. 特徵選擇（輸出更新 schema.py 的 FEATURE_COLS）
uv run --project service/model \
    python -m service.model.pipeline.feature_select \
        --data_dir service/model/dataset/parquet_clean/train \
        --val_dir  service/model/dataset/parquet_clean/test

# ─────── IF 訓練 ───────
# 4. 訓練 IsolationForest（BENIGN only）
uv run --project service/model \
    python -m service.model.pipeline.train \
        --model_type if \
        --data_dir service/model/dataset/parquet_clean/train \
        --sample_count 10000

# ─────── 推論 ───────
# 5a. Full IF 推論
uv run --project service/model \
    python -m service.model.pipeline.infer \
        --input  service/model/dataset/parquet_clean/test/ddos.parquet \
        --model  service/model/model_store/if_model.joblib \
        --output alerts_if.parquet \
        --report

# 5b. Distilled（eBPF 對齊）推論
uv run --project service/model \
    python -m service.model.pipeline.distill \
        --rules service/model/model_store/distilled_rules.json \
        --data  service/model/dataset/parquet_clean/test/ddos.parquet \
        --sample 5000
```

---

## 模型 Bundle 格式（joblib）

```python
{
    "model_type": "if",
    "scaler":  StandardScaler,         # 訓練時 fit，推論時 transform（不可重新 fit）
    "model":   IsolationForest,        # 200 棵樹，random_state=42
    "meta": {
        "feature_cols":  list[str],    # 26 個特徵名（與 FEATURE_COLS 一致）
        "threshold":     float,        # anomaly_score 超過此值即告警
        "contamination": float,        # 訓練時的 contamination 參數（預設 0.01）
    }
}
```

---

## 關鍵技術決策摘要

| 決策 | 說明 |
|------|------|
| **BENIGN-only 訓練** | IF 核心假設是「異常是少數」，balanced sampling 破壞此假設 |
| **StandardScaler** | Z-score 正規化，確保不同尺度特徵公平對待；推論時必須用同一個 scaler |
| **inf 替換而非刪除** | `Flow Bytes/s` 在 duration=0 時為 inf，代表極高速流量，是 DDoS 判斷依據 |
| **anomaly_score = -score_samples()** | 原始 IF score 越小越異常；取負後越大越可疑，符合直覺 |
| **threshold = quantile(1 - contamination)** | 基於訓練集分位數，適應不同資料分布；可透過 `--override_threshold` 在推論時覆寫 |
| **Mixed BENIGN 邊界** | 蒸餾模型的分位桶邊界必須以 CIC+BigFlow 混合 BENIGN 計算，純 CIC 邊界對 BigFlow 嚴重 overfit |
| **5 特徵查表法** | 2^5=32 種組合預先計算分數存入 SCORE_TABLE；kernel 端只需 5 次比較 + 1 次查表 |

---

## 相關文件

| 文件 | 內容 |
|------|------|
| `docs/kernel_defense_architecture.md` | eBPF 架構、分位桶決策、AUC 數字、蒸餾策略 |
| `docs/feature_selection_log.md` | 特徵選擇實驗（Run 01–16,18 + 附錄 A-1～A-9） |
| `docs/quantile_bucket_strategy_log.md` | 分位桶策略/模型訓練（Run 17,19–29 + A-10/11/12，contract Run 28/29） |
| `docs/claude_ref/codebase_map.md` | 函式導覽、資料夾用途、抽樣方法選擇 |
| `docs/claude_ref/dev_commands.md` | 常用命令、驗證 checklist、資料路徑 |
| `docs/claude_ref/failure_records.md` | 歷史失敗案例 |
