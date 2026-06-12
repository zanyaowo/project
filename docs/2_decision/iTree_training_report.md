# Isolation Forest 訓練報告

**最後更新：2026-05-31**  
**對應版本：CIC-IDS-2019 only 部署 contract（Run 28/29 校正、Run 30/31 後維持 N=2）**

> 本文是 Python ML pipeline 與離線 IF / 蒸餾流程說明，不是 runtime Layer 2 Full IF 的實作文件。現況 runtime 唯一推論層是 eBPF fast-path；Full IF 仍在 `service/model/` 作為離線訓練、評估與未來 Layer 2 設計素材。

---

## 系統概覽

Python ML pipeline 位於 `service/model/`，提供三條 model class（AUC 不可混引）：

| 路徑 | 特徵數 | 執行位置 | 用途 |
|------|:------:|---------|------|
| **Contract5 連續 IF**（最終 teacher） | 5 個連續（`protocol + pkt_len_mean + fwd_max_q + sym_ratio + pkt_cv_sq`）| Python 離線 pipeline | **最終 teacher**：可由 eBPF SessionValue 重建、與 student 同特徵空間，作蒸餾來源與 Layer 2 reference |
| **Full IF / Abs20**（baseline 參考） | 25/20 維絕對特徵（`FEATURE_COLS`）| Python 離線 pipeline | in-scope 上界參考；絕對特徵跨環境崩潰且 datapath 不可重建，**不作最終 teacher** |
| **Distilled student** | 5-bit 二值化（32-entry 查表） | eBPF kernel（+ Python 驗證）| 目前唯一 runtime 推論路徑；部署 AUC 以 Run 28/29 的 32-entry contract 為準 |

> **最終 teacher 是 Contract5 連續 IF，不是 Full25/Abs20。** in-scope CIC-DDoS2019 量測：Contract5 ROC-AUC=0.845 vs Abs20=0.892——Abs20 雖略高但不可部署（datapath 不可重建、跨環境崩潰）。完整對照與 Table 1/2 數據見 `docs/results_and_discussion.md`。

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
   └── test/    (01-12, 2018-12-01)   ← 驗證集（目前範圍：CIC-IDS-2019；BigFlow 技術路徑保留但暫不啟用）
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
FEATURE_COLS  # 25 個訓練特徵（固定順序；Python 離線 IF 使用）
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

計算 BigFlow 等需要衍生的比率特徵（FwdMax_ratio、Sym_ratio、Pkt_CV_sq 等）和 Protocol/Service 編碼，用於非 CICFlowMeter 格式資料的欄位對齊。BigFlow / Mixed BENIGN 路徑目前僅作跨資料集泛化預留，CIC-only 部署評估不啟用。

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

實現目前部署 contract 的 5 特徵、N=2 分位桶 + 32-entry 查表法推論，作為 eBPF kernel 的 Python 側驗證。注意：Run 25 是 IF-direct 證據模型；部署 AUC 必須以 Run 28/29 的 all-binary 32-entry contract 為準。

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
| `pkt_cv_sq` | `(Packet Length Std)^2` | `(Packet Length Mean)^2` | 封包大小 CV²；kernel 避免 sqrt，禁止使用 raw `pkt_cv` contract |
| `protocol` | `Protocol` | — | 協定號 |
| `pkt_len_mean` | `Packet Length Mean` | — | 平均封包大小 |

**蒸餾 JSON 格式：**
```json
{
  "version": 1,
  "feature_order": ["protocol", "pkt_len_mean", "fwd_max_q", "sym_ratio", "pkt_cv_sq"],
  "threshold_cmp": ">=",
  "score_scale": 10000,
  "length_unit": "packet_len",
  "threshold": 42,
  "quantile_bounds": [
    {"name": "fwd_max_q",    "type": "ratio",    "numer": 1048575, "denom": 1048576},
    {"name": "sym_ratio",    "type": "ratio",    "numer": ..., "denom": ...},
    {"name": "pkt_cv_sq",    "type": "ratio",    "numer": ..., "denom": ...},
    {"name": "protocol",     "type": "absolute", "value": 6},
    {"name": "pkt_len_mean", "type": "absolute", "value": 100}
  ],
  "score_table": [0, 5, 10, 20, 8, 30, 40, 50, ...]
}
```

> **注意：** 目前評估範圍限定 CIC-IDS-2019，部署 `model.json` 使用 CIC BENIGN only 邊界；Mixed BENIGN（CIC + BigFlow）只在未來恢復跨資料集泛化時啟用。`score_table` 由 Python 離線從訓練好的 IF 蒸餾，計算各 5-bit 組合的平均 IF anomaly_score。

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
        "feature_cols":  list[str],    # 25 個特徵名（與 FEATURE_COLS 一致）
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
| **CIC-only 部署範圍** | 目前評估與 `model.json` 以 CIC-IDS-2019 BENIGN 邊界為準；Mixed BENIGN 技術路徑保留給跨資料集泛化 |
| **5 特徵查表法** | 2^5=32 種組合預先計算分數存入 SCORE_TABLE；kernel 端只需 5 次比較 + 1 次查表；特徵順序以 `kernel_model_contract.md` 為準 |

---

## 相關文件

| 文件 | 內容 |
|------|------|
| `docs/_crosscut/kernel_defense_architecture.md` | eBPF 架構、分位桶決策、AUC 數字、蒸餾策略 |
| `docs/1_sensing/feature_selection_log.md` | 特徵選擇實驗（Run 01–16,18 + 附錄 A-1～A-9） |
| `docs/2_decision/quantile_bucket_strategy_log.md` | 分位桶策略/模型訓練（Run 17,19–29 + A-10/11/12，contract Run 28/29） |
| `docs/claude_ref/codebase_map.md` | 函式導覽、資料夾用途、抽樣方法選擇 |
| `docs/claude_ref/dev_commands.md` | 常用命令、驗證 checklist、資料路徑 |
| `docs/claude_ref/failure_records.md` | 歷史失敗案例 |
