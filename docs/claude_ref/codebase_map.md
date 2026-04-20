# Codebase Map — 函式與資料夾導覽

> 目的：避免重複實作已有函式、使用錯誤抽樣方法。修改前先查此文件確認是否已有對應實作。

---

## service/model/schema.py — 常數定義（唯一來源）

| 常數 | 內容 |
|------|------|
| `FEATURE_COLS` | 26 個模型特徵名稱（順序固定，對應 Rust ModelFeature struct） |
| `ID_COLS` | 不可入模型的識別符欄位（Flow ID、IP、Timestamp 等） |
| `STRING_TO_FLOAT_COLS` | 需要從字串轉 float 的欄位（`Flow Bytes/s`、`Flow Packets/s`） |
| `PROTO_MOD`, `SERVICE_MOD` | Protocol/Service hash bucket 數 |
| `CLIP_UPPER_PERCENTILE` | inf cap 的百分位數（0.999） |

**禁止**：在其他地方硬編碼特徵名稱清單，一律 `from service.model.schema import FEATURE_COLS`。

---

## service/model/data/ — 資料層

### cleaner.py
**唯一公開函式：`clean(lf: LazyFrame) → LazyFrame`**
執行：strip 欄位名空白 → cap inf → fill null → cast STRING_TO_FLOAT_COLS。
- 只用於**原始 parquet/CSV**。`clean_and_save()` 產出的 parquet_clean 已預處理，**不可再呼叫 clean()**。

### loader.py
| 函式 | 用途 |
|------|------|
| `_load_features_parquet(path)` | 載入單一 parquet（或 glob 路徑）為 LazyFrame |
| `csv_to_parquet()` | 批次將 dataset/ 下 CSV 轉 parquet |
| `clean_and_save(src_dir, out_dir)` | 清洗 parquet → 寫入 parquet_clean/ |

### sample.py — 抽樣函式（三選一，用途嚴格區分）

| 函式 | 適用場景 | 禁止用於 |
|------|---------|---------|
| `get_normal_sample_from_files(paths, n, seed)` | **IF 訓練**（BENIGN only） | 任何需要攻擊樣本的場景 |
| `get_binary_sample_from_files(paths, n_per_class, seed)` | **特徵選擇**（50/50 BENIGN vs 攻擊） | IF 訓練 |
| `get_balance_sample_from_files(paths, sample_count_per_label, seed)` | **評估/測試**（各 label 等量） | IF 訓練、特徵選擇（除非搭配 min_samples 過濾） |
| `random_sample_lazyframe(lf, n, seed)` | 從已有 LazyFrame 隨機抽樣 | — |

### features.py
`build_features(df: pd.DataFrame) → pd.DataFrame`
衍生比率特徵（Shape_Ratio、Sym_Ratio、Pkt_CV 等）與 Protocol/Service 編碼。
用於 BigFlow 等欄位需要計算派生特徵的場景。

---

## service/model/pipeline/ — ML Pipeline

### schema 相依關係
```
schema.py → feature_select.py → trainer/ → infer.py
```

### feature_select.py
| 函式 | 用途 |
|------|------|
| `variance_select(benign_df, var_threshold, corr_threshold)` | 方案 B：用 BENIGN 資料做 variance + correlation filter |
| `if_auc_validate(benign_df, val_df, feature_names, ...)` | 方案 D：訓練 IF 並在含攻擊的驗證集上計算 AUC |
| `_numeric_matrix(df)` | 取出非 ID 數值欄位，回傳 (X: float32 ndarray, names) |

**CLI**：`python -m service.model.pipeline.feature_select --data_dir ... --val_dir ...`

### correlation_filter.py
`drop_correlated(X, feature_names, threshold=0.9) → (X, names)`
移除 Pearson |r| > threshold 的冗餘特徵。已被 `variance_select()` 內部呼叫，通常不需直接使用。

### trainer/
| 類別 | 用途 |
|------|------|
| `BaseTrainer` | 抽象基底，定義 `fit(df)` 和 `bundle()` 介面 |
| `IsolationForestTrainer` | 主要模型。`fit(df)` 接受含 Label 欄的 DataFrame（BENIGN only），`bundle()` 回傳含 scaler/model/meta 的 dict |
| `RandomForestTrainer` | 存在但非主力；分類器，需要 BENIGN + 攻擊資料 |

### train.py
CLI 入口，呼叫對應 Trainer 並儲存 bundle 至 `model_store/`。
**CLI**：`python -m service.model.pipeline.train --model_type if`

### infer.py — 推論（直接用，不要自己重寫）
| 函式 | 用途 |
|------|------|
| `_infer_if(df, bundle)` | IF 推論，輸入只含 FEATURE_COLS 的 DataFrame，回傳含 `anomaly_score`、`is_alert` 的 DataFrame |
| `_infer_rf(df, bundle)` | RF 推論（相同介面） |
| `_check_features(df, feature_cols)` | 確認 df 含所有必要欄位，缺少則 raise |

**CLI**：`python -m service.model.pipeline.infer --input ... --model ...`

---

## service/model/tests/ — 測試 Harness

| 檔案 | 測試內容 |
|------|---------|
| `conftest.py` | 共用 fixtures（`trained_if_bundle`、`make_benign_df`、`make_attack_df`、`feature_cols`） |
| `harness_pipeline_regression.py` | bundle 結構、joblib round-trip、FPR < 2%、AUC > 0.90（@slow） |
| `harness_feature_integrity.py` | clean() 後無 inf/NaN、FEATURE_COLS 存在且 numeric、資料洩漏防護 |
| `harness_inference_engine.py` | shape 契約（26 個）、邊界值、確定性、攻擊偵測 |
| `test_cleaner.py` | cleaner 單元測試 |
| `test_feature_select.py` | variance_select、if_auc_validate 單元測試 |
| `test_loader.py` | _load_features_parquet 單元測試 |
| `test_sample.py` | 抽樣函式單元測試 |

---

## service/model/experiments/ — 一次性實驗腳本（唯讀參考）

存放已執行完的分析腳本，**不應被 import**，只作為實驗記錄查閱。

| 檔案 | 對應實驗 |
|------|---------|
| `bigflow_run17_eval.py` | BigFlow-NIDS-V2 跨資料集驗證（N 值掃描） |
| `cross_dataset_validation.py` | 跨資料集泛化評估 |
| `info_gain.py` | Information Gain 特徵重要性分析 |
| `permutation_importance.py` | Permutation Importance 分析 |
| `rerun_all_correct_temporal.py` | 2026-04-10 時序修正後全面重跑 |
| `run17_quantile_ratio.py` | Run 17 分位桶比率實驗 |
| `run18_bytes_sum.py` | Run 18 Bytes sum 特徵實驗 |

---

## service/model/old_code/ — 已棄用（禁止使用）

舊版 monolithic 實作，已被 pipeline/ 取代。**不可 import，不可參考邏輯。**

---

## docs/claude_ref/ — Claude 專用參考

| 檔案 | 內容 |
|------|------|
| `codebase_map.md` | 本文件 |
| `dev_commands.md` | 常用命令、驗證 checklist、資料路徑 |
| `failure_records.md` | 歷史失敗記錄（9+ 則） |

## docs/

| 檔案 | 內容 |
|------|------|
| `kernel_defense_architecture.md` | 架構設計唯一依據（eBPF 限制、分位桶決策、AUC 數字） |
| `feature_selection_log.md` | Run 01–17 + BigFlow 實驗記錄 |
| `packetinfo_redesign_proposal.md` | PacketInfo 重構提案（歷史文件） |
