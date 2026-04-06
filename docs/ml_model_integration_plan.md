# ML Model Integration Plan

## 概覽

將機器學習（Isolation Forest）異常偵測整合進 eBPF Firewall，
使用 CIC IDS 2019 資料集訓練，並透過 Unix socket 與 Rust userspace daemon 通訊。

---

## 架構定位

```
[Kernel] EVENTS_POOL (RingBuf)
    │ poll (AsyncFd)
    ▼
[Rust] Logger::aggregate_per_cpu()
    │
    ▼
Logger::build_feature() → ModelFeature (128B)
    │ Unix socket
    ▼
[Python] InferenceEngine::score(feature_vector)
    │
    ├─ score > threshold → AnomalyAlert { src_ip, score }
    │                           │
    │                           ▼
    │                  FirewallController::add_to_block_list(src_ip)
    │                           │
    │                           ▼
    │                  BLOCK_LIST (eBPF Map) → 下次封包直接 DROP
    │
    └─ score ≤ threshold → 記錄 log，繼續觀察
```

---

## 資料管線（service/model/）

### 模組職責

| 模組 | 檔案 | 職責 |
|------|------|------|
| Loader | `data/loader.py` | CSV → Parquet 轉換（`csv_to_parquet`）、批次清洗並寫回（`clean_and_save`） |
| Cleaner | `data/cleaner.py` | 清洗資料：strip 欄名、cast 型別、cap inf、fill nulls |
| Sampler | `data/sample.py` | 三種抽樣策略：balanced / normal-only / binary |
| Features | `data/features.py` | 特徵工程（目前為 stub，CIC IDS 2019 不需額外衍生欄位） |
| Schema | `schema.py` | 全域常數（STRING_TO_FLOAT_COLS、ID_COLS、FEATURE_COLS、CLIP_UPPER_PERCENTILE） |
| Correlation Filter | `pipeline/correlation_filter.py` | 移除 Pearson 相關係數 > threshold 的冗餘特徵 |
| Feature Select | `pipeline/feature_select.py` | 一次性分析：RF permutation importance 決定 FEATURE_COLS |
| Train | `pipeline/train.py` | CLI 入口：載入資料 → 選 Trainer → fit → save |
| Infer | `pipeline/infer.py` | CLI 入口：載入 bundle → 清洗 → score → 輸出 alerts |
| BaseTrainer | `pipeline/trainer/base.py` | 抽象基底：fit / bundle / save / resolve_feature_cols |
| IF Trainer | `pipeline/trainer/if_.py` | IsolationForest：BENIGN-only 建模，threshold = quantile(1−contamination) |
| Anomaly Plot | `view/if_anomaly_plot.py` | PCA 2D 散點圖 + anomaly score 分布直方圖 |

---

## 資料前處理流程

> **重要**：`csv_to_parquet` 與 `clean_and_save` 是**一次性離線前處理**，執行後資料存入
> `dataset/parquet_clean/`，後續的 `train`、`feature_select`、`infer` 直接讀取此目錄，
> **不再重複套用 `clean()`**。

```
原始 CIC IDS 2019 CSV
    │
    ▼
loader.csv_to_parquet()                         ← 一次性
    └── pl.scan_csv(schema_overrides) → sink_parquet
        dataset/parquet/*.parquet
    │
    ▼
loader.clean_and_save()                         ← 一次性
    └── cleaner.clean()
        1. _strip_column_names：rename {c: c.strip()}
        2. _cast_types：drop "Unnamed: 0"；String → Float64（strict=False）
        3. _cap_infinite：inf 值 → 非 inf 欄位的 quantile(0.999)
        4. _fill_nulls：fill_nan(None).fill_null(0.0)
        dataset/parquet_clean/*.parquet         ← 後續所有模組的輸入來源
```

### 執行方式

```bash
# Step 1：CSV → Parquet
python -m service.model.data.loader

# Step 2：清洗並存回
python -m service.model.data.loader clean
```

---

## 抽樣策略（data/sample.py）

| 函式 | 用途 | 說明 |
|------|------|------|
| `get_normal_sample_from_files` | IF 訓練 | 只取 BENIGN，跨檔依序抽取直到達到 n 筆 |
| `get_balance_sample_from_files` | RF 訓練、Feature Select | 每個 label 各抽 sample_count_per_label 筆，逐 label 逐檔過濾再 collect |
| `get_binary_sample_from_files` | Feature Select 二分類 | BENIGN n 筆 + 所有攻擊合計 n 筆，確保各攻擊類型有代表性 |

> **注意**：`transform=clean` 在 label 過濾後套用，清洗統計值（inf cap quantile）以各 label 子集計算，而非全資料集。

---

## Feature Selection 流程（一次性）

目的：用監督式 Random Forest permutation importance 找出對「BENIGN vs 攻擊」最有鑑別力的欄位，
填入 `schema.py` 的 `FEATURE_COLS`，供後續訓練使用。

```
parquet_clean/*.parquet
    │
    ▼
get_balance_sample_from_files(sample_count_per_label=5000, seed=42)
    │
    ▼
_extract_label()：Label → bool（BENIGN=False, 攻擊=True）
    │
    ▼
drop_correlated(threshold=0.9)
    └── Pearson |r| > 0.9 → 移除後出現的欄位（保留先出現者）
    │
    ▼
RandomForestClassifier(class_weight="balanced", n_estimators=100)
    │
    ▼
permutation_importance(n_repeats=10)
    │
    ├─ 排序 → 取 top_n
    ├─ 輸出圖片（matplotlib barh）
    └─ 印出可貼入 schema.py 的 FEATURE_COLS
```

### 執行方式

```bash
cd service/model
uv run python -m service.model.pipeline.feature_select \
    --top 20 \
    --trees 100 \
    --output feature_importance.png
```

---

## 訓練流程

### IsolationForest（無監督，異常偵測）

```
parquet_clean/*.parquet
    │
    ▼
get_normal_sample_from_files(n=10000, transform=clean)   ← 只取 BENIGN
    │
    ▼
IsolationForestTrainer.fit(df)
    1. resolve_feature_cols()（依 FEATURE_COLS 或自動選數值欄）
    2. StandardScaler.fit_transform(X)
    3. IsolationForest.fit(X_scaled)
       n_estimators=200, contamination=0.01, n_jobs=-1
    4. threshold = quantile(train_scores, 1 − contamination)
    │
    ▼
trainer.save("model_store/if_model.joblib")
    bundle = { model_type, scaler, model, meta:{feature_cols, threshold, contamination} }
```

### RandomForest（有監督，多分類）

```
parquet_clean/*.parquet
    │
    ▼
get_balance_sample_from_files(sample_count_per_label=10000, transform=clean)
    │
    ▼
RandomForestTrainer.fit(df)
    1. resolve_feature_cols()
    2. LabelEncoder.fit_transform(Label)
    3. StandardScaler.fit_transform(X)
    4. 5-fold CV F1 macro（訓練前驗證）
    5. RandomForestClassifier.fit(X, y)
       n_estimators=200, class_weight="balanced", n_jobs=-1
    │
    ▼
trainer.save("model_store/rf_model.joblib")
    bundle = { model_type, scaler, model, meta:{feature_cols, label_encoder, classes, cv_f1_*} }
```

### CLI 用法

```bash
# IsolationForest（預設）
python -m service.model.pipeline.train --model_type if \
    --data_dir service/model/dataset/parquet_clean \
    --sample_count 10000 --contamination 0.01

# RandomForest（多分類）
python -m service.model.pipeline.train --model_type rf \
    --data_dir service/model/dataset/parquet_clean \
    --sample_count 10000
```

---

## 推論流程

```
新資料（.parquet 或 .csv）
    │
    ▼
clean(_load_input(path)).collect()
    │
    ▼
bundle = joblib.load(model_path)
model_type = bundle["model_type"]   ← "if" or "rf"
    │
    ├─ IF：scaler.transform(X) → -model.score_samples(X)
    │       score > threshold → is_alert=True
    │       輸出欄位：anomaly_score, is_alert
    │
    └─ RF：scaler.transform(X) → model.predict(X) → le.inverse_transform()
            輸出欄位：pred_label, pred_confidence, is_alert
    │
    ▼
告警排序（anomaly_score / pred_confidence 降冪）→ 寫出 alerts.csv
```

### CLI 用法

```bash
python -m service.model.pipeline.infer \
    --input service/model/dataset/parquet_clean/some.parquet \
    --model service/model/model_store/if_model.joblib \
    --output alerts.csv \
    --report    # 若輸入有 Label 欄，印出 classification report
```

---

## 視覺化（view/if_anomaly_plot.py）

```bash
python -m service.model.view.if_anomaly_plot \
    --input  service/model/dataset/parquet_clean/some.parquet \
    --model  service/model/model_store/if_model.joblib \
    --output if_anomaly.png \
    --sample_n 5000
```

輸出雙圖：
- 左：PCA 2D 散點圖（正常=藍 / 異常=紅）
- 右：anomaly score 密度分布 + threshold 虛線

---

## CIC IDS 2019 資料清洗重點

| 問題 | 原因 | 處理方式 |
|------|------|----------|
| 欄位名稱有 leading space | CIC IDS 2019 已知問題 | `c.strip()` rename |
| `Flow Bytes/s` 是 String | 含 "Infinity" 字串 | `cast(Float64, strict=False)` |
| `Flow Packets/s` 是 String | 同上 | 同上 |
| inf 值 | Flow Duration=0 造成的除以零 | 以非 inf 值的 quantile(0.999) 替換（保留高流量語義） |
| NaN / null | cast 失敗或空字串 | `fill_nan(None).fill_null(0.0)` |
| `Unnamed: 0` | pandas 殘留 index 欄 | `drop("Unnamed: 0")` |
| 高度相關特徵 | 冗餘特徵影響 IF 分群 | `drop_correlated(threshold=0.9)` |

---

## Rust ↔ Python IPC

| 方案 | 階段 | 說明 |
|------|------|------|
| Unix socket + JSON | MVP | 簡單、低延遲、同主機 |
| gRPC (tonic + grpcio) | 生產 | 強型別、雙向串流 |

Rust 側送出 `ModelFeature (128B)`，Python 側回傳：

```json
{ "src_ip": "1.2.3.4", "score": 0.87, "is_anomaly": true }
```

---

## 相依套件（service/model/pyproject.toml）

```toml
dependencies = [
    "numpy>=2.2",
    "polars>=1.0",
    "scikit-learn>=1.6",
    "joblib>=1.4",
    "matplotlib>=3.9",
    "missingno",
    "pyarrow",
]
```

---

## 待完成項目

- [ ] `schema.py` — 跑完 `feature_select.py` 後填入 `FEATURE_COLS`
- [ ] `data/features.py` — 若需衍生特徵（ratio、throughput）再實作
- [ ] train/test split — 正式評估前需切出 held-out test set（見下方討論）
- [ ] IF threshold 校準 — 目前以訓練集分位決定，需用含攻擊的驗證集校準
- [ ] Rust 側 Unix socket 整合（`logger.rs`）
- [ ] 生產環境：CSV → 即時特徵向量的 online inference 路徑

---

## Kernel 推論可行性評估（2026-04-05，Run 17）

### 現況架構的限制

目前架構（`ml_model_integration_plan.md` 設計）為：

```
eBPF kernel（收集事件）
    → Rust daemon（聚合 + 建構特徵向量）
    → Python InferenceEngine（推論）
    → BLOCK_LIST BPF_MAP（下發封鎖決定）
```

這條路徑有 **userspace roundtrip**，延遲約 1–10 ms。對一般異常偵測足夠，但無法在 XDP 層做封包路徑內的即時決策。

### Kernel 推論的可行性條件

根據 `kernel_defense_architecture.md` 的定義，kernel 推論需三個條件同時成立。Run 17 驗證了**條件 1（特徵計算可整數化）**：

| 條件 | 狀態 | 依據 |
|------|------|------|
| 1. 特徵計算可整數化 | ✅ **已驗證** | Run 17：N=256 分位桶，AUC 損失 −0.016 |
| 2. 模型可蒸餾為 BPF_MAP 結構 | ⬜ 待驗證 | 線性蒸餾 / 決策樹蒸餾尚未測定 AUC |
| 3. 動作可在 XDP/TC 層執行 | ✅ 架構上可行 | XDP_DROP 已在防火牆實作中存在 |

### Run 17 AUC 結果

以 Run 16 log1p 浮點特徵為基準，測試分位桶整數特徵（Protocol + Packet Length Mean + Shape_q + Sym_q + Bytes_q）：

| 特徵計算方式 | DDoS2019 | HOIC | LOIC-HTTP | LOIC-UDP |
|------------|:--------:|:----:|:---------:|:--------:|
| 浮點 log1p（基準）| 0.9472 | 0.7144 | 0.4924 | 0.9995 |
| 分位桶 N=16 | 0.8101 | 0.8210 | 0.4431 | 0.9974 |
| 分位桶 N=64 | 0.8173 | 0.8211 | 0.4882 | 0.9974 |
| **分位桶 N=256** | **0.9309** | **0.8208** | 0.4755 | 0.9976 |

- N=256 DDoS2019 損失 −0.016，HOIC 反升 +0.106
- N<64 損失過大（DDoS2019 −0.13），不可用

### 推論位置選擇策略

兩種架構**不互斥**，可依攻擊特性分層部署：

```
封包到達
    │
    ▼
[Layer 1 — XDP/TC Kernel 推論]（< 1 µs）
    ├─ Sym_q = MAX_BUCKET → LOIC-UDP（Sym_Ratio 極值）→ 直接 DROP
    ├─ Shape_q = 0 AND Protocol = TCP → 疑似 SYN flood → rate-limit
    └─ 其他 → 通過，進入 ring buffer
         │
         ▼
[Layer 2 — Userspace 推論]（1–10 ms）
    ├─ 完整 log1p 特徵 + IsolationForest
    ├─ 處理邊緣案例（HOIC 等需高精度）
    └─ 決策寫回 BLOCK_LIST BPF_MAP
```

| 架構選擇 | 採用時機 |
|---------|---------|
| Kernel-side（分位桶 + 蒸餾）| 攻擊特徵明顯、需 µs 級回應、可接受 −0.016 AUC 損失 |
| Userspace（現況）| 需完整精度、模型需頻繁更新、邊緣攻擊型態（HOIC）|

### 下一步

1. **測試線性蒸餾 AUC**：以 `S = Σ w_j × q_j`（q_j 為分位桶索引）取代完整 IsolationForest，測定精度損失是否在 kernel 推論可接受範圍
2. **確認 BPF verifier 可通過**：實作 N=256 的 bounded loop 分位桶查找，確認 kernel 5.x 下能通過 verifier
3. **整合分層架構**：Layer 1 過濾明顯攻擊 → Layer 2 精細推論邊緣案例
