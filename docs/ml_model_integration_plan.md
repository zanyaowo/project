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
| Loader | `data/loader.py` | 讀取 CIC IDS 2019 CSV → `pl.LazyFrame` |
| Cleaner | `data/cleaner.py` | 清洗資料（strip、cast、fill nulls、clip） |
| Features | `data/features.py` | 選取 FEATURE_COLS、特徵工程 |
| Schema | `schema.py` | 全域常數（欄位名稱、FEATURE_COLS、CLIP_UPPER_PERCENTILE） |
| Feature Select | `pipeline/feature_select.py` | 一次性分析工具，用 RF 決定 FEATURE_COLS |
| Train | `pipeline/train.py` | 訓練 IsolationForest，存 model_store/ |
| Infer | `pipeline/infer.py` | 載入模型，對新資料評分，輸出 alerts |

---

## 訓練流程

```
CIC IDS 2019 CSV
    │
    ▼
loader.load_features_csv()
    │
    ▼
cleaner.clean()
    1. strip 欄位名稱空白
    2. drop "Unnamed: 0"
    3. cast "Flow Bytes/s", "Flow Packets/s" → Float64
    4. inf / NaN → null → 0.0
    5. clip 每欄 99.9 percentile 上限
    │
    ▼
features.build_features()
    選取 FEATURE_COLS（由 feature_select 決定）
    → numpy array X
    │
    ▼
StandardScaler.fit_transform(X)
    │
    ▼
IsolationForest.fit(X_scaled)
    │
    ▼
joblib.dump({ scaler, model, meta })
    → model_store/if_model.joblib
```

---

## 推論流程

```
新資料 CSV
    │
    ▼
loader → cleaner → features
    │
    ▼
scaler.transform(X)        ← 用訓練時的 scaler，不重新 fit
    │
    ▼
-model.score_samples(X)    ← 分數越高越可疑
    │
    ├─ score > threshold → AnomalyAlert
    └─ score ≤ threshold → benign
```

---

## Feature Selection 流程（一次性）

目的：用監督式 Random Forest 找出對「BENIGN vs 攻擊」最有鑑別力的欄位，
再將結果填入 `schema.py` 的 `FEATURE_COLS`，供 Isolation Forest 使用。

```
CIC IDS 2019 CSV（含 Label 欄）
    │
    ├─ 抽出 Label → 二元化（BENIGN=0, 其他攻擊=1）
    │
    ▼
cleaner.clean()（不含 Label 欄）
    │
    ▼
RandomForestClassifier.fit(X, y)
    class_weight="balanced"  ← 攻擊樣本通常為少數
    n_estimators=100
    │
    ▼
feature_importances_ 排序
    │
    ├─ 印出排名表
    ├─ 輸出圖片（matplotlib barh）
    └─ 印出可貼入 schema.py 的 FEATURE_COLS
```

### 執行方式

```bash
cd service/model
uv run python pipeline/feature_select.py \
    --input /path/to/cic_ids_2019.csv \
    --top 20 \
    --trees 100 \
    --output feature_importance.png
```

---

## CIC IDS 2019 資料清洗重點

| 問題 | 原因 | 處理方式 |
|------|------|----------|
| 欄位名稱有 leading space | CIC IDS 2019 已知問題 | `c.strip()` rename |
| `Flow Bytes/s` 是 String | 含 "Infinity" 字串 | `cast(Float64, strict=False)` |
| `Flow Packets/s` 是 String | 同上 | 同上 |
| inf / NaN 值 | 除以零產生 | `is_infinite() / is_nan()` → `fill_null(0.0)` |
| 極端大值 | 少數異常流量 | `clip(upper_bound=quantile(0.999))` |
| `Unnamed: 0` | pandas 殘留 index 欄 | `drop("Unnamed: 0")` |

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
]
```

---

## 待完成項目

- [ ] `data/loader.py` — 補完 `load_features_csv`
- [ ] `data/features.py` — 實作 `build_features`（依 FEATURE_COLS 選欄）
- [ ] `schema.py` — 跑完 feature_select 後填入 `FEATURE_COLS`
- [ ] `pipeline/feature_select.py` — 實作完整邏輯與圖片輸出
- [ ] `pipeline/train.py` — 實作訓練流程
- [ ] `pipeline/infer.py` — 實作推論流程
- [ ] Rust 側 Unix socket 整合（`logger.rs`）
