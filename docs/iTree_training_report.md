# Isolation Forest (iTree) 訓練實現報告

## 概述

本報告詳細說明 `service/model` 目錄下 Isolation Forest (iTree) 異常檢測模型的訓練實現流程、特徵工程及相關技術細節。

## 系統架構

系統包含以下核心模組:

- **build_features.py**: 特徵工程模組
- **train_if.py**: 模型訓練模組
- **infer_if.py**: 模型推論模組
- **utils.py**: 共用工具函數
- **rule_baseline.py**: 規則基線比較模組

## 資料流程

```
Zeek Conn.log (TSV)
    ↓
build_features.py (特徵提取)
    ↓
conn_features.csv
    ↓
train_if.py (模型訓練)
    ↓
if_model.joblib
    ↓
infer_if.py (異常偵測)
    ↓
alerts_if.csv
```

## 特徵工程詳解

### 輸入資料格式

來源: Zeek `conn.log` (使用 `zeek-cut` 提取的 TSV 格式)

**原始欄位** (build_features.py:11-14):
- `ts`: 時間戳記
- `uid`: 連線唯一識別碼
- `src`: 來源 IP
- `sport`: 來源埠號
- `dst`: 目的 IP
- `dport`: 目的埠號
- `proto`: 協定類型
- `service`: 服務類型
- `duration`: 連線持續時間
- `orig_bytes`: 發送端位元組數
- `resp_bytes`: 接收端位元組數
- `orig_ip_bytes`: 發送端 IP 層位元組數
- `resp_ip_bytes`: 接收端 IP 層位元組數
- `orig_pkts`: 發送端封包數
- `resp_pkts`: 接收端封包數
- `history`: 連線狀態歷史

### 特徵轉換

#### 1. 數值型特徵正規化 (utils.py:12-15)

將以下欄位轉換為數值型態，無法轉換的值填充為 0.0:
```python
NUM_COLS = [
    "duration", "orig_bytes", "resp_bytes", "orig_ip_bytes", "resp_ip_bytes",
    "orig_pkts", "resp_pkts"
]
```

#### 2. 類別型特徵雜湊編碼 (utils.py:17-18, 24-25)

使用雜湊桶 (Hash Bucket) 技術處理類別型欄位:
- `proto_h`: 協定雜湊值 (mod 16)
- `service_h`: 服務雜湊值 (mod 128)

```python
HASH_PROTO_MOD = 16
HASH_SERVICE_MOD = 128
```

**優點**: 避免高基數類別特徵造成的維度爆炸，同時保留部分區分性。

#### 3. 衍生特徵 (utils.py:27-35)

| 特徵名稱 | 計算公式 | 說明 |
|---------|---------|------|
| `history_len` | `len(history)` | 連線狀態歷史字串長度 |
| `bytes_sum` | `orig_bytes + resp_bytes` | 總傳輸位元組數 |
| `pkts_sum` | `orig_pkts + resp_pkts` | 總封包數 |
| `bytes_ratio` | `orig_bytes / resp_bytes` | 位元組比率 (防除零) |
| `pkts_ratio` | `orig_pkts / resp_pkts` | 封包比率 (防除零) |
| `bps_approx` | `bytes_sum / duration` | 近似頻寬 (Bytes per Second) |

**特殊處理**:
- `bytes_ratio` 和 `pkts_ratio`: 當分母為 0 時，比率設為 0
- `bps_approx`: 當 `duration ≤ 0` 時，直接使用 `bytes_sum`

### 最終特徵集 (utils.py:44-48)

**共 15 個特徵**用於訓練 Isolation Forest:

```python
FEATURE_COLS = [
    "duration",          # 持續時間
    "orig_bytes",        # 發送端位元組
    "resp_bytes",        # 接收端位元組
    "orig_ip_bytes",     # 發送端 IP 位元組
    "resp_ip_bytes",     # 接收端 IP 位元組
    "orig_pkts",         # 發送端封包數
    "resp_pkts",         # 接收端封包數
    "history_len",       # 歷史長度
    "bytes_sum",         # 總位元組數
    "pkts_sum",          # 總封包數
    "bytes_ratio",       # 位元組比率
    "pkts_ratio",        # 封包比率
    "bps_approx",        # 近似頻寬
    "proto_h",           # 協定雜湊
    "service_h"          # 服務雜湊
]
```

## 模型訓練流程

### 訓練腳本: train_if.py

#### 1. 命令列參數 (train_if.py:10-15)

| 參數 | 型別 | 預設值 | 說明 |
|-----|------|--------|------|
| `--input` | str | 必填 | 輸入特徵檔案 (conn_features.csv) |
| `--model` | str | if_model.joblib | 輸出模型檔案路徑 |
| `--alert_rate` | float | 0.005 | 預期異常比例 (0.5%) |
| `--trees` | int | 300 | Isolation Forest 樹的數量 |

#### 2. 資料前處理 (train_if.py:17-21)

```python
df = pd.read_csv(args.input)
X = df[FEATURE_COLS].replace([np.inf, -np.inf], np.nan).fillna(0.0).values
scaler = StandardScaler()
Xn = scaler.fit_transform(X)
```

**處理步驟**:
1. 讀取特徵 CSV
2. 選取 15 個訓練特徵
3. 處理無限值: `inf` 和 `-inf` 替換為 `NaN`，再填充為 `0.0`
4. **標準化**: 使用 `StandardScaler` 進行 Z-score 正規化

#### 3. Isolation Forest 訓練 (train_if.py:23-29)

```python
model = IsolationForest(
    n_estimators=args.trees,         # 樹的數量 (預設 300)
    contamination=args.alert_rate,   # 預期異常比例 (預設 0.005)
    random_state=42,                 # 隨機種子確保可重現性
    n_jobs=-1,                       # 使用所有 CPU 核心
)
model.fit(Xn)
```

**關鍵參數說明**:
- **n_estimators**: 決策樹數量，越多越穩定但訓練時間越長
- **contamination**: 影響內部異常分數閾值估計，但不直接決定最終閾值
- **random_state=42**: 確保結果可重現

#### 4. 閾值計算 (train_if.py:31-32)

```python
scores = -model.score_samples(Xn)  # 值越大越可疑
thr = float(np.quantile(scores, 1.0 - args.alert_rate))
```

**計算邏輯**:
- Isolation Forest 原始分數越小越異常
- 取負號後，**分數越大表示越可疑**
- 閾值 = (1 - alert_rate) 分位數
  - 例如 alert_rate=0.005 → 取 99.5% 分位數
  - 超過此閾值的樣本被標記為異常

#### 5. 模型保存 (train_if.py:34-40)

```python
meta = {
    "feature_cols": FEATURE_COLS,
    "threshold": thr,
    "alert_rate": args.alert_rate,
}
dump({"scaler": scaler, "model": model, "meta": meta}, args.model)
```

**保存內容**:
- `scaler`: StandardScaler 物件 (用於推論時的標準化)
- `model`: 訓練好的 IsolationForest 模型
- `meta`: 元資料 (特徵欄位、閾值、警報率)

## 模型推論流程

### 推論腳本: infer_if.py

#### 1. 命令列參數 (infer_if.py:8-13)

| 參數 | 型別 | 預設值 | 說明 |
|-----|------|--------|------|
| `--input` | str | 必填 | 特徵檔案 (conn_features.csv) |
| `--model` | str | 必填 | 模型檔案 (if_model.joblib) |
| `--output` | str | alerts_if.csv | 輸出警報檔案 |
| `--override_threshold` | float | None | 覆寫預設閾值 (可選) |

#### 2. 載入模型與計算分數 (infer_if.py:15-26)

```python
bundle = load(args.model)
scaler = bundle["scaler"]
model = bundle["model"]
meta = bundle.get("meta", {})

df = pd.read_csv(args.input)
X = df[FEATURE_COLS].replace([np.inf, -np.inf], np.nan).fillna(0.0).values
Xn = scaler.transform(X)  # 使用訓練時的 scaler
scores = -model.score_samples(Xn)
df["anomaly_score"] = scores
```

#### 3. 異常判定 (infer_if.py:28-34)

```python
thr = args.override_threshold if args.override_threshold is not None else meta.get("threshold", None)

if thr is None:
    thr = float(np.quantile(scores, 0.995))  # 保底: 99.5% 分位數

df["is_alert"] = df["anomaly_score"] > thr
```

#### 4. 警報輸出 (infer_if.py:33-37)

輸出欄位:
- `ts`: 時間戳記
- `src`, `sport`, `dst`, `dport`: 連線五元組
- `anomaly_score`: 異常分數
- `bytes_sum`, `pkts_sum`, `bps_approx`, `bytes_ratio`: 關鍵特徵

依 `anomaly_score` 降序排列，僅保留 `is_alert=True` 的紀錄。

## 規則基線比較 (rule_baseline.py)

### 規則評分邏輯 (rule_baseline.py:4-15)

```python
def score_rule(row):
    s = 0
    # 規則 1: 單向小封包洪流
    if row["bytes_sum"] < 400 and row["pkts_sum"] > 20:
        s += 2
    # 規則 2: 非典型服務 + 高連線速度
    if (str(row.get("service","")) in {"-","unknown",""}) and row["bps_approx"] > 1e6:
        s += 1
    # 規則 3: 流量極度不對稱
    if row["bytes_ratio"] > 20 or row["bytes_ratio"] < 0.05:
        s += 1
    return s
```

**警報條件**: `rule_score >= 2`

**用途**: 作為機器學習模型的基線對照，評估 Isolation Forest 的效能提升。

## 技術要點總結

### 優點

1. **無監督學習**: 不需要標記資料即可訓練
2. **特徵工程完整**: 涵蓋流量統計、比率、頻寬等多維度特徵
3. **可擴展性**: 使用 joblib 平行化，支援大規模資料
4. **可解釋性**: 保存完整元資料，方便追溯與調整閾值

### 關鍵技術

1. **雜湊編碼**: 處理高基數類別特徵 (proto, service)
2. **標準化**: Z-score 正規化確保不同尺度特徵的公平性
3. **動態閾值**: 基於分位數計算，適應不同資料分佈
4. **分數反轉**: `-score_samples()` 使高分代表高風險，符合直覺

### 注意事項

1. **防除零**: `bytes_ratio` 和 `pkts_ratio` 計算時需檢查分母
2. **無限值處理**: 訓練與推論都需一致處理 `inf` 值
3. **Scaler 一致性**: 推論時必須使用訓練時的 StandardScaler
4. **閾值選擇**: 可透過 `--override_threshold` 調整敏感度

## 使用範例

### 完整訓練與推論流程

```bash
# 步驟 1: 從 Zeek conn.log 提取特徵
python build_features.py \
    --input conn.tsv \
    --output conn_features.csv

# 步驟 2: 訓練 Isolation Forest 模型
python train_if.py \
    --input conn_features.csv \
    --model if_model.joblib \
    --alert_rate 0.005 \
    --trees 300

# 步驟 3: 進行異常偵測
python infer_if.py \
    --input conn_features.csv \
    --model if_model.joblib \
    --output alerts_if.csv

# (可選) 步驟 4: 執行規則基線比較
python rule_baseline.py \
    --input conn_features.csv \
    --output alerts_rule.csv
```

## 相關檔案

- `service/model/train_if.py` - 主要訓練邏輯
- `service/model/build_features.py` - 特徵提取流程
- `service/model/utils.py:44-48` - 特徵欄位定義
- `service/model/infer_if.py` - 推論與警報產生
- `service/model/rule_baseline.py` - 規則基線實現

---

**報告生成日期**: 2025-12-21
**分析版本**: 基於 commit fd79630
