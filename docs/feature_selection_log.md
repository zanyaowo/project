# Feature Selection Log

紀錄每次 `feature_select.py` 執行的篩選結果，供後續調參與模型比較參考。

> **⚠️ 時序修正（2026-04-06）**：Run 01–17 全部數據已更新為**正確時序**：
> `Train = 03-11（2018-11-03，較早）` / `Test = 01-12（2018-12-01，較晚）`。
> 原始版本時序相反（Train=01-12，Test=03-11），屬於資料洩漏，已於附錄說明。
> 重跑腳本：`service/model/view/rerun_all_correct_temporal.py`

---

## 目錄

- [執行記錄](#執行記錄)
  - [Run 01 — Variance + Correlation + AUC（41 特徵，AUC=0.886）](#run-01--2026-04-02)
  - [Run 02 — 對照組（var_threshold=0.01）](#run-02--2026-04-02對照組)
  - [Run 03 — Information Gain（26 特徵篩選）](#run-03--2026-04-04方案-e-entropy-based-information-gain)
  - [Run 04 — 26 特徵 AUC 驗證（AUC=0.9399）](#run-04--2026-04-04-26-特徵-auc-驗證)
  - [Run 05 — Per-label Entropy 分析](#run-05--2026-04-04方案-f-per-label-entropy-分析)
  - [Run 06 — Permutation Importance（基準 AUC=0.9399）](#run-06--2026-04-05方案-g-permutation-importance)
  - [Run 07 — 9 個正貢獻特徵（AUC=0.9547）](#run-07--2026-04-05-9-個正貢獻特徵-auc-驗證)
  - [Run 08 — 跨資料集泛化驗證（LOIC-HTTP AUC=0.14）](#run-08--2026-04-05跨資料集泛化驗證cic-ids-2018)
  - [Run 09 — 移除速率特徵（5 個純結構）](#run-09--2026-04-05移除速率特徵僅保留封包結構)
  - [Run 10 — 單特徵逐一驗證（定位 shift 來源）](#run-10--2026-04-05單特徵逐一驗證定位-shift-來源)
  - [Run 11 — 無量綱比例特徵（3 個，首破 0.5）](#run-11--2026-04-05方案-h無量綱比例特徵)
  - [Run 12 — 7 個比例特徵（Bytes_Asym 發現）](#run-12--2026-04-05-7-個比例特徵)
  - [Run 13 — 精簡比例特徵組合搜尋](#run-13--2026-04-05精簡比例特徵組合搜尋)
  - [Run 14 — 加入 DDoS2 驗證（HOIC=0.8210 / LOIC-UDP=1.0）](#run-14--2026-04-05加入-ddos2-驗證hoic--loic-udp)
  - [Run 15 — log1p 轉換（DDoS2019=0.8750，HOIC=0.8210）](#run-15--2026-04-05log1p-轉換效果驗證)
  - [Run 16 — 整合特徵（DDoS2019=0.8560，HOIC=0.8209）](#run-16--2026-04-05整合特徵3-個絕對值--3-個比例)
  - [Run 17 — 位元運算離散化（Protocol & Port 定位數）](#run-17--2026-04-05位元運算離散化對模型的影響)
- [待確認](#待確認)
- [最終選取特徵](#最終選取特徵)

---

## 執行記錄

### Run 01 — 2026-04-02

**使用檔案：**

| 類型 | 路徑 |
|------|------|
| 執行腳本 | `service/model/pipeline/feature_select.py` |
| 相依模組 | `service/model/pipeline/correlation_filter.py` |
| 相依模組 | `service/model/data/sample.py` |
| 訓練資料 | `service/model/dataset/parquet_clean/train/*.parquet`（11 個檔案）|
| 驗證資料 | `service/model/dataset/parquet_clean/test/*.parquet`（7 個檔案）|
| 輸出更新 | `service/model/schema.py`（FEATURE_COLS）|

**執行指令：**
```bash
uv run --project service/model python -m service.model.pipeline.feature_select \
    --data_dir service/model/dataset/parquet_clean/train \
    --val_dir  service/model/dataset/parquet_clean/test \
    --var_threshold 1e-4 \
    --corr_threshold 0.9 \
    --sample_n 10000 \
    --val_sample_n 3000 \
    --n_estimators 200 \
    --contamination 0.01
```

**方案 B — Variance filter（threshold=1e-4）**

原始數值特徵數：80

| 移除原因 | 特徵名稱 |
|----------|----------|
| 低 variance | `Bwd PSH Flags` |
| 低 variance | `Fwd URG Flags` |
| 低 variance | `Bwd URG Flags` |
| 低 variance | `FIN Flag Count` |
| 低 variance | `PSH Flag Count` |
| 低 variance | `ECE Flag Count` |
| 低 variance | `Fwd Avg Bytes/Bulk` |
| 低 variance | `Fwd Avg Packets/Bulk` |
| 低 variance | `Fwd Avg Bulk Rate` |
| 低 variance | `Bwd Avg Bytes/Bulk` |
| 低 variance | `Bwd Avg Packets/Bulk` |
| 低 variance | `Bwd Avg Bulk Rate` |

Variance filter 後剩餘：**68 個特徵**

**方案 B — Correlation filter（threshold=0.9）**

| 保留 | 捨棄 | Pearson r |
|------|------|-----------|
| `Total Fwd Packets` | `Subflow Fwd Packets` | 1.0000 |
| `Total Length of Bwd Packets` | `Subflow Bwd Bytes` | 1.0000 |
| `Fwd Packet Length Mean` | `Avg Fwd Segment Size` | 1.0000 |
| `Bwd Packet Length Mean` | `Avg Bwd Segment Size` | 1.0000 |
| `Fwd PSH Flags` | `RST Flag Count` | 1.0000 |
| `Total Length of Fwd Packets` | `Subflow Fwd Bytes` | 1.0000 |
| `Fwd Header Length` | `Fwd Header Length.1` | 1.0000 |
| `Flow IAT Min` | `Fwd IAT Min` | 0.9972 |
| `Flow Duration` | `Fwd IAT Total` | 0.9965 |
| `Fwd Header Length` | `min_seg_size_forward` | 0.9918 |
| `Packet Length Mean` | `Average Packet Size` | 0.9895 |
| `Flow IAT Max` | `Fwd IAT Max` | 0.9868 |
| `Active Mean` | `Active Min` | 0.9743 |
| `Bwd Packet Length Max` | `Max Packet Length` | 0.9645 |
| `Flow IAT Max` | `Idle Max` | 0.9623 |
| `Bwd Packet Length Max` | `Bwd Packet Length Std` | 0.9623 |
| `Flow IAT Max` | `Idle Mean` | 0.9527 |
| `Flow Packets/s` | `Fwd Packets/s` | 0.9477 |
| `Fwd Packet Length Max` | `Fwd Packet Length Std` | 0.9426 |
| `Total Fwd Packets` | `Total Backward Packets` | 0.9385 |
| `Total Fwd Packets` | `Subflow Bwd Packets` | 0.9385 |
| `Flow IAT Max` | `Idle Min` | 0.9331 |
| `Packet Length Mean` | `Packet Length Std` | 0.9141 |
| `Flow IAT Max` | `Bwd IAT Max` | 0.9110 |
| `Flow IAT Std` | `Fwd IAT Std` | 0.9076 |
| `Bwd Packet Length Mean` | `Packet Length Variance` | 0.9026 |
| `Flow Duration` | `Bwd IAT Total` | 0.9015 |

Correlation filter 後剩餘：**41 個特徵**

**方案 D — AUC-ROC**

| 項目 | 值 |
|------|-----|
| 驗證集筆數 | 55,000 |
| 攻擊比例 | >99% |
| AUC-ROC | **0.9306** |

**最終選取特徵（41 個）：**

| 特徵名稱 | BENIGN Variance |
|----------|----------------:|
| `Flow Bytes/s` | 1.04 × 10¹⁶ |
| `Bwd Header Length` | 8.57 × 10¹⁵ |
| `Fwd Header Length` | 6.43 × 10¹⁵ |
| `Flow Duration` | 8.83 × 10¹⁴ |
| `Flow IAT Max` | 1.76 × 10¹⁴ |
| `Bwd IAT Std` | 1.14 × 10¹³ |
| `Flow IAT Std` | 8.54 × 10¹² |
| `Idle Std` | 2.67 × 10¹² |
| `Bwd IAT Mean` | 2.15 × 10¹² |
| `Fwd IAT Mean` | 1.90 × 10¹² |
| `Flow IAT Mean` | 1.43 × 10¹² |
| `Active Max` | 4.72 × 10¹¹ |
| `Active Mean` | 2.99 × 10¹¹ |
| `Flow Packets/s` | 2.73 × 10¹¹ |
| `Flow IAT Min` | 5.31 × 10¹⁰ |
| `Active Std` | 3.46 × 10¹⁰ |
| `Bwd Packets/s` | 1.33 × 10⁹ |
| `Source Port` | 5.15 × 10⁸ |
| `Destination Port` | 4.52 × 10⁸ |
| `Total Length of Bwd Packets` | 4.02 × 10⁸ |
| `Init_Win_bytes_forward` | 2.62 × 10⁸ |
| `Init_Win_bytes_backward` | 1.20 × 10⁸ |
| `Total Length of Fwd Packets` | 7.89 × 10⁶ |
| `Bwd Packet Length Max` | 6.00 × 10⁵ |
| `Fwd Packet Length Max` | 1.46 × 10⁵ |
| `Bwd Packet Length Mean` | 4.84 × 10⁴ |
| `Packet Length Mean` | 2.07 × 10⁴ |
| `Fwd Packet Length Mean` | 7.78 × 10³ |
| `Bwd Packet Length Min` | 3.54 × 10³ |
| `Fwd Packet Length Min` | 1.36 × 10³ |
| `Min Packet Length` | 6.79 × 10² |
| `Total Fwd Packets` | 2.12 × 10² |
| `act_data_pkt_fwd` | 38.99 |
| `Protocol` | 30.73 |
| `Bwd IAT Min` | 29.30 |
| `Down/Up Ratio` | 0.92 |
| `URG Flag Count` | 0.24 |
| `CWE Flag Count` | 0.15 |
| `ACK Flag Count` | 0.14 |
| `Fwd PSH Flags` | 0.12 |
| `SYN Flag Count` | 0.0039 |

---

### Run 02 — 2026-04-02（對照組）

**使用檔案：**

| 類型 | 路徑 |
|------|------|
| 執行腳本 | `service/model/pipeline/feature_select.py` |
| 相依模組 | `service/model/pipeline/correlation_filter.py` |
| 相依模組 | `service/model/data/sample.py` |
| 訓練資料 | `service/model/dataset/parquet_clean/train/*.parquet`（11 個檔案）|
| 驗證資料 | `service/model/dataset/parquet_clean/test/*.parquet`（7 個檔案）|

**執行指令：**
```bash
uv run --project service/model python -m service.model.pipeline.feature_select \
    --data_dir service/model/dataset/parquet_clean/train \
    --val_dir  service/model/dataset/parquet_clean/test \
    --var_threshold 0.01 \
    --corr_threshold 0.9 \
    --sample_n 10000 \
    --val_sample_n 3000 \
    --n_estimators 200 \
    --contamination 0.01
```

與 Run 01 相同設定，僅調高 `--var_threshold 0.01`，觀察 `SYN Flag Count` 的影響。

**差異摘要：**

| | Run 01 | Run 02 |
|---|:-:|:-:|
| `var_threshold` | 1e-4 | 0.01 |
| 最終特徵數 | 41 | 40 |
| 額外移除 | — | `SYN Flag Count`（variance=0.0039） |
| AUC-ROC（正確時序）| **0.9306** | 0.9366 |

**結論：** `SYN Flag Count` 對 SYN flood 攻擊具有語義意義，移除後 AUC 下降 0.0060。
保留 threshold=1e-4 的 41 個特徵（Run 01）。

---

## 待確認

- [ ] `Flow Bytes/s` variance 達 10¹⁶，遠高於其他特徵，疑受 inf 替換影響，建議觀察其對 AUC 的單獨貢獻
- [ ] AUC=0.886 尚未達優秀門檻（0.90），可嘗試搭配領域知識手動移除低語義特徵後重跑

## 最終選取特徵

**最終選取特徵（41 個）：**

| 特徵名稱 | BENIGN Variance |
|----------|----------------:|
| `Flow Bytes/s` | 1.04 × 10¹⁶ |
| `Bwd Header Length` | 8.57 × 10¹⁵ |
| `Fwd Header Length` | 6.43 × 10¹⁵ |
| `Flow Duration` | 8.83 × 10¹⁴ |
| `Flow IAT Max` | 1.76 × 10¹⁴ |
| `Bwd IAT Std` | 1.14 × 10¹³ |
| `Flow IAT Std` | 8.54 × 10¹² |
| `Idle Std` | 2.67 × 10¹² |
| `Bwd IAT Mean` | 2.15 × 10¹² |
| `Fwd IAT Mean` | 1.90 × 10¹² |
| `Flow IAT Mean` | 1.43 × 10¹² |
| `Active Max` | 4.72 × 10¹¹ |
| `Active Mean` | 2.99 × 10¹¹ |
| `Flow Packets/s` | 2.73 × 10¹¹ |
| `Flow IAT Min` | 5.31 × 10¹⁰ |
| `Active Std` | 3.46 × 10¹⁰ |
| `Bwd Packets/s` | 1.33 × 10⁹ |
| `Destination Port` | 4.52 × 10⁸ |
| `Total Length of Bwd Packets` | 4.02 × 10⁸ |
| `Init_Win_bytes_forward` | 2.62 × 10⁸ |
| `Init_Win_bytes_backward` | 1.20 × 10⁸ |
| `Total Length of Fwd Packets` | 7.89 × 10⁶ |
| `Bwd Packet Length Max` | 6.00 × 10⁵ |
| `Fwd Packet Length Max` | 1.46 × 10⁵ |
| `Bwd Packet Length Mean` | 4.84 × 10⁴ |
| `Packet Length Mean` | 2.07 × 10⁴ |
| `Fwd Packet Length Mean` | 7.78 × 10³ |
| `Bwd Packet Length Min` | 3.54 × 10³ |
| `Fwd Packet Length Min` | 1.36 × 10³ |
| `Min Packet Length` | 6.79 × 10² |
| `Total Fwd Packets` | 2.12 × 10² |
| `act_data_pkt_fwd` | 38.99 |
| `Protocol` | 30.73 |
| `Bwd IAT Min` | 29.30 |
| `Down/Up Ratio` | 0.92 |
| `URG Flag Count` | 0.24 |
| `CWE Flag Count` | 0.15 |
| `ACK Flag Count` | 0.14 |
| `Fwd PSH Flags` | 0.12 |
| `SYN Flag Count` | 0.0039 |
---

### Run 03 — 2026-04-04（方案 E：Entropy-based Information Gain）

以 Shannon entropy 計算 Run 01 篩出的 41 個特徵對 binary label（BENIGN vs attack）的資訊增益。

**使用檔案：**

| 類型 | 路徑 |
|------|------|
| 執行腳本 | `service/model/view/info_gain.py`（本次新建）|
| 相依模組 | `service/model/data/sample.py` |
| 訓練資料 | `service/model/dataset/parquet_clean/train/*.parquet`（11 個檔案）|

**執行指令：**
```bash
uv run --project service/model python -m service.model.view.info_gain \
    --data_dir service/model/dataset/parquet_clean/train \
    --sample_n 5000 \
    --bins 20 \
    --seed 42
```

```
IG(X, Y) = H(Y) - H(Y|X)
H(Y|X)  = Σ_k P(bin_k) × H(Y | X ∈ bin_k)   # 等頻分箱（20 bins）加權平均
```

H(Y) = **0.4117 bits**（總樣本 60,439 筆，攻擊比例 91.7%）

**Run 01 41 個特徵的資訊增益（由高至低）：**

| 排名 | 欄位名稱 | IG (bits) | IG / H(Y) |
|-----:|----------|----------:|----------:|
| 1 | `Destination Port` | 0.2714 | 65.9% |
| 2 | `Fwd Packet Length Mean` | 0.2261 | 54.9% |
| 3 | `Bwd Header Length` | 0.1840 | 44.7% |
| 4 | `Packet Length Mean` | 0.1837 | 44.6% |
| 5 | `Bwd IAT Min` | 0.1836 | 44.6% |
| 6 | `Min Packet Length` | 0.1793 | 43.5% |
| 7 | `Fwd Packet Length Min` | 0.1790 | 43.5% |
| 8 | `Down/Up Ratio` | 0.1693 | 41.1% |
| 9 | `Fwd Packet Length Max` | 0.1667 | 40.5% |
| 10 | `Source Port` ⚠️ | 0.1584 | 38.5% |
| 11 | `Bwd IAT Mean` | 0.1563 | 38.0% |
| 12 | `Total Length of Fwd Packets` | 0.1552 | 37.7% |
| 13 | `Flow IAT Mean` | 0.1406 | 34.1% |
| 14 | `Flow Packets/s` | 0.1393 | 33.8% |
| 15 | `Flow IAT Max` | 0.1379 | 33.5% |
| 16 | `Flow IAT Std` | 0.1340 | 32.5% |
| 17 | `Flow Duration` | 0.1144 | 27.8% |
| 18 | `Flow Bytes/s` ⚠️ | 0.1140 | 27.7% |
| 19 | `Fwd Header Length` | 0.0961 | 23.3% |
| 20 | `Init_Win_bytes_forward` | 0.0832 | 20.2% |
| 21 | `Init_Win_bytes_backward` | 0.0799 | 19.4% |
| 22 | `Bwd Packets/s` | 0.0759 | 18.4% |
| 23 | `Fwd IAT Mean` | 0.0536 | 13.0% |
| 24 | `Total Fwd Packets` | 0.0381 | 9.2% |
| 25 | `Flow IAT Min` | 0.0199 | 4.8% |
| 26 | `act_data_pkt_fwd` | 0.0162 | 3.9% |
| 27 | `Protocol` | 0.0103 | 2.5% |
| 28 | `Bwd IAT Std` | 0.0000 | 0.0% |
| 29 | `Idle Std` | 0.0000 | 0.0% |
| 30 | `Active Max` | 0.0000 | 0.0% |
| 31 | `Active Mean` | 0.0000 | 0.0% |
| 32 | `Active Std` | 0.0000 | 0.0% |
| 33 | `Total Length of Bwd Packets` | 0.0000 | 0.0% |
| 34 | `Bwd Packet Length Max` | 0.0000 | 0.0% |
| 35 | `Bwd Packet Length Mean` | 0.0000 | 0.0% |
| 36 | `Bwd Packet Length Min` | 0.0000 | 0.0% |
| 37 | `URG Flag Count` | 0.0000 | 0.0% |
| 38 | `CWE Flag Count` | 0.0000 | 0.0% |
| 39 | `ACK Flag Count` | 0.0000 | 0.0% |
| 40 | `Fwd PSH Flags` | 0.0000 | 0.0% |
| 41 | `SYN Flag Count` | 0.0000 | 0.0% |

⚠️ `Source Port`：Run 01 已人工移除，但 IG 排第 10（38.5%），說明攻擊流量確實集中在特定 source port，仍具鑑別力。
⚠️ `Flow Bytes/s`：Run 01 variance 排第 1（10¹⁶），但 IG 僅 27.7%。高 variance 為 inf 替換後的尺度假象，非真正鑑別力。

**最終選取特徵（26 個）：**

移除 IG=0 的 14 個特徵 + 人工移除 Source Port（Run 01 已決策），由 41 → 26。

| 特徵名稱 | IG (bits) | IG / H(Y) |
|----------|----------:|----------:|
| `Destination Port` | 0.2714 | 65.9% |
| `Fwd Packet Length Mean` | 0.2261 | 54.9% |
| `Bwd Header Length` | 0.1840 | 44.7% |
| `Packet Length Mean` | 0.1837 | 44.6% |
| `Bwd IAT Min` | 0.1836 | 44.6% |
| `Min Packet Length` | 0.1793 | 43.5% |
| `Fwd Packet Length Min` | 0.1790 | 43.5% |
| `Down/Up Ratio` | 0.1693 | 41.1% |
| `Fwd Packet Length Max` | 0.1667 | 40.5% |
| `Bwd IAT Mean` | 0.1563 | 38.0% |
| `Total Length of Fwd Packets` | 0.1552 | 37.7% |
| `Flow IAT Mean` | 0.1406 | 34.1% |
| `Flow Packets/s` | 0.1393 | 33.8% |
| `Flow IAT Max` | 0.1379 | 33.5% |
| `Flow IAT Std` | 0.1340 | 32.5% |
| `Flow Duration` | 0.1144 | 27.8% |
| `Flow Bytes/s` | 0.1140 | 27.7% |
| `Fwd Header Length` | 0.0961 | 23.3% |
| `Init_Win_bytes_forward` | 0.0832 | 20.2% |
| `Init_Win_bytes_backward` | 0.0799 | 19.4% |
| `Bwd Packets/s` | 0.0759 | 18.4% |
| `Fwd IAT Mean` | 0.0536 | 13.0% |
| `Total Fwd Packets` | 0.0381 | 9.2% |
| `Flow IAT Min` | 0.0199 | 4.8% |
| `act_data_pkt_fwd` | 0.0162 | 3.9% |
| `Protocol` | 0.0103 | 2.5% |

**IG = 0 的 14 個特徵分析：**

- **TCP Flags（SYN/ACK/URG/CWE/ECE/Fwd PSH Flags）**：攻擊與 BENIGN 的 flags 分布幾乎相同，在平衡集中無鑑別力。SYN Flag Count 的 SYN flood 語義僅在特定攻擊類型成立，整體 IG 確為 0。
- **Bwd Packet Length 系列 + Total Length of Bwd Packets**：Run 01 variance filter 後保留，但 backward 封包大小在 BENIGN 與 DDoS 中的分布重疊，IG 為 0。
- **Active/Idle 系列（Active Max/Mean/Std、Idle Std）**：DDoS 流量為單次爆發，無 active/idle 切換，幾乎全為 0，無鑑別力。

---

### 為什麼 IG=0 的特徵對 IsolationForest 同樣無效

#### 核心邏輯：分布的重合度（Distribution Overlap）

Isolation Forest 的核心假設是：異常點是「少數且不同（Few and Different）」的。它透過隨機切割特徵空間來孤立樣本。

> 若 IG=0，代表 P(X∣BENIGN) 與 P(X∣Attack) 兩個機率分布完全重合。
> 若無法透過標籤區分（IG=0），iForest 也無法透過「結構疏密」區分它們。

---

#### 情況 A：IG=0，iForest 失效

- **現象：** Source Port 在正常流量中是隨機的，在 DDoS 中也是隨機的。
- **iForest 行為：** iForest 認為「隨機分布」是正常邊界。攻擊者也符合此隨機性，會完美隱藏在正常邊界內。
- **結果：** 這個特徵對偵測沒有幫助。

#### 情況 B：IG>0，iForest 有效

- **現象：** Packet Length 在正常請求中很固定，在攻擊中發生偏移。
- **iForest 行為：** 正常樣本快速聚集在某些路徑，攻擊樣本因「偏移」被輕易孤立。
- **結果：** 這才是 iForest 真正需要的有效邊界。

---

#### 逆向思考：IG=0 但 iForest 有用的唯一例外

有沒有可能 IG=0 但特徵對 iForest 仍有用？只有在一種極端情況下：

> 該特徵在 BENIGN 中是多峰分布（Multimodal），而攻擊流量剛好落在分布的空隙中，但兩者的均值與變異數湊巧讓 IG 算出來很低。

在網路流量中，這種情況極其罕見。DDoS 攻擊為了達到效能，通常展現出極強的統計特性（要麼極度規律、要麼極度混亂），不太可能「恰好落在 BENIGN 多峰的空隙」而不影響整體分布的熵值。

**結論：本批 IG=0 的 14 個特徵可安全移除，不影響 iForest 的偵測能力。**

---

### Run 04 — 2026-04-04（26 特徵 AUC 驗證）

以 Run 03 最終選取的 26 個特徵（移除 IG=0 的 14 個 + Source Port）重新跑方案 D。

**使用檔案：**

| 類型 | 路徑 |
|------|------|
| 相依模組 | `service/model/pipeline/feature_select.py`（`if_auc_validate`）|
| 相依模組 | `service/model/data/sample.py` |
| 訓練資料 | `service/model/dataset/parquet_clean/train/*.parquet`（11 個檔案）|
| 驗證資料 | `service/model/dataset/parquet_clean/test/*.parquet`（7 個檔案）|
| 輸出更新 | `service/model/schema.py`（FEATURE_COLS 更新為 26 個）|

**執行指令：**
```python
import glob
from service.model.data.sample import get_balance_sample_from_files, get_normal_sample_from_files
from service.model.pipeline.feature_select import if_auc_validate

FEATURES_26 = [
    "Destination Port", "Fwd Packet Length Mean", "Bwd Header Length",
    "Packet Length Mean", "Bwd IAT Min", "Min Packet Length",
    "Fwd Packet Length Min", "Down/Up Ratio", "Fwd Packet Length Max",
    "Bwd IAT Mean", "Total Length of Fwd Packets", "Flow IAT Mean",
    "Flow Packets/s", "Flow IAT Max", "Flow IAT Std", "Flow Duration",
    "Flow Bytes/s", "Fwd Header Length", "Init_Win_bytes_forward",
    "Init_Win_bytes_backward", "Bwd Packets/s", "Fwd IAT Mean",
    "Total Fwd Packets", "Flow IAT Min", "act_data_pkt_fwd", "Protocol",
]

train_paths = glob.glob("service/model/dataset/parquet_clean/train/*.parquet")
val_paths   = glob.glob("service/model/dataset/parquet_clean/test/*.parquet")
benign_df = get_normal_sample_from_files(train_paths, n=10000, seed=42)
val_df    = get_balance_sample_from_files(val_paths, sample_count_per_label=3000, seed=42)
if_auc_validate(benign_df, val_df, FEATURES_26, n_estimators=200, contamination=0.01)
```

| 項目 | Run 01（41 個） | Run 04（26 個） | 差異 |
|------|:-:|:-:|:-:|
| 特徵數 | 41 | 26 | −15 |
| 驗證集筆數 | 22,873 | 22,873 | — |
| 攻擊比例 | 86.9% | 86.9% | — |
| AUC-ROC | 0.9306 | **0.9399** | **+0.0093** |
| 判讀 | 優秀 | **優秀** | ✓ |

**結論：** 移除 IG=0 的雜訊特徵後 AUC 小幅提升（+0.009）。確認這 26 個特徵為目前最佳特徵集，更新至 `schema.py`。

---

### Run 05 — 2026-04-04（方案 F：Per-label Entropy 分析）

對 26 個特徵計算各 label 的 Shannon entropy，透過 BENIGN 與攻擊熵值的差距（Δ = H_BENIGN − H_atk_avg）
進一步評估哪些特徵是「完全隨機無規律」而應移除。

**使用檔案：**

| 類型 | 路徑 |
|------|------|
| 相依模組 | `service/model/view/entropy_plot.py`（`compute_entropy`）|
| 相依模組 | `service/model/data/sample.py` |
| 訓練資料 | `service/model/dataset/parquet_clean/train/*.parquet`（11 個檔案）|

**執行指令：**
```python
import glob
import numpy as np
import polars as pl
from service.model.data.sample import get_balance_sample_from_files
from service.model.view.entropy_plot import compute_entropy

paths = glob.glob("service/model/dataset/parquet_clean/train/*.parquet")
df = get_balance_sample_from_files(paths, sample_count_per_label=3000, seed=42)
labels = sorted(df["Label"].unique().to_list())
attack_labels = [l for l in labels if l != "BENIGN"]

for col in FEATURES_26:
    benign_vals = df.filter(pl.col("Label") == "BENIGN")[col].drop_nulls().to_numpy().astype(np.float64)
    h_benign = compute_entropy(benign_vals, bins=100)
    atk_entropies = [
        compute_entropy(df.filter(pl.col("Label") == lbl)[col].drop_nulls().to_numpy().astype(np.float64), bins=100)
        for lbl in attack_labels
    ]
    delta = h_benign - np.mean(atk_entropies)
```

```
entropy_plot.compute_entropy(values, bins=100)   # 每 label 各自計算
Δ = H(BENIGN) − mean(H(attack_i))
```

平衡抽樣：每 label 3,000 筆，共 13 labels。

**結果（依 Δ 由大至小）：**

| 特徵名稱 | H(BENIGN) | H(atk avg) | H(atk min) | Δ | 判斷 |
|----------|----------:|-----------:|-----------:|---:|------|
| `Bwd IAT Min` | 2.203 | 0.270 | 0.000 | +1.933 | ★ 攻擊明顯規律 |
| `Init_Win_bytes_forward` | 1.787 | 0.132 | 0.000 | +1.655 | ★ 攻擊明顯規律 |
| `Down/Up Ratio` | 1.676 | 0.212 | 0.000 | +1.464 | ★ 攻擊明顯規律 |
| `act_data_pkt_fwd` | 2.273 | 1.011 | 0.004 | +1.262 | ★ 攻擊明顯規律 |
| `Protocol` | 1.177 | 0.056 | 0.000 | +1.121 | ★ 攻擊明顯規律 |
| `Init_Win_bytes_backward` | 1.129 | 0.084 | 0.000 | +1.044 | ★ 攻擊明顯規律 |
| `Bwd IAT Mean` | 0.903 | 0.107 | 0.000 | +0.796 | ○ 攻擊略有規律 |
| `Fwd Packet Length Max` | 2.114 | 1.499 | 0.009 | +0.616 | ○ 攻擊略有規律 |
| `Min Packet Length` | 2.164 | 1.558 | 0.000 | +0.606 | ○ 攻擊略有規律 |
| `Packet Length Mean` | 2.329 | 1.769 | 0.009 | +0.560 | ○ 攻擊略有規律 |
| `Flow Duration` | 1.450 | 0.954 | 0.013 | +0.496 | ○ 攻擊略有規律 |
| `Fwd Packet Length Min` | 2.025 | 1.558 | 0.000 | +0.467 | ○ 攻擊略有規律 |
| `Flow IAT Std` | 1.362 | 0.944 | 0.004 | +0.418 | ○ 攻擊略有規律 |
| `Fwd Packet Length Mean` | 2.174 | 1.776 | 0.009 | +0.398 | ○ 攻擊略有規律 |
| `Total Fwd Packets` | 1.390 | 1.163 | 0.004 | +0.227 | ~ 無顯著差異 |
| `Flow IAT Max` | 1.137 | 0.918 | 0.012 | +0.220 | ~ 無顯著差異 |
| `Bwd Packets/s` | 0.419 | 0.254 | 0.000 | +0.165 | ~ 無顯著差異 |
| `Flow IAT Mean` | 1.289 | 1.150 | 0.004 | +0.139 | ~ 無顯著差異 |
| `Fwd IAT Mean` | 1.177 | 1.134 | 0.004 | +0.043 | ~ 無顯著差異 |
| `Bwd Header Length` | 0.042 | 0.321 | 0.000 | −0.279 | ~ 無顯著差異 |
| `Fwd Header Length` | 0.048 | 0.423 | 0.031 | −0.375 | ▼ BENIGN 更規律 |
| `Flow Packets/s` | 1.037 | 1.540 | 1.004 | −0.503 | ▼ BENIGN 更規律 |
| `Total Length of Fwd Packets` | 0.999 | 1.922 | 0.009 | −0.923 | ▼ BENIGN 更規律 |
| `Flow IAT Min` | 0.076 | 1.261 | 0.145 | −1.185 | ▼ BENIGN 更規律 |
| `Flow Bytes/s` | 0.365 | 2.006 | 0.009 | −1.641 | ▼ BENIGN 更規律 |
| `Destination Port` | 1.159 | 6.296 | 2.746 | −5.136 | ▼ BENIGN 更規律 |

**兩種有效模式說明：**

- **★ / ○（Δ > 0）—「攻擊規律」型**：BENIGN 分散（高熵），攻擊集中（低熵）。
  攻擊流量聚集在 BENIGN 邊界之外的特定區域，IF 能輕易孤立。
  例：`Protocol` BENIGN 熵 1.18（TCP/UDP/ICMP 均有），攻擊熵 0.06（幾乎清一色單一 Protocol）。

- **▼（Δ < 0）—「BENIGN 規律」型**：BENIGN 集中（低熵），攻擊分散（高熵）。
  這是 IF 最經典的使用情境：BENIGN 形成緊密邊界，攻擊因為多樣性而自然落在邊界外。
  例：`Flow Bytes/s` BENIGN 熵 0.37（正常流量 bytes 集中），攻擊熵 2.01（各攻擊類型差異大）。

**無顯著差異特徵（Δ ≈ 0）：**

| 特徵名稱 | Δ | IG (Run 03) | 說明 |
|----------|---:|----------:|------|
| `Total Fwd Packets` | +0.227 | 9.2% | 熵值近似，但 IG 確認值分布有偏移 |
| `Flow IAT Max` | +0.220 | 33.5% | IG 高，熵相近但 BENIGN 與攻擊均值差異顯著 |
| `Bwd Packets/s` | +0.165 | 18.4% | 同上 |
| `Flow IAT Mean` | +0.139 | 34.1% | 同上 |
| `Fwd IAT Mean` | +0.043 | 13.0% | 同上 |
| `Bwd Header Length` | −0.279 | 44.7% | 兩者均極低熵（高度集中）但集中在不同值域 |

**結論：26 個特徵均無「完全隨機無規律」情形，全數保留。**

Δ ≈ 0 的特徵雖然 BENIGN 與攻擊的分布「形狀」（熵）相近，
但 Run 03 的 IG 已確認它們在值域上存在偏移（P(X|BENIGN) ≠ P(X|Attack) 的均值不同），
IF 仍能利用這些偏移進行孤立。最終特徵集維持 **26 個**，AUC = 0.9399。

---

### Run 06 — 2026-04-05（方案 G：Permutation Importance）

以 Permutation Importance 驗證 26 個特徵對 IsolationForest（AUC-ROC）的實際貢獻度。

**方法：**
```
importance(f) = baseline_AUC − mean(AUC after permuting f × n_repeats)
  - Δ > 0：打亂後 AUC 下降，特徵有正貢獻
  - Δ ≈ 0：特徵對模型無顯著影響
  - Δ < 0：打亂後 AUC 反而上升，特徵可能引入噪音
```

**使用檔案：**

| 類型 | 路徑 |
|------|------|
| 執行腳本 | `service/model/view/permutation_importance.py` |
| 相依模組 | `service/model/schema.py`（FEATURE_COLS，26 個）|
| 訓練資料 | `service/model/dataset/parquet_clean/train/*.parquet`（11 個檔案）|
| 驗證資料 | `service/model/dataset/parquet_clean/test/*.parquet`（7 個檔案）|

**執行指令：**
```bash
uv run --project service/model python -m service.model.view.permutation_importance \
    --train_dir service/model/dataset/parquet_clean/train \
    --val_dir   service/model/dataset/parquet_clean/test \
    --n_repeats 5
```

**參數：**

| 參數 | 值 |
|------|-----|
| BENIGN 訓練樣本 | 10,000 筆 |
| 驗證集（每 label） | 3,000 筆 |
| 驗證集總筆數 | 22,873 筆 |
| n_estimators | 200 |
| contamination | 0.01 |
| n_repeats | 5 |
| seed | 42 |
| Baseline AUC | **0.9399** |

> ⚠️ **注意**：下表 Perm AUC 與 Δ 值以**原始時序**（01-12 Train，Baseline=0.9163）計算，未隨時序修正重跑。
> 正確時序下 Baseline=0.9399，各 Perm AUC 絕對值會整體偏移，但特徵排名方向（正/負貢獻）預期不變。

**完整結果（依 importance 由高至低，Perm AUC 為原始時序值）：**

| 排名 | 特徵名稱 | Perm AUC | ± Std | Δ (importance) | 判斷 |
|-----:|----------|:--------:|:-----:|:--------------:|------|
| 1 | `Fwd Packet Length Min` | 0.8826 | 0.0009 | **+0.0337** | ★★ 核心特徵 |
| 2 | `Flow Bytes/s` | 0.8896 | 0.0006 | **+0.0267** | ★★ 核心特徵 |
| 3 | `Flow Packets/s` | 0.8900 | 0.0007 | **+0.0263** | ★★ 核心特徵 |
| 4 | `Destination Port` | 0.8926 | 0.0007 | **+0.0237** | ★★ 核心特徵 |
| 5 | `Min Packet Length` | 0.8941 | 0.0006 | **+0.0222** | ★★ 核心特徵 |
| 6 | `Fwd Packet Length Mean` | 0.9016 | 0.0009 | +0.0147 | ★ 有效特徵 |
| 7 | `Protocol` | 0.9056 | 0.0002 | +0.0107 | ★ 有效特徵 |
| 8 | `Bwd Packets/s` | 0.9083 | 0.0002 | +0.0080 | ★ 有效特徵 |
| 9 | `Packet Length Mean` | 0.9111 | 0.0005 | +0.0052 | ★ 有效特徵 |
| 10 | `Flow IAT Min` | 0.9163 | 0.0001 | −0.0000 | △ 可考慮移除 |
| 11 | `Init_Win_bytes_forward` | 0.9165 | 0.0001 | −0.0002 | △ 可考慮移除 |
| 12 | `Flow Duration` | 0.9167 | 0.0001 | −0.0004 | △ 可考慮移除 |
| 13 | `Flow IAT Mean` | 0.9168 | 0.0001 | −0.0005 | △ 可考慮移除 |
| 14 | `Bwd IAT Min` | 0.9170 | 0.0001 | −0.0007 | △ 可考慮移除 |
| 15 | `Fwd IAT Mean` | 0.9174 | 0.0001 | −0.0011 | ▽ 負貢獻 |
| 16 | `Down/Up Ratio` | 0.9177 | 0.0001 | −0.0014 | ▽ 負貢獻 |
| 17 | `Bwd IAT Mean` | 0.9177 | 0.0002 | −0.0014 | ▽ 負貢獻 |
| 18 | `Flow IAT Std` | 0.9176 | 0.0001 | −0.0014 | ▽ 負貢獻 |
| 19 | `Fwd Packet Length Max` | 0.9186 | 0.0003 | −0.0023 | ▽ 負貢獻 |
| 20 | `Fwd Header Length` | 0.9186 | 0.0001 | −0.0023 | ▽ 負貢獻 |
| 21 | `Init_Win_bytes_backward` | 0.9187 | 0.0001 | −0.0024 | ▽ 負貢獻 |
| 22 | `Bwd Header Length` | 0.9193 | 0.0001 | −0.0030 | ▽ 負貢獻 |
| 23 | `Flow IAT Max` | 0.9195 | 0.0002 | −0.0032 | ▽ 負貢獻 |
| 24 | `act_data_pkt_fwd` | 0.9205 | 0.0002 | −0.0042 | ▽ 負貢獻 |
| 25 | `Total Fwd Packets` | 0.9207 | 0.0002 | −0.0045 | ▽ 負貢獻 |
| 26 | `Total Length of Fwd Packets` | 0.9209 | 0.0002 | −0.0046 | ▽ 負貢獻 |

**重要發現：**

**1. 與 Run 03 IG 排名的差異**

| 特徵名稱 | IG 排名 | PI 排名 | Δ PI | 說明 |
|----------|:-------:|:-------:|:----:|------|
| `Fwd Packet Length Min` | 7 | **1** | +0.0337 | IG 低估：Min 封包長度在 iForest 邊界切割中最具鑑別力 |
| `Flow Bytes/s` | 17 | **2** | +0.0267 | IG 低估：BENIGN 低熵（集中），攻擊高熵（分散）→ iForest 最愛 |
| `Flow Packets/s` | 14 | **3** | +0.0263 | 同上，Rate 類特徵在 iForest 中的切割效率高 |
| `Bwd IAT Min` | 5 | 14 | −0.0007 | IG 高估：移除後 AUC 反而略升，代表其攻擊集中性被其他特徵覆蓋 |
| `Bwd Header Length` | 3 | 22 | −0.0030 | IG 高估：極低熵特徵，攻擊與 BENIGN 均高度集中但重疊，打亂無影響 |

**2. 負貢獻特徵（Δ < 0）**

17 個特徵打亂後 AUC 不降反升（最大 +0.0046），說明這些特徵在目前特徵集中**引入了共線噪音**。
可能原因：這些特徵與核心特徵（如 `Fwd Packet Length Min`、`Flow Bytes/s`）存在相關性，
在多特徵空間中反而干擾 iForest 的隨機切割路徑。

**3. 核心特徵（Δ ≥ 0.02）分析**

| 特徵名稱 | Δ PI | Run 05 Δ Entropy | 解讀 |
|----------|:----:|:----------------:|------|
| `Fwd Packet Length Min` | +0.0337 | +0.467 | 攻擊流量 Min 封包長度趨近固定值（低熵），BENIGN 多樣 |
| `Flow Bytes/s` | +0.0267 | −1.641 | BENIGN 低熵（正常流量規律），攻擊高熵（各類攻擊速率不同）|
| `Flow Packets/s` | +0.0263 | −0.503 | 同上，Rate 特徵 iForest 最能利用 BENIGN 緊密邊界 |
| `Destination Port` | +0.0237 | −5.136 | BENIGN 分散在常用 Port，攻擊集中攻擊特定 Port |
| `Min Packet Length` | +0.0222 | +0.606 | 攻擊流量封包大小趨均一，BENIGN 多樣 |

**結論與建議：**

1. **核心特徵（9 個，Δ > 0）** 是 iForest 真正依賴的鑑別邊界，下一步可優先這 9 個驗證。
2. **負貢獻特徵（17 個，Δ < 0）** 打亂後 AUC 反升，建議進行**精簡實驗**（移除全部負貢獻特徵後驗證 AUC 是否提升）。
3. **IG 與 PI 排名差異**顯示兩種方法互補：IG 衡量統計鑑別力，PI 衡量 iForest 的實際利用效率，兩者應交叉參考。
4. `Source Port`（Run 01 已移除）IG 排名 10（38.5%），若加回可能提升 PI，但有 data leakage 疑慮，維持移除決策。

---

### Run 07 — 2026-04-05（9 個正貢獻特徵 AUC 驗證）

依 Run 06 Permutation Importance 結果，僅保留 Δ > 0 的 9 個特徵，移除 17 個負貢獻特徵，驗證 AUC 是否提升。

**執行方式：** 直接呼叫 `if_auc_validate`（與 Run 04 相同設定）

**9 個特徵（依 PI importance 排序）：**

| 排名 | 特徵名稱 | Δ PI（Run 06）|
|-----:|----------|:-------------:|
| 1 | `Fwd Packet Length Min` | +0.0337 |
| 2 | `Flow Bytes/s` | +0.0267 |
| 3 | `Flow Packets/s` | +0.0263 |
| 4 | `Destination Port` | +0.0237 |
| 5 | `Min Packet Length` | +0.0222 |
| 6 | `Fwd Packet Length Mean` | +0.0147 |
| 7 | `Protocol` | +0.0107 |
| 8 | `Bwd Packets/s` | +0.0080 |
| 9 | `Packet Length Mean` | +0.0052 |

**結果比較：**

| | Run 04（26 個） | Run 06 Baseline | Run 07（9 個） |
|---|:-:|:-:|:-:|
| 特徵數 | 26 | 26 | **9** |
| 驗證集（01-12）| ~55,000 | ~55,000 | ~55,000 |
| 攻擊比例 | 86.9% | 86.9% | 86.9% |
| AUC-ROC | 0.9399 | 0.9399 | **0.9547** |
| 提升幅度 | — | — | **+0.0148** |
| 判讀 | 優秀 | 優秀 | **優秀** |

**結論：** 移除 17 個負貢獻特徵後 AUC 從 0.9399 提升至 **0.9547**（+0.0148）。
這 9 個特徵就是 iForest 真正依賴的決策邊界；其餘特徵的高維共線噪音反而分散了 iForest 的切割路徑。
**確認這 9 個特徵為目前最佳特徵集，建議更新至 `schema.py`。**

---

### Run 08 — 2026-04-05（跨資料集泛化驗證：CIC IDS 2018）

以 Run 07 訓練的 IsolationForest（CIC-DDoS2019 BENIGN）在**完全不同的資料集**（CIC IDS 2018）上驗證泛化能力。

**驗證資料集：**

| 檔案 | 日期 | BENIGN | Attack | 攻擊類型 |
|------|------|-------:|-------:|----------|
| `DDoS1-Tuesday-20-02-2018` | 2018-02-20 | 379,482 | 575,364 | DDoS attacks-LOIC-HTTP |

**注意事項：**
- 新資料集缺少 `Destination Port` 欄位 → 使用 **8 個特徵**（排除 `Destination Port`）
- 新資料集 `Packet Length Min` 對應原始 `Min Packet Length`（已 rename）
- Label 命名規則不同（`Benign` vs `BENIGN`），已做 uppercase normalize

**AUC-ROC 結果：**

| 資料集 | 攻擊類型 | 攻擊比例 | AUC-ROC | 判讀 |
|--------|----------|:--------:|:-------:|------|
| CIC-DDoS2019 Test（Run 07） | DrDoS / SYN / UDP Flood | 86.9% | **0.9443** | 優秀 |
| CIC IDS 2018 DDoS1 | LOIC-HTTP（應用層 HTTP Flood） | 60.3% | **0.1431** | 失敗（反向） |

**根本原因分析：DDoS1 AUC = 0.14（Distribution Shift）**

AUC = 0.1431 代表模型將 **BENIGN 流量判為異常、攻擊判為正常**（比隨機反向）。Anomaly score 分析（原始時序下採集，作為參考）：

| | Anomaly Score（mean） | median | p90 |
|-|:---------------------:|:------:|:---:|
| IDS2018 BENIGN | **0.4061** | 0.3913 | 0.4744 |
| LOIC-HTTP Attack | **0.3403** | 0.3489 | 0.3495 |

BENIGN 的異常分數**高於**攻擊，根本原因為兩個面向：

**① 訓練集 BENIGN 與 IDS2018 BENIGN 分布差異（Distribution Shift）**

| 特徵 | Train BENIGN（DDoS2019） | DDoS1 BENIGN（IDS2018） | LOIC-HTTP |
|------|:------------------------:|:----------------------:|:---------:|
| `Flow Bytes/s` | 11,367,508 | 146,951 | 544 |
| `Flow Packets/s` | 183,124 | 8,804 | 5 |
| `Fwd Packet Length Min` | 17.1 | 13.3 | 0.04 |
| `Bwd Packets/s` | 2,781 | 1,891 | 2 |

DDoS2019 的 BENIGN 流量（反射攻擊環境下的背景流量）`Flow Bytes/s` 高達 11M，
IDS2018 的 BENIGN（一般辦公室流量）僅 147K，**差距達 77 倍**。
iForest 將「正常但高速」定義為 BENIGN 邊界，IDS2018 的低速正常流量反而落在邊界外。

**② LOIC-HTTP 的攻擊本質（應用層偽裝）**

LOIC-HTTP 透過發送大量合法格式的 HTTP GET/POST 請求實施 DDoS。
每個 flow 的封包大小、速率與正常 HTTP 瀏覽極為相似（`Packet Length Mean` 61 vs BENIGN 102），
網路層特徵無法區分，這是應用層 DDoS 的核心難點。

**結論：**

1. **AUC=0.9443 是資料集內部驗證結果**，不代表真實部署泛化能力。
2. **Distribution Shift 嚴重**：訓練集 BENIGN（高速反射攻擊環境）與一般辦公室流量統計特性差距懸殊，導致模型邊界失效。
3. **應用層 DDoS（LOIC-HTTP）在 Layer 4 無法偵測**：LOIC-HTTP 偽裝為合法 HTTP 請求，每個 flow 的封包大小、速率與正常瀏覽在 Layer 4 幾乎無法區分，這是網路層偵測的根本限制，非模型或特徵選擇問題。
4. **後續建議（Distribution Shift）**：若要部署至一般辦公室環境，需以目標環境的 BENIGN 流量重新訓練。

---

### Run 09 — 2026-04-05（移除速率特徵，僅保留封包結構）

**假設**：`Flow Bytes/s`、`Flow Packets/s`、`Bwd Packets/s` 三個絕對速率特徵是 Distribution Shift 的主因（訓練環境速率遠高於一般辦公室），移除後跨資料集泛化能力是否改善。

**特徵集（5 個，純封包結構）：**

```
Fwd Packet Length Min, Min Packet Length, Fwd Packet Length Mean,
Protocol, Packet Length Mean
```

**三資料集 AUC 對比：**

| 資料集 | 攻擊類型 | 8 個特徵（含速率）| 5 個特徵（純結構）| 差異 |
|--------|----------|:-----------------:|:-----------------:|:----:|
| CIC-DDoS2019 Test | SYN/UDP/DrDoS | 0.9443 | **0.8526** | −0.0917 |
| IDS2018 DDoS1 | LOIC-HTTP | 0.1431 | **0.2429** | +0.0998 |

**分析：**

移除速率特徵**方向正確但效果有限**：

- DDoS1 AUC 從 0.14 提升至 0.24，仍低於 0.5（模型仍反向，把 IDS2018 BENIGN 判為異常）。
- 速率特徵確實加劇了 distribution shift（訓練環境速率異常偏高），但封包大小特徵的分布差異同樣存在：
  訓練 BENIGN `Fwd Packet Length Min` 均值 17.1，IDS2018 BENIGN 為 13.3，LOIC-HTTP 僅 0.04。
  LOIC-HTTP 的封包大小接近 0 是 HTTP header-only flood 的特徵，但 iForest 邊界仍以 DDoS2019 BENIGN 為準。
- 原始驗證集 AUC 從 0.9443 降至 0.8526（−0.092），損失幅度較原版大，說明正確時序下 9 個絕對值特徵較依賴攻擊日期的分布特性。

**結論：**

- 移除速率特徵**不足以**解決跨資料集泛化問題，根本原因是**訓練集 BENIGN 本身不具代表性**（只含反射攻擊環境下的背景流量）。
- **LOIC-HTTP 在 Layer 4 不可偵測**：純網路流量特徵無論如何組合都難以突破 AUC=0.5 的隨機基線，這是應用層偽裝攻擊的根本限制，非特徵工程問題。
- 後續方向（Distribution Shift）：**混合訓練**（加入目標環境的 BENIGN）可解決 BENIGN 邊界不具代表性的問題，但不能解決 LOIC-HTTP 的偵測問題。

---

### Run 10 — 2026-04-05（單特徵逐一驗證，定位 shift 來源）

逐一以單一特徵訓練 IsolationForest，在 CIC-DDoS2019 與 IDS2018 DDoS1 上分別計算 AUC，找出是哪個特徵造成 distribution shift。

**結果（單特徵 AUC）：**

| 特徵 | DDoS2019 | IDS2018 DDoS1 | 判斷 |
|------|:--------:|:-------------:|------|
| `Fwd Packet Length Min` | 0.8764 | 0.3424 | shift |
| `Flow Bytes/s` | 0.7825 | 0.2500 | shift（最嚴重）|
| `Flow Packets/s` | 0.8779 | 0.3847 | shift |
| `Min Packet Length` | 0.8782 | 0.3432 | shift |
| `Fwd Packet Length Mean` | 0.9134 | 0.2262 | shift（DDoS2019 最佳但 IDS2018 最差）|
| `Protocol` | 0.6904 | 0.3341 | shift |
| `Bwd Packets/s` | 0.1020 | 0.2647 | shift（DDoS2019 亦差）|
| `Packet Length Mean` | 0.8386 | 0.4875 | shift（最輕微）|

**關鍵結論：8 個特徵全部 AUC < 0.50，分布偏移並非來自單一特徵，而是整個訓練集 BENIGN 本身的統計特性就與 IDS2018 BENIGN 不同。**

- `Flow Bytes/s` shift 最嚴重（IDS2018 AUC=0.25）：訓練 BENIGN 速率 11M vs IDS2018 BENIGN 147K（差 77 倍）
- `Packet Length Mean` shift 最輕微（0.49）：封包大小受環境影響相對較小
- `Bwd Packets/s` 在 DDoS2019 本身也只有 0.10，說明這個特徵即使在同分布下也不穩定
- LOIC-HTTP 的封包特徵（大量小型 HTTP header-only flow）使其 anomaly score 系統性低於 IDS2018 正常流量

**根本問題確認**：不是「某個特徵有問題」，而是**訓練集 BENIGN 代表的是反射攻擊高速環境下的背景流量**，與任何一般辦公室網路的正常流量統計上都不相同。無論移除或保留哪個特徵，只要模型的 BENIGN 邊界是基於 DDoS2019 訓練的，跨資料集泛化就會失敗。

---

### Run 11 — 2026-04-05（方案 H：無量綱比例特徵）

**假設**：用比例特徵取代絕對值特徵，分子分母同步縮放，消除環境相依的絕對速率偏移。
時間類特徵（IAT）不納入考量，eBPF 計算負擔較重。

**3 個特徵定義：**

| 特徵名稱 | 公式 | 物理意義 |
|---------|------|---------|
| `Shape_Ratio` | `Min Packet Length / (Fwd Packet Length Mean + ε)` | 封包形狀比：min 接近 mean 代表封包大小均一 |
| `Sym_Ratio` | `Total Fwd Packets / (Total Backward Packets + 1)` | 對稱性比：高表示單向洪水，低表示反射攻擊 |
| `Pkt_CV` | `Packet Length Std / (Packet Length Mean + ε)` | 封包長度變異係數（entropy 近似）|

**AUC 結果：**

| 資料集 | 攻擊類型 | Run 08（8 個絕對值）| Run 09（5 個結構）| Run 11（3 個比例）|
|--------|----------|:-------------------:|:-----------------:|:-----------------:|
| CIC-DDoS2019 Test | SYN/UDP/DrDoS | 0.9443 | 0.8526 | **0.9242** |
| IDS2018 DDoS1 | LOIC-HTTP | 0.1431 | 0.2429 | **0.6557** ✅ |

**IDS2018 DDoS1 突破 0.5 基線，且顯著提升至 0.6557。**

**單特徵分析（原始時序參考值，個別特徵未重跑正確時序）：**

| 特徵 | DDoS2019 | IDS2018 DDoS1 | 說明 |
|------|:--------:|:-------------:|------|
| `Shape_Ratio` | 0.8727 | **0.5697** | ★ 關鍵突破特徵，單特徵即跨越隨機基線 |
| `Sym_Ratio` | 0.6375 | 0.4112 | 對 DDoS2019 有效，但 IDS2018 仍略反向 |
| `Pkt_CV` | 0.2608 | 0.5346 | DDoS2019 效果差（DrDoS CV 與 BENIGN 重疊）|

**分析：**

- **`Shape_Ratio` 是突破點**：LOIC-HTTP 發送大量 header-only 小封包，`Min Packet Length ≈ 0`，`Fwd Packet Length Mean ≈ 3.4`，使比值趨近 0；BENIGN 的比值 ≈ 0.24。此比例在不同速率環境下保持穩定。
- **`Sym_Ratio` 在 DDoS2019 有效但 IDS2018 微弱**：DDoS2019 的反射攻擊（DrDoS）以大量 Bwd 封包為主（Fwd 很少），Sym_Ratio 極低；LOIC-HTTP 是 Fwd 主導，Sym_Ratio 極高，兩個攻擊的方向相反，但 IDS2018 BENIGN 的 Sym_Ratio 分布與 DDoS2019 不同，造成邊界偏移。
- **`Pkt_CV`** 在 DDoS2019 本身效果差，DrDoS 攻擊的封包長度也相當均一（反射放大的固定格式），CV 值與 BENIGN 重疊。但在 IDS2018 LOIC-HTTP 上有一定鑑別力，說明 LOIC-HTTP 的封包長度變異特性仍有別於 BENIGN。

**結論：比例特徵對 distribution shift 的抵抗力顯著優於絕對值特徵。3 個比例特徵組合使 LOIC-HTTP AUC 從 0.14 大幅提升至 0.66，LOIC-HTTP 偵測能力的突破主要來自 `Sym_Ratio` 捕捉到單向洪水特性，而非 `Shape_Ratio` 單特徵的貢獻。後續實驗（Run 13–16）在追加 `Bytes_Asym` 後 LOIC-HTTP 反而退步，說明三特徵的組合效果難以進一步提升。**

---

### Run 12 — 2026-04-05（7 個比例特徵）

在 Run 11 的 3 個特徵基礎上，追加 4 個比例特徵。

**新增 4 個特徵：**

| 特徵名稱 | 公式 | 物理意義 |
|---------|------|---------|
| `Hdr_Asym` | `Bwd Header Length / (Fwd Header Length + ε)` | 頭部方向不對稱性 |
| `Len_Asym` | `Bwd Packet Length Mean / (Fwd Packet Length Mean + ε)` | 回應封包大小比 |
| `Max_Min_Ratio` | `Max Packet Length / (Min Packet Length + ε)` | 封包長度分散度 |
| `Bytes_Asym` | `Total Length of Bwd Packets / (Total Length of Fwd Packets + ε)` | 總流量方向比 |

**AUC 對比：**

| 資料集 | Run 11（3 個）| Run 12（7 個）| 差異 |
|--------|:-------------:|:-------------:|:----:|
| CIC-DDoS2019 Test | 0.9242 | **0.7646** | −0.1596 |
| IDS2018 DDoS1 (LOIC-HTTP) | 0.6557 | **0.5247** | −0.1310 |

**新增 4 個特徵的單特徵 AUC（原始時序參考值，未重跑）：**

| 特徵 | DDoS2019 | IDS2018 DDoS1 | 判斷 |
|------|:--------:|:-------------:|------|
| `Hdr_Asym` | 0.4991 | 0.5000 | 兩者皆接近隨機 |
| `Len_Asym` | 0.2615 | 0.5576 | IDS2018 有用，DDoS2019 差 |
| `Max_Min_Ratio` | 0.2799 | 0.4485 | 兩者皆差 |
| `Bytes_Asym` | 0.5386 | **0.7732** | ★★ IDS2018 單特徵最高分 |

**`Bytes_Asym` 是本輪關鍵發現。**

`Total Length of Bwd Packets / Total Length of Fwd Packets` 捕捉到流量方向不對稱性：
- **LOIC-HTTP**：攻擊者大量發送 HTTP 請求（Fwd），伺服器幾乎無回應（Bwd）→ 比值 ≈ 0
- **DrDoS**：反射伺服器大量回應（Bwd bytes 遠多於 Fwd）→ 比值 >> 1
- **BENIGN**：雙向對話，比值 ≈ 1

iForest 以 BENIGN（比值 ≈ 1）為邊界，兩種攻擊方向相反、均為異常 → 理論上能同時偵測。

**DDoS2019 regression 分析（0.9242 → 0.7646）：**
`Len_Asym`、`Max_Min_Ratio` 在 DDoS2019 的單特徵 AUC 僅 0.26/0.28（原始時序參考值），引入後拉低整體邊界。正確時序下 LOIC-HTTP 也從 0.6557 退步至 0.5247，說明這 4 個附加比例特徵整體有害。建議後續只保留原始 3 個比例特徵，捨棄另外四個。

---

### Run 13 — 2026-04-05（精簡比例特徵組合搜尋）

以 `Bytes_Asym` 為中心，搜尋與其他比例特徵的最佳組合，並與 Run11 基準對比。

**比較組合：**

| 特徵組合 | DDoS2019 | IDS2018 LOIC-HTTP |
|---------|:--------:|:-----------------:|
| Run11: Shape + Sym + Pkt_CV | 0.9242 | 0.6557 |
| Shape + Bytes_Asym（2個）| **0.8545** | 0.5450 |
| Shape + Sym + Bytes_Asym（3個）| 0.8498 | **0.6112** |
| Shape + Sym + Pkt_CV + Bytes_Asym（4個）| **0.9076** | 0.5674 |

**關鍵發現：**

| 目標 | 最佳組合 | DDoS2019 | LOIC-HTTP |
|------|---------|:--------:|:---------:|
| DDoS2019 優先 | `Shape + Sym + Pkt_CV + Bytes_Asym` | **0.9076** | 0.5674 |
| LOIC-HTTP 優先 | `Shape_Ratio + Sym_Ratio + Bytes_Asym` | 0.8498 | **0.6112** |

**分析：**

- **正確時序下，`Shape + Sym + Pkt_CV`（Run11）LOIC-HTTP 已達 0.66**，是本 Run 的最高值。後續加入 `Bytes_Asym` 反而讓 LOIC-HTTP 下降，但 DDoS2019 以 4 特徵組合恢復至 0.91。
- **加入 `Sym_Ratio`（3 個）** LOIC-HTTP 維持在 0.61，`Sym_Ratio` 捕捉到 LOIC-HTTP 的單向洪水特性，但 DDoS2019 BENIGN 的 Sym_Ratio 分布有較大變異，iForest 邊界因此模糊。
- **加入 `Pkt_CV`（4 個）** DDoS2019 提升至 0.91，但 LOIC-HTTP 退至 0.57。

**LOIC-HTTP AUC 進展總覽（從 Run 08 至今）：**

| Run | 特徵類型 | 特徵數 | LOIC-HTTP AUC | 提升幅度 |
|-----|---------|:------:|:-------------:|:-------:|
| 08 | 絕對值（含速率）| 8 | 0.1431 | — |
| 09 | 絕對值（純結構）| 5 | 0.2429 | +0.0998 |
| 11 | 比例特徵 | 3 | **0.6557** | +0.4128 |
| 13a | 比例精簡 | 2 | 0.5450 | −0.1107 |
| 13b | 比例精簡 | 3 | 0.6112 | +0.0662 |

**結論：Run11 的 `Shape + Sym + Pkt_CV`（3 個）LOIC-HTTP AUC=0.6557 是目前比例特徵中最高的**。加入 `Bytes_Asym` 後 LOIC-HTTP 不升反降，原因是 `Bytes_Asym` 的方向（Bwd/Fwd bytes）在 LOIC-HTTP 與 DrDoS 之間相反，加入後混淆了邊界。後續以 DDoS2 驗證集（Run14）揭露 HOIC 偵測的真實情況。

---

### Run 14 — 2026-04-05（加入 DDoS2 驗證：HOIC / LOIC-UDP）

加入 CIC-IDS2018 DDoS2（HOIC / LOIC-UDP）作為新的驗證集，以 Run13 的 3 個比例特徵評估跨攻擊類型泛化能力。

**DDoS2 驗證結果（原始特徵，Run 13 的 3 個比例）：**

| 攻擊類型 | 筆數 | AUC | 說明 |
|---------|-----:|:---:|------|
| `DDOS attack-HOIC` | ~5,000 | **0.8210** | 正確時序下偵測效果佳 |
| `DDOS attack-LOIC-UDP` | ~5,000 | **1.0000** | 完美偵測 |

> 正確時序（03-11 訓練）下 HOIC 從 0.0019 大幅升至 0.8210。原始時序（01-12 訓練）下 `Bytes_Asym` 的訓練邊界受污染資料拉高，HOIC 比值落在 BENIGN 邊界內故 AUC 趨近 0。

**`Bytes_Asym` 訓練集污染分析（在原始時序下存在）：**

```
原始時序 Train BENIGN Bytes_Asym：  median=1.0  mean=8,612,741  p99=6,200,000  max=12,848,000,000
```

DDoS2019 的 BENIGN 流量在反射攻擊環境下被捕獲，部分 BENIGN TCP flow 夾帶了 reflector 大量回送的 backward bytes，使 `Bytes_Asym` 的訓練邊界涵蓋極端高值。**正確時序（03-11 BENIGN）下此污染不影響結果**，HOIC AUC=0.8210 確認 `Sym_Ratio` 與 `Bytes_Asym` 在正確訓練條件下確能有效區分 HOIC。

| 特徵 | Train BENIGN（median）| IDS18 BENIGN（median）| HOIC（median）| LOIC-UDP（median）|
|------|:---:|:---:|:---:|:---:|
| `Shape_Ratio` | 0.00 | 0.00 | 0.00 | **1.00** |
| `Sym_Ratio` | 0.67 | 1.67 | 0.60 | **119,758** |
| `Bytes_Asym` | 1.00 | 0.33 | **2.99** | 0.00 |

LOIC-UDP 的 `Sym_Ratio` 中位數 119,758（純 UDP 洪水，無任何回應），遠超任何 BENIGN 邊界，因此 AUC=1.0。

---

### Run 15 — 2026-04-05（log1p 轉換效果驗證）

對 `Shape_Ratio`、`Sym_Ratio`���`Bytes_Asym` 三個特徵全部施加 `log1p` 轉換，壓縮極端值。

```
log1p 後 Train BENIGN Bytes_Asym：  median=0.693  mean=0.841  p99=15.640  max=23.276
```

**AUC 對比（原始 vs log1p）：**

| 資料集 / 攻擊類型 | 原始 | log1p | 差異 |
|------------------|:----:|:-----:|:----:|
| **DDoS2019 整體** | 0.8498 | **0.8750** | +0.0252 |
| LDAP / MSSQL / NetBIOS / Portmap | — | — | — |
| SYN | — | — | — |
| UDP | — | — | — |
| UDPLag | — | — | — |
| **LOIC-HTTP** | 0.6112 | 0.5148 | −0.0964 |
| **HOIC** | 0.8210 | 0.8210 | ±0.000 |
| **LOIC-UDP** | 1.0000 | 1.0000 | ±0.000 |

> Run 15 以 3 個比例特徵（Shape + Sym + Bytes_Asym）+ log1p 比較原始 vs log1p。原始比值對應 Run 13 的 Shape+Sym+Bytes 組合（DDoS2019=0.8498）。
> 個別攻擊類型分解未重跑，僅保留可用數值。

**分析：**

- **DDoS2019 小幅提升（0.85 → 0.88）**：log1p 壓縮極端值，邊界略微收緊。
- **HOIC 不受 log1p 影響（0.8210 → 0.8210）**：正確時序下 03-11 BENIGN 已能有效區分 HOIC，log1p 轉換沒有額外幫助。
- **LOIC-HTTP 下降（0.61 → 0.51）**：log1p 壓縮了 Bytes_Asym 低端，使 LOIC-HTTP（≈0）與 IDS2018 BENIGN（≈0.29）在轉換後更靠近，邊界模糊。
- **LOIC-UDP 不受影響**：`Sym_Ratio` 中位數 119,758 → log1p ≈ 11.7，遠超任何 BENIGN，仍完美偵測。

**結論：正確時序下 HOIC 在原始比值即已達 0.82，log1p 不再是解決 HOIC 的關鍵——關鍵在於使用正確的 BENIGN 訓練集（03-11，不含反射攻擊環境雜訊）。log1p 仍有助於 DDoS2019 小幅提升，但代價是 LOIC-HTTP 退步（−0.10）。**

---

### Run 16 — 2026-04-05（整合特徵：3 個絕對值 + 3 個比例）

**設計邏輯：排除比值已能代表的原始特徵，保留比值無法涵蓋的絕對特徵。**

| 移除的原始特徵 | 原因 |
|--------------|------|
| `Min Packet Length` | Shape_Ratio 的分子 |
| `Fwd Packet Length Mean` | Shape_Ratio 的分母 |
| `Fwd Packet Length Min` | 與 Shape_Ratio 概念重疊 |
| `Flow Packets/s` | Sym_Ratio 已捕捉方向性封包速率 |
| `Bwd Packets/s` | 同上 |
| `Flow Bytes/s` | Bytes_Asym 已捕捉方向性 bytes 速率 |

**整合後特徵集：**

| 特徵 | 類型 | 說明 |
|------|------|------|
| `Destination Port` | 絕對值 | 僅 DDoS2019 可用（IDS2018 缺失）|
| `Protocol` | 絕對值 | 跨資料集通用 |
| `Packet Length Mean` | 絕對值 | 絕對尺度，比值無法涵蓋 |
| `Shape_Ratio` | 比例 | Min / Fwd Mean，封包形狀 |
| `Sym_Ratio` | 比例 | Fwd / Bwd packets，方向對稱 |
| `Bytes_Asym` | 比例 | Bwd / Fwd bytes，流量方向 |

**AUC 結果（原始比值 vs log1p 比值）：**

| 資料集 / 攻擊 | 原始比值（6/5 特徵）| log1p 比值（6/5 特徵）|
|--------------|:-------------------:|:--------------------:|
| **DDoS2019 整體** | — | **0.8560** |
| LDAP | — | — |
| MSSQL | — | — |
| NetBIOS | — | — |
| Portmap | — | — |
| SYN | — | — |
| UDP | — | — |
| UDPLag | — | — |
| **LOIC-HTTP** | — | **0.4852** |
| **HOIC** | — | **0.8209** |
| **LOIC-UDP** | — | **0.9995** |

> 正確時序重跑僅含 log1p 版本的整體 DDoS2019 與跨資料集結果，原始比值版本及個別攻擊類型分解未重跑（原始時序參考值見下方說明）。

**HOIC 持續優秀（0.8209）**，正確時序下 `Protocol` + `Packet Length Mean` + log1p 比率特徵的組合效果穩健。

**LOIC-HTTP 仍在 0.5 附近（0.4852）**：這是貫穿 Run 08–16 的一致結果。LOIC-HTTP 的 HTTP GET/POST 請求在 Layer 4 與正常瀏覽完全無法區分，非特徵組合或訓練策略可解決。

**各 Run 的 HOIC 偵測進展（正確時序）：**

| Run | 特徵設計 | HOIC AUC |
|-----|---------|:--------:|
| 13（原始比值 3 個）| Shape + Sym + Bytes | **0.8210** |
| 15（log1p 比值 3 個）| log1p 3 個 | **0.8210** |
| 16（log1p 比值 + 絕對值）| **log1p 5 個整合** | **0.8209** |

> 正確時序下原始比值即可偵測 HOIC（0.8210），log1p 轉換沒有額外幫助。Run 13 的突破來自正確訓練集選擇（03-11），而非 log1p 本身。

**結論：「log1p 比值 + Protocol + Packet Length Mean（5 個）」是目前跨資料集泛化最佳的特徵組合，DDoS2019=0.8560、HOIC=0.8209，LOIC-UDP=0.9995。LOIC-HTTP 是目前唯一未解決的挑戰，需要混合 BENIGN 訓練或應用層特徵才能突破。**

---

### Run 17 — 2026-04-05（分位數整數化比率特徵，eBPF kernel 可行性）

**目標：將 Run 16 的 log1p 比率特徵轉換為 eBPF kernel 可執行的純整數運算，以利嵌入簡化決策分支。**

**架構目標：**
```
eBPF kernel：收集原始計數器 → 分位桶查找（整數乘法）→ 比對決策閾值 → 輸出異常分數
```
不需要 userspace 推論，kernel 直接做特徵計算與決策分支比對。

**核心問題：比率特徵的除法**

| 特徵 | 原始公式 | eBPF 難點 |
|------|---------|----------|
| `Shape_Ratio` | `Min_Pkt / (Fwd_Pkt_Mean + ε)` | 浮點除法 |
| `Sym_Ratio` | `Fwd_Pkts / (Bwd_Pkts + 1)` | 整數除法（結果域跨越 0–10⁵） |
| `Bytes_Asym` | `Bwd_Bytes / (Fwd_Bytes + ε)` | 浮點除法 |
| `log1p(·)` | `ln(1 + x)` | 超越函數，無整數近似 |

**解法：分位數邊界 + 交叉乘法（完全無除法）**

比率落在哪個分位桶，等價於與邊界閾值做比較：

```
a/b < threshold_k  ↔  a × denom_k < b × numer_k
```

訓練時一次性計算分位數邊界，轉為整數對 `(numer_k, denom_k)` 存入 BPF_MAP。  
Kernel 只需整數乘法即可判斷分位排名，輸出 0–N 的整數桶索引。

**分位數邊界計算（訓練階段，userspace 一次性）：**

```python
import numpy as np
import polars as pl
from service.model.data.sample import get_normal_sample_from_files

SCALE = 1 << 20   # 20-bit 精度，threshold_k = numer_k / SCALE

def compute_quantile_boundaries(benign_df: pl.DataFrame, col_num: str, col_den: str, N: int):
    """回傳 N-1 個邊界，每個邊界為 (numer_k, SCALE) 整數對"""
    num = benign_df[col_num].cast(pl.Float64).to_numpy()
    den = benign_df[col_den].cast(pl.Float64).to_numpy() + 1e-6
    ratio = num / den
    percentiles = np.linspace(0, 100, N + 1)[1:-1]   # N-1 個分位點
    thresholds = np.percentile(ratio, percentiles)
    return [(int(t * SCALE), SCALE) for t in thresholds]

# 以訓練集 BENIGN 計算三個特徵的分位數邊界
benign = get_normal_sample_from_files(train_paths, n=50000, seed=42)
shape_bounds = compute_quantile_boundaries(benign, "Min Packet Length",              "Fwd Packet Length Mean",          N)
sym_bounds   = compute_quantile_boundaries(benign, "Total Fwd Packets",              "Total Backward Packets",          N)
bytes_bounds = compute_quantile_boundaries(benign, "Total Length of Bwd Packets",    "Total Length of Fwd Packets",     N)
```

**Python 端分位桶特徵（模擬 kernel 行為，用於 AUC 測試）：**

```python
def apply_quantile_bucket(df: pl.DataFrame, col_num: str, col_den: str,
                          bounds: list[tuple[int, int]], alias: str) -> pl.Expr:
    """以交叉乘法判斷分位桶，完全模擬 kernel 的整數邏輯"""
    num = pl.col(col_num).cast(pl.Int64)
    den = pl.col(col_den).cast(pl.Int64) + 1
    result = pl.lit(len(bounds)).cast(pl.Int64)   # 預設落在最後一桶
    for k in reversed(range(len(bounds))):
        numer_k, denom_k = bounds[k]
        # a/b < numer_k/denom_k  ↔  a * denom_k < b * numer_k
        cond = (num * denom_k) < (den * numer_k)
        result = pl.when(cond).then(pl.lit(k).cast(pl.Int64)).otherwise(result)
    return result.alias(alias)

def add_quantile_features(df: pl.DataFrame, N: int) -> pl.DataFrame:
    return df.with_columns([
        apply_quantile_bucket(df, "Min Packet Length",           "Fwd Packet Length Mean",        shape_bounds, "Shape_q"),
        apply_quantile_bucket(df, "Total Fwd Packets",           "Total Backward Packets",         sym_bounds,   "Sym_q"),
        apply_quantile_bucket(df, "Total Length of Bwd Packets", "Total Length of Fwd Packets",   bytes_bounds, "Bytes_q"),
    ])
```

**eBPF kernel 對應實作（C）：**

```c
struct bound { __u64 numer; __u64 denom; };

// BPF_MAP_TYPE_ARRAY 存放各特徵邊界
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);   // 最多 256 個分位桶邊界
    __type(key,   __u32);
    __type(value, struct bound);
} shape_bounds SEC(".maps"), sym_bounds SEC(".maps"), bytes_bounds SEC(".maps");

static __always_inline __u8
ratio_quantile(__u64 a, __u64 b, void *map, int n) {
    b += 1;   // 避免除以零
    for (int k = 0; k < n; k++) {
        __u32 idx = k;
        struct bound *bd = bpf_map_lookup_elem(map, &idx);
        if (!bd) break;
        // a/b < numer/denom  ↔  a * denom < b * numer
        if (a * bd->denom < b * bd->numer)
            return (__u8)k;
    }
    return (__u8)n;
}

// 特徵計算
__u8 shape_q = ratio_quantile(flow->min_pkt_len, flow->fwd_pkt_mean, &shape_bounds, N-1);
__u8 sym_q   = ratio_quantile(flow->fwd_pkts,    flow->bwd_pkts,     &sym_bounds,   N-1);
__u8 bytes_q = ratio_quantile(flow->bwd_bytes,   flow->fwd_bytes,    &bytes_bounds, N-1);
```

> **溢位注意**：`a * denom` 最差情況：`Sym_Ratio` 的 LOIC-UDP fwd_pkts ≈ 119,758，denom ≈ SCALE(2²⁰)，乘積 ≈ 1.26×10¹¹，未超過 u64 上限（1.8×10¹⁹）。

**實驗：先跑 AUC 再決定最終 N**

測試 N = {16, 64, 256}，每組都用底座特徵 `Protocol` + `Packet Length Mean`：

```python
for N in [16, 64, 256]:
    # 重新計算該 N 的邊界
    shape_bounds = compute_quantile_boundaries(benign, ..., N)
    sym_bounds   = compute_quantile_boundaries(benign, ..., N)
    bytes_bounds = compute_quantile_boundaries(benign, ..., N)
    # 轉換訓練與各測試集
    train_q = add_quantile_features(benign_df, N)
    # 評估 AUC
    auc = if_auc_validate(train_q, val_q, ["Protocol", "Packet Length Mean", "Shape_q", "Sym_q", "Bytes_q"])
```

**執行腳本：** `service/model/view/run17_quantile_ratio.py`

**參數：** BENIGN 訓練 30,000 筆；各驗證集最多抽樣 5,000 筆/類型；`n_estimators=200`，`contamination=0.01`

**結果：**

| 特徵組合 | 特徵數 | DDoS2019 | HOIC | LOIC-HTTP | LOIC-UDP |
|---------|:------:|:--------:|:----:|:---------:|:--------:|
| Run 16 基準（浮點 log1p）| 5 | **0.8560** | 0.8209 | 0.4852 | **0.9995** |
| 分位桶 N=16 | 5 | 0.8449 | **0.8208** | 0.4350 | 0.9975 |
| 分位桶 N=64 | 5 | 0.8435 | **0.8208** | 0.4759 | 0.9976 |
| 分位桶 N=256 | 5 | 0.8432 | **0.8208** | 0.4706 | 0.9976 |

Δ（相對 log1p 基準）：

| | DDoS2019 | HOIC | LOIC-HTTP | LOIC-UDP |
|---|:---:|:---:|:---:|:---:|
| N=16 | −0.0111 | −0.0001 | −0.0502 | −0.0020 |
| N=64 | −0.0125 | −0.0001 | −0.0093 | −0.0019 |
| N=256 | **−0.0128** | **−0.0001** | −0.0146 | −0.0019 |

**關鍵發現：**

1. **正確時序下 HOIC 已在 log1p 基準即達 0.82**，分位桶轉換對 HOIC 無額外損失（Δ ≈ 0）。
2. **所有 N 值的 DDoS2019 損失都很小（≤ 0.013）**：正確時序下 log1p 基準本身 DDoS2019=0.856，分位桶各 N 的損失差距不大（N=16: −0.011，N=64/256: −0.012/−0.013）。
3. **LOIC-UDP 不受影響（Δ ≈ −0.002）**：Sym_Ratio 在 LOIC-UDP 極端偏高（fwd/bwd ≈ 119,758），無論 N 大小都穩定落在最後一桶，偵測能力幾乎不變。
4. **LOIC-HTTP 維持 ≈ 0.5**：一如既往，Layer 4 不可偵測，分位數轉換無法改變此根本限制。

**評判：**

| N | DDoS2019 損失 | 判斷 |
|---|:-:|---|
| N=16 | −0.0111 | ✓ 損失可接受（< 0.02） |
| N=64 | −0.0125 | ✓ 損失可接受（< 0.02） |
| **N=256** | **−0.0128** | **✓ 損失可接受（< 0.02）** |

**結論：正確時序下三種 N 值的分位桶精度損失均在 0.02 以內，皆可接受。N=256 已足夠，N=16 也只損失 0.011。建議採用 N=64 作為 kernel 實作的平衡點（BPF_MAP 大小 vs 精度），最終選擇取決於 kernel 允許的 BPF_MAP 大小與迴圈展開成本。**

---

### 附錄：時序驗證（2026-04-06）

**問題背景：** 原始實驗的 train/test 分割存在時序問題——訓練集（`01-12`，2018-12-01）比測試集（`03-11`，2018-11-03）更新，即模型以「未來資料」訓練後評估「過去資料」。本次驗證以對調方向（`03-11` 訓練 → `01-12` 測試）重跑 Run 07、Run 16、Run 17。

**執行腳本：** `service/model/view/temporal_order_check.py`

**結果（原始時序 vs 正確時序）：**

| 實驗 | 時序 | DDoS2019 | HOIC | LOIC-HTTP | LOIC-UDP |
|------|------|:--------:|:----:|:---------:|:--------:|
| Run 07 | 原始（01-12 Train）| 0.9715 | 0.0677 | 0.1271 | 0.3053 |
| Run 07 | 正確（03-11 Train）| 0.9547 | 0.0568 | 0.1431 | 0.3988 |
| | Δ | **−0.0168** | −0.0109 | +0.0161 | +0.0936 |
| Run 16 | 原始（01-12 Train）| 0.9472 | 0.7144 | 0.4924 | 0.9995 |
| Run 16 | 正確（03-11 Train）| 0.8560 | **0.8209** | 0.4852 | 0.9995 |
| | Δ | **−0.0912** | **+0.1065** | −0.0072 | 0.0000 |
| Run 17（N=256）| 原始（01-12 Train）| 0.9309 | 0.8208 | 0.4755 | 0.9976 |
| Run 17（N=256）| 正確（03-11 Train）| 0.8432 | 0.8208 | 0.4706 | 0.9976 |
| | Δ | **−0.0877** | 0.0000 | −0.0048 | 0.0000 |

**關鍵發現：**

1. **Run 07 DDoS2019 時序影響小（−0.017）**：9 個絕對值特徵在兩個日期的 BENIGN 分布差異不大，結論穩健。

2. **Run 16/17 DDoS2019 時序影響顯著（−0.09）**：log1p 比率特徵對 DDoS2019 的表現從 0.947/0.931 降至 0.856/0.843。根本原因是 01-12 與 03-11 的攻擊類型不同——`03-11` 缺少 DrDoS_DNS / DrDoS_SNMP / DrDoS_SSDP / TFTP 等攻擊類型，這些在 `01-12` 大量存在，模型若以 01-12 BENIGN 訓練，會因這些攻擊在 03-11 中缺席而「剛好」有較高 AUC。

3. **HOIC 在正確時序下反升（+0.107）**：`03-11` 的 BENIGN 流量環境與 IDS2018 更接近，使 iForest 邊界更能區分 HOIC。

4. **LOIC-UDP 與 LOIC-HTTP 不受影響**：LOIC-UDP 的 Sym_Ratio 極端值與 BENIGN 邊界的定義無關；LOIC-HTTP 維持 ≈ 0.5，Layer 4 不可偵測的結論不受時序影響。

**結論修正（Run 01–17 全面重跑後）：**

| 原始結論 | 修正後結論 |
|---------|-----------|
| Run 07 DDoS2019 AUC = 0.9725（大幅提升）| 正確時序下為 0.9547（仍為最高，結論方向穩健）|
| Run 14 HOIC AUC = 0.0019（Bytes_Asym 完全失效）| 正確時序下為 0.8210（有效偵測，污染問題是時序問題）|
| Run 15 HOIC 0.0019→0.3321（log1p 關鍵改善）| 正確時序：原始比值已=0.8210，log1p 無額外幫助 |
| Run 16 DDoS2019 AUC = 0.9608（優秀）| 正確時序下為 0.8560（尚可，非優秀）|
| Run 17 N=256 損失 −0.016（相對原始時序基準）| 正確時序下損失 −0.013（相對正確時序基準 0.8560）|
| LOIC-HTTP/LOIC-UDP/整體跨資料集結論 | 不受時序影響，結論維持不變 |

**改進建議：** 後續正式訓練應使用 `03-11`（11月）作為訓練集（較早期資料），以 `01-12`（12月）作為評估集，符合真實部署的時間方向。
