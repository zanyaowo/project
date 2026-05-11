# Feature Selection Log

紀錄每次 `feature_select.py` 執行的篩選結果，供後續調參與模型比較參考。

> **✅ 正確時序（2026-04-10）**：Run 01–17 全部以**正確時序**完整重跑：
> `Train = 03-11（2018-11-03，較早）` / `Test = 01-12（2018-12-01，較晚）`。
> 原始版本時序相反（Train=01-12，Test=03-11），屬於資料洩漏。
> 重跑後 Run 01 的特徵集由 41 個變為 **39 個**（相關性結構改變），後續 Run 04/06/07 的特徵集亦隨之更新。
> 重跑腳本：`service/model/view/rerun_all_correct_temporal.py`

---

## 目錄

- [執行記錄](#執行記錄)
  - [Run 01 — Variance + Correlation + AUC（39 特徵，AUC=0.9114）](#run-01--2026-04-02)
  - [Run 02 — 對照組（移除 SYN Flag Count，38 特徵，AUC=0.9159）](#run-02--2026-04-02對照組)
  - [Run 03 — Information Gain（39→29 特徵篩選）](#run-03--2026-04-04方案-e-entropy-based-information-gain)
  - [Run 04 — 29 特徵 AUC 驗證（AUC=0.8757）](#run-04--2026-04-04-29-特徵-auc-驗證)
  - [Run 05 — Per-label Entropy 分析（29 特徵）](#run-05--2026-04-04方案-f-per-label-entropy-分析)
  - [Run 06 — Permutation Importance（基準 AUC=0.8757）](#run-06--2026-04-05方案-g-permutation-importance)
  - [Run 07 — 17 個正貢獻特徵（AUC=0.9257）](#run-07--2026-04-05-17-個正貢獻特徵-auc-驗證)
  - [Run 08 — 跨資料集泛化驗證（LOIC-HTTP AUC=0.28）](#run-08--2026-04-05跨資料集泛化驗證cic-ids-2018)
  - [Run 09 — 移除速率特徵（5 個純結構）](#run-09--2026-04-05移除速率特徵僅保留封包結構)
  - [Run 10 — 單特徵逐一驗證（定位 shift 來源）](#run-10--2026-04-05單特徵逐一驗證定位-shift-來源)
  - [Run 11 — 無量綱比例特徵（3 個，首破 0.5）](#run-11--2026-04-05方案-h無量綱比例特徵)
  - [Run 12 — 7 個比例特徵（Bytes_Asym 發現）](#run-12--2026-04-05-7-個比例特徵)
  - [Run 13 — 精簡比例特徵組合搜尋](#run-13--2026-04-05精簡比例特徵組合搜尋)
  - [Run 14 — 加入 DDoS2 驗證（HOIC=0.0022 失敗 / LOIC-UDP=1.0）](#run-14--2026-04-05加入-ddos2-驗證hoic--loic-udp)
  - [Run 15 — log1p 轉換（DDoS2019=0.9198，HOIC 仍失敗）](#run-15--2026-04-05log1p-轉換效果驗證)
  - [Run 16 — 整合特徵（DDoS2019=0.9114，HOIC 仍失敗）](#run-16--2026-04-05整合特徵3-個絕對值--3-個比例)
  - [Run 17 — 分位桶整數化 N=2（全面超越浮點基準：HOIC=0.9934）](#run-17--2026-04-05分位數整數化比率特徵ebpf-kernel-可行性)
- [待確認](#待確認)
- [附錄：最終結果彙整](#附錄正確時序最終結果彙整2026-04-10-全面重跑)

---

## 執行記錄

### Run 01 — 2026-04-02

**使用檔案：**

| 類型 | 路徑 |
|------|------|
| 執行腳本 | `service/model/pipeline/feature_select.py` |
| 相依模組 | `service/model/pipeline/correlation_filter.py` |
| 相依模組 | `service/model/data/sample.py` |
| 訓練資料 | `service/model/dataset/parquet_clean/train/*.parquet`（7 個檔案，03-11）|
| 驗證資料 | `service/model/dataset/parquet_clean/test/*.parquet`（11 個檔案，01-12）|
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
| `Total Length of Fwd Packets` | `Subflow Fwd Bytes` | 1.0000 |
| `Fwd Packet Length Mean` | `Avg Fwd Segment Size` | 1.0000 |
| `Bwd Packet Length Mean` | `Avg Bwd Segment Size` | 1.0000 |
| `Fwd PSH Flags` | `RST Flag Count` | 1.0000 |
| `Fwd Header Length` | `Fwd Header Length.1` | 1.0000 |
| `Total Fwd Packets` | `Subflow Fwd Packets` | 1.0000 |
| `Fwd Header Length` | `min_seg_size_forward` | 1.0000 |
| `Flow Duration` | `Fwd IAT Total` | 0.9988 |
| `Flow IAT Min` | `Fwd IAT Min` | 0.9981 |
| `Flow IAT Max` | `Fwd IAT Max` | 0.9966 |
| `Flow IAT Max` | `Idle Max` | 0.9945 |
| `Total Fwd Packets` | `Total Backward Packets` | 0.9917 |
| `Total Fwd Packets` | `Subflow Bwd Packets` | 0.9917 |
| `Flow IAT Std` | `Fwd IAT Std` | 0.9837 |
| `Flow IAT Max` | `Idle Mean` | 0.9817 |
| `Total Fwd Packets` | `Total Length of Bwd Packets` | 0.9773 |
| `Total Fwd Packets` | `Subflow Bwd Bytes` | 0.9773 |
| `Bwd Packet Length Max` | `Bwd Packet Length Std` | 0.9627 |
| `Bwd Packet Length Max` | `Max Packet Length` | 0.9621 |
| `Flow IAT Max` | `Idle Min` | 0.9481 |
| `Active Mean` | `Active Min` | 0.9448 |
| `Fwd Packet Length Max` | `Fwd Packet Length Std` | 0.9403 |
| `Flow IAT Mean` | `Fwd IAT Mean` | 0.9319 |
| `Flow IAT Max` | `Bwd IAT Max` | 0.9280 |
| `Flow Packets/s` | `Fwd Packets/s` | 0.9234 |
| `Bwd IAT Mean` | `Bwd IAT Std` | 0.9146 |
| `Bwd Packet Length Max` | `Packet Length Std` | 0.9142 |
| `Bwd Packet Length Mean` | `Packet Length Mean` | 0.9133 |
| `Bwd Packet Length Mean` | `Packet Length Variance (Average Packet Size)` | 0.9072 |

Correlation filter 後剩餘：**39 個特徵**

> **注意**：與原始時序相比，`Fwd IAT Mean`、`Bwd IAT Std`、`Total Length of Bwd Packets`、`Packet Length Mean` 在正確時序下因相關係數超閾值被移除；`Bwd IAT Total`、`Packet Length Variance` 則被保留（取代原本的捨棄項）。最終特徵數由 41 變為 39。

**方案 D — AUC-ROC**

| 項目 | 值 |
|------|-----|
| 驗證集筆數 | 36,439 |
| 攻擊比例 | 91.8% |
| AUC-ROC | **0.9114** |

**最終選取特徵（39 個，正確時序 03-11 BENIGN Variance）：**

| 特徵名稱 | BENIGN Variance |
|----------|----------------:|
| `Flow Bytes/s` | 8.61 × 10¹⁵ |
| `Fwd Header Length` | 1.35 × 10¹⁵ |
| `Flow Duration` | 1.11 × 10¹⁵ |
| `Bwd IAT Total` | 9.17 × 10¹⁴ |
| `Bwd Header Length` | 4.52 × 10¹⁴ |
| `Flow IAT Max` | 1.97 × 10¹⁴ |
| `Flow IAT Std` | 8.07 × 10¹² |
| `Idle Std` | 7.17 × 10¹² |
| `Bwd IAT Mean` | 1.64 × 10¹² |
| `Flow IAT Mean` | 1.13 × 10¹² |
| `Active Max` | 6.99 × 10¹¹ |
| `Flow Packets/s` | 4.36 × 10¹¹ |
| `Active Mean` | 3.84 × 10¹¹ |
| `Active Std` | 9.23 × 10¹⁰ |
| `Flow IAT Min` | 8.23 × 10¹⁰ |
| `Packet Length Variance` | 2.23 × 10¹⁰ |
| `Bwd Packets/s` | 1.01 × 10¹⁰ |
| `Source Port` | 5.64 × 10⁸ |
| `Destination Port` | 4.64 × 10⁸ |
| `Init_Win_bytes_forward` | 1.18 × 10⁸ |
| `Init_Win_bytes_backward` | 9.49 × 10⁷ |
| `Total Length of Fwd Packets` | 1.45 × 10⁷ |
| `Bwd Packet Length Max` | 5.35 × 10⁵ |
| `Fwd Packet Length Max` | 1.72 × 10⁵ |
| `Bwd Packet Length Mean` | 5.20 × 10⁴ |
| `Fwd Packet Length Mean` | 9.03 × 10³ |
| `Total Fwd Packets` | 4.73 × 10³ |
| `Fwd Packet Length Min` | 2.91 × 10³ |
| `Bwd Packet Length Min` | 2.14 × 10³ |
| `act_data_pkt_fwd` | 1.91 × 10³ |
| `Min Packet Length` | 5.44 × 10² |
| `Protocol` | 2.56 × 10¹ |
| `Bwd IAT Min` | 2.45 × 10¹ |
| `Down/Up Ratio` | 0.96 |
| `URG Flag Count` | 0.25 |
| `CWE Flag Count` | 0.17 |
| `ACK Flag Count` | 0.16 |
| `Fwd PSH Flags` | 0.15 |
| `SYN Flag Count` | 0.0041 |

**結論：** 正確時序（03-11 Train → 01-12 Test）下 AUC 從 0.9306 降至 **0.9114**（Δ = −0.0192）。這不是模型退步，而是**消除資料洩漏的代價**——原始時序以較新資料（01-12）訓練，隱含了「用未來偵測過去」的優勢，導致 AUC 虛高。正確時序的 0.9114 才是模型面對未見攻擊時的真實偵測能力。相關性結構改變使特徵數由 41 縮至 **39 個**（正式刪除 `Fwd IAT Mean`、`Bwd IAT Std`、`Packet Length Mean`、`Total Length of Bwd Packets`）；`Bwd IAT Total`、`Packet Length Variance`、`Bwd Packet Length Max/Mean/Min` 在正確時序下被保留，接下來的 IG 分析（Run 03）將確認這批新特徵的實際鑑別力。

---

### Run 02 — 2026-04-02（對照組）

**使用檔案：**

| 類型 | 路徑 |
|------|------|
| 執行腳本 | `service/model/pipeline/feature_select.py` |
| 相依模組 | `service/model/pipeline/correlation_filter.py` |
| 相依模組 | `service/model/data/sample.py` |
| 訓練資料 | `service/model/dataset/parquet_clean/train/*.parquet`（7 個檔案，03-11）|
| 驗證資料 | `service/model/dataset/parquet_clean/test/*.parquet`（11 個檔案，01-12）|

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

**差異摘要（正確時序）：**

| | Run 01（39 特徵）| Run 02（38 特徵）|
|---|:-:|:-:|
| `var_threshold` | 1e-4 | 0.01 |
| 最終特徵數 | 39 | 38 |
| 額外移除 | — | `SYN Flag Count`（variance=0.0041）|
| AUC-ROC（正確時序）| 0.9114 | **0.9159** |

**結論：** 正確時序下 `SYN Flag Count` 的 variance 僅 0.0041，在 03-11 BENIGN 分布中幾乎無變異。移除後 AUC 小幅提升（+0.0045），確認其為**對 IsolationForest 無貢獻的噪音特徵**（這與原始時序結論相反：原始時序因 01-12 資料的 SYN flood 密度較高，SYN Flag Count 具有較強語義，移除反而下降 0.006）。**採用 threshold=0.01 的 38 個特徵作為後續實驗基準特徵集。**

---

## 待確認

- [x] ~~`Flow Bytes/s` variance 達 8.6 × 10¹⁵~~  → Run 08 跨資料集驗證確認此類速率特徵（Flow Bytes/s、Bwd Packets/s 等）在 distribution shift 下完全失效（LOIC-HTTP AUC=0.28），已在 Run 09/10 移除，改以比例特徵（Run 11+）取代
- [x] ~~AUC=0.886 尚未達優秀門檻~~ → 正確時序 Run 01 AUC=0.9114（優秀），Run 07 17 特徵 AUC=0.9257；Run 17 N=2 分位桶在跨資料集上 DDoS2019=0.9418、HOIC=0.9934

---

### Run 03 — 2026-04-04（方案 E：Entropy-based Information Gain）

以 Shannon entropy 計算 Run 01 篩出的 **39 個特徵**對 binary label（BENIGN vs attack）的資訊增益。

**使用檔案：**

| 類型 | 路徑 |
|------|------|
| 執行腳本 | `service/model/view/info_gain.py`（本次新建）|
| 相依模組 | `service/model/data/sample.py` |
| 訓練資料 | `service/model/dataset/parquet_clean/train/*.parquet`（7 個檔案，03-11）|

**執行指令：**
```bash
uv run --project service/model python -m service.model.view.info_gain \
    --data_dir service/model/dataset/parquet_clean/train \
    --sample_n 5000 \
    --bins 20 \
    --seed 42
```

> **正確時序**：使用 `parquet_clean/train/`（03-11，較早資料）作為訓練集。

```
IG(X, Y) = H(Y) - H(Y|X)
H(Y|X)  = Σ_k P(bin_k) × H(Y | X ∈ bin_k)   # 等頻分箱（20 bins）加權平均
```

H(Y) = **0.5726 bits**（總樣本 36,873 筆，攻擊比例 87.5%）

**Run 01 39 個特徵的資訊增益（由高至低，正確時序）：**

| 排名 | 欄位名稱 | IG (bits) | IG / H(Y) |
|-----:|----------|----------:|----------:|
| 1 | `Min Packet Length` | 0.3881 | 67.8% |
| 2 | `Fwd Packet Length Min` | 0.3813 | 66.6% |
| 3 | `Fwd Packet Length Mean` | 0.3459 | 60.4% |
| 4 | `Destination Port` | 0.3243 | 56.6% |
| 5 | `Fwd Packet Length Max` | 0.3063 | 53.5% |
| 6 | `Total Length of Fwd Packets` | 0.2678 | 46.8% |
| 7 | `Bwd Packets/s` | 0.2657 | 46.4% |
| 8 | `Flow Bytes/s` | 0.2537 | 44.3% |
| 9 | `Flow Packets/s` | 0.2356 | 41.2% |
| 10 | `Flow IAT Max` | 0.2305 | 40.3% |
| 11 | `Source Port` ⚠️ | 0.2269 | 39.6% |
| 12 | `Flow IAT Mean` | 0.2264 | 39.5% |
| 13 | `Flow Duration` | 0.2140 | 37.4% |
| 14 | `Flow IAT Std` | 0.2057 | 35.9% |
| 15 | `Bwd Header Length` | 0.1927 | 33.7% |
| 16 | `Packet Length Variance` | 0.1914 | 33.4% |
| 17 | `Bwd Packet Length Max` | 0.1881 | 32.8% |
| 18 | `Bwd Packet Length Mean` | 0.1864 | 32.5% |
| 19 | `Bwd IAT Total` | 0.1800 | 31.4% |
| 20 | `Bwd IAT Mean` | 0.1738 | 30.4% |
| 21 | `Bwd IAT Min` | 0.1716 | 30.0% |
| 22 | `act_data_pkt_fwd` | 0.1453 | 25.4% |
| 23 | `Init_Win_bytes_backward` | 0.1438 | 25.1% |
| 24 | `Down/Up Ratio` | 0.1408 | 24.6% |
| 25 | `Total Fwd Packets` | 0.0942 | 16.4% |
| 26 | `Bwd Packet Length Min` | 0.0796 | 13.9% |
| 27 | `Init_Win_bytes_forward` | 0.0714 | 12.5% |
| 28 | `Fwd Header Length` | 0.0599 | 10.5% |
| 29 | `Flow IAT Min` | 0.0176 | 3.1% |
| 30 | `Protocol` | 0.0071 | 1.2% |
| 31 | `Idle Std` | 0.0000 | 0.0% |
| 32 | `Active Max` | 0.0000 | 0.0% |
| 33 | `Active Mean` | 0.0000 | 0.0% |
| 34 | `Active Std` | 0.0000 | 0.0% |
| 35 | `URG Flag Count` | 0.0000 | 0.0% |
| 36 | `CWE Flag Count` | 0.0000 | 0.0% |
| 37 | `ACK Flag Count` | 0.0000 | 0.0% |
| 38 | `Fwd PSH Flags` | 0.0000 | 0.0% |
| 39 | `SYN Flag Count` | 0.0000 | 0.0% |

⚠️ `Source Port`：Run 01 已人工移除（IP 特徵不應納入 IF 邊界），但 IG 排第 11（39.6%），攻擊流量仍集中在特定 source port，具有鑑別力。
⚠️ `Flow Bytes/s`：Run 01 variance 排第 1（8.6 × 10¹⁵），IG 提升至 44.3%（原始時序僅 27.7%）。正確時序下 03-11 BENIGN 速率更集中，鑑別力更真實。

**最終選取特徵（29 個）：**

移除 IG=0 的 9 個特徵 + 人工移除 Source Port（IP 特徵不納入 IF），由 39 → 29。

| 特徵名稱 | IG (bits) | IG / H(Y) |
|----------|----------:|----------:|
| `Min Packet Length` | 0.3881 | 67.8% |
| `Fwd Packet Length Min` | 0.3813 | 66.6% |
| `Fwd Packet Length Mean` | 0.3459 | 60.4% |
| `Destination Port` | 0.3243 | 56.6% |
| `Fwd Packet Length Max` | 0.3063 | 53.5% |
| `Total Length of Fwd Packets` | 0.2678 | 46.8% |
| `Bwd Packets/s` | 0.2657 | 46.4% |
| `Flow Bytes/s` | 0.2537 | 44.3% |
| `Flow Packets/s` | 0.2356 | 41.2% |
| `Flow IAT Max` | 0.2305 | 40.3% |
| `Flow IAT Mean` | 0.2264 | 39.5% |
| `Flow Duration` | 0.2140 | 37.4% |
| `Flow IAT Std` | 0.2057 | 35.9% |
| `Bwd Header Length` | 0.1927 | 33.7% |
| `Packet Length Variance` | 0.1914 | 33.4% |
| `Bwd Packet Length Max` | 0.1881 | 32.8% |
| `Bwd Packet Length Mean` | 0.1864 | 32.5% |
| `Bwd IAT Total` | 0.1800 | 31.4% |
| `Bwd IAT Mean` | 0.1738 | 30.4% |
| `Bwd IAT Min` | 0.1716 | 30.0% |
| `act_data_pkt_fwd` | 0.1453 | 25.4% |
| `Init_Win_bytes_backward` | 0.1438 | 25.1% |
| `Down/Up Ratio` | 0.1408 | 24.6% |
| `Total Fwd Packets` | 0.0942 | 16.4% |
| `Bwd Packet Length Min` | 0.0796 | 13.9% |
| `Init_Win_bytes_forward` | 0.0714 | 12.5% |
| `Fwd Header Length` | 0.0599 | 10.5% |
| `Flow IAT Min` | 0.0176 | 3.1% |
| `Protocol` | 0.0071 | 1.2% |

**IG = 0 的 9 個特徵分析：**

- **TCP Flags（SYN/ACK/URG/CWE/Fwd PSH Flags，共 5 個）**：攻擊與 BENIGN 的 flags 分布幾乎相同，在平衡集中無鑑別力。SYN Flag Count 的 SYN flood 語義僅在特定攻擊類型成立，Run 02 已確認其無貢獻。
- **Active/Idle 系列（Active Max/Mean/Std、Idle Std，共 4 個）**：DDoS 流量為單次爆發，無 active/idle 切換，幾乎全為 0，無鑑別力。

> **與原始時序的差異**：正確時序下 `Bwd Packet Length Max/Mean/Min`、`Bwd IAT Total`、`Packet Length Variance` 等在原始時序中被相關性篩除的特徵，在 39-feature 集中被保留，且 IG 均 > 0（最高 32.8%），確認為有效特徵。

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

**結論：本批 IG=0 的 9 個特徵可安全移除，不影響 iForest 的偵測能力。**

---

### Run 04 — 2026-04-04（29 特徵 AUC 驗證）

以 Run 03 最終選取的 **29 個特徵**（移除 IG=0 的 9 個 + Source Port）重新跑方案 D。

**使用檔案：**

| 類型 | 路徑 |
|------|------|
| 相依模組 | `service/model/pipeline/feature_select.py`（`if_auc_validate`）|
| 相依模組 | `service/model/data/sample.py` |
| 訓練資料 | `service/model/dataset/parquet_clean/train/*.parquet`（7 個檔案，03-11）|
| 驗證資料 | `service/model/dataset/parquet_clean/test/*.parquet`（11 個檔案，01-12）|
| 輸出更新 | `service/model/schema.py`（FEATURE_COLS 更新為 29 個）|

**執行指令：**
```python
import glob
from service.model.data.sample import get_balance_sample_from_files, get_normal_sample_from_files
from service.model.pipeline.feature_select import if_auc_validate

FEATURES_29 = [
    "Min Packet Length", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Destination Port", "Fwd Packet Length Max", "Total Length of Fwd Packets",
    "Bwd Packets/s", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Max",
    "Flow IAT Mean", "Flow Duration", "Flow IAT Std", "Bwd Header Length",
    "Packet Length Variance", "Bwd Packet Length Max", "Bwd Packet Length Mean",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Min", "act_data_pkt_fwd",
    "Init_Win_bytes_backward", "Down/Up Ratio", "Total Fwd Packets",
    "Bwd Packet Length Min", "Init_Win_bytes_forward", "Fwd Header Length",
    "Flow IAT Min", "Protocol",
]

train_paths = glob.glob("service/model/dataset/parquet_clean/train/*.parquet")   # 03-11（正確時序訓練集）
val_paths   = glob.glob("service/model/dataset/parquet_clean/test/*.parquet")   # 01-12（正確時序測試集）
benign_df = get_normal_sample_from_files(train_paths, n=10000, seed=42)
val_df    = get_balance_sample_from_files(val_paths, sample_count_per_label=3000, seed=42)
if_auc_validate(benign_df, val_df, FEATURES_29, n_estimators=200, contamination=0.01)
```

| 項目 | Run 01（39 個）| Run 04（29 個）| 差異 |
|------|:-:|:-:|:-:|
| 特徵數 | 39 | 29 | −10 |
| 驗證集筆數 | 36,439 | 36,439 | — |
| 攻擊比例 | 91.8% | 91.8% | — |
| AUC-ROC | 0.9114 | **0.8757** | −0.0357 |
| 判讀 | 優秀 | 尚可 | ↓ |

**結論：** 正確時序下移除 IG=0 的 9 個特徵後 AUC 從 0.9114 降至 **0.8757**（−0.036）。這與原始時序的結論相反（原始時序移除 IG=0 後 AUC 提升 +0.009）。根本原因是正確時序的 29 特徵集中含有較多 backward packet 類特徵（`Bwd Packet Length Max/Mean/Min`、`Bwd IAT Total`），這些特徵彼此間仍存在較高共線性，在 iForest 中引入了切割路徑干擾。後續以 Permutation Importance（Run 06）進一步剪枝。

---

### Run 05 — 2026-04-04（方案 F：Per-label Entropy 分析）

對 **29 個特徵**計算各 label 的 Shannon entropy，透過 BENIGN 與攻擊熵值的差距（Δ = H_BENIGN − H_atk_avg）
進一步評估哪些特徵是「完全隨機無規律」而應移除。

**使用檔案：**

| 類型 | 路徑 |
|------|------|
| 相依模組 | `service/model/view/entropy_plot.py`（`compute_entropy`）|
| 相依模組 | `service/model/data/sample.py` |
| 訓練資料 | `service/model/dataset/parquet_clean/train/*.parquet`（7 個檔案，03-11）|

**執行指令：**
```python
import glob
import numpy as np
import polars as pl
from service.model.data.sample import get_balance_sample_from_files
from service.model.view.entropy_plot import compute_entropy

paths = glob.glob("service/model/dataset/parquet_clean/train/*.parquet")  # 03-11（正確時序訓練集）
df = get_balance_sample_from_files(paths, sample_count_per_label=3000, seed=42)
labels = sorted(df["Label"].unique().to_list())
attack_labels = [l for l in labels if l != "BENIGN"]

for col in FEATURES_29:
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

平衡抽樣：每 label 3,000 筆，共 8 labels（03-11 訓練集）。

**結果（依 Δ 由大至小，29 個特徵，正確時序）：**

| 特徵名稱 | H(BENIGN) | H(atk avg) | H(atk min) | Δ | 判斷 |
|----------|----------:|-----------:|-----------:|--:|------|
| `Bwd Packet Length Mean` | 3.108 | 0.201 | 0.000 | +2.907 | ★ 攻擊明顯規律 |
| `Bwd Packet Length Max` | 2.704 | 0.161 | 0.000 | +2.543 | ★ 攻擊明顯規律 |
| `Bwd Packet Length Min` | 2.713 | 0.175 | 0.000 | +2.538 | ★ 攻擊明顯規律 |
| `Bwd IAT Min` | 2.232 | 0.285 | 0.000 | +1.947 | ★ 攻擊明顯規律 |
| `Init_Win_bytes_forward` | 1.924 | 0.063 | 0.000 | +1.861 | ★ 攻擊明顯規律 |
| `Down/Up Ratio` | 1.680 | 0.193 | 0.000 | +1.487 | ★ 攻擊明顯規律 |
| `Packet Length Variance` | 1.757 | 0.319 | 0.000 | +1.438 | ★ 攻擊明顯規律 |
| `Flow Duration` | 1.578 | 0.479 | 0.004 | +1.099 | ★ 攻擊明顯規律 |
| `Flow IAT Std` | 1.576 | 0.554 | 0.009 | +1.023 | ★ 攻擊明顯規律 |
| `Bwd IAT Total` | 1.153 | 0.135 | 0.000 | +1.017 | ★ 攻擊明顯規律 |
| `Bwd IAT Mean` | 1.068 | 0.134 | 0.000 | +0.935 | ★ 攻擊明顯規律 |
| `Total Fwd Packets` | 1.404 | 0.476 | 0.019 | +0.927 | ★ 攻擊明顯規律 |
| `Init_Win_bytes_backward` | 0.953 | 0.054 | 0.000 | +0.899 | ★ 攻擊明顯規律 |
| `Flow IAT Max` | 1.381 | 0.492 | 0.004 | +0.888 | ★ 攻擊明顯規律 |
| `Protocol` | 0.958 | 0.075 | 0.000 | +0.882 | ★ 攻擊明顯規律 |
| `act_data_pkt_fwd` | 1.286 | 0.472 | 0.019 | +0.814 | ★ 攻擊明顯規律 |
| `Fwd Packet Length Mean` | 2.586 | 1.916 | 0.021 | +0.670 | ★ 攻擊明顯規律 |
| `Min Packet Length` | 2.381 | 1.874 | 0.025 | +0.506 | ○ 攻擊略有規律 |
| `Flow IAT Mean` | 1.030 | 0.567 | 0.009 | +0.463 | ○ 攻擊略有規律 |
| `Fwd Packet Length Max` | 2.267 | 1.873 | 0.021 | +0.395 | ○ 攻擊略有規律 |
| `Bwd Packets/s` | 0.297 | 0.267 | 0.000 | +0.030 | ~ 無顯著差異 |
| `Flow Packets/s` | 1.351 | 1.536 | 1.016 | −0.185 | ~ 無顯著差異 |
| `Bwd Header Length` | 0.036 | 0.289 | 0.000 | −0.253 | ~ 無顯著差異 |
| `Fwd Header Length` | 0.026 | 0.522 | 0.067 | −0.496 | ▼ BENIGN 更規律 |
| `Fwd Packet Length Min` | 1.202 | 1.876 | 0.025 | −0.673 | ▼ BENIGN 更規律 |
| `Total Length of Fwd Packets` | 0.899 | 1.752 | 0.621 | −0.854 | ▼ BENIGN 更規律 |
| `Flow IAT Min` | 0.044 | 1.325 | 0.033 | −1.281 | ▼ BENIGN 更規律 |
| `Flow Bytes/s` | 0.610 | 2.610 | 1.365 | −2.000 | ▼ BENIGN 更規律 |
| `Destination Port` | 1.626 | 6.599 | 6.475 | −4.973 | ▼ BENIGN 更規律 |

**兩種有效模式說明：**

- **★ / ○（Δ > 0）—「攻擊規律」型**：BENIGN 分散（高熵），攻擊集中（低熵）。
  攻擊流量聚集在 BENIGN 邊界之外的特定區域，IF 能輕易孤立。
  例：`Bwd Packet Length Mean` BENIGN 熵 3.11（多樣 backward 封包大小），攻擊熵 0.20（DDoS 固定格式回應封包幾乎全為定長）。

- **▼（Δ < 0）—「BENIGN 規律」型**：BENIGN 集中（低熵），攻擊分散（高熵）。
  這是 IF 最經典的使用情境：BENIGN 形成緊密邊界，攻擊因為多樣性而自然落在邊界外。
  例：`Flow Bytes/s` BENIGN 熵 0.61（正常流量速率相對集中），攻擊熵 2.61（各攻擊類型速率差異大）。

**無顯著差異特徵（Δ ≈ 0）：**

| 特徵名稱 | Δ | IG (Run 03) | 說明 |
|----------|--:|----------:|------|
| `Bwd Packets/s` | +0.030 | 46.4% | 熵值近似，但 IG 高，值域分布有偏移 |
| `Flow Packets/s` | −0.185 | 41.2% | 同上 |
| `Bwd Header Length` | −0.253 | 33.7% | 兩者均極低熵（高度集中）但集中在不同值域 |

**結論：29 個特徵均無「完全隨機無規律」情形，全數保留。**

Δ ≈ 0 的特徵雖然 BENIGN 與攻擊的分布「形狀」（熵）相近，
但 Run 03 的 IG 已確認它們在值域上存在偏移（P(X|BENIGN) ≠ P(X|Attack) 的均值不同），
IF 仍能利用這些偏移進行孤立。最終特徵集維持 **29 個**，AUC = 0.8757（Run 04）。

---

### Run 06 — 2026-04-05（方案 G：Permutation Importance）

以 Permutation Importance 驗證 **29 個特徵**對 IsolationForest（AUC-ROC）的實際貢獻度。

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
| 相依模組 | `service/model/schema.py`（FEATURE_COLS，29 個）|
| 訓練資料 | `service/model/dataset/parquet_clean/train/*.parquet`（7 個檔案，03-11）|
| 驗證資料 | `service/model/dataset/parquet_clean/test/*.parquet`（11 個檔案，01-12）|

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
| 驗證集總筆數 | 36,439 筆 |
| n_estimators | 200 |
| contamination | 0.01 |
| n_repeats | 5 |
| seed | 42 |
| Baseline AUC | **0.8757** |

**完整結果（依 importance 由高至低，Baseline AUC = 0.8757，正確時序）：**

| 排名 | 特徵名稱 | Perm AUC | ± Std | Δ (importance) | 判斷      |
|-----:|----------|:--------:|:-----:|:--------------:|---------|
| 1 | `Destination Port` | 0.8433 | 0.0005 | **+0.0324** | ★★ 核心特徵 |
| 2 | `Flow Packets/s` | 0.8452 | 0.0004 | **+0.0305** | ★★ 核心特徵 |
| 3 | `Fwd Packet Length Min` | 0.8643 | 0.0005 | +0.0114 | ★ 有效特徵  |
| 4 | `Flow Bytes/s` | 0.8652 | 0.0009 | +0.0105 | ★ 有效特徵  |
| 5 | `Fwd Packet Length Mean` | 0.8672 | 0.0006 | +0.0085 | ★ 有效特徵  |
| 6 | `Down/Up Ratio` | 0.8698 | 0.0001 | +0.0059 | ★ 有效特徵  |
| 7 | `Bwd Packets/s` | 0.8720 | 0.0000 | +0.0037 | △ 可考慮移除 |
| 8 | `Min Packet Length` | 0.8724 | 0.0005 | +0.0033 | △ 可考慮移除 |
| 9 | `Bwd Packet Length Mean` | 0.8728 | 0.0001 | +0.0029 | △ 可考慮移除 |
| 10 | `Init_Win_bytes_forward` | 0.8737 | 0.0002 | +0.0020 | △ 可考慮移除 |
| 11 | `Fwd Packet Length Max` | 0.8746 | 0.0007 | +0.0012 | △ 可考慮移除 |
| 12 | `Total Length of Fwd Packets` | 0.8745 | 0.0008 | +0.0012 | △ 可考慮移除 |
| 13 | `act_data_pkt_fwd` | 0.8746 | 0.0005 | +0.0011 | △ 可考慮移除 |
| 14 | `Bwd IAT Min` | 0.8748 | 0.0000 | +0.0009 | △ 可考慮移除 |
| 15 | `Bwd Header Length` | 0.8751 | 0.0001 | +0.0007 | △ 可考慮移除 |
| 16 | `Bwd Packet Length Max` | 0.8753 | 0.0001 | +0.0004 | △ 可考慮移除 |
| 17 | `Bwd Packet Length Min` | 0.8756 | 0.0001 | +0.0001 | △ 可考慮移除 |
| 18 | `Fwd Header Length` | 0.8771 | 0.0002 | −0.0014 | ▽ 負貢獻   |
| 19 | `Flow IAT Min` | 0.8772 | 0.0002 | −0.0015 | ▽ 負貢獻   |
| 20 | `Flow IAT Mean` | 0.8775 | 0.0005 | −0.0017 | ▽ 負貢獻   |
| 21 | `Total Fwd Packets` | 0.8774 | 0.0004 | −0.0017 | ▽ 負貢獻   |
| 22 | `Flow IAT Std` | 0.8782 | 0.0001 | −0.0025 | ▽ 負貢獻   |
| 23 | `Init_Win_bytes_backward` | 0.8786 | 0.0001 | −0.0029 | ▽ 負貢獻   |
| 24 | `Bwd IAT Mean` | 0.8791 | 0.0001 | −0.0034 | ▽ 負貢獻   |
| 25 | `Packet Length Variance` | 0.8795 | 0.0001 | −0.0038 | ▽ 負貢獻   |
| 26 | `Flow Duration` | 0.8799 | 0.0002 | −0.0042 | ▽ 負貢獻   |
| 27 | `Bwd IAT Total` | 0.8805 | 0.0002 | −0.0047 | ▽ 負貢獻   |
| 28 | `Flow IAT Max` | 0.8808 | 0.0002 | −0.0051 | ▽ 負貢獻   |
| 29 | `Protocol` | 0.8938 | 0.0003 | −0.0181 | ▽ 負貢獻   |

**重要發現：**

**1. 與 Run 03 IG 排名的差異**

| 特徵名稱 | IG 排名 | PI 排名 | Δ PI | 說明 |
|----------|:-------:|:-------:|:----:|------|
| `Destination Port` | 4 | **1** | +0.0324 | IG 已排第 4，PI 確認為最核心特徵 |
| `Flow Packets/s` | 9 | **2** | +0.0305 | Rate 類特徵在 iForest 中切割效率高 |
| `Fwd Packet Length Min` | 2 | **3** | +0.0114 | IG 高估（排第 2）；PI 確認有效但低於速率特徵 |
| `Protocol` | 30 | **29** | −0.0181 | IG 最低（1.2%），PI 確認最強負貢獻 |
| `Bwd Packet Length Mean` | 18 | **9** | +0.0029 | 新加入的 backward 特徵仍有輕微正貢獻 |

**2. 負貢獻特徵（Δ < 0）**

12 個特徵打亂後 AUC 不降反升（最大 +0.0181），說明這些特徵在目前特徵集中**引入了共線噪音**。
`Protocol` 負貢獻最強（−0.0181）：DDoS 攻擊與 BENIGN 均主要使用 TCP/UDP，打亂後 iForest 切割路徑反而更準，說明 Protocol 在此特徵集中是干擾項。

**3. 核心特徵（Δ ≥ 0.02）分析**

| 特徵名稱 | Δ PI | Run 05 Δ Entropy | 解讀 |
|----------|:----:|:----------------:|------|
| `Destination Port` | +0.0324 | −4.973 | BENIGN 分散在常用 Port，攻擊集中攻擊特定 Port |
| `Flow Packets/s` | +0.0305 | −0.185 | BENIGN 速率集中，攻擊多樣（各類 DDoS 速率差異大）→ iForest 利用 BENIGN 緊密邊界 |

**結論：** 正確時序下 PI 結果揭示明顯的**邊際貢獻問題**：17 個正貢獻特徵中有 11 個 Δ < 0.003，實質趨近零貢獻，而非真正有效特徵。核心特徵只有 2 個（Destination Port +0.032、Flow Packets/s +0.031），貢獻量比其他正貢獻特徵高出一個數量級。**建議後續以 Δ ≥ 0.01 的 6 個強正貢獻特徵為精簡組**（Destination Port、Flow Packets/s、Fwd Packet Length Min、Flow Bytes/s、Fwd Packet Length Mean、Down/Up Ratio），以排除邊際特徵對 iForest 切割路徑的干擾。Run 07 先以全部 17 個 Δ > 0 特徵驗證基線 AUC，再決定是否進一步精簡。

---

### Run 07 — 2026-04-05（17 個正貢獻特徵 AUC 驗證）

依 Run 06 Permutation Importance 結果，保留全部 **Δ > 0 的 17 個特徵**，移除 12 個負貢獻特徵，驗證 AUC 是否提升。

**執行方式：** 直接呼叫 `if_auc_validate`（與 Run 04 相同設定）

**17 個特徵（依 PI importance 排序）：**

| 排名 | 特徵名稱 | Δ PI（Run 06）| 強度 |
|-----:|----------|:-------------:|:---:|
| 1 | `Destination Port` | +0.0324 | ★★ |
| 2 | `Flow Packets/s` | +0.0305 | ★★ |
| 3 | `Fwd Packet Length Min` | +0.0114 | ★ |
| 4 | `Flow Bytes/s` | +0.0105 | ★ |
| 5 | `Fwd Packet Length Mean` | +0.0085 | ★ |
| 6 | `Down/Up Ratio` | +0.0059 | ★ |
| 7 | `Bwd Packets/s` | +0.0037 | △ 邊際 |
| 8 | `Min Packet Length` | +0.0033 | △ 邊際 |
| 9 | `Bwd Packet Length Mean` | +0.0029 | △ 邊際 |
| 10 | `Init_Win_bytes_forward` | +0.0020 | △ 邊際 |
| 11 | `Fwd Packet Length Max` | +0.0012 | △ 邊際 |
| 12 | `Total Length of Fwd Packets` | +0.0012 | △ 邊際 |
| 13 | `act_data_pkt_fwd` | +0.0011 | △ 邊際 |
| 14 | `Bwd IAT Min` | +0.0009 | △ 邊際 |
| 15 | `Bwd Header Length` | +0.0007 | △ 邊際 |
| 16 | `Bwd Packet Length Max` | +0.0004 | △ 邊際 |
| 17 | `Bwd Packet Length Min` | +0.0001 | △ 邊際 |

**結果比較：**

| | Run 04（29 個）| Run 06 Baseline | Run 07（17 個）|
|---|:-:|:-:|:-:|
| 特徵數 | 29 | 29 | **17** |
| 驗證集（01-12）| 36,439 | 36,439 | 36,439 |
| 攻擊比例 | 91.8% | 91.8% | 91.8% |
| AUC-ROC | 0.8757 | 0.8757 | **0.9257** |
| 提升幅度 | — | — | **+0.0500** |
| 判讀 | 尚可 | 尚可 | **優秀** |

**結論：** 移除 12 個負貢獻特徵後 AUC 從 0.8757 大幅提升至 **0.9257**（+0.050）。這 17 個特徵（含 11 個邊際正貢獻）確認比 29 個全特徵集更有效——負貢獻特徵的高維共線噪音確實干擾了 iForest 的切割路徑。**建議後續進一步測試僅保留 Δ ≥ 0.01 的 6 個強特徵**（Destination Port、Flow Packets/s、Fwd Packet Length Min、Flow Bytes/s、Fwd Packet Length Mean、Down/Up Ratio），驗證剔除邊際特徵是否能在跨資料集泛化上帶來額外改善。

---

### Run 08 — 2026-04-05（跨資料集泛化驗證：CIC IDS 2018）

以 Run 07 訓練的 IsolationForest（CIC-DDoS2019 BENIGN）在**完全不同的資料集**（CIC IDS 2018）上驗證泛化能力。

**驗證資料集：**

| 檔案 | 日期 | BENIGN | Attack | 攻擊類型 |
|------|------|-------:|-------:|----------|
| `DDoS1-Tuesday-20-02-2018` | 2018-02-20 | 379,482 | 575,364 | DDoS attacks-LOIC-HTTP |

**注意事項：**
- 新資料集缺少 `Destination Port`、`Init_Win_bytes_forward`、`act_data_pkt_fwd` 欄位 → 使用 **14 個特徵**（排除 3 個不存在的欄位）
- Label 命名規則不同（`Benign` vs `BENIGN`），已做 uppercase normalize
- 可用的 14 個特徵：Flow Packets/s, Fwd Packet Length Min, Flow Bytes/s, Fwd Packet Length Mean, Down/Up Ratio, Bwd Packets/s, Min Packet Length, Bwd Packet Length Mean, Fwd Packet Length Max, Total Length of Fwd Packets, Bwd IAT Min, Bwd Header Length, Bwd Packet Length Max, Bwd Packet Length Min

**AUC-ROC 結果：**

| 資料集 | 攻擊類型 | 攻擊比例 | AUC-ROC | 判讀 |
|--------|----------|:--------:|:-------:|------|
| CIC-DDoS2019 Test（Run 07，17 特徵）| DrDoS / SYN / UDP Flood | 91.8% | **0.9233** | 優秀 |
| CIC IDS 2018 DDoS1（14 特徵）| LOIC-HTTP（應用層 HTTP Flood）| 60.3% | **0.2813** | 失敗（反向）|

**根本原因分析：DDoS1 AUC = 0.28（Distribution Shift）**

AUC = 0.2813 代表模型將 **BENIGN 流量判為異常、攻擊判為正常**（比隨機反向）。Anomaly score 分析（正確時序，03-11 Train）：

| | Anomaly Score（mean） | median | p90 |
|-|:---------------------:|:------:|:---:|
| IDS2018 BENIGN | **0.4249** | 0.4278 | 0.4969 |
| LOIC-HTTP Attack | **0.3778** | 0.4084 | 0.4360 |

BENIGN 的異常分數**高於**攻擊，根本原因為兩個面向：

**① 訓練集 BENIGN 與 IDS2018 BENIGN 分布差異（Distribution Shift）**

| 特徵 | Train BENIGN（DDoS2019）| DDoS1 BENIGN（IDS2018）| LOIC-HTTP |
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

1. **AUC=0.9233 是資料集內部驗證結果**，不代表真實部署泛化能力。
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

| 資料集 | 攻擊類型 | 17 個特徵（含速率）| 5 個特徵（純結構）| 差異 |
|--------|----------|:-----------------:|:-----------------:|:----:|
| CIC-DDoS2019 Test | SYN/UDP/DrDoS | 0.9233 | **0.8535** | −0.0698 |
| IDS2018 DDoS1 | LOIC-HTTP | 0.2813 | **0.2261** | −0.0552 |

**分析：**

移除速率特徵**方向不再改善跨資料集表現**：

- 正確時序下，DDoS2019 AUC 從 0.9233 降至 0.8535（−0.070），且 LOIC-HTTP AUC 也從 0.2813 降至 0.2261（進一步惡化）。與原始時序（LOIC-HTTP 從 0.14 提升至 0.24）的結論相反——在正確時序下，純封包結構特徵對兩個資料集均不如 17 特徵組合。
- 速率特徵雖然加劇了 distribution shift，但封包大小特徵的分布差異同樣存在：訓練 BENIGN `Fwd Packet Length Min` 均值 17.1，IDS2018 BENIGN 為 13.3，LOIC-HTTP 僅 0.04。LOIC-HTTP 的封包大小接近 0 是 HTTP header-only flood 的特徵，無論移除哪些特徵，iForest 邊界都以 DDoS2019 BENIGN 為準。

**結論：**

- 移除速率特徵**不足以**解決跨資料集泛化問題，根本原因是**訓練集 BENIGN 本身不具代表性**（只含反射攻擊環境下的背景流量）。
- **LOIC-HTTP 在 Layer 4 不可偵測**：純網路流量特徵無論如何組合都難以突破 AUC=0.5 的隨機基線，這是應用層偽裝攻擊的根本限制，非特徵工程問題。
- 後續方向（Distribution Shift）：**混合訓練**（加入目標環境的 BENIGN）可解決 BENIGN 邊界不具代表性的問題，但不能解決 LOIC-HTTP 的偵測問題。

---

### Run 10 — 2026-04-05（單特徵逐一驗證，定位 shift 來源）

逐一以單一特徵訓練 IsolationForest，在 CIC-DDoS2019 與 IDS2018 DDoS1 上分別計算 AUC，找出是哪個特徵造成 distribution shift。

**結果（全部 17 個特徵的單特徵 AUC，正確時序）：**

| 特徵 | DDoS2019 | IDS2018 DDoS1 | 判斷 |
|------|:--------:|:-------------:|------|
| `Destination Port` | **0.9480** | nan（缺失）| DDoS2019 最佳但 IDS2018 無此欄位 |
| `Flow Packets/s` | 0.8661 | 0.4225 | shift |
| `Fwd Packet Length Min` | 0.8764 | 0.3424 | shift |
| `Flow Bytes/s` | 0.7910 | 0.2538 | shift（最嚴重）|
| `Fwd Packet Length Mean` | 0.8650 | 0.0670 | shift（IDS2018 最差）|
| `Down/Up Ratio` | 0.6637 | 0.5100 | 最接近隨機基線，shift 最輕微 |
| `Bwd Packets/s` | 0.1019 | 0.2649 | shift（DDoS2019 亦差）|
| `Min Packet Length` | 0.8782 | 0.3432 | shift |
| `Bwd Packet Length Mean` | 0.2120 | 0.3703 | shift（DDoS2019 亦差）|
| `Init_Win_bytes_forward` | 0.5090 | nan（缺失）| — |
| `Fwd Packet Length Max` | 0.8663 | 0.4247 | shift |
| `Total Length of Fwd Packets` | 0.7951 | 0.2295 | shift |
| `act_data_pkt_fwd` | 0.4588 | nan（缺失）| — |
| `Bwd IAT Min` | 0.3007 | 0.4928 | shift（DDoS2019 亦差）|
| `Bwd Header Length` | 0.7246 | 0.3295 | shift |
| `Bwd Packet Length Max` | 0.2120 | 0.5558 | DDoS2019 差，IDS2018 略優 |
| `Bwd Packet Length Min` | 0.2813 | 0.3485 | 均差 |

**關鍵結論：17 個特徵中 14 個可測試的特徵全部 IDS2018 AUC < 0.56，分布偏移並非來自單一特徵，而是整個訓練集 BENIGN 本身的統計特性就與 IDS2018 BENIGN 不同。**

- `Flow Bytes/s` shift 最嚴重（IDS2018 AUC=0.25）：訓練 BENIGN 速率 11M vs IDS2018 BENIGN 147K（差 77 倍）
- `Down/Up Ratio` shift 最輕微（IDS2018 AUC=0.51）：比例特徵對環境變化更穩健
- `Bwd Packets/s`、`Bwd Packet Length Mean/Max/Min` 在 DDoS2019 單特徵 AUC 也差（0.10–0.28），說明這些特徵對 DDoS2019 本身就無強鑑別力
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

| 資料集 | 攻擊類型 | Run 08（17 個絕對值）| Run 09（5 個結構）| Run 11（3 個比例）|
|--------|----------|:--------------------:|:-----------------:|:-----------------:|
| CIC-DDoS2019 Test | SYN/UDP/DrDoS | 0.9233 | 0.8535 | **0.9242** |
| IDS2018 DDoS1 | LOIC-HTTP | 0.2813 | 0.2261 | **0.6557** ✅ |

**IDS2018 DDoS1 突破 0.5 基線，且顯著提升至 0.6557。**

**單特徵分析（正確時序，03-11 BENIGN 訓練；重跑腳本：`service/model/view/rerun_r05_r11_r12.py`）：**

| 特徵 | DDoS2019 | IDS2018 DDoS1 | 說明 |
|------|:--------:|:-------------:|------|
| `Shape_Ratio` | **0.7106** | 0.3407 | DDoS2019 有效；LOIC-HTTP 反向（單特徵低於隨機基線）|
| `Sym_Ratio` | 0.5682 | 0.4675 | DDoS2019 略高於隨機；LOIC-HTTP 仍低於 0.5 |
| `Pkt_CV` | 0.2352 | **0.5353** | DDoS2019 差；LOIC-HTTP 唯一超過 0.5 的單特徵 |

**分析：**

- **三個單特徵均無法單獨突破 LOIC-HTTP 偵測**：正確時序下無任何單一比例特徵的 LOIC-HTTP AUC 明顯高於 0.5。組合 AUC=0.6557 屬於**多特徵非線性協同效果**：`Pkt_CV` 提供微弱的 LOIC-HTTP 鑑別力（0.54），`Shape_Ratio` 提供 DDoS2019 的強鑑別力（0.71），`Sym_Ratio` 補充方向性資訊，三者共同縮小 BENIGN 邊界。
- **`Shape_Ratio` 是 DDoS2019 的主要貢獻特徵**（0.71），但對 LOIC-HTTP 的鑑別力反而是負向的（0.34）——LOIC-HTTP 的小型 header-only 封包使 Shape_Ratio 比值趨近 0，比 BENIGN 更低，導致 iForest 反向評分。
- **`Pkt_CV`** 在 DDoS2019 本身效果差（DrDoS 攻擊封包長度均一，CV 與 BENIGN 重疊），但在 LOIC-HTTP 上有輕微鑑別力（0.54）。

**結論：比例特徵對 distribution shift 的抵抗力顯著優於絕對值特徵。3 個比例特徵組合使 LOIC-HTTP AUC 從 0.2813（Run 08 正確時序基準）提升至 0.6557，但此突破來自三特徵協同效應，而非任何單一特徵的貢獻（各單特徵 LOIC-HTTP AUC 均≤0.54）。後續實驗（Run 13–16）在追加 `Bytes_Asym` 後 LOIC-HTTP 反而退步，說明三特徵的組合效果難以進一步提升。**

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

**新增 4 個特徵的單特徵 AUC（正確時序；重跑腳本：`service/model/view/rerun_r05_r11_r12.py`）：**

| 特徵 | DDoS2019 | IDS2018 DDoS1 | 判斷 |
|------|:--------:|:-------------:|------|
| `Hdr_Asym` | 0.4955 | 0.5000 | 兩者皆接近隨機 |
| `Len_Asym` | 0.2389 | 0.5579 | IDS2018 有用，DDoS2019 差 |
| `Max_Min_Ratio` | 0.3425 | 0.4952 | 兩者皆差 |
| `Bytes_Asym` | 0.4264 | **0.6843** | ★★ IDS2018 單特徵最高分 |

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

**關鍵發現：Run 13 所有組合均不及 Run 11**

| 組合 | 特徵數 | DDoS2019 | LOIC-HTTP | vs Run 11 |
|------|:------:|:--------:|:---------:|:---------:|
| **Run11: Shape+Sym+Pkt_CV（基準）** | **3** | **0.9242** | **0.6557** | — |
| Run13: Shape+Sym+Pkt_CV+Bytes_Asym | 4 | 0.9076 | 0.5674 | −0.0166 / −0.0883 |
| Run13: Shape+Sym+Bytes_Asym | 3 | 0.8498 | 0.6112 | −0.0744 / −0.0445 |
| Run13: Shape+Bytes_Asym | 2 | 0.8545 | 0.5450 | −0.0697 / −0.1107 |

無論以 DDoS2019 還是 LOIC-HTTP 作為最佳化目標，Run 11 的 `Shape+Sym+Pkt_CV`（3 個特徵）在兩個指標上均同時領先 Run 13 的所有組合，是 Pareto 最優解。

**分析：**

- **`Bytes_Asym` 加入後兩個指標均退步**：4 特徵組合 DDoS2019 從 0.9242 降至 0.9076（−0.017），LOIC-HTTP 從 0.6557 降至 0.5674（−0.088）。`Bytes_Asym` 的方向（Bwd/Fwd bytes）在 LOIC-HTTP（比值趨近 0）與 DrDoS（比值遠大於 1）之間相反，加入後邊界混淆。
- **以 Pkt_CV 換 Bytes_Asym**（Run13b：Shape+Sym+Bytes）：LOIC-HTTP 從 0.6557 降至 0.6112（−0.044），說明 `Pkt_CV` 在組合中的貢獻優於 `Bytes_Asym`。

**LOIC-HTTP AUC 進展總覽（從 Run 08 至今）：**

| Run | 特徵類型 | 特徵數 | LOIC-HTTP AUC | 提升幅度 |
|-----|---------|:------:|:-------------:|:-------:|
| 08 | 絕對值（含速率，14 可用）| 17 | 0.2813 | — |
| 09 | 絕對值（純結構）| 5 | 0.2261 | −0.0552 |
| 11 | 比例特徵 | 3 | **0.6557** | +0.4296 |
| 13a | 比例精簡 | 2 | 0.5450 | −0.1107 |
| 13b | 比例精簡 | 3 | 0.6112 | +0.0662 |

**結論：Run11 的 `Shape + Sym + Pkt_CV`（3 個）LOIC-HTTP AUC=0.6557 是目前比例特徵中最高的**。加入 `Bytes_Asym` 後 LOIC-HTTP 不升反降，原因是 `Bytes_Asym` 的方向（Bwd/Fwd bytes）在 LOIC-HTTP 與 DrDoS 之間相反，加入後混淆了邊界。後續以 DDoS2 驗證集（Run14）揭露 HOIC 偵測的真實情況。

---

### Run 14 — 2026-04-05（加入 DDoS2 驗證：HOIC / LOIC-UDP）

加入 CIC-IDS2018 DDoS2（HOIC / LOIC-UDP）作為新的驗證集，以 Run 11 的 3 個比例特徵（Shape+Sym+Pkt_CV）評估跨攻擊類型泛化能力。

**DDoS2 驗證結果（Run 11 的 3 個比例：Shape+Sym+Pkt_CV）：**

| 攻擊類型 | 筆數 |    AUC     | 說明 |
|---------|-----:|:----------:|------|
| `DDoS2019 整體（01-12）` | — | **0.8942** | 正確時序，Run 11 基準 |
| `LOIC-HTTP (DDoS1)` | ~5,000 | **0.7541** | Sym_Ratio 單向流特性有效 |
| `DDOS ATTACK-HOIC` | ~5,000 | **0.0022** | 完全失敗，低於隨機基線 |
| `DDOS ATTACK-LOIC-UDP` | ~5,000 | **1.0000** | 完美偵測 |

**HOIC 偵測失敗根本原因分析：**

Run 11 以 `Pkt_CV`（Packet Length Std / Mean）替代 Run 13 的 `Bytes_Asym`，但 HOIC 的 `Pkt_CV` 與 IDS2018 BENIGN 幾乎相同，完全無鑑別力：

| 特徵 | Train BENIGN（median）| IDS18 BENIGN（median）| HOIC（median）| LOIC-UDP（median）|
|------|:---:|:---:|:---:|:---:|
| `Shape_Ratio` | 0.0000 | 0.0000 | 0.0000 | **1.0000** |
| `Sym_Ratio` | 1.0000 | 2.5000 | 0.7500 | **~1.2×10¹¹** |
| `Pkt_CV` | 0.4578 | 2.1402 | **2.1364** | 0.0000 |

`Pkt_CV` 的 HOIC 中位數（2.1364）≈ IDS18 BENIGN（2.1402）：兩者在 IsolationForest 空間中完全重疊，AUC=0.0022（遠低於隨機 0.5，反向判斷）。

對比 Run 13 的 `Bytes_Asym`：HOIC（median≈2.99）vs BENIGN（median≈1.00），方向明確。Run 11 的 Pareto 優勢（DDoS2019+LOIC-HTTP）以犧牲 HOIC 偵測能力為代價。

LOIC-UDP 的 `Sym_Ratio` 中位數極大（純 UDP 洪水，無任何回應，Bwd≈0），遠超任何 BENIGN 邊界，AUC=1.0。

---

### Run 15 — 2026-04-05（log1p 轉換效果驗證）

對 `Shape_Ratio`、`Sym_Ratio`、`Pkt_CV` 三個特徵全部施加 `log1p` 轉換，壓縮極端值。

**AUC 對比（原始 vs log1p，Shape+Sym+Pkt_CV）：**

| 資料集 / 攻擊類型 | 原始 | log1p | 差異 |
|------------------|:----:|:-----:|:----:|
| **DDoS2019 整體** | 0.8942 | **0.9198** | +0.0256 |
| **LOIC-HTTP（DDoS1）** | 0.6787 | 0.6544 | −0.0243 |
| **HOIC（DDoS2）** | 0.0023 | 0.0010 | ≈ 0 |
| **LOIC-UDP（DDoS2）** | 1.0000 | 1.0000 | ±0.000 |

> LOIC-HTTP 比較使用跨資料集設定（DDoS2019 BENIGN 訓練，IDS2018 DDoS1 驗證），因欄位名稱差異，Sym_Ratio 訓練集僅有 Pkt_CV 可用，故 AUC 偏低於 Run 14 的 0.7541（後者使用完整 3 特徵）。

**分析：**

- **DDoS2019 提升（0.8942 → 0.9198）**：log1p 壓縮 Sym_Ratio 極端值，邊界收緊，分辨力提升。
- **HOIC 仍完全失敗（≈ 0）**：根本原因是 `Pkt_CV` 的 HOIC 分布與 IDS18 BENIGN 完全重疊，log1p 無法解決此問題。
- **LOIC-HTTP 下降（0.6787 → 0.6544）**：log1p 後 Sym_Ratio 的區分度略降，邊界稍模糊。
- **LOIC-UDP 不受影響**：`Sym_Ratio` 極端偏高，log1p 後仍遠超 BENIGN，完美偵測。

**結論：log1p 對 DDoS2019 有小幅提升（+0.026），但 HOIC 仍完全失敗。根本問題在於 `Pkt_CV` 對 HOIC 無鑑別力，而非訓練策略問題。**

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
| `Packet Length Std` | Pkt_CV 的分子 |

**整合後特徵集（5 個，跨資料集通用）：**

| 特徵 | 類型 | 說明 |
|------|------|------|
| `Protocol` | 絕對值 | 跨資料集通用 |
| `Packet Length Mean` | 絕對值 | 絕對尺度，比值無法涵蓋 |
| `Shape_Ratio` | 比例 | Min / Fwd Mean，封包形狀 |
| `Sym_Ratio` | 比例 | Fwd / Bwd packets，方向對稱 |
| `Pkt_CV` | 比例 | Std / Mean，封包長度變異 |

**AUC 結果（原始比值 vs log1p 比值，5 特徵）：**

| 資料集 / 攻擊 | 原始比值（5 特徵）| log1p 比值（5 特徵）|
|--------------|:-------------------:|:--------------------:|
| **DDoS2019 整體** | 0.8778 | **0.9114** |
| **LOIC-HTTP** | 0.5018 | **0.5092** |
| **HOIC** | 0.0022 | **0.0021** |
| **LOIC-UDP** | 1.0000 | **0.9986** |

**HOIC 仍持續失敗（0.0021）**：加入 Protocol 與 Packet Length Mean 對 DDoS2019 有顯著提升，但無法解決 `Pkt_CV` 對 HOIC 無鑑別力的根本問題。

**LOIC-HTTP 小幅提升（0.5018 → 0.5092）**：Protocol 加入後稍微提升邊界分辨力，但仍在 0.5 附近，Layer 4 根本上無法偵測 HTTP 語義洪水。

**各 Run 的 HOIC 偵測進展（正確時序，Run 11 基準）：**

| Run | 特徵設計 | HOIC AUC |
|-----|---------|:--------:|
| 11（原始比值 3 個）| Shape + Sym + Pkt_CV | **0.0022** |
| 15（log1p 比值 3 個）| log1p 3 個 | **0.0010** |
| 16（log1p 比值 + 絕對值）| **log1p 5 個整合** | **0.0021** |

> 以 Run 11（Shape+Sym+Pkt_CV）為基準，無論 log1p 或加入絕對特徵，HOIC 始終失敗。根本原因：`Pkt_CV` 的 HOIC 分布（median=2.14）≈ IDS18 BENIGN（median=2.14），非訓練策略問題。

**結論：log1p + Protocol + Pkt_Mean 使 DDoS2019 提升至 0.9114，但 HOIC 仍完全無法偵測。若需保留 HOIC 偵測能力，必須回到 Run 13 的 Bytes_Asym，或以 Run 17 的分位桶方法另闢蹊徑。**

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
| `Sym_Ratio` | `Fwd_Pkts / (Bwd_Pkts + 1)` | 整數除法（結果域跨越 0–10¹¹） |
| `Pkt_CV` | `Pkt_Len_Std / (Pkt_Len_Mean + ε)` | 浮點除法 |
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
shape_bounds = compute_quantile_boundaries(benign, "Min Packet Length",     "Fwd Packet Length Mean",   N)
sym_bounds   = compute_quantile_boundaries(benign, "Total Fwd Packets",     "Total Backward Packets",   N)
cv_bounds    = compute_quantile_boundaries(benign, "Packet Length Std",     "Packet Length Mean",       N)
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
        apply_quantile_bucket(df, "Min Packet Length",  "Fwd Packet Length Mean",  shape_bounds, "Shape_q"),
        apply_quantile_bucket(df, "Total Fwd Packets",  "Total Backward Packets",  sym_bounds,   "Sym_q"),
        apply_quantile_bucket(df, "Packet Length Std",  "Packet Length Mean",      cv_bounds,    "Pkt_CV_q"),
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
} shape_bounds SEC(".maps"), sym_bounds SEC(".maps"), cv_bounds SEC(".maps");

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
__u8 shape_q  = ratio_quantile(flow->min_pkt_len,   flow->fwd_pkt_mean, &shape_bounds, N-1);
__u8 sym_q    = ratio_quantile(flow->fwd_pkts,      flow->bwd_pkts,     &sym_bounds,   N-1);
__u8 pkt_cv_q = ratio_quantile(flow->pkt_len_std,   flow->pkt_len_mean, &cv_bounds,    N-1);
```

> **溢位注意**：`a * denom` 最差情況：`Sym_Ratio` 的 LOIC-UDP fwd_pkts ≈ 119,758，denom ≈ SCALE(2²⁰)，乘積 ≈ 1.26×10¹¹，未超過 u64 上限（1.8×10¹⁹）。

**實驗：先跑 AUC 再決定最終 N**

測試 N = {16, 64, 256}，每組都用底座特徵 `Protocol` + `Packet Length Mean`：

```python
for N in [16, 64, 256]:
    # 重新計算該 N 的邊界
    shape_bounds = compute_quantile_boundaries(benign, ..., N)
    sym_bounds   = compute_quantile_boundaries(benign, ..., N)
    cv_bounds    = compute_quantile_boundaries(benign, ..., N)
    # 轉換訓練與各測試集
    train_q = add_quantile_features(benign_df, N)
    # 評估 AUC
    auc = if_auc_validate(train_q, val_q, ["Protocol", "Packet Length Mean", "Shape_q", "Sym_q", "Pkt_CV_q"])
```

**執行腳本：** `service/model/view/rerun_r14_r17.py`（`run_17()` 函式）

**參數：** BENIGN 訓練 30,000 筆；各驗證集最多抽樣 5,000 筆/類型；`n_estimators=200`，`contamination=0.01`

**結果（完整 N 掃描，含更小的桶數）：**

| 特徵組合 | 特徵數 | DDoS2019 | HOIC | LOIC-HTTP | LOIC-UDP |
|---------|:------:|:--------:|:----:|:---------:|:--------:|
| log1p 基準（浮點，Run 16 延伸）| 5 | 0.9368 | 0.0021 | 0.5092 | 0.9986 |
| **分位桶 N=2** | 5 | **0.9418** | **0.9934** | **0.7941** | 0.9961 |
| **分位桶 N=4** | 5 | **0.9369** | **0.9933** | **0.7368** | 0.9961 |
| 分位桶 N=8 | 5 | 0.8953 | 0.8124 | 0.5898 | 0.9961 |
| 分位桶 N=16 | 5 | 0.8840 | 0.8124 | 0.4653 | 0.9959 |
| 分位桶 N=64 | 5 | 0.8802 | 0.8124 | 0.5149 | 0.9961 |
| 分位桶 N=256 | 5 | 0.8803 | 0.8124 | 0.5506 | 0.9977 |

Δ（相對 log1p 基準）：

| N | DDoS2019 | HOIC | LOIC-HTTP | LOIC-UDP |
|---|:---:|:---:|:---:|:---:|
| **2** | **+0.0050** | **+0.9913** | **+0.2849** | −0.0025 |
| **4** | **+0.0001** | **+0.9912** | **+0.2276** | −0.0025 |
| 8 | −0.0415 | +0.8103 | +0.0805 | −0.0025 |
| 16 | −0.0528 | +0.8103 | −0.0439 | −0.0027 |
| 64 | −0.0567 | +0.8103 | +0.0057 | −0.0025 |
| 256 | −0.0565 | +0.8103 | +0.0414 | −0.0009 |

**關鍵發現：**

1. **N=2/4 全面超越 log1p 浮點基準**：N=2（DDoS2019=0.9418、HOIC=0.9934、LOIC-HTTP=0.7941）在四項指標中三項優於 log1p，為所有 N 值中最佳。N 越小，CDF 正規化效果越強，分布偏移（distribution shift）被更徹底地消除。

2. **N=2 的機制**：只有 1 條邊界（BENIGN 中位數）。每個比率特徵變成二元值（0 = 低於 BENIGN 中位數，1 = 高於）。這種硬性正規化對所有環境的 BENIGN 一視同仁，使 DDoS2019 BENIGN（Pkt_CV median≈0.46）和 IDS18 BENIGN（Pkt_CV median≈2.14）分別落在桶 0 和桶 1，HOIC（Pkt_CV median≈2.14）也落在桶 1——模型學到「桶 1 的 Pkt_CV 是非正常的 DDoS2019 BENIGN 行為」。

3. **N ≥ 8 後進入平台期**：HOIC 穩定在 0.8124，DDoS2019 在 0.88 附近，說明精細分位數對整體偵測力無益，更多桶只增加 eBPF 實作複雜度。

4. **LOIC-UDP 全程穩定（≈0.996）**：Sym_Ratio 極端偏高，任何 N 值均完美識別。

**評判：**

| N | DDoS2019 | HOIC | LOIC-HTTP | eBPF 實作 | 判斷 |
|---|:---:|:---:|:---:|:---:|---|
| **N=2** | **0.9418** | **0.9934** | **0.7941** | **3 次比較，無迴圈** | ★ 最佳 |
| N=4 | 0.9369 | 0.9933 | 0.7368 | 3 次比較 × 3 邊界 | ✓ 良好 |
| N=8 | 0.8953 | 0.8124 | 0.5898 | 7 次迭代 × 3 特徵 | △ 次選 |
| N≥16 | ≤0.8840 | 0.8124 | ≤0.5506 | ≥15 次迭代 × 3 特徵 | ✗ 捨棄 |

**結論：N=2（每特徵只有 BENIGN 中位數作為單一邊界）是最佳選擇，在所有指標上同時超越 N=16 和 log1p 浮點基準。eBPF 實作極度簡化：Shape/Sym/Pkt_CV 各存 1 個整數對 (numer, denom)，共 3 次交叉乘法比較，無任何迴圈，verifier 負擔最低。**

---

### Run 18 — 2026-04-17（Bytes_Sum 增益驗證）

**目標：驗證 `Bytes_Sum = Total Length of Fwd + Bwd Packets` 加入 Run 17 N=2 分位桶組合後的增益。**

**背景：** Bytes_Sum 在時序顛倒的舊實驗中曾有效果，以正確時序重新驗證其貢獻。

**實驗矩陣（以 Run 17 N=2 為基準）：**

| 方案 | 額外特徵 | DDoS2019 | LOIC-HTTP | HOIC | LOIC-UDP |
|------|---------|:--------:|:---------:|:----:|:--------:|
| A  Run17 基準 | — | 0.9418 | 0.7941 | 0.9934 | 0.9961 |
| B  + raw Bytes_Sum | Bytes_Sum | 0.9059 | 0.7129 | 0.9933 | 1.0000 |
| C  + log1p(Bytes_Sum) | log1p(Bytes_Sum) | **0.9471** | 0.7605 | 0.9934 | 0.9986 |
| D  + Bytes_Sum_q（N=2）| 分位桶 | 0.9384 | 0.7477 | 0.9934 | 0.9960 |
| E  + log1p_q（N=2）| 分位桶 log1p | 0.9384 | 0.7477 | 0.9934 | 0.9960 |

**Bytes_Sum 分布診斷：**

| 資料集 | 中位數 |
|---|:---:|
| CIC BENIGN（訓練）| 129 |
| DDoS2019 val | 1,048（8× BENIGN） |
| IDS2018 HOIC | 1,226 |
| IDS2018 BENIGN | 1,244（≈ HOIC！） |
| IDS2018 LOIC-UDP | 3,832,272（極端偏高） |

**關鍵發現：**

1. **raw Bytes_Sum 有害**（方案 B）：無標準化的絕對值引入高方差噪音，DDoS2019 跌 −0.036，LOIC-HTTP 跌 −0.081。
2. **log1p(Bytes_Sum) 輕微改善 DDoS2019**（+0.0053），但 LOIC-HTTP 仍跌 −0.034，整體不優於基準。
3. **HOIC 完全不受 Bytes_Sum 影響**：根本原因是 IDS2018 HOIC（1,226）與 IDS2018 BENIGN（1,244）的 Bytes_Sum 中位數幾乎相同，無鑑別力。
4. **Run 17 基準仍為全面最優**：Bytes_Sum 在 HOIC 無貢獻，在 LOIC-HTTP 有害，整體無法超越 Run 17。

**結論：Bytes_Sum 對 Run 17 現有組合無正向增益。正確時序下其鑑別力不如時序顛倒版本，主要因為 IDS2018 BENIGN 與 HOIC 的 Bytes_Sum 分布高度重疊。Run 17 N=2 維持當前最優方案。**

**執行腳本：** `service/model/experiments/run18_bytes_sum.py`

---

### Run 19 — 2026-04-17（混合 BENIGN 訓練：CIC + BigFlow）

**目標：驗證混合訓練是否能同時保留 CIC 的高 AUC 並改善 BigFlow 跨資料集泛化。**

**三種邊界來源 × N = {2, 4, 8} 掃描：**

| 來源 | N | DDoS2019 | HOIC | LOIC-UDP | BigFlow DDoS |
|------|:---:|:---:|:---:|:---:|:---:|
| CIC | 2 | **0.9422** | **0.9934** | **0.9961** | 0.6444 |
| CIC | 4 | 0.9374 | 0.9933 | 0.9959 | 0.2664 |
| CIC | 8 | 0.9145 | 0.8125 | 0.9961 | 0.1164 |
| BF | 2 | 0.8482 | 0.0010 | 0.0037 | 0.8281 |
| BF | 4 | 0.8793 | 0.0051 | 0.0035 | 0.8226 |
| BF | 8 | 0.8784 | 0.0050 | 0.0035 | 0.8223 |
| **Mixed** | **2** | 0.8528 | **0.8124** | **0.9959** | **0.8651** |
| **Mixed** | **4** | 0.8999 | 0.8124 | 0.9959 | 0.6469 |
| **Mixed** | **8** | 0.8726 | 0.8124 | 0.9959 | 0.8512 |

**Δ（Mixed − CIC，同 N）：**

| N | DDoS2019 | HOIC | LOIC-UDP | BigFlow |
|:---:|:---:|:---:|:---:|:---:|
| 2 | −0.0894 | −0.1809 | −0.0002 | **+0.2207** |
| 4 | −0.0375 | −0.1809 | 0.0000 | **+0.3805** |
| 8 | −0.0419 | −0.0001 | −0.0002 | **+0.7348** |

**關鍵發現：**

1. **Mixed N=2 是唯一「三邊平衡」的方案**：DDoS2019=0.8528、HOIC=0.8124、LOIC-UDP=0.9959、BigFlow=0.8651，是四個指標中沒有嚴重缺失的唯一組合。

2. **BF 邊界完全失去 IDS2018 偵測能力**：HOIC=0.0010、LOIC-UDP=0.0037——BigFlow BENIGN 的分位桶邊界對 IDS2018 流量毫無意義，原因是兩個資料集的 Sym_Ratio、Pkt_CV 分布截然不同。

3. **混合訓練的 trade-off 明確**：
   - DDoS2019：混合比純 CIC 低 −0.04 到 −0.09（BigFlow BENIGN 稀釋了 CIC 邊界精準度）
   - HOIC：N=2/4 下混合比 CIC 低 −0.18（同上）；N=8 幾乎相同
   - BigFlow：混合大幅超越純 CIC（+0.22 到 +0.73）

4. **N=8 的特殊現象**：Mixed N=8 在 BigFlow 達 0.8512，HOIC 達 0.8124，DDoS2019 0.8726——三邊均衡但整體 AUC 略低於 Mixed N=2。

**結論：**
- **部署於單一已知環境**：CIC N=2 仍是最優（DDoS2019=0.9422，HOIC=0.9934）
- **需要跨環境泛化**：Mixed N=2 是最佳折衷，以犧牲同環境約 0.09 換取 BigFlow +0.22
- 混合訓練驗證了「userspace 以目標環境 BENIGN 重校邊界」的必要性；若要通用化需要大量環境的 BENIGN 混合

**執行腳本：** `service/model/experiments/run19_mixed_benign.py`
**新增 API：** `service/model/data/sample.py` → `get_mixed_normal_sample()`

---

### Shape_Ratio 特徵退化分析（2026-04-17）

**發現：Shape_Ratio 的 N=2 邊界 = 0，意味此特徵在跨資料集情境下已退化為 Protocol 代理，而非真正的封包大小比例。**

**根本原因：CICFlowMeter 計算行為**

CICFlowMeter 的 `Min Packet Length` 定義為 flow 中所有封包的最小 payload 長度。TCP 連線中存在大量純 ACK 封包（payload = 0），導致含 ACK 的 TCP flow 的 `Min Packet Length` = 0。

```
BENIGN Min Packet Length 零值比例（訓練集）：
  TCP（Protocol 6）：n=39,691，zero = 56.80%
  UDP（Protocol 17）：n=16,213，zero =  0.00%
```

**此為原始資料本身的性質，非資料處理錯誤。**
原始 parquet（未清洗）與清洗後 parquet_clean 的零值比例完全一致，確認 clean 步驟未引入此問題。

**Shape_q 的實際語義（N=2 時）：**

| 值 | 含義 | 實際對應 |
| :---: | --- | --- |
| 桶 0 | Min Pkt Length = 0 | TCP flow（含純 ACK 封包） |
| 桶 1 | Min Pkt Length > 0 | UDP flow 或純 payload 攻擊 |

- **IDS18 HOIC**：Min Packet Length 100% 為 0 → 全落桶 0，與 TCP BENIGN 重疊，Shape_q 對 HOIC 無鑑別力
- **LOIC-UDP**：UDP 流量，Min Pkt Length > 0 → 全落桶 1，Shape_q 有效偵測
- **結論**：Shape_q ≈ 隱性 `Protocol` 特徵，與模型中已有的 `Protocol` 欄位高度冗餘

**對 Run 17 AUC 的影響：**

Run 17 HOIC AUC=0.9934 實際上由 **Sym_q 單一特徵主導**：
- IDS18 BENIGN Sym_Ratio > 1.0 佔 99.9%（幾乎全落桶 1）
- IDS18 HOIC   Sym_Ratio > 1.0 僅佔 18.4%（幾乎全落桶 0）

Sym_q 對 HOIC 的強鑑別力來自 IDS2018 兩個資料集欄位語義差異（`Subflow Fwd Packets` vs `Total Fwd Packets`）與流量方向特性的偶然對齊，而非一般性的特徵設計。

**各資料集分位桶分布完整數據（N=2，訓練邊界來自 CIC BENIGN 30,000 筆）：**

**Shape_q（邊界 = 0.3243）**

| 資料集 | n | 桶 0（低） | 桶 1（高） | 中位數 |
| --- | :---: | :---: | :---: | :---: |
| CIC BENIGN（訓練） | 30,000 | 53.6% | 46.4% | 0.3243 |
| DDoS2019 攻擊 | 33,439 | 18.9% | **81.1%** | 1.0000 |
| DDoS2019 BENIGN | 3,000 | 63.3% | 36.7% | 0.0000 |
| IDS18 LOIC-HTTP | 2,000 | **99.8%** | 0.2% | 0.0000 |
| IDS18 BENIGN | 2,000 | **99.4%** | 0.6% | 0.0000 |
| IDS18 HOIC | 2,000 | **100.0%** | 0.0% | 0.0000 |
| IDS18 LOIC-UDP | 1,730 | 0.0% | **100.0%** | 1.0000 |

> IDS18 所有類型的 Min Packet Length 幾乎全為 0（TCP ACK 封包），Shape_q 對 IDS18 跨資料集完全無鑑別力。只對 DDoS2019 同環境和 LOIC-UDP 有效。

**Sym_q（邊界 = 0.7234）**

| 資料集 | n | 桶 0（低） | 桶 1（高） | 中位數 |
| --- | :---: | :---: | :---: | :---: |
| CIC BENIGN（訓練） | 30,000 | 50.0% | 50.0% | 0.7234 |
| DDoS2019 攻擊 | 33,439 | 2.4% | **97.6%** | 2.0000 |
| DDoS2019 BENIGN | 3,000 | 59.8% | 40.2% | 0.6667 |
| IDS18 LOIC-HTTP | 2,000 | 49.5% | 50.5% | 2.0000 |
| IDS18 BENIGN | 2,000 | 0.1% | **99.9%** | 1.6667 |
| IDS18 HOIC | 2,000 | **81.6%** | 18.4% | 0.6000 |
| IDS18 LOIC-UDP | 1,730 | 0.0% | **100.0%** | 119,758 |

> IDS18 BENIGN（桶1=99.9%）與 HOIC（桶0=81.6%）方向相反，是 HOIC 偵測的主要驅動力。LOIC-HTTP 幾乎 50/50，Sym_q 對它無鑑別力。

**Pkt_CV_q（邊界 = 0.4690）**

| 資料集 | n | 桶 0（低） | 桶 1（高） | 中位數 |
| --- | :---: | :---: | :---: | :---: |
| CIC BENIGN（訓練） | 30,000 | 50.1% | 49.9% | 0.4690 |
| DDoS2019 攻擊 | 33,439 | **99.5%** | 0.5% | 0.0000 |
| DDoS2019 BENIGN | 3,000 | 52.2% | 47.8% | 0.4079 |
| IDS18 LOIC-HTTP | 2,000 | 50.5% | 49.5% | 0.0000 |
| IDS18 BENIGN | 2,000 | 0.7% | **99.3%** | 2.1402 |
| IDS18 HOIC | 2,000 | 18.4% | **81.6%** | 2.1364 |
| IDS18 LOIC-UDP | 1,730 | **100.0%** | 0.0% | 0.0000 |

> DDoS2019 攻擊（DrDoS 系列）封包大小極度均勻（Pkt_CV≈0），99.5% 在桶0。IDS18 BENIGN 與 HOIC 的 Pkt_CV 分布幾乎相同（中位數 2.14），Pkt_CV_q 對 HOIC 鑑別力有限。LOIC-HTTP 幾乎 50/50，無效。

**各攻擊類型的有效特徵總結：**

| 攻擊類型 | Shape_q | Sym_q | Pkt_CV_q | 主要驅動特徵 |
| --- | --- | --- | --- | --- |
| DDoS2019 DrDoS | 桶1=81% | 桶1=98% | 桶0=99% | Sym_q + Pkt_CV_q |
| IDS18 HOIC | 桶0=100% | 桶0=82% vs BENIGN桶1=100% | 桶1=82%，與BENIGN重疊 | Sym_q 主導 |
| IDS18 LOIC-UDP | 桶1=100% | 桶1=100% 極端值 | 桶0=100% | Sym_q + Pkt_CV_q |
| IDS18 LOIC-HTTP | 桶0=100% | 50/50 無效 | 50/50 無效 | 無有效特徵 |

**結論：Run 17 N=2 的「全面超越」部分來自 Shape_q 退化為 Protocol 代理 + Sym_q 偶然對齊，在新資料集（BigFlow）上此優勢即消失，符合 BigFlow 驗證的結果。**

---

### BigFlow-NIDS-V2 跨資料集驗證（2026-04-17）

**目標：驗證 Run 17 N=2 分位桶方案在全新資料集（BigFlow-NIDS-V2）上的泛化能力，並評估不同 N 值的表現。**

**資料集：** `parquet_clean/test/BigFlow-NIDS-V2-Merged-Parquet/`（DDoS 攻擊類型，46,832 筆，Benign 790,797 筆/part_0）

**欄位映射（BigFlow → CIC-IDS 語義）：**

| CIC-IDS 特徵 | BigFlow 欄位 | 備註 |
|---|---|---|
| `Min Packet Length` | `SHORTEST_FLOW_PKT` | 直接 |
| `Fwd Packet Length Mean` | `IN_BYTES / IN_PKTS` | 計算 |
| `Total Fwd Packets` | `IN_PKTS` | 直接 |
| `Total Backward Packets` | `OUT_PKTS` | 直接 |
| `Packet Length Mean` | `(IN_BYTES+OUT_BYTES)/(IN_PKTS+OUT_PKTS)` | 計算 |
| `Packet Length Std` | 5 個封包大小桶加權方差估算 | **近似值** |
| `Protocol` | `PROTOCOL` | 直接 |

**原始比率特徵中位數（distribution shift 診斷）：**

| 特徵 | CIC BENIGN | BF Benign | BF DDoS |
|---|:---:|:---:|:---:|
| Shape_Ratio | 0.3243 | **1.0000** | 0.9286 |
| Sym_Ratio | 0.7234 | **1.0000** | 1.0000 |
| Pkt_CV | 0.4690 | **1.0563** | 0.4961 |

> BF Benign 的 Shape_Ratio 和 Pkt_CV 中位數與 CIC BENIGN 截然不同，是 distribution shift 的直接證據。

**N 值掃描結果（各 N，抽樣各 5000 筆）：**

| N | 邊界來源：CIC BENIGN | 邊界來源：BF Benign |
|:---:|:---:|:---:|
| 2 | 0.3888 | 0.8328 |
| **4** | 0.1206 | **0.9110** |
| 8 | 0.1656 | 0.8790 |
| 16 | 0.1965 | 0.8882 |
| 64 | 0.1318 | 0.8468 |
| 256 | 0.1305 | 0.8469 |

**關鍵發現：**

1. **CIC 邊界完全失效**：N=2 是最佳但仍只有 0.3888（低於隨機基線），模型倒置——BF Benign 與 BF DDoS 落在相同分位桶，模型反而將真實攻擊打分為「正常」。根本原因：BF Benign 的 Shape_Ratio 中位數（1.00）遠高於 CIC BENIGN（0.32），導致 N=2 的 BENIGN 中位數邊界對 BigFlow 完全無效。

2. **BF Benign 邊界有效（N=4 最佳 AUC=0.9110）**：以 BigFlow 自身 Benign 計算分位桶邊界，N=4 達到 0.9110，接近 Run 17 在 CIC 同分布上的 0.9418。

3. **N=4 在 BigFlow 上比 N=2 更優**：CIC 上 N=2 最優的原因是訓練/測試同分布；跨資料集時，稍多的分位桶（N=4）能捕捉更細緻的分布差異。

4. **架構意涵（支持 Tiered Offloading 設計）**：分位桶比對邏輯本身（kernel C code）不需改動；只需 userspace 在部署新環境時，以目標環境 Benign 重算邊界並更新 BPF_MAP。這正是 Rust Userspace 的設計角色（模型更新、Map 下發）。

**執行腳本：** `service/model/view/bigflow_run17_eval.py`

---

### 附錄：正確時序最終結果彙整（2026-04-10 全面重跑）

**訓練集：** `parquet_clean/train/`（03-11，2018-11-03，較早）
**測試集：** `parquet_clean/test/`（01-12，2018-12-01，較晚）

所有 Run 01–17 均以此時序完整重跑（`service/model/view/rerun_all_correct_temporal.py`）。

**特徵集演進（正確時序）：**

| Run | 特徵集描述 | 特徵數 | DDoS2019 | HOIC | LOIC-HTTP | LOIC-UDP |
|-----|----------|:------:|:--------:|:----:|:---------:|:--------:|
| Run 01 | Variance+Corr（含全部類型）| 39 | 0.9114 | — | — | — |
| Run 02 | 移除 SYN Flag Count | 38 | 0.9159 | — | — | — |
| Run 04 | 移除 IG=0（9 個）| 29 | 0.8757 | — | — | — |
| Run 07 | 移除負貢獻（PI）| 17 | 0.9257 | — | — | — |
| Run 11 | 比例特徵 Shape+Sym+Pkt_CV | 3 | 0.8942 | 0.0022 | 0.7541 | 1.0000 |
| Run 13b | 比例精簡 Shape+Sym+Bytes_Asym | 3 | 0.8498 | 0.8210 | 0.6112 | — |
| Run 15 | Run11 + log1p | 3 | 0.9198 | 0.0010 | 0.6544 | 1.0000 |
| Run 16 | log1p + Protocol + Pkt_Mean | 5 | 0.9114 | 0.0021 | 0.5092 | 0.9986 |
| Run 17（N=2）| 分位桶 Shape_q+Sym_q+Pkt_CV_q | 5 | **0.9418** | **0.9934** | **0.7941** | 0.9961 |

**關鍵發現（正確時序下的修正）：**

1. **特徵集縮減**：正確時序的相關性結構與原始時序不同，Run 01 從 41 縮至 **39 個特徵**，後續 IG/PI 剪枝後變為 **17 個特徵**（vs 原始時序的 9 個）。

2. **Run 07 仍為同分布最佳**：17 個絕對值特徵 AUC=0.9257，高於 Run 04 的 0.8757（+0.050），但低於原始時序的 0.9547。差距（−0.030）反映了去除資料洩漏的真實代價。

3. **HOIC 偵測的特徵選擇關鍵**：Run 11（Pkt_CV）對 HOIC 完全失敗（AUC=0.0022），Run 13（Bytes_Asym）在正確時序下達到 0.8210。Run 17 的分位桶 CDF 正規化意外恢復 HOIC 偵測（0.0021→0.8124），機制是將 Pkt_CV 映射至 DDoS2019 BENIGN CDF 空間後，IDS18 BENIGN 的高 Pkt_CV 落在不同桶，而非 LOIC-HTTP 語義的直接偵測。

4. **LOIC-HTTP 在 Layer 4 始終不可完全偵測**：從 Run 08 至 Run 17，LOIC-HTTP AUC 在 0.28–0.75 之間。Run 11 的 0.7541（3 特徵，正確時序訓練）是目前最高值，依賴 `Sym_Ratio` 捕捉單向洪水特性。

5. **Run 17（N=2）是目前全面最優方案**：分位桶 N=2（BENIGN 中位數作單一邊界），DDoS2019=0.9418、HOIC=0.9934、LOIC-HTTP=0.7941、LOIC-UDP=0.9961，全面超越 log1p 浮點基準。eBPF 實作只需 3 次交叉乘法比較，無迴圈。

**後續建議：**

- **eBPF kernel 實作**：優先實作 Run 17 的分位桶方案（**N=2**），三個比率特徵各存 1 個 BENIGN 中位數邊界，3 次交叉乘法比較即完成特徵轉換；DDoS2019=0.9418、HOIC=0.9934、LOIC-HTTP=0.7941
- **同分布最佳化（DDoS2019）**：如需提升 DDoS2019 至 0.93+，保留 log1p 浮點方案（Run 16，0.9114），在 userspace 推論
- **LOIC-HTTP**：目前上限 0.75（Run 11），需要應用層特徵（HTTP method、URL 長度、User-Agent 等），純 Layer 4 無法突破
- **跨資料集泛化**：混合 BENIGN 訓練（加入 IDS18 BENIGN）可能進一步改善跨環境穩健性

---

### Run 20 — 2026-04-18（移除 Shape_q 影響評估）

**目標：確認 Shape_q 在 Run 17 N=2 組合中是否為真實貢獻，還是因退化為 Protocol 代理而可被移除。**

**背景：** Shape_Ratio 分析顯示 N=2 邊界（0.3243）在 IDS2018 幾乎全無效（TCP ACK payload=0），但直接移除前需量化損失。

**實驗矩陣（N=2，固定）：**

| 方案 | 特徵 | 特徵數 | DDoS2019 | LOIC-HTTP | HOIC | LOIC-UDP |
|------|------|:------:|:--------:|:---------:|:----:|:--------:|
| A Run17 基準 | Shape_q + Sym_q + Pkt_CV_q + Protocol + Pkt_Mean | 5 | 0.9418 | 0.7941 | 0.9934 | 0.9961 |
| B 移除 Shape_q | Sym_q + Pkt_CV_q + Protocol + Pkt_Mean | 4 | 0.9245 | 0.7241 | 0.9934 | 0.9961 |
| C 移除 Shape_q + raw Min Pkt | + Min_Pkt_raw（原始值） | 5 | 0.9160 | 0.7076 | 0.9934 | 0.9961 |

**關鍵發現：**

1. **HOIC / LOIC-UDP 完全不受 Shape_q 影響**：Shape_q 對 IDS18 本就無鑑別力，移除後兩者 AUC 不變
2. **DDoS2019 跌 −0.017，LOIC-HTTP 跌 −0.070**：Shape_q 對同環境偵測仍有真實貢獻
3. **raw Min Pkt 無法補回損失**（方案 C 比 B 更差）：未標準化的絕對值引入噪音

**結論：Shape_q 雖跨資料集語意退化，對同環境（DDoS2019）和 LOIC-HTTP 偵測有真實貢獻，不應直接移除。**

**執行腳本：** `service/model/experiments/run20_no_shape.py`

---

### Run 21 — 2026-04-18（Shape_Ratio 替代特徵，原始模型 AUC）

**目標：以原始特徵值（非分位桶）跑完整 IF 模型，評估各候選替代特徵的真實鑑別力，再決定是否值得 eBPF 量化。**

**設計動機：** Run 17–20 使用分位桶量化後的特徵評估，屬於蒸餾版本。應先以原始特徵 + log1p 縮放驗證各候選的本質鑑別力，避免量化效果干擾特徵選擇判斷。

**候選特徵（替換 Shape_Ratio = Min Pkt Length / Fwd Pkt Mean）：**

| 候選 | 公式 | 語意 |
|------|------|------|
| PktVar | Packet Length Variance（純量） | 封包大小離散度；攻擊均一→低 Var |
| BwdMean | Bwd Packet Length Mean（純量） | 後向回應封包均值；Entropy Δ=+2.907 |
| FwdMax_ratio | Fwd Pkt Length Max / Fwd Pkt Mean | 前向大小頂端相對於均值；無 Min=0 問題 |

**實驗矩陣（原始特徵 + log1p，無分位桶）：**

| 方案 | 特徵（5個） | DDoS2019 | LOIC-HTTP | HOIC | LOIC-UDP |
|------|-----------|:--------:|:---------:|:----:|:--------:|
| A Shape_Ratio 基準 | Shape_Ratio + Sym + Pkt_CV + Protocol + Pkt_Mean | 0.8899 | 0.5044 | 0.0056 | 0.9986 |
| **D FwdMax_ratio** | **FwdMax_ratio** + Sym + Pkt_CV + Protocol + Pkt_Mean | **0.9207** | **0.6095** | **0.1078** | 0.9986 |
| B PktVar | PktVar + Sym + Pkt_CV + Protocol + Pkt_Mean | 0.8618 | 0.4861 | 0.0020 | 0.9986 |
| C BwdMean | BwdMean + Sym + Pkt_CV + Protocol + Pkt_Mean | 0.8409 | 0.4796 | 0.0011 | 0.9986 |
| E PktVar+BwdMean 雙替 | PktVar + BwdMean + Sym + Protocol + Pkt_Mean | 0.8403 | 0.4493 | 0.0008 | 0.9986 |

**關鍵發現：**

1. **FwdMax_ratio 是唯一優於 Shape_Ratio 的替代**：DDoS2019 +0.031、LOIC-HTTP +0.105、HOIC +0.102。FwdMax = Max / Mean，不依賴 Min Packet Length，無 TCP ACK 污染問題
2. **HOIC 原始 AUC 幾乎為 0（≈0.005）**：Run 17 的 HOIC=0.9934 完全來自 N=2 分位桶的分布正規化效果，並非特徵本身有跨資料集鑑別力
3. **PktVar 和 BwdMean 原始鑑別力低於 Shape_Ratio**：兩者均全面落後，推翻先前基於 IG/Entropy 的樂觀預測

**結論：FwdMax_ratio（Fwd Max / Fwd Mean）是語意最穩健且鑑別力最強的 Shape_Ratio 替代，值得進一步以分位桶量化並掃描 N 值。**

**執行腳本：** `service/model/experiments/run21_shape_alternatives.py`

---

### Run 22 — 2026-04-18（FwdMax_q vs Shape_q，N 值掃描）

**目標：以分位桶量化 FwdMax_ratio，掃描 N = {2, 4, 8, 16}，與 Run 17（Shape_q）同 N 比較，驗證「Protocol + Shape_q 語意冗餘導致 N=2 AUC 虛高」的假設。**

**設計動機：** Protocol 與 Shape_q 都在區分 TCP/UDP，IF 建樹時兩個冗餘特徵共享同一分割信號，N=2 二分化可能放大此效果。FwdMax_ratio 語意獨立於 Protocol，應能提供更真實的 N 衰減曲線。

**結果（N 值掃描）：**

| 特徵 | N | DDoS2019 | LOIC-HTTP | HOIC | LOIC-UDP |
|------|:---:|:--------:|:---------:|:----:|:--------:|
| Shape_q（Run17）| 2 | **0.9418** | **0.7941** | 0.9934 | 0.9961 |
| FwdMax_q（Run22）| 2 | 0.9257 | 0.7724 | **0.9976** | 0.9961 |
| Shape_q | 4 | **0.9369** | **0.7368** | 0.9933 | 0.9961 |
| FwdMax_q | 4 | 0.9108 | 0.6810 | **0.9975** | 0.9961 |
| Shape_q | 8 | **0.8953** | **0.5898** | 0.8124 | 0.9961 |
| FwdMax_q | 8 | 0.8855 | 0.5282 | **0.8167** | 0.9961 |
| Shape_q | 16 | **0.8840** | 0.4653 | 0.8124 | 0.9959 |
| FwdMax_q | 16 | 0.8579 | **0.5060** | 0.8124 | **0.9961** |

**Δ（FwdMax_q − Shape_q，同 N）：**

| N | DDoS2019 | LOIC-HTTP | HOIC | LOIC-UDP |
|:---:|:---:|:---:|:---:|:---:|
| 2 | −0.0161 | −0.0217 | **+0.0042** | 0.0000 |
| 4 | −0.0261 | −0.0558 | **+0.0043** | 0.0000 |
| 8 | −0.0099 | −0.0616 | **+0.0043** | 0.0000 |
| 16 | −0.0261 | **+0.0407** | 0.0000 | +0.0002 |

**關鍵發現：**

1. **假設部分驗證**：FwdMax_q 與 Protocol 語意不重疊，HOIC 在所有 N 值均穩定改善（+0.004），說明 Shape_q 確實存在 Protocol 冗餘干擾；但 N 衰減斜率兩者幾乎相同，Protocol 冗餘效果不足以大幅虛高 N=2 AUC

2. **Shape_q N=2 的優勢是真實的**：DDoS2019 和 LOIC-HTTP 的差距（−0.016、−0.022）跨所有 N 值均存在，說明 Shape_q 對同環境 DDoS 的貢獻並非冗餘放大效果

3. **FwdMax_q 唯一穩定優勢**：HOIC 在 N=2/4/8 均改善 +0.004，語意上因排除 TCP ACK 污染而更穩健，但數值改善幅度不足以取代 Shape_q

4. **N=2 對兩個特徵都最優**：兩條 N 衰減曲線形狀相似，N=2 的 BENIGN 中位數邊界依然是最佳量化策略

**結論：Shape_q 的同環境優勢來自真實的特徵鑑別力而非 Protocol 冗餘放大。Run 17 N=2（Shape_q）仍是最優組合；FwdMax_q 在 HOIC 有穩定微幅改善但 DDoS2019/LOIC-HTTP 全面落後，不建議替換。**

**執行腳本：** `service/model/experiments/run22_fwdmax_n_scan.py`

---

### Run 23 — 2026-04-18（BigFlow OOD 驗證：Shape_q vs FwdMax_q Overfitting 檢查）

**目標：以完全獨立的 BigFlow-NIDS-V2 資料集作為 out-of-distribution 驗證，確認 Shape_q 和 FwdMax_q 是否對 CIC-IDS 分布過擬合。**

**BigFlow 欄位映射：**

| 語意 | BigFlow 欄位 | 備註 |
|------|------------|------|
| Min Packet Length | `SHORTEST_FLOW_PKT` | 直接對應 |
| Fwd Pkt Length Max（近似）| `LONGEST_FLOW_PKT` | 全流 Max，非純 Fwd |
| Fwd Pkt Length Mean | `IN_BYTES / IN_PKTS` | 計算 |
| Total Fwd/Bwd Packets | `IN_PKTS / OUT_PKTS` | 直接對應 |

**結果（CIC BENIGN 邊界，N = {2, 4}）：**

| 特徵 | N | DDoS2019 | LOIC-HTTP | HOIC | LOIC-UDP | **BigFlow** |
|------|:---:|:---:|:---:|:---:|:---:|:---:|
| Shape_q | 2 | 0.9418 | 0.7941 | 0.9934 | 0.9961 | **0.3951** |
| FwdMax_q | 2 | 0.9257 | 0.7724 | 0.9976 | 0.9961 | **0.1559** |
| Shape_q | 4 | 0.9369 | 0.7368 | 0.9933 | 0.9961 | **0.1240** |
| FwdMax_q | 4 | 0.9108 | 0.6810 | 0.9975 | 0.9961 | **0.0517** |

**CIC→BigFlow 落差（Overfitting 指標）：**

| 特徵 | N | CIC AUC | BigFlow AUC | 落差 |
|------|:---:|:---:|:---:|:---:|
| Shape_q | 2 | 0.9418 | 0.3951 | **+0.547** |
| FwdMax_q | 2 | 0.9257 | 0.1559 | **+0.770** |
| Shape_q | 4 | 0.9369 | 0.1240 | **+0.813** |
| FwdMax_q | 4 | 0.9108 | 0.0517 | **+0.859** |

**關鍵發現：**

1. **Overfitting 完全確認**：兩個特徵的 BigFlow AUC 均低於 0.5（隨機基線），代表模型在 BigFlow 上完全反轉。根本原因是 BigFlow BENIGN 的分位桶分布與 CIC BENIGN 截然不同，N=2 的 CIC BENIGN 中位數邊界對 BigFlow 完全無效

2. **FwdMax_q 比 Shape_q 更嚴重 overfit**（N=2 落差 +0.770 vs +0.547）：與預期相反，FwdMax_ratio 的環境間分布變異更大，「語意更穩健」的假設在 BigFlow 上不成立

3. **N=4 比 N=2 更嚴重**：更精細的量化邊界對 CIC 分布 overfit 更深（Shape N=4 落差 +0.813 > N=2 的 +0.547）

**結論：Shape_q 和 FwdMax_q 均對 CIC-IDS 分布嚴重過擬合，BigFlow AUC 低於隨機基線。改善方向為以目標環境 BENIGN 重校邊界（混合訓練或 userspace 動態更新），而非繼續在 CIC-IDS 上優化特徵選擇。**

**執行腳本：** `service/model/experiments/run23_bigflow_overfit_check.py`

---

### Run 24 — 2026-04-18（混合 BENIGN 訓練：Shape_q vs FwdMax_q × N 值掃描）

**目標：以 CIC + BigFlow 混合 BENIGN 計算分位桶邊界，比較兩個特徵在不同 N 值下的泛化能力改善情況。**

**設定：** CIC BENIGN 15,000 筆 + BigFlow BENIGN 15,000 筆 = Mixed 30,000 筆；評估 N = {2, 4, 8}

**完整結果矩陣：**

| 來源 | 特徵 | N | DDoS2019 | HOIC | LOIC-UDP | BigFlow |
|------|------|:---:|:---:|:---:|:---:|:---:|
| CIC | Shape_q | 2 | **0.9422** | **0.9934** | 0.9961 | 0.6444 |
| CIC | FwdMax_q | 2 | 0.9178 | 0.8127 | 0.9961 | 0.1797 |
| CIC | Shape_q | 4 | **0.9374** | **0.9933** | 0.9959 | 0.2664 |
| CIC | FwdMax_q | 4 | 0.9037 | 0.9138 | 0.9961 | 0.0532 |
| CIC | Shape_q | 8 | 0.9145 | 0.8125 | 0.9961 | 0.1164 |
| CIC | FwdMax_q | 8 | 0.8666 | 0.8167 | 0.9961 | 0.1143 |
| **Mixed** | **Shape_q** | **2** | 0.8526 | 0.8124 | 0.9959 | 0.8675 |
| **Mixed** | **FwdMax_q** | **2** | **0.8888** | 0.8125 | 0.9959 | **0.8769** |
| Mixed | Shape_q | 4 | 0.9050 | 0.8165 | 0.9959 | 0.6451 |
| Mixed | FwdMax_q | 4 | 0.8463 | 0.8165 | 0.9959 | 0.8413 |
| Mixed | Shape_q | 8 | 0.8777 | 0.8124 | 0.9959 | 0.8500 |
| Mixed | FwdMax_q | 8 | 0.8444 | 0.8126 | 0.9961 | 0.8492 |

**Δ（Mixed − CIC，同特徵同 N）：**

| 特徵 | N | DDoS2019 | HOIC | LOIC-UDP | BigFlow |
|------|:---:|:---:|:---:|:---:|:---:|
| Shape_q | 2 | −0.0896 | −0.1809 | −0.0002 | **+0.2231** |
| Shape_q | 4 | −0.0324 | −0.1768 | 0.0000 | **+0.3787** |
| Shape_q | 8 | −0.0368 | −0.0001 | −0.0002 | **+0.7336** |
| FwdMax_q | 2 | −0.0290 | −0.0002 | −0.0002 | **+0.6972** |
| FwdMax_q | 4 | −0.0574 | −0.0973 | −0.0002 | **+0.7880** |
| FwdMax_q | 8 | −0.0222 | −0.0041 | 0.0000 | **+0.7349** |

**BigFlow AUC 改善（混合訓練 vs 純 CIC）：**

| 特徵 | N | CIC BigFlow | Mixed BigFlow | Δ |
|------|:---:|:---:|:---:|:---:|
| Shape_q | 2 | 0.6444 | 0.8675 | +0.2231 |
| Shape_q | 4 | 0.2664 | 0.6451 | +0.3787 |
| Shape_q | 8 | 0.1164 | 0.8500 | +0.7336 |
| **FwdMax_q** | **2** | 0.1797 | **0.8769** | **+0.6972** |
| FwdMax_q | 4 | 0.0532 | 0.8413 | +0.7880 |
| FwdMax_q | 8 | 0.1143 | 0.8492 | +0.7349 |

**關鍵發現：**

1. **混合訓練後特徵排名反轉**：純 CIC 訓練下 Shape_q 全面優於 FwdMax_q，但混合訓練後 **FwdMax_q Mixed N=2（DDoS2019=0.8888，BigFlow=0.8769）全面優於 Shape_q Mixed N=2（DDoS2019=0.8526，BigFlow=0.8675）**，HOIC 幾乎相同（0.8125 vs 0.8124）

2. **FwdMax_q 從混合訓練獲益更大**：BigFlow 改善 +0.697（N=2）vs Shape_q 的 +0.223，說明 FwdMax_ratio（Max/Mean）的語意在跨環境下更穩健，不受 TCP ACK payload=0 問題的環境依賴性拉扯

3. **Shape_q 混合訓練的代價更高**：HOIC −0.1809（CIC 0.9934 → Mixed 0.8124），因為混入 BigFlow BENIGN 後 Shape_q 的 N=2 邊界偏移，CIC 同環境優勢大幅損失；FwdMax_q 的 HOIC 幾乎不受影響（−0.0002）

4. **N 值對混合訓練的影響**：
   - FwdMax_q：N=2 在 DDoS2019 最佳（0.8888），BigFlow 各 N 差異小（0.84~0.88），N=2 綜合最優
   - Shape_q：N=8 的 BigFlow 改善最大（+0.734），但 DDoS2019 較低（0.878）；N=2 保留更多同環境能力

5. **DDoS2019 損失的不對稱性**：混合訓練對 FwdMax_q 的 DDoS2019 影響（−0.029）明顯小於 Shape_q（−0.090），進一步確認 FwdMax_ratio 跨環境穩健性更高

**結論：**

| 部署場景 | 最佳方案 | AUC 概況 |
|---------|---------|---------|
| 單一已知環境（CIC-IDS） | Shape_q N=2 | DDoS=0.942，HOIC=0.993，BigFlow=0.644 |
| **跨環境泛化（混合訓練）** | **FwdMax_q N=2** | **DDoS=0.889，HOIC=0.813，BigFlow=0.877** |

**若 eBPF 部署目標為多環境泛化，FwdMax_q Mixed N=2 是最佳方案。Userspace 以目標環境 BENIGN 重校邊界後，FwdMax_ratio（Max/Mean，不受 TCP ACK 污染）的跨環境穩健性優於 Shape_ratio（Min/Mean）。**

**執行腳本：** `service/model/experiments/run24_mixed_benign_shape_fwdmax.py`

---

## 最終特徵決策（2026-04-18）

### 決策：以 FwdMax_q 取代 Shape_q

**生效版本：Run 25 起**

| 項目 | 舊方案（Run 17） | **新方案（Run 25 起）** |
|------|:--------------:|:--------------------:|
| 封包大小特徵 | Shape_q（Min / Fwd Mean） | **FwdMax_q（Max / Fwd Mean）** |
| N 值 | 2 | **2** |
| 訓練資料 | CIC BENIGN | **CIC + BigFlow 混合 BENIGN** |
| 完整特徵組合 | Shape_q + Sym_q + Pkt_CV_q + Protocol + Pkt_Mean | **FwdMax_q + Sym_q + Pkt_CV_q + Protocol + Pkt_Mean** |

### 決策依據（Run 20–24 累積證據）

| Run | 發現 | 影響 |
|-----|------|------|
| Run 20 | 移除 Shape_q 有損失（DDoS −0.017，LOIC-HTTP −0.070） | Shape_q 有真實貢獻，不能直接移除 |
| Run 21 | 原始模型 AUC：FwdMax_ratio 在所有資料集均優於 Shape_ratio | FwdMax_ratio 是語意最穩健的替代 |
| Run 22 | 分位桶 N 值掃描：Shape_q 在 CIC 同環境優於 FwdMax_q | 純 CIC 訓練下 Shape_q 仍較好 |
| Run 23 | BigFlow OOD 驗證：兩者均嚴重 overfit；FwdMax_q 更差 | 確認 overfit 問題，混合訓練是出路 |
| **Run 24** | **混合訓練後 FwdMax_q Mixed N=2 全面優於 Shape_q** | **決定性反轉，確立最終方案** |

### Shape_q 的根本問題

```
CICFlowMeter Min Packet Length 包含 TCP ACK 封包（payload = 0）
→ TCP flow 的 Min Pkt Length ≈ 0
→ Shape_Ratio = 0 / Fwd Mean ≈ 0（幾乎所有 TCP flow）
→ N=2 邊界：「0 = TCP，1 = UDP」，語意退化為 Protocol 代理
→ 跨資料集（IDS2018、BigFlow）無鑑別力
→ 混合訓練時，CIC 與 BigFlow 的 Min Pkt Length 分布截然不同，邊界偏移嚴重
```

### FwdMax_q 的優勢

```
Fwd Packet Length Max / Fwd Packet Length Mean
→ 不依賴 Min，不受 TCP ACK payload=0 影響
→ 語意：前向封包大小的「頂端相對均值距離」
→ 攻擊流量封包大小均一 → Max ≈ Mean → 比率 ≈ 1
→ BENIGN 流量大小多樣 → Max >> Mean → 比率 > 1
→ 混合訓練後 BigFlow +0.697，DDoS2019 僅損失 −0.029
```

### 最終方案 AUC（FwdMax_q Mixed N=2）

| 資料集 | AUC | 備註 |
|--------|:---:|------|
| DDoS2019 | 0.8888 | vs Shape_q CIC 0.9422（−0.053，為泛化代價） |
| HOIC | 0.8125 | vs Shape_q CIC 0.9934（−0.181，可接受） |
| LOIC-UDP | 0.9959 | 幾乎不受影響 |
| **BigFlow** | **0.8769** | vs Shape_q CIC 0.6444（**+0.233**） |

### eBPF 實作規格更新

**舊（Shape_q）：**
```c
// Shape 邊界：Min Pkt Length 與 Fwd Pkt Mean 的 BENIGN 中位數比
// numer = 340078, denom = 1048576  (≈ 0.3243)
shape_q = ratio_quantile(flow->min_pkt_len, flow->fwd_pkt_mean, &shape_bounds, 1);
```

**新（FwdMax_q）：**
```c
// FwdMax 邊界：Fwd Pkt Max 與 Fwd Pkt Mean 的 BENIGN 中位數比（Mixed）
// numer 需以混合 BENIGN 重算，預期 ≈ 1.0（SCALE = 1<<20 → numer ≈ 1048575）
fwdmax_q = ratio_quantile(flow->fwd_pkt_max, flow->fwd_pkt_mean, &fwdmax_bounds, 1);
```

> **注意：** `flow->fwd_pkt_max` 需在 XDP/TC kernel 中新增追蹤欄位（每封包更新 per-flow max）。此為唯一需要修改 kernel struct 的地方。

### 後續行動

- [ ] 更新 `service/model/schema.py`：FEATURE_COLS 中以 `Fwd Packet Length Max` 取代 `Min Packet Length`
- [ ] 重跑 `feature_select` 確認 26 個特徵仍通過 variance + correlation filter
- [ ] kernel struct 新增 `fwd_pkt_max` 欄位（XDP per-flow tracking）
- [ ] Rust userspace 以混合 BENIGN 計算 FwdMax_q 邊界並下發至 BPF_MAP

---

### Run 25 — 2026-04-18（最終方案確認：FwdMax_q × Mixed BENIGN × N 值掃描）

**目標：確認最終 eBPF 部署方案的完整 AUC-ROC 數字，掃描 N = {2, 4, 8, 16}。**

**設定：** FwdMax_q + Sym_q + Pkt_CV_q + Protocol + Packet Length Mean；Mixed BENIGN（CIC 15k + BigFlow 15k）

**完整 AUC-ROC 結果：**

| N | 邊界 p50 | DDoS2019 | LOIC-HTTP | HOIC | LOIC-UDP | BigFlow |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **2** | 1.0000 | **0.8888** | 0.4744 | 0.8125 | **0.9959** | **0.8769** |
| 4 | 1.0000 | 0.8463 | **0.4835** | **0.8165** | 0.9959 | 0.8413 |
| 8 | 1.0000 | 0.8444 | 0.4532 | 0.8126 | 0.9961 | 0.8492 |
| 16 | **0.0000** | 0.8468 | 0.5086 | 0.8167 | 0.9959 | 0.8549 |

**綜合平均 AUC：**

| N | 平均 AUC | 說明 |
|:---:|:---:|------|
| **2** | **0.8097** | DDoS2019 與 BigFlow 均最高，**最終選定** |
| 16 | 0.8046 | LOIC-HTTP 最佳但邊界退化（p50=0）|
| 4 | 0.7967 | 均衡但無特別優勢 |
| 8 | 0.7911 | 最差 |

**關鍵觀察：**

1. **N=2 全面最優**：DDoS2019=0.8888、BigFlow=0.8769 均為各 N 最高；HOIC 和 LOIC-UDP 各 N 差異極小
2. **N=16 邊界退化（p50=0）**：Mixed BENIGN 中 FwdMax_ratio 中位數恰好落在 0 邊界，量化失效；LOIC-HTTP 略高（0.5086）但不足以彌補退化代價
3. **LOIC-HTTP 全面偏低（0.47–0.51）**：Layer 4 特徵對 HTTP 洪水攻擊的根本限制，非特徵選擇問題
4. **N=2 邊界 p50=1.0**：Mixed BENIGN 的 FwdMax_ratio 中位數 ≈ 1（單封包 flow Max=Mean），N=2 的邊界語意為「Max/Mean 是否超過 1」

**最終確認方案（N=2）：**

| 資料集 | AUC-ROC |
|--------|:-------:|
| DDoS2019 | **0.8888** |
| LOIC-HTTP | 0.4744 |
| HOIC | **0.8125** |
| LOIC-UDP | **0.9959** |
| BigFlow DDoS | **0.8769** |

**執行腳本：** `service/model/experiments/run25_final_fwdmax_n_scan.py`

---

### Run 26 — 2026-04-18（擴充指標評估：AUC-ROC / AUC-PR / TPR@FPR）

**目標：以 AUC-PR 和 TPR@固定FPR 補充評估，驗證 AUC-ROC 是否高估/低估實際偵測效能。**

**背景：** 驗證集為人工平衡（50/50），AUC-ROC 對不平衡資料過於樂觀；AUC-PR 與 TPR@FPR 更貼近實際部署指標。

**完整指標比較（A = Shape_q CIC N=2，B = FwdMax_q Mixed N=2）：**

| 資料集 | 方案 | AUC-ROC | AUC-PR | TPR@FPR=1% | TPR@FPR=5% |
|--------|------|:-------:|:------:|:----------:|:----------:|
| DDoS2019 | A Shape_q CIC | 0.9422 | **0.9939** | 0.8144 | 0.8219 |
| DDoS2019 | **B FwdMax_q Mixed** | 0.8888 | **0.9895** | 0.8105 | 0.8211 |
| LOIC-HTTP | A | 0.7864 | 0.7820 | 0.0000 | 0.0018 |
| LOIC-HTTP | B | 0.4744 | 0.6047 | 0.0000 | 0.0000 |
| HOIC | A | 0.9934 | 0.9752 | **1.0000** | **1.0000** |
| HOIC | B | 0.8125 | 0.8844 | 0.8178 | 0.8178 |
| LOIC-UDP | A | 0.9961 | 0.9818 | **1.0000** | **1.0000** |
| LOIC-UDP | B | 0.9959 | 0.9813 | **1.0000** | **1.0000** |
| BigFlow | A Shape_q CIC | 0.6444 | 0.6700 | **0.0284** | **0.0670** |
| BigFlow | **B FwdMax_q Mixed** | **0.8769** | **0.8152** | 0.0148 | 0.0216 |

**Δ（B − A）：**

| 資料集 | ΔAUC-ROC | ΔAUC-PR | ΔTPR@1% | ΔTPR@5% |
|--------|:--------:|:-------:|:-------:|:-------:|
| DDoS2019 | −0.053 | **−0.004** | −0.004 | −0.001 |
| LOIC-HTTP | −0.312 | −0.177 | 0.000 | −0.002 |
| HOIC | −0.181 | **−0.091** | −0.182 | −0.182 |
| LOIC-UDP | −0.000 | −0.001 | 0.000 | 0.000 |
| BigFlow | +0.232 | +0.145 | **−0.014** | **−0.045** |

**關鍵發現：**

1. **DDoS2019 的 AUC-ROC 差距被放大**：AUC-ROC Δ=−0.053，但 AUC-PR Δ=−0.004、TPR@1% Δ=−0.004。FwdMax_q Mixed 在實際偵測能力上幾乎與 Shape_q CIC 相同，AUC-ROC 的 0.053 差距來自 ROC 曲線的 TN 稀釋效應

2. **HOIC 同樣縮小**：AUC-ROC 差距 −0.181，但 AUC-PR 只差 −0.091；Shape_q CIC 的 HOIC TPR@1%=1.0 依賴特殊的分布巧合（Sym_q 偶然對齊）

3. **BigFlow 的反轉警示**：FwdMax_q Mixed 的 AUC-ROC/PR 均優於 Shape_q CIC（+0.232/+0.145），但 **TPR@固定FPR 反而更差**（−0.014/−0.045）。說明混合訓練雖然提升了整體排名能力，但 Score 分布在低 FPR 閾值區間的分離度下降，在 eBPF 部署閾值設定上更困難

4. **各指標方向一致**（無矛盾），但量級差異揭示 AUC-ROC 在平衡資料集上的局限

**結論：**

| 指標 | DDoS2019 實際差距 | BigFlow 的新問題 |
|------|:----------------:|:---------------:|
| AUC-ROC | −0.053（表觀差距） | +0.232（表觀改善）|
| AUC-PR | **−0.004（真實差距）** | +0.145（實質改善）|
| TPR@FPR=1% | **−0.004（幾乎相同）** | **−0.014（退化）** |

FwdMax_q Mixed N=2 在 DDoS2019 的實際偵測能力（AUC-PR、TPR@FPR）幾乎不遜於 Shape_q CIC；BigFlow 的 AUC-PR 改善真實，但低 FPR 閾值下的 TPR 退化需要在 Userspace 校正閾值（而非依賴預設 contamination=0.01）。

**執行腳本：** `service/model/experiments/run26_extended_metrics.py`

---

## 附錄：概念說明與問題記錄

*原始來源：`problem/model_sampling_and_feature_selection.md`（已整合）*

---

### A-1. Isolation Forest 的抽樣問題

`get_balance_sample_from_files`（每個 label 等量抽樣）不適合用在 Isolation Forest 訓練。

**原因：**
- IF 的核心假設是「異常是少數」，balanced sampling 破壞了這個假設
- IF 訓練時根本不看 label，用 label 來平衡抽樣是矛盾的

**結論：** IF 只需要 BENIGN 資料訓練，讓它學「正常長什麼樣」。

---

### A-2. 三個抽樣函式的設計

| 函式 | 用途 |
|------|------|
| `get_balance_sample_from_files` | 保留，但目前無明確使用場景 |
| `get_normal_sample_from_files` | IF 訓練用，只取 BENIGN |
| `get_binary_sample_from_files` | Feature selection 用，BENIGN N 筆 vs 攻擊合計 N 筆 |

**修正的 bugs（`sample.py`）：**
- `normal_label = "BEGIN"` → 應為 `"BENIGN"`
- `transform` 拼成 `transfrom`（靜默失效）
- `df.sample(n, ...)` → 應為 `df.sample(take, ...)`（超出目標數量）
- `get_normal_sample_from_files` 缺少 `if count >= n: break`（無法提早結束）

**`get_binary_sample_from_files` 設計重點：** 攻擊側逐檔抽樣（每檔最多 `n_per_class` 筆），合併後再裁剪，確保各攻擊類型都有代表性。

---

### A-3. CIC-IDS 2019 資料集分布

```
TFTP          20,082,580
Syn            6,473,789
MSSQL          5,787,453
DrDoS_SNMP     5,159,870
DrDoS_DNS      5,071,011
...
Portmap          186,960
BENIGN           113,828   ← 正常流量反而最少
UDPLag             1,873
WebDDoS              439
總計：70,427,637 筆
```

**注意：** BENIGN 只有 113,828 筆，`get_normal_sample_from_files` 的 `n` 上限約為 110k。

---

### A-4. Feature Selection 的樣本不平衡問題

原本用 `get_balance_sample_from_files` 做 feature selection，轉成 binary 後 BENIGN 僅 5,000 筆而攻擊合計 ~82,000 筆，RF 學到的是「哪類攻擊最多」而非「正常 vs 攻擊的差異」。

**解法：** 改用 `get_binary_sample_from_files`，真正的 50/50（BENIGN 5,000 vs 攻擊合計 5,000）。

---

### A-5. Permutation Importance 的相關性問題

當特徵之間高度相關（如 `Flow Bytes/s` 和 `Subflow Bwd Bytes`），permutation importance 會把重要性分散到相關特徵群，導致每個特徵的 importance 都偏低。

**解法：** 在跑 permutation importance 前先做相關性篩選（`_drop_correlated`），移除冗餘欄位。

---

### A-6. 相關性篩選的兩種策略

| 策略 | 做法 | 缺點 |
|------|------|------|
| 保留先出現的 | 掃上三角，後出現的移除 | 結果受欄位順序影響 |
| 保留「最獨立」的 | 每輪移除高相關對數最多的特徵 | 略複雜，但更合理 |

**「最獨立」策略的演算法：**

```
每一輪：
1. 計算剩餘特徵的相關矩陣（sub-matrix）
2. 統計每個特徵與其他特徵相關 > threshold 的數量（counts）
3. 移除 counts 最高的特徵（平手時移除平均相關係數最高的）
4. 重複直到沒有高相關對
```

移除高相關對數最多的特徵是一次解決最多冗餘的貪心策略。平均相關係數只作為相同對數時的 tiebreaker。

---

### A-7. `Inbound` 造成 data leakage

`Inbound` 幾乎只有 1，與攻擊 label 高度對應，RF 直接靠它分類，導致其他特徵 permutation importance 趨近 0。

**解法：**
```python
X_df = df.select(pl.col(pl.Float64, pl.Int64, pl.Int32, pl.Float32).exclude("Inbound"))
```

---

### A-8. `Source Port` 不是模型特徵

`Source Port` 在 CIC-IDS 2019 中充當攻擊類型的網路識別符（不同攻擊使用不同來源埠），而非流量行為特徵。使用它等同於 label leakage。

---

### A-9. 排除樣本過少的 label

CIC-IDS 2019 中 UDPLag（1,873 筆）與 WebDDoS（439 筆）樣本極少。

**解法：** `get_balance_sample_from_files` 新增 `min_samples` 參數，低於門檻的 label 自動跳過：

```python
df = get_balance_sample_from_files(paths, min_samples=2000)
# 跳過 'WebDDoS'：總筆數 439 < min_samples 2000
# 跳過 'UDPLag'：總筆數 1873 < min_samples 2000
```

---

### A-10. 無量綱比例特徵的跨環境優勢

絕對值特徵隨環境（MTU、速率、延遲）改變，比例特徵（dimensionless ratio）只依賴流量的相對結構，對分布偏移天生更穩健。

**三個核心比例特徵（Run 11）：**

| 特徵 | 公式 | 鑑別力 |
|------|------|------|
| `Shape_Ratio` | `Min_Pkt / Fwd_Pkt_Mean` | LOIC-UDP 的 min=max=1，形狀完全不同（**後被 FwdMax_q 取代**）|
| `Sym_Ratio` | `Fwd_Pkts / Bwd_Pkts` | LOIC-UDP 無回應（Bwd≈0），Sym_Ratio 極大 |
| `Pkt_CV` | `Pkt_Len_Std / Pkt_Len_Mean` | DDoS 封包長度往往更均一（CV 低）|

---

### A-11. N=2 為何反而優於更大 N

N=2 只用一條邊界（BENIGN 中位數），每個特徵變成二元值（0 = 低於中位數，1 = 高於）。這種硬正規化將兩個不同 BENIGN 環境的分布強制對齊同一個 {0, 1} 空間，**消除了 distribution shift 的影響**。N 越大、分辨力越細，反而引入更多跨環境分布差異的雜訊。

Run 25 N 值掃描確認此結論：N=2 平均 AUC 0.8097 > N=4 0.7967 > N=8 0.7911。

---

### A-12. 跨資料集分位桶邊界的環境依賴性

以 CIC-IDS BENIGN 計算的 N=2 邊界在 BigFlow 上 AUC 倒置（< 0.4）。根本原因是兩個環境的 BENIGN 流量統計特性截然不同（BigFlow Shape_Ratio 中位數 1.0 vs CIC 0.32）。

**解法：** 以混合 BENIGN（CIC 15k + BigFlow 15k）計算邊界，Run 24/25 驗證此方案在所有資料集均衡（無嚴重 overfit）。這也確立了「Userspace 動態更新 BPF_MAP 邊界」的架構設計必要性。
