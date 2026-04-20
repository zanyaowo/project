# Model 抽樣策略與 Feature Selection 問題記錄

## 一、Isolation Forest 的抽樣問題

### 問題
`get_balance_sample_from_files`（每個 label 等量抽樣）不適合用在 Isolation Forest 訓練。

### 原因
- IF 的核心假設是「異常是少數」，balanced sampling 破壞了這個假設
- IF 訓練時根本不看 label，用 label 來平衡抽樣是矛盾的
- CIC-IDS 2019 每筆資料都有 label，有 label 就應該優先考慮監督式方法

### 結論
IF 只需要 BENIGN 資料訓練，讓它學「正常長什麼樣」。

---

## 二、三個抽樣函式的設計

| 函式 | 用途 |
|------|------|
| `get_balance_sample_from_files` | 保留，但目前無明確使用場景 |
| `get_normal_sample_from_files` | IF 訓練用，只取 BENIGN |
| `get_binary_sample_from_files` | Feature selection 用，BENIGN N 筆 vs 攻擊合計 N 筆 |

### 修正的 bugs（`sample.py`）
- `normal_label = "BEGIN"` → 應為 `"BENIGN"`
- `transform` 拼成 `transfrom`（靜默失效）
- `df.sample(n, ...)` → 應為 `df.sample(take, ...)`（超出目標數量）
- `get_normal_sample_from_files` 缺少 `if count >= n: break`（無法提早結束）

### `get_binary_sample_from_files` 設計重點
- 攻擊側逐檔抽樣（每檔最多 `n_per_class` 筆），合併後再裁剪
- 確保各攻擊類型都有代表性，不會因大量攻擊集中在少數檔案而偏斜

---

## 三、CIC-IDS 2019 資料集分布

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

## 四、Feature Selection 的問題

### 問題
原本用 `get_balance_sample_from_files` 做 feature selection，轉成 binary 後：
- BENIGN：5,000 筆（二次 cap 後）
- 攻擊合計：~82,000 筆（18 個攻擊類 × 5,000）

→ 嚴重不平衡，RF 學到的是「哪類攻擊最多」而非「正常 vs 攻擊的差異」。

### 解法
改用 `get_binary_sample_from_files`，真正的 50/50：
- BENIGN：5,000 筆
- 攻擊合計：5,000 筆（各攻擊類型均有代表）

---

## 五、Permutation Importance 的相關性問題

### 觀念
當特徵之間高度相關（如 `Flow Bytes/s` 和 `Subflow Bwd Bytes`），permutation importance 會把重要性分散到相關特徵群，導致每個特徵的 importance 都偏低，看起來「沒幾個有用」。

### 解法
在跑 permutation importance 前先做相關性篩選（`_drop_correlated`），移除冗餘欄位。

---

## 六、相關性篩選的兩種策略

| 策略 | 做法 | 缺點 |
|------|------|------|
| 保留先出現的 | 掃上三角，後出現的移除 | 結果受欄位順序影響 |
| 保留「最獨立」的 | 每輪移除高相關對數最多的特徵 | 略複雜，但更合理 |

### 「最獨立」策略的演算法

```
每一輪：
1. 計算剩餘特徵的相關矩陣（sub-matrix）
2. 統計每個特徵與其他特徵相關 > threshold 的數量（counts）
3. 移除 counts 最高的特徵（平手時移除平均相關係數最高的）
4. 重複直到沒有高相關對
```

### 為何用「高相關對數」而非「平均相關係數」作為主要指標

移除高相關對數最多的特徵，是一次解決最多冗餘的貪心策略。

**反例：**
```
A-B: 0.95（唯一一對）
C-D: 0.91, C-E: 0.91, C-F: 0.91（三對）
```
A 的平均相關係數比 C 高，但移除 A 只解決 1 個問題；移除 C 一次解決 3 個問題。

→ 平均相關係數只作為高相關對數相同時的 tiebreaker。

---

## 七、相關性篩選模組化（2026-03-23）

### 變更
將 `_drop_correlated` 從 `feature_select.py` 拆出，獨立為 `service/model/pipeline/correlation_filter.py`，函式改為 public（`drop_correlated`）。

### 加入印出 pair 的邏輯
過濾時印出被移除的 pair 清單（依相關係數由高到低排序），方便審查：

```
       保留                捨棄           相關係數
----------------------------------------------------
Total Backward Packets  Subflow Bwd Packets   1.0000
...
相關性篩選：81 → 54 個特徵（移除 27 個）
```

---

## 八、Feature Selection 結果異常：只有 2 個特徵有可見重要性（2026-03-23）

### 問題
圖表上只有 2 個特徵有明顯的 permutation importance，其餘接近 0。

### 根本原因：`Inbound` 造成 data leakage
`Inbound` 幾乎只有 1，與攻擊 label 高度對應，RF 直接靠它分類。
permutation 其他特徵對 accuracy 幾乎沒有影響，導致其他特徵 importance 趨近 0。

### 解法
在選取特徵欄位時排除 `Inbound`：
```python
X_df = df.select(pl.col(pl.Float64, pl.Int64, pl.Int32, pl.Float32).exclude("Inbound"))
```

---

## 九、固定 random_state 確保 Feature Selection 可重現（2026-03-23）

### 問題
每次跑 feature selection 結果不同。

### 原因
`RandomForestClassifier` 沒有設 `random_state`，三個隨機來源：
1. 抽樣（`seed=42` 已固定）
2. RF 建樹（未固定）
3. permutation importance（`random_state=42` 已固定）

### 解法
```python
RandomForestClassifier(n_estimators=n_estimators, class_weight="balanced", random_state=42)
```

---

## 十、改用 `get_balance_sample_from_files` 做 Feature Selection（2026-03-23）

### 問題
`get_binary_sample_from_files` 攻擊側把所有攻擊混池抽樣，筆數多的類型佔比高，少的可能根本抽不到。

### 解法
改用 `get_balance_sample_from_files`，逐 label 各抽 N 筆，每種攻擊類型代表數量相同。

---

## 十一、排除樣本過少的 label（2026-03-23）

### 問題
CIC-IDS 2019 中 UDPLag（1,873 筆）與 WebDDoS（439 筆）樣本極少，在平衡抽樣裡佔比過低，對 RF 影響微弱但可能引入噪音。

### 解法
`get_balance_sample_from_files` 新增 `min_samples` 參數，低於門檻的 label 自動跳過：

```python
df = get_balance_sample_from_files(paths, min_samples=2000)
# 跳過 'WebDDoS'：總筆數 439 < min_samples 2000
# 跳過 'UDPLag'：總筆數 1873 < min_samples 2000
```

---

## 十二、Distribution Shift：同分布特徵在跨資料集上失效（2026-04-05）

### 問題（Run 08）
Run 07 的 17 個特徵在 DDoS2019 同分布驗證 AUC=0.9257，但在 CIC-IDS2018（LOIC-HTTP）上 AUC=0.28，低於隨機基線。

### 根本原因
訓練集 BENIGN（DDoS2019，反射攻擊高速環境）與測試集 BENIGN（IDS2018，一般辦公室流量）的統計分布截然不同：

| 特徵類型 | 問題 |
|---------|------|
| 速率特徵（Flow Bytes/s、Bwd Packets/s）| 訓練環境速率極高，辦公室流量落在「異常」區域 |
| 絕對封包長度特徵 | 不同環境的 MTU、應用層行為差異使邊界偏移 |
| 絕對時間特徵（IAT）| 高速環境 IAT 極短，辦公室 IAT 較長 → 誤判 |

### 結論
跨環境部署必須用目標環境的 BENIGN 重新訓練，或改用對分布偏移不敏感的特徵。

---

## 十三、無量綱比例特徵（Run 11–13，2026-04-05）

### 設計思路
絕對值特徵隨環境（MTU、速率、延遲）改變，比例特徵（dimensionless ratio）只依賴流量的相對結構，對分布偏移天生更穩健。

### 三個核心比例特徵（Run 11，DDoS2019 AUC=0.8942）

| 特徵 | 公式 | 鑑別力 |
|------|------|------|
| `Shape_Ratio` | `Min_Pkt / Fwd_Pkt_Mean` | LOIC-UDP 的 min=max=1（flood），形狀完全不同 |
| `Sym_Ratio` | `Fwd_Pkts / Bwd_Pkts` | LOIC-UDP 無回應（Bwd≈0），Sym_Ratio 極大 |
| `Pkt_CV` | `Pkt_Len_Std / Pkt_Len_Mean` | DDoS 封包長度往往更均一（CV 低）|

### Pareto 比較（Run 11 vs Run 13 的 Bytes_Asym 組合）

| 組合 | DDoS2019 | LOIC-HTTP | HOIC |
|------|:---:|:---:|:---:|
| Run 11（Shape+Sym+Pkt_CV）| **0.8942** | **0.7541** | 0.0022 |
| Run 13（Shape+Sym+Bytes_Asym）| 0.8498 | 0.6112 | **0.8210** |

Run 11 在 DDoS2019 與 LOIC-HTTP 上是 Pareto 最優，但 `Pkt_CV` 對 HOIC 完全無鑑別力（HOIC 的 Pkt_CV median ≈ IDS18 BENIGN），需要分位桶方法才能解決。

---

## 十四、分位桶整數化與 N=2 突破（Run 17，2026-04-05）

### 核心問題
比率特徵（Shape_Ratio、Sym_Ratio）涉及浮點除法，eBPF kernel 無法直接執行。

### 解法：交叉乘法（完全無除法）
```
a / b < threshold_k  ↔  a × denom_k < b × numer_k
```
訓練時計算 BENIGN 的分位數邊界，存為整數對 `(numer_k, denom_k)` 寫入 BPF_MAP。  
Kernel 只需整數乘法即可判斷分位排名。

### N=2 是全面最優（意外發現）

測試 N=2、4、8、16、64、256 後，N 越小結果越好：

| N | DDoS2019 | HOIC | LOIC-HTTP | LOIC-UDP | eBPF 迭代數 |
|---|:---:|:---:|:---:|:---:|:---:|
| log1p 浮點基準 | 0.9368 | 0.0021 | 0.5092 | 0.9986 | Userspace |
| **N=2** | **0.9418** | **0.9934** | **0.7941** | 0.9961 | **3 次比較，無迴圈** |
| N=4 | 0.9369 | 0.9933 | 0.7368 | 0.9961 | 9 次 |
| N=8 | 0.8953 | 0.8124 | 0.5898 | 0.9961 | 21 次 |
| N≥16 | ≤0.8840 | 0.8124 | ≤0.5506 | ≈0.996 | ≥45 次 |

### 為何 N=2 反而最好

N=2 只用一條邊界（BENIGN 中位數），每個特徵變成二元值（0 = 低於 BENIGN 中位數，1 = 高於）。  
這種硬正規化將兩個不同 BENIGN 環境的分布強制對齊同一個 {0, 1} 空間，**消除了 distribution shift 的影響**。  
N 越大、分辨力越細，反而引入更多跨環境分布差異的雜訊。

### eBPF 實作（N=2）
每個特徵只存 1 個整數對（BENIGN 中位數），整個 kernel 只需 3 次交叉乘法比較，無任何迴圈，verifier 壓力最低：

```c
// BENIGN 中位數邊界，各存 1 個整數對
struct bound shape_med, sym_med, cv_med;  // numer/denom

__u8 shape_q  = (flow->min_pkt_len * shape_med.denom < flow->fwd_pkt_mean * shape_med.numer) ? 0 : 1;
__u8 sym_q    = (flow->fwd_pkts    * sym_med.denom   < flow->bwd_pkts     * sym_med.numer)   ? 0 : 1;
__u8 pkt_cv_q = (flow->pkt_len_std * cv_med.denom    < flow->pkt_len_mean * cv_med.numer)    ? 0 : 1;
```

### 抽樣注意事項
- IF 訓練：`get_normal_sample_from_files`（BENIGN only，30,000 筆）
- 跨資料集驗證：各攻擊類型最多 5,000 筆（`load_ids2018` + `sample`）
- IDS2018 欄位名與 DDoS2019 不同（如 `Packet Length Min` vs `Min Packet Length`），需維護獨立的欄位映射 dict
