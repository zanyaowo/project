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
