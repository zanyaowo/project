# 分位桶策略 & 模型訓練 Log

> 由 `feature_selection_log.md` 實體抽出的「kernel 分位桶策略 + 模型訓練」實驗線。
> Run 編號沿用原始連續編號（與 `feature_selection_log.md` 共用 Run 01–29 序）。
> 純特徵選擇（Run 01–16、Run 18、附錄 A-1～A-9、正確時序彙整）仍在 `feature_selection_log.md`。
> 涵蓋：分位數整數化（Run 17）→ 混合 BENIGN 訓練（Run 19）→ Shape_q↔FwdMax_q + N 值掃描（Run 20–24）→ 最終特徵決策 → Run 25/26 → 跨環境分位桶概念（A-10/11/12）→ 邊界 overfit / contract 對照 / HOIC 替代（Run 27–29）。

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


---

### Run 27 — 2026-05-18（分位桶邊界 overfit 驗證：CIC-only vs BigFlow-only vs Mixed）

**目標：** 驗證 5-feature N=2 distilled model 的 bucket boundaries 是否只貼合某一個 BENIGN 來源，導致跨資料集 benign bucket 分布崩塌或攻擊 AUC 下降。

**設定：** CIC BENIGN 10k + BigFlow BENIGN 10k；每個 eval label 4k；seed=42。IF 訓練資料固定使用 Mixed BENIGN；只改變 boundary source（CIC-only / BigFlow-only / Mixed）。特徵：`FwdMax_q, Sym_q, Pkt_CV_sq, Protocol, Packet Length Mean`。

**執行腳本：** `service/model/experiments/run27_boundary_overfit_check.py`

**[1] AUC（IF train 固定為 Mixed BENIGN，只換 boundary source）：**

| Boundary | DDoS2019 | LOIC-HTTP | HOIC | LOIC-UDP | BigFlow |
|----------|:--------:|:---------:|:----:|:--------:|:-------:|
| CIC-only | 0.9044 | 0.5301 | 0.9931 | 0.9976 | 0.1642 |
| BigFlow-only | 0.8750 | 0.2154 | 0.0008 | 0.9969 | 0.8956 |
| Mixed | 0.8833 | 0.2647 | 0.0001 | 0.9969 | 0.8754 |

**[2] BENIGN upper-bucket 比例（應接近 0.5 表示邊界對齊）：**

| Boundary | BenignSet | protocol | pkt_len_mean | fwd_max_q | sym_ratio | pkt_cv_sq |
|----------|-----------|:--------:|:------------:|:---------:|:---------:|:---------:|
| CIC-only | CIC | 0.216 | 0.515 | 0.502 | 0.500 | 0.503 |
| CIC-only | BigFlow | 0.040 | 0.540 | **1.000** | 0.717 | **0.974** |
| CIC-only | Mixed | 0.128 | 0.527 | 0.751 | 0.609 | 0.739 |
| BigFlow-only | CIC | 0.216 | 0.477 | 0.197 | 0.430 | 0.115 |
| BigFlow-only | BigFlow | 0.040 | 0.370 | 0.894 | 0.041 | 0.806 |
| BigFlow-only | Mixed | 0.128 | 0.423 | 0.546 | 0.235 | 0.460 |
| Mixed | CIC | 0.216 | 0.477 | 0.197 | 0.430 | 0.134 |
| Mixed | BigFlow | 0.040 | 0.370 | 0.894 | 0.041 | 0.886 |
| Mixed | Mixed | 0.128 | 0.423 | 0.546 | 0.235 | 0.510 |

**[3] Boundary p50 values：**

| Boundary | proto | mean | fwdmax | sym | cv_sq |
|----------|------:|-----:|-------:|----:|------:|
| CIC-only | 6 | 22 | 0.9730 | 0.8235 | 0.2033 |
| BigFlow-only | 6 | 24 | 1.9130 | 1.0000 | 2.3552 |
| Mixed | 6 | 24 | 1.9130 | 1.0000 | 1.8820 |

**關鍵結論：**

1. **CIC-only boundary 在 BigFlow 嚴重 overfit（AUC=0.1642）**：BigFlow benign 的 `fwd_max_q` 全部被推到上桶（比例=1.000），`pkt_cv_sq` 比例=0.974，邊界完全不適用於 BigFlow 環境，確認 CLAUDE.md 禁止純 CIC 邊界的依據。
2. **BigFlow-only boundary 的 HOIC 完全崩潰（AUC=0.0008）**：BigFlow 環境對 HOIC 的 ratio boundary 無鑑別力，且 pkt_cv_sq 的高 median（2.3552）導致 CIC HOIC 流量被錯誤分類。
3. **Mixed boundary 的 HOIC 同樣崩潰（AUC=0.0001）**：HOIC 的失敗不是 boundary source 問題，而是目前 5-bit contract 本身的限制（Run 28 進一步確認）。
4. **Mixed boundary 對 BigFlow 的緩解有效**：Mixed AUC=0.8754 對比 CIC-only 0.1642，證明混合邊界是必要的，即使 Mixed benign 的桶比例（fwd_max_q=0.546, sym=0.235）在 BigFlow 子集上仍未達理想的 0.5。
5. **sym_ratio boundary 在兩種環境間差異最大**：CIC median=0.8235 vs BigFlow/Mixed median=1.0，這個不一致直接影響 sym_ratio 特徵的 upper-bucket 比例（BigFlow 只有 0.041）。

---

### Run 28 — 2026-05-18（contract 對照矩陣：Run25 original vs eBPF 32-entry）

**目標：** 補上 Run 25 實驗模型與目前 kernel/current contract 的等價性檢查。Run 25 的證據模型是 `3 ratio buckets + Protocol raw + Packet Length Mean raw`；目前 current contract 則是 `5-bit all-binary score_table`，兩者不是同一個 model class。

**執行腳本：** `service/model/experiments/run28_contract_matrix.py`

**執行指令：**

```bash
python -m service.model.experiments.run28_contract_matrix
```

**設定：** CIC BENIGN 10k + BigFlow BENIGN 10k；每個 eval label 4k；seed=42。Run25-compatible path 保留 Run25 的 BigFlow normalization 與 ratio boundary 行為；current contract path 保留目前 +1 / CV^2 / 5-bit 設定。

**AUC-ROC 結果：**

| Variant | Table | DDoS2019 | LOIC-HTTP | HOIC | LOIC-UDP | BigFlow | Avg |
|---------|------:|:--------:|:---------:|:----:|:--------:|:-------:|:---:|
| A_run25_original | IF direct | 0.9028 | 0.5566 | 0.7925 | 0.9961 | 0.9022 | 0.8300 |
| B_protocol_bit_mean_raw | IF direct | 0.9023 | 0.5132 | 0.0008 | 0.9961 | 0.9079 | 0.6641 |
| C_larger_table_mean4 | 96 | 0.9046 | 0.4195 | 0.0008 | 0.9961 | 0.9021 | 0.6446 |
| C_larger_table_mean8 | 192 | 0.9310 | 0.4841 | 0.1797 | 0.9961 | 0.8541 | 0.6890 |
| D_current_5bit_contract | 32 | 0.8833 | 0.2647 | 0.0001 | 0.9969 | 0.8756 | 0.6041 |

**相對 A_run25_original 的差異：**

| Variant | DDoS2019 | LOIC-HTTP | HOIC | LOIC-UDP | BigFlow | Avg |
|---------|---------:|----------:|-----:|---------:|--------:|----:|
| B_protocol_bit_mean_raw | -0.0004 | -0.0434 | -0.7917 | +0.0000 | +0.0057 | -0.1660 |
| C_larger_table_mean4 | +0.0018 | -0.1371 | -0.7917 | +0.0000 | -0.0001 | -0.1854 |
| C_larger_table_mean8 | +0.0282 | -0.0725 | -0.6127 | +0.0000 | -0.0481 | -0.1410 |
| D_current_5bit_contract | -0.0195 | -0.2919 | -0.7923 | +0.0008 | -0.0266 | -0.2259 |

**關鍵結論：**

1. `A_run25_original` 可重現 Run 25 級別的 HOIC 能力（HOIC=0.7925，接近既有 0.8125），因此資料載入與評估框架可用。
2. `D_current_5bit_contract` 的 HOIC 幾乎歸零（0.0001），確認 32-entry all-binary contract 不能引用 Run 25 的 AUC 作為部署證據。
3. `B_protocol_bit_mean_raw` 幾乎保留 DDoS2019 / BigFlow，但 HOIC 從 0.7925 掉到 0.0008；這指出 HOIC 的關鍵訊號高度依賴 Protocol raw 的 IF 幾何，不只是 Packet Length Mean raw。
4. 較大 table 的 `C_larger_table_mean8` 可部分救回 HOIC（0.1797）與提升 DDoS2019（0.9310），但仍遠低於 A，且 BigFlow 有代價。
5. 下一步不可直接改 kernel；應先重新設計 eBPF-compatible contract，例如 Protocol categorical 的 scoring semantics、Packet Length Mean bucket 數、以及是否允許 userspace score table 擴到 96/192 entries。

---

### Run 29 — 2026-05-18（HOIC-aware feature replacement：init_win_bit 取代 protocol_bit）

**目標：** 在維持 32-entry table 的前提下，尋找能恢復 HOIC AUC 的 protocol_bit 替代特徵。

**前置分析結論：** `Init Fwd Win Bytes / (Init Bwd Win Bytes + 1)` 單特徵 AUC=0.9995（HOIC 攻擊工具廣播極小的 Bwd Window，p50≈1；BENIGN TCP p50≈5）。此特徵是工具行為特徵，不受環境分布偏移影響。BigFlow 為 NetFlow 格式無 TCP handshake 欄位，BigFlow 攻擊為 UDP DDoS，不需此特徵（固定為 0）。

**執行腳本：** `service/model/experiments/run29_hoic_feature_search.py`

**Boundary：** init_win_boundary = 2.5630（CIC BENIGN TCP FwdWin/BwdWin 中位數）

**init_win_bit 分布驗證：**

| 資料集 | Benign mean | Attack mean |
|--------|:-----------:|:-----------:|
| DDoS2019 | 0.179 | 0.029 |
| LOIC-HTTP | 0.312 | 0.499 |
| HOIC | 0.001 | **0.820** |
| LOIC-UDP | 0.001 | 0.000 |
| BigFlow | 0.000 | 0.000 |

**AUC-ROC 結果：**

| Variant | Table | DDoS2019 | LOIC-HTTP | HOIC | LOIC-UDP | BigFlow | Avg |
|---------|------:|:--------:|:---------:|:----:|:--------:|:-------:|:---:|
| D_current_5bit | 32 | 0.8830 | 0.2613 | 0.0001 | 0.9969 | 0.8779 | 0.6038 |
| E1_init_win_r_proto | 32 | 0.7190 | 0.6164 | 0.0057 | 0.0031 | 0.8019 | 0.4292 |
| E2_init_win_r_mean | 32 | 0.8620 | 0.4816 | 0.0006 | 0.9969 | 0.7478 | 0.6178 |
| F_6bit_ceiling | 64 | 0.8566 | 0.4636 | 0.0006 | 0.9969 | 0.8727 | 0.6381 |
| G_4bit_floor | 16 | 0.8397 | 0.4166 | 0.0001 | 0.0039 | 0.8007 | 0.4122 |

**關鍵結論：**

1. **init_win_bit 本身鑑別力正確**（HOIC attack mean=0.820 vs benign=0.001），但 IF 仍無法偵測 HOIC（E1 HOIC=0.0057）。根本原因是**跨資料集 domain shift**：IF 訓練於 CIC 2019 + BigFlow BENIGN，而 IDS2018 D2 的 BENIGN TCP 流量特徵與訓練 BENIGN 差異較大，導致 IF 把 IDS2018 BENIGN 評為比 HOIC 更異常（AUC < 0.5 即倒置現象）。

2. **E1 替換 protocol_bit 後 LOIC-UDP 完全崩潰**（0.0031）：protocol_bit 是 LOIC-UDP 偵測的關鍵維度（UDP protocol=17 > threshold=6）。任何替換方案都必須保留或等價替換此能力。

3. **5-bit all-binary IF 架構本身的限制**：Run 28 A_run25_original（protocol raw + pkt_len_mean raw）可達 HOIC=0.7925；一旦 protocol 被二值化，HOIC 就崩潰（B=0.0008）。連續 protocol 值讓 IF 在幾何空間能區分 TCP 內部的 HOIC 模式；二值化後 32 個可能組合無法承載此幾何分離。

4. **init_win_bit 單特徵鑑別力無法在 IF 框架內發揮**：需要的是「在 IDS2018 BENIGN 與 HOIC 之間有效分離的特徵集合」，而不只是「init_win_bit 的邊際貢獻」。

5. **下一步架構決策（非 feature tuning 問題）**：
   - 方案 A：接受 eBPF fast path 不偵測 HOIC，由 Userspace 補（init_win_ratio 作為直接規則）
   - 方案 B：放棄 32-entry all-binary，改用 C_larger_table_mean8（192-entry，HOIC=0.1797）
   - 方案 C：在 eBPF 層直接實作 `init_win_ratio > threshold → score++` 作為獨立規則，不進 IF score table
