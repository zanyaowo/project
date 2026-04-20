# DDoS 內核態防禦架構：閉環控制系統設計

## 概覽

自適應限流、模型蒸餾內核化、流式熵值分析三個方向在架構上構成一個完整的
**閉環控制系統（Closed-Loop Control System）**。

從第一性原理出發，一個防禦系統必須包含三個核心組件：
感測（Sensors）、決策（Decision Making）、執行（Actuation）。

---

## 系統組件對應

| 組件 | 對應方向 | 角色 | 邏輯 |
|------|----------|------|------|
| **感測層 (Sensors)** | 流式熵值分析 | 提取封包「混亂程度」特徵 | 識別流量中的非自然規律（低熵或異常高熵） |
| **決策層 (Processor)** | 模型蒸餾內核化 | 將感測數據轉化為「威脅分數」 | 透過 eBPF Map 中的分位桶邊界進行超高速推論 |
| **執行層 (Actuator)** | 自適應限流 | 根據威脅分數執行「動態調節」 | 減少誤殺，實現系統的抗脆弱性 |

---

## 當前最優特徵方案（Run 25，2026-04-18 確立）

### 分位桶特徵（5 個，N=2）

| 特徵 | 公式 | Kernel 欄位 | 語意 |
|------|------|------------|------|
| **FwdMax_q** | Fwd Pkt Max / Fwd Pkt Mean | `fwd_pkt_max / fwd_pkt_mean` | 前向封包大小分散度；攻擊均一→比率≈1 |
| **Sym_q** | Total Fwd Pkts / Total Bwd Pkts | `fwd_pkts / bwd_pkts` | 流量方向對稱性；單向洪水→極端不對稱 |
| **Pkt_CV_q** | Packet Length Std / Packet Length Mean | `pkt_len_std / pkt_len_mean` | 封包大小變異係數；攻擊均一→低 CV |
| Protocol | 原始值 | `protocol` | TCP=6, UDP=17, ICMP=1 |
| Packet Length Mean | 原始值 | `pkt_len_mean` | 整體封包平均大小 |

**棄用 Shape_q 原因（Min / Fwd Mean）：**
CICFlowMeter 的 `Min Packet Length` 包含 TCP ACK 封包（payload=0），導致 TCP flow 的 min≈0，N=2 邊界退化為 Protocol 代理，跨環境完全失去鑑別力（IDS2018 BigFlow AUC<0.5）。

### 訓練邊界來源

**必須使用 Mixed BENIGN**（CIC 15k + BigFlow 15k = 30k）計算分位桶邊界。

純 CIC 邊界已確認對 BigFlow 嚴重 overfit：CIC 訓練後 BigFlow AUC < 0.4，反轉為低於隨機基線。

### 最終 AUC-ROC（Run 25）

| DDoS2019 | LOIC-HTTP | HOIC | LOIC-UDP | BigFlow |
|:---:|:---:|:---:|:---:|:---:|
| 0.8888 | 0.4744 | 0.8125 | 0.9959 | 0.8769 |

> LOIC-HTTP（0.4744）為 Layer 4 特徵的根本限制，非特徵選擇問題；HTTP 洪水攻擊需應用層特徵才可突破。

---

## 數學模型

### 1. 分位桶推論（Kernel-side）

以交叉乘法在 kernel 判斷分位排名，完全避免浮點除法：

$$\frac{a}{b} < \frac{n_k}{d_k} \iff a \cdot d_k < b \cdot n_k$$

其中 $(n_k, d_k)$ 為預存於 `BPF_MAP_TYPE_ARRAY` 的整數對（SCALE = $2^{20}$）。

N=2 時每個特徵只需 **1 條邊界、1 次交叉乘法比較**，三個比率特徵共 3 次乘法，無迴圈，verifier 負擔最低。

**eBPF C 實作（FwdMax_q）：**

```c
struct bound { __u64 numer; __u64 denom; };

// BPF_MAP_TYPE_ARRAY，max_entries = N-1 = 1（N=2）
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,   __u32);
    __type(value, struct bound);
} fwdmax_bounds SEC(".maps"),
  sym_bounds    SEC(".maps"),
  cv_bounds     SEC(".maps");

static __always_inline __u8
ratio_quantile(__u64 a, __u64 b, void *map) {
    b += 1;  // 避免除以零
    __u32 idx = 0;
    struct bound *bd = bpf_map_lookup_elem(map, &idx);
    if (!bd) return 1;
    // a/b < numer/denom  ↔  a * denom < b * numer
    return (a * bd->denom < b * bd->numer) ? 0 : 1;
}

// 特徵計算（per-flow，於 TC hook）
__u8 fwdmax_q = ratio_quantile(flow->fwd_pkt_max,  flow->fwd_pkt_mean, &fwdmax_bounds);
__u8 sym_q    = ratio_quantile(flow->fwd_pkts,     flow->bwd_pkts,     &sym_bounds);
__u8 pkt_cv_q = ratio_quantile(flow->pkt_len_std,  flow->pkt_len_mean, &cv_bounds);
```

> **溢位分析**：最差情況 `fwd_pkt_max ≈ 65535`（MTU），`denom = 2^20`，乘積 ≈ 6.9×10¹⁰，未超過 u64 上限（1.8×10¹⁹）。

### 2. 熵值特徵提取（待實作）

在 eBPF 中不計算複雜對數，而是計算封包間隔時間（IAT）的簡化熵值：

$$H_{approx} = -\sum (P_i \cdot \text{FixedPointLog}(P_i))$$

其中 `FixedPointLog` 預先存放在 `BPF_MAP_TYPE_ARRAY` 中，避免內核態浮點運算。

### 3. 負反饋執行

限流器流速 $R$ 隨異常評分 $S$ 動態調整：

$$R(t) = R_{max} \cdot (1 - \text{sigmoid}(S(x) - \theta))$$

當異常分數 $S$ 超過閾值 $\theta$ 時，流速迅速收縮。

---

## eBPF 實作策略

### 查表法代替運算

eBPF 最強大的功能是 `BPF_MAP`。與其在內核計算 log 或複雜乘法，不如在 Userspace
預算出結果，以 Map 形式下發到 Kernel。

- Kernel 只做特徵抓取與 Map 查找（分位桶比對）
- Userspace 負責後台模型更新、邊界重算、Map 下發

### 定點數轉換

將所有浮點數轉化為整數（SCALE = $2^{20}$ = 1,048,576），繞過 eBPF 不支援浮點數的限制：

```
邊界比值 1.0 → numer=1048575, denom=1048576
邊界比值 0.72 → numer=758544, denom=1048576
```

### 階段性卸載（Tiered Offloading）

| 層級 | 職責 | 特徵 |
|------|------|------|
| **XDP** | 黑名單比對、特徵計數器更新 | per-flow fwd_pkt_max 追蹤（需新增欄位）|
| **TC** | 分位桶推論、限流執行 | FwdMax_q / Sym_q / Pkt_CV_q 計算 |
| **Userspace（Rust）** | 邊界重算、Map 下發、模型更新 | 以 Mixed BENIGN 計算新邊界 |
| **Userspace（Python）** | 完整 IF 推論（邊緣案例） | 26 個 FEATURE_COLS，Run 07 基準 |

**XDP 新增需求：** per-flow struct 需新增 `fwd_pkt_max` 欄位，在 XDP hook 每封包更新：

```c
if (pkt_len > flow->fwd_pkt_max && direction == FWD)
    flow->fwd_pkt_max = pkt_len;
```

---

## Kernel 推論定義與邊界

### 定義

**Kernel 推論（Kernel-side Inference）** 是指 eBPF 程式在不觸發任何 userspace roundtrip 的情況下，於封包處理路徑（XDP / TC hook）上直接完成以下三個步驟的能力：

```
封包到達 → [1] 特徵計算 → [2] 分位桶比對 → [3] 動作執行（DROP / rate-limit）
               ↑                ↑                  ↑
           整數運算         BPF_MAP 查表       XDP_DROP /
           無浮點除法        交叉乘法比對       TC redirect
```

**與 Userspace 推論的對比：**

| 維度 | Kernel 推論 | Userspace 推論（現況） |
|------|------------|----------------------|
| 決策延遲 | < 1 µs（封包路徑內）| 1–10 ms（ring buffer + IPC）|
| 模型複雜度 | 受 verifier 限制，需蒸餾 | 無限制，可用完整 IF |
| 模型更新 | userspace 計算邊界後下發 BPF_MAP | Python 重訓後 reload |
| 精度損失 | 存在（Run 25: BigFlow AUC −0.12 vs 純 BF 邊界）| 無 |
| 部署複雜度 | 高（需蒸餾 + verifier 通過）| 低（Python 直接推論）|
| 適用場景 | 大流量快速過濾，明顯攻擊特徵 | 邊緣案例、需高精度判斷 |

### 三個必要條件

Kernel 推論要能實現，以下三個條件必須**全部滿足**：

**條件 1：特徵計算可整數化**

所有特徵計算必須只用整數加減乘法與 BPF_MAP 查表。Run 25 驗證的方案：
- 比率特徵（FwdMax/Sym/Pkt_CV）以分位桶交叉乘法取代浮點除法：`a/b < t` ↔ `a × denom < b × numer`
- 分位數邊界預存為整數對 `(numer_k, denom_k)` 於 `BPF_MAP_TYPE_ARRAY`
- N=2 時每特徵只需 1 個整數對，共 3 個 BPF_MAP entries

**條件 2：模型可蒸餾為 BPF_MAP 可儲存的結構**

IsolationForest 完整模型有 200 棵樹 × ~100 節點 = ~20,000 節點，超過 BPF verifier 的指令數限制。Run 25 採用最簡形式：

| 蒸餾形式 | BPF_MAP 結構 | 複雜度 | 驗證狀態 |
|---------|------------|--------|---------|
| **分位桶閾值比對（N=2）** | **ARRAY[1] × 3 個特徵** | **O(3)，3 次乘法** | **Run 25 ✓** |
| 線性加權評分 `S = Σ w_j × q_j` | ARRAY[5] 儲存權重 | O(5) | 待驗證 |
| 單層決策樹（深度 ≤ 4）| ARRAY[16] 葉節點閾值 | O(4) | 待驗證 |
| 完整 IsolationForest | 不可行 | ~20,000 節點 | 超過 kernel 限制 |

**條件 3：動作可在 XDP/TC 層直接執行**

- **XDP_DROP**：封包未進入協議棧，最快，但只能丟棄
- **TC redirect + token bucket**：可做 rate limiting，但延遲略高
- 需注意：per-flow 狀態儲存於 `LRU_HASH` 或 `PERCPU_HASH`，高流量下有鎖競爭風險

### eBPF 計算限制清單

| 限制 | 說明 | 繞過方式 |
|------|------|---------|
| 無浮點運算 | eBPF JIT 不支援 IEEE 754 浮點指令 | 定點數（位移）或分位桶查表 |
| 無動態記憶體 | 不能呼叫 malloc/free | 使用 BPF_MAP 或 per-CPU stack |
| Bounded loop only | verifier 需能靜態確認迴圈終止 | N=2 時無迴圈，直接單次比較 |
| 單函式指令數上限 | 預設 4096 條 BPF 指令（kernel ≥ 5.3 放寬至 100 萬） | 拆分為多個 BPF 函式（tail call）|
| 無遞迴 | verifier 不允許遞迴函式呼叫 | 展開為迭代 |
| Stack 大小 512B | BPF 程式 stack 上限 512 位元組 | 大型陣列放 BPF_MAP |

---

## 架構決策軸心

### 軸心一：推論位置

| 選項 | 延遲 | 精度 | 適用時機 |
|------|------|------|---------|
| **Kernel-side（目標）** | < 1 µs | Run 25 AUC 見上表 | 大流量快速過濾，明顯攻擊型態 |
| Userspace（現況）| 1–10 ms | 完整精度（Run 07: 0.9257）| 邊緣案例、需完整 IF 模型 |

**本專案選擇：分層架構（兩者不互斥）**
- **Layer 1 — Kernel**：過濾特徵分位值極端的明顯攻擊（LOIC-UDP Sym_q 最大桶、DDoS FwdMax_q 最小桶）
- **Layer 2 — Userspace**：處理邊緣案例（LOIC-HTTP 需應用層特徵，Layer 4 無法突破）

### 軸心二：特徵計算方式

| 選項 | Kernel 可行 | 精度（DDoS2019）| 依據 |
|------|:-----------:|:----------------:|------|
| 原始計數器（無比率）| ✓ 直接讀取 | 未測定 | — |
| 浮點 log1p 比率 | ✗ | 0.9114（基準）| Run 16 |
| 分位桶 N=2（Shape_q）| ✓ 交叉乘法 | 0.9418 CIC-only | Run 17（已棄用）|
| **分位桶 N=2（FwdMax_q）** | **✓ 交叉乘法** | **0.8888 Mixed** | **Run 25 ✓ 當前最優** |

**本專案選擇：FwdMax_q 分位桶 N=2**，Mixed BENIGN 邊界，以 `(a × denom) < (b × numer)` 在 kernel 判斷分位排名。

N 值選擇依據（Run 25 掃描）：

| N | DDoS2019 | BigFlow | 平均 | 結論 |
|:---:|:---:|:---:|:---:|------|
| **2** | **0.8888** | **0.8769** | **0.8097** | **最優，eBPF 最簡（1 次比較/特徵）** |
| 4 | 0.8463 | 0.8413 | 0.7967 | 次選 |
| 8 | 0.8444 | 0.8492 | 0.7911 | 最差 |
| 16 | 0.8468 | 0.8549 | 0.8046 | 邊界退化（p50=0）|

### 軸心三：模型蒸餾形式

| 選項 | 狀態 | 備注 |
|------|------|------|
| **分位桶閾值比對（N=2）+ Userspace IF** | **Run 25 已驗證** | **當前方案：Userspace 推論，Kernel 做前置過濾** |
| 線性加權評分 `S = Σ w_j × q_j`（Kernel 端）| 待蒸餾驗證 | AUC 損失需 < 0.02，才值得移至 Kernel |
| 單層決策樹（深度 ≤ 4）| 待驗證 | 可表達非線性邊界，比線性更接近 IF 行為 |
| 完整 IsolationForest | Userspace 已實作 | ~20,000 節點，不可入 Kernel |

#### 線性加權的使用邊界

**N=2 下加線性加權無意義**：

N=2 時每個特徵只有 0/1 兩個值，線性加權退化為對二元特徵做加權求和，
等價於 logistic regression，比 IF 的非線性組合能力更弱（IF 能捕捉
「Sym_q=1 且 FwdMax_q=0」的交叉組合，線性做不到），加了反而退步。

**線性加權的正確用途：Kernel 端推論蒸餾**

目的不是提升 AUC，而是將 Userspace IF 的決策邏輯濃縮為一行 kernel 指令：

```c
// IF 蒸餾後的 kernel 端線性評分
// 權重 w_j 由 Userspace 從訓練好的 IF 蒸餾，存於 BPF_MAP_TYPE_ARRAY
__s64 score = w_fwdmax * fwdmax_q
            + w_sym    * sym_q
            + w_cv     * pkt_cv_q
            + w_proto  * protocol_bucket
            + w_mean   * mean_bucket;

if (score > THRESHOLD) { /* 疑似攻擊，DROP 或 rate-limit */ }
```

優點：完全不需要儲存樹節點，整個推論只有 5 次乘法 + 加法 + 1 次比較。

**何時考慮移至 Kernel：**

```
前提：蒸餾實驗驗證 AUC 損失 < 0.02
  → 是：部署為 Kernel 端線性評分，取代 Userspace roundtrip
  → 否：保持 Userspace IF，Kernel 只做 FPR 極低的前置硬規則過濾
          （例如 Sym_q=1 AND Pkt_CV_q=0 → 直接 DROP，不經 Userspace）
```

**線性加權有意義的前提是升 N**：若未來升至 N=4/8（q_j 為 0~3/0~7 的整數），
特徵帶有連續性資訊，線性加權才能捕捉「第 3 桶比第 1 桶更像攻擊」的梯度。
但 Run 25 已確認 N=2 AUC 優於 N=4，升 N 需要新的理由支持。

---

## Userspace 邊界管理（Rust）

Rust userspace 負責在部署新環境時以目標環境 BENIGN 重校邊界並下發至 BPF_MAP：

```
目標環境 BENIGN 採樣
    ↓
計算 FwdMax_ratio / Sym_ratio / Pkt_CV 的 p50（N=2 邊界）
    ↓
轉換為整數對 (numer = p50 × 2^20, denom = 2^20)
    ↓
bpf_map_update_elem(&fwdmax_bounds, &idx, &bound, BPF_ANY)
    ↓
Kernel 即時生效，無需重新載入 eBPF 程式
```

**混合訓練的 trade-off（Run 24 確認）：**

| 邊界來源 | DDoS2019 | BigFlow | 說明 |
|---------|:---:|:---:|------|
| 純 CIC | 0.9178 | 0.1797 | 同環境最優，跨環境 overfit |
| **Mixed（CIC+BF）** | **0.8888** | **0.8769** | **跨環境均衡，建議部署方案** |
| 純 BigFlow | 未測 | ~0.88 | 僅適用 BigFlow 環境 |

---

## 待研究問題

- [ ] `LruCpuHashmap` 在高流量併發下是否出現 **Lock Contention（鎖競爭）** 或性能下降？
      → 這將直接影響 per-flow fwd_pkt_max 追蹤的 Map 類型選擇
- [ ] 熵值計算的定點數精度是否足夠區分正常流量與攻擊流量？
- [ ] 線性蒸餾（`S = Σ w_j × q_j`，q_j 為分位桶索引）AUC 是否優於純閾值比對？
- [ ] LOIC-HTTP 偵測：應用層特徵（HTTP method、URL 長度）是否可在 TC hook 解析？