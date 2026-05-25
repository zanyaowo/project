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

## 當前部署特徵方案（特徵集 Run 25 確立；contract AUC 以 Run 28/29 為準）

### 分位桶特徵（5 個，N=2）

| 特徵 | 公式 | Kernel 欄位 | 語意 |
|------|------|------------|------|
| **FwdMax_q** | Fwd Pkt Max / Fwd Pkt Mean | `fwd_pkt_max / fwd_pkt_mean` | 前向封包大小分散度；攻擊均一→比率≈1 |
| **Sym_q** | Total Fwd Pkts / Total Bwd Pkts | `fwd_pkts / bwd_pkts` | 流量方向對稱性；單向洪水→極端不對稱 |
| **Pkt_CV_q** | (Packet Length Std / Packet Length Mean)^2 | `cv_numer / pkt_len_sum^2` | 封包大小變異係數平方；kernel 避免 sqrt |
| Protocol | 原始值 | `protocol` | TCP=6, UDP=17, ICMP=1 |
| Packet Length Mean | 原始值 | `pkt_len_mean` | 整體封包平均大小 |

**棄用 Shape_q 原因（Min / Fwd Mean）：**
CICFlowMeter 的 `Min Packet Length` 包含 TCP ACK 封包（payload=0），導致 TCP flow 的 min≈0，N=2 邊界退化為 Protocol 代理，跨環境完全失去鑑別力（IDS2018 BigFlow AUC<0.5）。

### 訓練邊界來源

> **當前評估範圍（2026-05-25）：CIC-IDS-2019 only**。以下 Mixed BENIGN 規則為跨資料集泛化需求；範圍限定 CIC 2019 時使用 CIC BENIGN only 邊界（`get_normal_sample_from_files`）。

**跨資料集泛化時必須使用 Mixed BENIGN**（CIC 15k + BigFlow 15k = 30k）計算分位桶邊界。

純 CIC 邊界已確認對 BigFlow 嚴重 overfit：CIC 訓練後 BigFlow AUC < 0.4，反轉為低於隨機基線。

### AUC-ROC：證據模型 ≠ 部署 contract（Run 28/29 確認，2026-05-18）

> ⚠️ **下表 Run 25 那行不是部署證據。** Run 25 的證據模型 Protocol/Packet Length Mean 為 raw 連續值直接丟 IsolationForest（IF-direct，`table_size=None`），**與本文件描述的全二值化 32-entry score table contract 是不同 model class**。Run 28 對照矩陣（`service/model/experiments/run28_contract_matrix.py`）在同資料同設定下證實：一旦把 Protocol/PktLenMean 二值化（即實際 ship 的 `distill_export.py` 輸出），HOIC 從 0.79 崩到 0.0001，平均 AUC 從 0.81 掉到 0.60。

| 模型 | Run 28 對應 | DDoS2019 | LOIC-HTTP | HOIC | LOIC-UDP | BigFlow | Avg |
|------|------|:---:|:---:|:---:|:---:|:---:|:---:|
| Run 25 證據（IF-direct；Protocol/PktLenMean raw、CV 未平方） | `A_run25_original` | 0.8888 | 0.4744 | 0.8125 | 0.9959 | 0.8769 | 0.8097 |
| **實際部署（5-bit all-binary，32-entry，`distill_export.py`）** | `D_current_5bit_contract` | 0.8833 | 0.2647 | **0.0001** | 0.9969 | 0.8756 | **0.6041** |

> LOIC-HTTP（0.4744，Run 25 證據模型）為 Layer 4 特徵的根本限制，非特徵選擇問題；HTTP 洪水攻擊需應用層特徵才可突破。
> HOIC 在部署 contract 下完全失效（0.0001），不是 boundary overfit，而是 Protocol 二值化抹掉 IF 在 TCP 內部的幾何分離能力（Run 28 結論 #3、Run 29 結論 #3）。後續所有引用部署 AUC 的決策必須用 `D` 那行。

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
__u64 pkt_cv_sq_numer = flow->pkt_len_sum_sq * flow->total_pkts - flow->pkt_len_sum * flow->pkt_len_sum;
__u8 pkt_cv_q = ratio_quantile(pkt_cv_sq_numer, flow->pkt_len_sum * flow->pkt_len_sum, &cv_bounds);
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
| **Userspace（Rust）** | 邊界重算、Map 下發、自適應校準 | 以 Mixed BENIGN 計算新邊界；adaptive boundary（`boundary_updater.rs`）|

> ⚠️ **規劃中，尚未實作：** 「Userspace（Python）完整 IF 推論（邊緣案例）」為 Layer 2 設計目標，**目前未實作**——`firewall` userspace 僅有 logging（`logger.rs`）+ adaptive boundary（`boundary_updater.rs`），無任何 runtime IF 推論路徑。**離線** IF 程式碼存在於 `service/model/`（`train.py`/`infer.py`/`trainer/if_.py`），但與 runtime 未接通。現況唯一推論層為 eBPF fast-path；HOIC 等為其已知限制。Layer 2 的集成步驟待撰寫（計畫文件尚未建立）。

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

**Kernel 推論（現況）vs Userspace 完整 IF（Layer 2，規劃中未實作）：**

> 右欄為 **Layer 2 設計目標**，目前未實作（集成計畫待撰寫）。左欄是現況唯一推論層。右欄數字為規劃預期，非已驗證。

| 維度 | Kernel 推論（現況）| Userspace 完整 IF（Layer 2，規劃）|
|------|------------|----------------------|
| 決策延遲 | < 1 µs（封包路徑內）| 1–10 ms（ring buffer + IPC）|
| 模型複雜度 | 受 verifier 限制，需蒸餾 | 無限制，可用完整 IF |
| 精度損失 | 存在（Run 28 D：HOIC 0.0001、avg 0.60）| 預期無（取決於特徵重建完整度）|
| 適用場景 | 全部流量；HOIC 等為已知限制 | 邊緣案例（需特徵重建管線就位）|

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

| 選項 | 延遲 | 精度 | 狀態 |
|------|------|------|---------|
| **Kernel-side（現況唯一推論層）** | < 1 µs | 部署 contract = Run 28 D（HOIC 0.0001、avg 0.60，見「最終 AUC-ROC」）| 已實作 |
| Userspace 完整 IF（Layer 2）| 1–10 ms | 預期完整精度（取決於特徵重建）| **規劃中，未實作** |

**目標架構：分層（Layer 1 Kernel + Layer 2 Userspace）；現況：僅 Layer 1 已實作。**
Layer 2（Userspace 完整 IF）為設計目標但尚未接通 runtime（離線 IF 在 `service/model/`，未與 `firewall` userspace 整合）。在 Layer 2 就位前，LOIC-HTTP（Layer 4 特徵無法突破，Layer 2 用同樣 Layer 4 特徵亦無法救）、HOIC（Protocol 二值化抹掉 IF 幾何，Run 28/29）皆為 **eBPF fast-path 的已知限制**。HOIC 的低成本替代解（eBPF 端 `init_win_ratio` 硬規則，無需整個 Layer 2 IF）見「待研究問題」；Layer 2 集成步驟待撰寫。

### 軸心二：特徵計算方式

| 選項 | Kernel 可行 | 精度（DDoS2019）| 依據 |
|------|:-----------:|:----------------:|------|
| 原始計數器（無比率）| ✓ 直接讀取 | 未測定 | — |
| 浮點 log1p 比率 | ✗ | 0.9114（基準）| Run 16 |
| 分位桶 N=2（Shape_q）| ✓ 交叉乘法 | 0.9418 CIC-only | Run 17（已棄用）|
| 分位桶 N=2（FwdMax_q）| ✓ 交叉乘法 | 0.8888（**IF-direct 證據，非部署 contract**）| Run 25（見「最終 AUC-ROC」caveat）|

**本專案選擇：FwdMax_q 分位桶 N=2**，CIC 2019 BENIGN 邊界（跨資料集泛化時改用 Mixed BENIGN），以 `(a × denom) < (b × numer)` 在 kernel 判斷分位排名。

> ⚠️ 下表 N 掃描全部走 **IF-direct（Protocol/PktLenMean raw）**，**從未在實際 score-table contract 上驗證**（Run 17/22/25 皆然）。「N=2 最優」僅對 IF-direct 成立；部署 contract 的 N 行為未測。新 N-scan 必須走 binary contract path（仿 `run28_contract_matrix.py` D 結構）。

N 值選擇依據（Run 25 掃描，**IF-direct 證據，非部署 contract**）：

| N | DDoS2019 | BigFlow | 平均 | 結論（僅限 IF-direct）|
|:---:|:---:|:---:|:---:|------|
| 2 | 0.8888 | 0.8769 | 0.8097 | IF-direct 下最優，eBPF 最簡 |
| 4 | 0.8463 | 0.8413 | 0.7967 | — |
| 8 | 0.8444 | 0.8492 | 0.7911 | — |
| 16 | 0.8468 | 0.8549 | 0.8046 | 邊界退化（p50=0）|

### 軸心三：模型蒸餾形式

| 選項 | 狀態 | 備注 |
|------|------|------|
| **分位桶 N=2 + 32-entry score-table（全 kernel）** | **現況部署（唯一已實作）** | Run 28 D；HOIC 0.0001、avg 0.60。Userspace IF（Layer 2）規劃中未實作 |
| 線性加權評分 `S = Σ w_j × q_j`（Kernel 端）| 待蒸餾驗證 | AUC 損失需 < 0.02，才值得移至 Kernel |
| 單層決策樹（深度 ≤ 4）| 待驗證 | 可表達非線性邊界，比線性更接近 IF 行為 |
| 完整 IsolationForest | **Layer 2 規劃中（離線在 `service/model/`，runtime 未接通）**| ~20,000 節點，不可入 Kernel；屬 Userspace Layer 2 |

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

if (score >= THRESHOLD) { /* 疑似攻擊，DROP 或 rate-limit */ }
```

優點：完全不需要儲存樹節點，整個推論只有 5 次乘法 + 加法 + 1 次比較。

**何時考慮移至 Kernel：**

```
前提：蒸餾實驗驗證 AUC 損失 < 0.02（基準為現況 kernel 32-entry score-table）
  → 是：部署為 Kernel 端線性評分，取代現況 32-entry 查表
  → 否：保持現況 kernel 32-entry score-table（Layer 2 Userspace IF 就位前無退路）
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

---

## 蒸餾策略分析

針對 Isolation Forest（IF）的 eBPF kernel-side 蒸餾，評估了六種常見策略：

| 策略 | Per-feature 非線性 | 特徵交互 | Kernel 計算量 | 精度預期 |
|------|:------------------:|:--------:|:------------:|:--------:|
| 1. 分位桶閾值比對 | O | X | O(d) 比較 | 中 |
| 2. 線性加權評分 | X | 部分 | O(d) 乘加 | 低~中 |
| 3. 分位桶 + 線性加權 | O | 部分 | O(d+N) | 中 |
| 4. 淺層決策樹 | O | O | O(depth) | 中~高 |
| **5. 分位桶 + 查表法** | **O** | **O（全組合）** | **O(d) + O(1)** | **高** |
| 6. 分段線性近似 | O | X | O(K*d) | 中~高 |

### IF 特性對策略選擇的影響

IF 的核心機制是**逐特徵隨機分裂**，異常分數本質上是各特徵邊際貢獻的加法模型：

```
S(x) ≈ Σ g_j(x_j)    ← 每個特徵的邊際貢獻（非線性）
```

這意味著：
- **「無法捕捉特徵交互」對 IF 蒸餾幾乎不是問題** — IF 本身就不依賴強交互
- **真正的分界線是能否捕捉 per-feature 非線性** — 路徑長度與特徵值的關係是非線性的
- 策略 4、5 的「交互優勢」大幅貶值，策略 2 的「無非線性」仍是硬傷

### 當前選擇（2026-04-28 確立）

採用**策略 5（分位桶 N=2 + 查表法）**：5 個特徵共 2^5 = 32 種桶組合，userspace 預先計算每種組合的 IF 分數，存入 `SCORE_TABLE[32]`；kernel 端只做 5 次邊界比較 + 1 次陣列查表。

> ⚠️ **2026-05-18 修正：** 策略 5 的「機制」（查表捕捉特徵交互）成立，但**目前 32-entry all-binary 實例的 AUC 不佳**——Run 28/29 證實此 contract HOIC=0.0001、avg=0.60（見「最終 AUC-ROC」D 行）。真因是 Protocol/PktLenMean 二值化抹掉 IF 幾何（與比率特徵 N 正交）。查表法本身不是問題（Run 28 C 192-entry 保 Protocol categorical 可部分救 HOIC）；待決架構問題見下方「待研究問題」。本段描述的是現況部署實例，非「已驗證最優」。

**優勢：**
- 能捕捉特徵交互（例如「Sym_q=1 且 Pkt_CV_q=0」的組合分數可獨立設定）
- kernel 只需整數比較 + 索引計算，計算量 O(d) + O(1)
- 不需儲存 IF 樹節點，整個推論只有 5 次比較 + 1 次查表

**BPF_MAP 結構：**
```c
// 5 個特徵各 1 個邊界（N=2 中位數）→ 3 個 ARRAY map（比率特徵）
// 1 個 SCORE_TABLE ARRAY，32 個 entries（2^5 種組合）
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 32); ... } SCORE_TABLE;

// kernel 端評分；正式 bit order 由 kernel_model_contract.md 定義：
// bit0 protocol, bit1 pkt_len_mean, bit2 fwd_max_q, bit3 sym_ratio, bit4 pkt_cv_sq
__u32 bucket_idx = proto_bucket
                 | (mean_bucket   << 1)
                 | (fwdmax_q      << 2)
                 | (sym_q         << 3)
                 | (pkt_cv_sq_q   << 4);
__s32 *score = bpf_map_lookup_elem(&SCORE_TABLE, &bucket_idx);
if (score && *score >= THRESHOLD) return XDP_DROP;
```

> **早期設計（2026-04-13）曾選擇策略 3（N=16 + 線性加權），但 Run 25 確認 N=2 全面優於 N≥4，且查表法比線性加權能捕捉特徵交互。現已棄用 N=16 + 線性加權方案。**

---

## 分位桶切割方法

> **目前使用**: Equal-Frequency（N=2 時即 p50 中位數切割）  
> **狀態**: 日後探討，記錄於此供未來實驗參考

### 方法總覽

| # | 方法 | 切點邏輯 | 優點 | 缺點 | 適用場景 |
|---|------|---------|------|------|---------|
| 1 | Equal-Frequency | 每桶樣本數相同（p50 for N=2） | 簡單穩定、對離群值魯棒 | 切點不一定在分佈密度變化處 | 通用場景、首選基線 |
| 2 | Equal-Width | 等間距切割 `(max-min)/N` | 直覺、實作最簡 | 受離群值嚴重影響、桶分佈極不均 | 特徵分佈接近均勻時 |
| 3 | Optimal Threshold | 最大化 IF score 差異的切點（如 Youden's J） | 直接對齊異常偵測目標 | 需要 label 或 IF score 作為 proxy | 有明確異常/正常分群 |
| 4 | IF Score-Driven | 在 IF 的 per-feature 分數 g_j(x) 上找拐點 | 捕捉 IF 內部的非線性轉折 | 依賴 IF 模型品質、計算較複雜 | IF 蒸餾專用 |
| 5 | Decision Tree Split | 用深度-1 決策樹找最佳分割點 | 有理論基礎（Gini/Entropy） | 對 N=2 等價於 Optimal Threshold | 多桶場景 |
| 6 | KDE Valley | Kernel Density Estimation 找密度谷點 | 在多模態分佈中找自然分界 | 需調 bandwidth、不保證找到 N-1 個谷 | 已知多模態特徵 |

### 目前選擇：Equal-Frequency

Python 模型端的 `compute_quantile_boundaries()` 使用 `np.quantile` 計算等頻分位點。N=2 時只有一個切點即 p50（中位數），將樣本均分為兩半。

選擇原因：
- **穩定性**: 不受離群值影響，適合網路流量的長尾分佈
- **無需額外依賴**: 不需要 IF score 或 label 資訊
- **實驗驗證**: N=2 + equal-frequency 在當前資料集上 AUC 表現已足夠

### 未來探討方向

1. **Optimal Threshold（方法 3）**: 對每個特徵分別計算 IF score，找使正常/異常分群最分離的切點。預期能提升 N=2 的表達力，但需要 IF score 作為 proxy label。

2. **IF Score-Driven（方法 4）**: 計算 per-feature partial dependence `g_j(x_j)`，在曲線的最大曲率變化處切割。理論上最能保留 IF 的決策邊界，但實作複雜度較高。

3. **混合策略**: 不同特徵使用不同切割方法。例如 Protocol（離散值）用 equal-frequency，Pkt_CV（連續值）用 optimal threshold。

---

## 驗證計劃

| 測試項目 | 方法 | 通過標準 |
|---------|------|---------|
| Verifier 通過 | `FirewallController::load()` 成功 | 無 verifier error |
| 模型禁用回退 | `MODEL_CONFIG.enabled=0`，送流量 | 所有封包 PASS，無效能退化 |
| 已知模型評分 | 載入固定邊界，送已知特徵的合成封包 | kernel 分位桶索引與 Python 離線計算一致 |
| 特徵正確性 | 比對 kernel 分位桶索引 vs Python 計算 | 桶索引完全一致 |
| 效能影響 | 啟用/禁用模型時測量 XDP throughput | 額外開銷 < 5% pps 下降 |
| 熱更新正確性 | 運行中更換模型檔 | 新舊模型切換無封包丟失（log-only 模式） |

---

## 開發時序記錄

| 日期 | 事項 |
|------|------|
| 2026-02-13 | TC egress 流量紀錄開發 |
| 2026-02-20 | 新增 ICMP 協議解析 |
| 2026-04-13 | kernel_inference_design v1.0：N=16 分位桶 + 線性加權方案（後被 Run 25 推翻） |
| 2026-04-18 | Run 25 確立最終方案：N=2 + FwdMax_q + Mixed BENIGN |
| 2026-04-28 | 架構轉向：改為 N=2 + 32 entry score table；Shape_Ratio → FwdMax_q |

**已知問題（待處理）：**
- `proto_h` 欄位的 Feature hashing 值（16）過小，Protocol 為 u8（256），容易碰撞
- IPv6 支援尚未實作（XDP 目前直接丟棄 IPv6 封包）
- `syn_cookie` ACK 驗證已實作但邏輯待審查
- `logger.rs` 內舊的 `ModelFeature` 建構邏輯可清理