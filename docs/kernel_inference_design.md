# Kernel-Side ML Inference 架構設計文件

> **版本**: v1.0  
> **日期**: 2026-04-13  
> **分支**: feat/ebpf-core-mvp  
> **狀態**: 設計確認，待實作

---

## 1. 背景與目標

### 1.1 現況

現有防火牆已具備完整的封包解析、雙向 session 追蹤（`LruPerCpuHashMap`）、SYN cookie 防護、IP 黑名單、以及透過 RingBuf 向 userspace 傳送事件的管線。Userspace 端的 `Logger` 會從 session 資料建構 `ModelFeature`，但**建構後直接丟棄**，無任何推論或異常偵測。

### 1.2 目標

在 XDP 封包處理路徑中實現 **kernel-side 異常評分**，形成「感測 + 決策」兩層閉環：

- **感測層**: IAT（封包間隔時間）熵值特徵提取
- **決策層**: 蒸餾模型推論（分位桶量化 + 線性加權評分）

自適應限流（執行層）留到下一階段。

---

## 2. 蒸餾策略選擇

### 2.1 策略評估過程

針對 Isolation Forest（IF）的 eBPF kernel-side 蒸餾，評估了六種常見策略：

| 策略 | Per-feature 非線性 | 特徵交互 | Kernel 計算量 | 精度預期 |
|------|:------------------:|:--------:|:------------:|:--------:|
| 1. 分位桶閾值比對 | O | X | O(d) 比較 | 中 |
| 2. 線性加權評分 | X | 部分 | O(d) 乘加 | 低~中 |
| **3. 分位桶 + 線性加權** | **O** | **部分** | **O(d+N)** | **中** |
| 4. 淺層決策樹 | O | O | O(depth) | 中~高 |
| 5. 查表法 | O | O | O(1) | 高 |
| 6. 分段線性近似 | O | X | O(K*d) | 中~高 |

### 2.2 IF 特性對策略選擇的影響

IF 的核心機制是**逐特徵隨機分裂**，異常分數本質上是各特徵邊際貢獻的加法模型：

```
S(x) ≈ Σ g_j(x_j)    ← 每個特徵的邊際貢獻（非線性）
```

這意味著：
- **「無法捕捉特徵交互」對 IF 蒸餾幾乎不是問題** — IF 本身就不依賴強交互
- **真正的分界線是能否捕捉 per-feature 非線性** — 路徑長度與特徵值的關係是非線性的
- 策略 4、5 的「交互優勢」大幅貶值，策略 2 的「無非線性」仍是硬傷

### 2.3 最終決策：策略 3（分位桶 N=16 + 線性加權）

**選擇理由：**

1. **分位桶捕捉 per-feature 非線性** — 將 `g_j(x_j)` 離散化為階梯函數
2. **線性加權匹配 IF 的加法結構** — `S = Σ w_j × q_j` 天然對齊 IF 的分數加法語義
3. **N=16 已足夠** — 實驗結果顯示 N=16 與 N=256 的 AUC 差距不大，N 越大反而 AUC 下降

**演算法：**
```
Step 1: 對每個特徵 x_j，查分位桶 map 找到桶索引 q_j ∈ [0, 15]
Step 2: 計算異常分數 S = Σ w_j × q_j（全整數運算，權重為定點數 ×1024）
Step 3: if S > threshold → 異常（XDP_DROP 或 log-only）
```

---

## 3. 特徵定義

### 3.1 特徵清單（5 個特徵）

| # | 特徵名稱 | 類型 | 定義 | 資料來源 |
|---|----------|------|------|---------|
| 0 | Protocol | 絕對值 | IP 協定號 | `SessionKey.proto` |
| 1 | Pkt_Len_Mean | 絕對值(交叉乘法) | 平均封包長度 | `total_bytes / total_pkts` |
| 2 | Shape_Ratio | 比例 | 封包形狀：Min / Fwd Mean | `min_pkt_len × orig_pkts / orig_bytes` |
| 3 | Sym_Ratio | 比例 | 方向對稱：Fwd / Bwd packets | `orig_pkts / resp_pkts` |
| 4 | Pkt_CV | 比例 | 封包長度變異係數：Std / Mean | `CV² = (sum_sq×n - sum²) / sum²` |

> **未來擴充**: IAT 熵值將作為第 6 個特徵加入，本次先建好 IAT 基礎設施。

### 3.2 eBPF 計算映射

所有比例特徵使用**交叉乘法**避免 eBPF 中的除法運算：

```
原始比較:  val_numer / val_denom  <=  bound_numer / bound_denom
交叉乘法:  val_numer × bound_denom  <=  bound_numer × val_denom
```

| # | val_numer | val_denom | 備註 |
|---|-----------|-----------|------|
| 0 | `proto` | 1 | 絕對值，直接比較 |
| 1 | `orig_bytes + resp_bytes` | `orig_pkts + resp_pkts` | mean = bytes/pkts |
| 2 | `min_pkt_len × orig_pkts` | `orig_bytes` | shape = min × pkts / bytes |
| 3 | `orig_pkts` | `resp_pkts` | sym = fwd_pkts / bwd_pkts |
| 4 | `sum_sq × n - sum²` | `sum²` | CV² 避免 sqrt |

### 3.3 特殊處理

**Pkt_CV（CV²）**: 儲存 CV² 的桶邊界（userspace 預先平方），kernel 端完全避免 sqrt。

**除零處理**: 交叉乘法天然處理 — 當 `val_denom = 0` 時，右側為 0，`val_numer × bound_denom <= 0` 只在 `val_numer = 0` 時成立，否則自動落入最高桶（最異常）。

**溢位處理**: `u64 × u64` 交叉乘法可能溢位。對策：當任一操作數 > `u32::MAX` 時，兩側同時右移 16 位再比較。

---

## 4. 新增 eBPF Maps

### 4.1 Map 清單

| Map 名稱 | 類型 | 大小 | 用途 |
|----------|------|------|------|
| `QUANTILE_BOUNDS` | `Array<QuantileBound>` | 80 entries (5×16) | 分位桶邊界 |
| `MODEL_WEIGHTS` | `Array<ModelWeight>` | 5 entries | 線性加權權重 |
| `MODEL_CONFIG` | `Array<ModelConfig>` | 1 entry | 模型開關/閾值/動作 |
| `ENTROPY_LOG_TABLE` | `Array<u32>` | 256 entries | 熵值查表（定點數） |
| `IAT_STATE` | `LruHashMap<SessionKey, IatState>` | 65536 entries | Per-flow IAT 追蹤 |

### 4.2 記憶體估算

| Map | 計算 | 大小 |
|-----|------|------|
| QUANTILE_BOUNDS | 80 × 24B | ~1.9 KB |
| MODEL_WEIGHTS | 5 × 8B | 40 B |
| MODEL_CONFIG | 1 × 16B | 16 B |
| ENTROPY_LOG_TABLE | 256 × 4B | 1 KB |
| IAT_STATE | 65536 × (16+32)B | ~3 MB |
| **新增合計** | | **~3 MB** |
| 既有 SESSIONS | 65536 × (16+64)B per CPU | ~5.2 MB × CPU |

---

## 5. 資料結構定義

### 5.1 新增共享結構（firewall-common）

```rust
/// 分位桶邊界
#[repr(C)]
pub struct QuantileBound {
    pub value: u64,    // 絕對特徵桶上界
    pub numer: u64,    // 比例特徵邊界分子
    pub denom: u64,    // 比例特徵邊界分母
}

/// 模型權重（定點數 ×1024）
#[repr(C)]
pub struct ModelWeight {
    pub weight: i32,
    pub _padding: [u8; 4],
}

/// 模型設定
#[repr(C)]
pub struct ModelConfig {
    pub enabled: u32,       // 0=關閉, 1=啟用
    pub feature_count: u32, // 特徵數
    pub threshold: i32,     // 評分閾值（定點數 ×1024）
    pub action: u32,        // 0=log-only, 1=XDP_DROP
}

/// Per-flow IAT 追蹤狀態
#[repr(C)]
pub struct IatState {
    pub last_timestamp_ns: u64,
    pub bucket_counts: [u16; 8],   // 8 個時間區間桶
    pub total_packets: u32,
    pub _padding: [u8; 4],
}
```

### 5.2 既有結構修改

**SessionValue 新增欄位：**
```rust
pub min_pkt_len: u16,       // 整個 flow 最小封包長度（Shape_Ratio 用）
pub pkt_len_sum_sq: u64,    // Σ(pkt_len²)（Pkt_CV 用）
```

**SessionEvent 新增欄位：**
```rust
pub score: i32,             // 模型評分，傳遞給 userspace
```

### 5.3 常數定義

```rust
pub const FEATURE_COUNT: u32 = 5;
pub const BUCKET_COUNT: u32 = 16;
pub const CROSS_MULT_MASK: u32 = 0b11110;  // features 1,2,3,4 需要交叉乘法

// 特徵索引
pub const FEAT_PROTOCOL: u32 = 0;
pub const FEAT_PKT_LEN_MEAN: u32 = 1;
pub const FEAT_SHAPE_RATIO: u32 = 2;
pub const FEAT_SYM_RATIO: u32 = 3;
pub const FEAT_PKT_CV: u32 = 4;
```

---

## 6. Kernel 端演算法

### 6.1 評分流程（scorer.rs）

```
fn score_session(sv: &SessionValue, sk: &SessionKey) -> Option<i32>:

    config = MODEL_CONFIG[0]
    if config.enabled == 0 → return None

    // 1. 計算特徵的 numerator / denominator
    total_bytes = sv.orig_bytes + sv.resp_bytes
    total_pkts  = sv.orig_pkts + sv.resp_pkts
    cv2_numer   = sv.pkt_len_sum_sq × total_pkts  saturating_sub  total_bytes × total_bytes

    features = [
        (proto,                          1                    ),  // 絕對值
        (total_bytes,                    total_pkts           ),  // mean
        (min_pkt_len × sv.orig_pkts,     sv.orig_bytes        ),  // shape
        (sv.orig_pkts,                   sv.resp_pkts         ),  // sym
        (cv2_numer,                      total_bytes × total_bytes),  // cv²
    ]

    // 2. 對每個特徵找分位桶
    score = 0
    FOR feat_idx = 0..5 (compile-time bounded):
        bucket = 15   // default: 最高桶（最異常）
        is_cross = (CROSS_MULT_MASK >> feat_idx) & 1 == 1

        FOR b = 0..16 (compile-time bounded):
            bound = QUANTILE_BOUNDS[feat_idx × 16 + b]
            IF is_cross:
                IF val_numer × bound.denom <= bound.numer × val_denom:
                    bucket = b; BREAK
            ELSE:
                IF val_numer <= bound.value:
                    bucket = b; BREAK

        weight = MODEL_WEIGHTS[feat_idx].weight
        score += weight × bucket

    RETURN Some(score)
```

### 6.2 IAT 熵值計算（iat.rs）

```
fn update_iat(key: &SessionKey, current_ts: u64) -> u32:

    state = IAT_STATE.get_ptr_mut(key)
    if state is None:
        初始化 IatState { last_ts = current_ts, counts = [0;8], total = 0 }
        INSERT into IAT_STATE
        return 0

    delta = current_ts - state.last_timestamp_ns
    state.last_timestamp_ns = current_ts

    // if-else chain 分類（非迴圈，verifier 友好）
    bucket = match delta:
        < 1ms   → 0
        < 10ms  → 1
        < 100ms → 2
        < 500ms → 3
        < 1s    → 4
        < 5s    → 5
        < 10s   → 6
        else    → 7

    state.bucket_counts[bucket] += 1  (saturating)
    state.total_packets += 1

    // 近似 Shannon 熵
    entropy_sum = 0
    FOR i = 0..8 (bounded):
        if bucket_counts[i] > 0:
            idx = (count × 255) / total, clamp [0, 255]
            entropy_sum += ENTROPY_LOG_TABLE[idx]
    return entropy_sum    // 定點數 ×1024
```

`ENTROPY_LOG_TABLE[i]` 在 userspace 預算：`round(-p × log2(p) × 1024)` 其中 `p = i/256`。

### 6.3 XDP 主流程修改

```
try_xdp_firewall:
    pkt = parse_packet(ctx)

    // SYN cookie（不變）
    if TCP SYN  → send_syn_cookie()
    if TCP ACK  → validate cookie

    // 黑名單（不變）
    if is_blocked(src_ip) → XDP_DROP

    // Session 更新（修改回傳值）
    session = update_session(params)  → Option<SessionValue>

    // ── 新增 ──
    // IAT 更新
    iat_entropy = iat::update_iat(&session_key, bpf_ktime_get_ns())

    // ML 評分
    if let Some(sv) = session:
        if let Some(score) = scorer::score_session(&sv, &key):
            config = MODEL_CONFIG[0]
            if score > config.threshold && config.action == 1:
                return XDP_DROP

    // 事件提交（新增 score 欄位）
    submit_event(params, score)

    XDP_PASS
```

TC egress 路徑**不變**（僅做 session update + blocklist，不評分）。

---

## 7. Userspace 端設計

### 7.1 模型載入器（model_loader.rs）

**職責：**
1. 從 JSON 檔案解析模型參數
2. 寫入 BPF maps（QUANTILE_BOUNDS, MODEL_WEIGHTS, MODEL_CONFIG）
3. 預算 entropy log table 並寫入 ENTROPY_LOG_TABLE
4. 提供熱更新介面

**模型 JSON 格式：**
```json
{
  "feature_count": 5,
  "threshold": 8500,
  "features": [
    {
      "name": "protocol",
      "type": "absolute",
      "quantile_bounds": [1, 6, 17, 58, 89, 103, 115, 128, 142, 156, 170, 184, 200, 220, 240, 255],
      "weight": 120
    },
    {
      "name": "pkt_len_mean",
      "type": "ratio",
      "quantile_bounds": [
        {"numer": 64,  "denom": 1},
        {"numer": 128, "denom": 1},
        ...
      ],
      "weight": 150
    },
    {
      "name": "shape_ratio",
      "type": "ratio",
      "quantile_bounds": [
        {"numer": 1, "denom": 100},
        {"numer": 1, "denom": 10},
        ...
      ],
      "weight": 200
    },
    {
      "name": "sym_ratio",
      "type": "ratio",
      "quantile_bounds": [
        {"numer": 1, "denom": 50},
        ...
      ],
      "weight": 180
    },
    {
      "name": "pkt_cv",
      "type": "ratio_squared",
      "quantile_bounds": [
        {"numer": 1, "denom": 10000},
        ...
      ],
      "weight": 160
    }
  ]
}
```

> `type: "ratio_squared"` 表示桶邊界儲存的是 CV² 值（userspace 預先平方）。

### 7.2 熱更新機制

```
1. MODEL_CONFIG.enabled = 0        （停用模型，XDP 路徑 skip 評分）
2. 逐一更新 QUANTILE_BOUNDS entries
3. 逐一更新 MODEL_WEIGHTS entries
4. 更新 MODEL_CONFIG（threshold, action 等）
5. MODEL_CONFIG.enabled = 1        （重新啟用）
```

不一致窗口：step 1~5 之間模型處於停用狀態，封包正常 PASS，不會出現半新半舊的評分。

### 7.3 設定檔擴充

```toml
# config.toml 新增

[model]
enabled = true
model_file = "model.json"
action = "log"           # "log" = pass + 記錄分數, "drop" = 超過閾值直接丟棄
hot_reload = true

[maps]
# 既有
block_list_size = 1024
session_table_size = 65536
event_ring_buffer_size = 4096
# 新增
quantile_bounds_size = 80       # 5 features × 16 buckets
model_weights_size = 5
model_config_size = 1
iat_state_size = 65536
entropy_log_table_size = 256
```

---

## 8. BPF Verifier 合規分析

| 約束 | 本設計的應對 |
|------|------------|
| **無浮點運算** | 全整數：定點數 ×1024、交叉乘法避免除法、CV² 避免 sqrt |
| **Bounded loops** | 外層 5 次（特徵數）× 內層 16 次（桶數）= 80 次，均為編譯期常數 |
| **Stack 512B** | features 陣列 ~80B + 局部變數 ~40B = ~120B，充裕 |
| **Map null check** | 所有 `Array.get()` 回傳 `Option`，match/if-let 處理 |
| **無遞迴** | 無 |
| **無動態記憶體** | 所有狀態存 BPF Map |
| **單函式指令數** | ~80 迭代 × ~10 指令/迭代 ≈ 800 指令，遠低於 4096 限制 |

---

## 9. 修改檔案清單

### 新建檔案
| 檔案 | 用途 |
|------|------|
| `firewall-common/src/model.rs` | 模型相關共享型別與常數 |
| `firewall-common/src/iat.rs` | IAT 共享型別 |
| `firewall-ebpf/src/scorer.rs` | Kernel 端評分引擎 + 模型 Maps |
| `firewall-ebpf/src/iat.rs` | Kernel 端 IAT 追蹤 + IAT Map |
| `firewall/src/lib/model_loader.rs` | Userspace 模型載入器 |

### 修改檔案
| 檔案 | 修改內容 |
|------|---------|
| `firewall-common/src/lib.rs` | 加入 `pub mod model;` 和 `pub mod iat;` |
| `firewall-common/src/session.rs` | SessionValue 新增 `min_pkt_len`, `pkt_len_sum_sq`；SessionEvent 新增 `score` |
| `firewall-common/build.rs` | 擴展 map size 常數生成 |
| `firewall-ebpf/src/table.rs` | `update_session` 回傳 `Option<SessionValue>`；追蹤 min_pkt_len, pkt_len_sum_sq |
| `firewall-ebpf/src/main.rs` | XDP 路徑整合 IAT + scorer |
| `firewall-ebpf/src/collector.rs` | `submit_event` 新增 score 參數 |
| `firewall/src/lib/config.rs` | 新增 `ModelSettings`、擴展 `MapsConfig` |
| `firewall/src/main.rs` | 提取新 maps、建立 ModelLoader |
| `firewall/src/lib/logger.rs` | 讀取並顯示 score |
| `firewall/src/lib/mod.rs` | 加入 `pub mod model_loader;` |
| `firewall/Cargo.toml` | 新增 `serde_json` 依賴 |
| `firewall/config.toml` | 新增 `[model]` 區段、擴展 `[maps]` |

---

## 10. 實作順序

| 順序 | 目標 | 依賴 |
|------|------|------|
| 1 | 共享型別（model.rs, iat.rs, lib.rs） | 無 |
| 2 | SessionValue / SessionEvent 擴充 | Step 1 |
| 3 | build.rs + config.toml map 常數 | Step 1 |
| 4 | table.rs 修改（回傳值 + 新欄位追蹤） | Step 2 |
| 5 | scorer.rs（評分引擎） | Step 1, 3 |
| 6 | iat.rs（IAT 追蹤） | Step 1, 3 |
| 7 | main.rs XDP 整合 | Step 4, 5, 6 |
| 8 | collector.rs 更新 | Step 2 |
| 9 | Userspace config.rs | Step 1 |
| 10 | model_loader.rs | Step 9 |
| 11 | Userspace main.rs + logger.rs 整合 | Step 10 |

---

## 11. 風險與對策

| 風險 | 嚴重度 | 對策 |
|------|:------:|------|
| u64×u64 交叉乘法溢位 | 高 | 操作數 > u32::MAX 時兩側右移 16 位再比較 |
| SessionValue 結構大小改變 | 高 | kernel + userspace 必須同步更新，否則 map 讀寫錯位 |
| Pkt_CV 的 cv2_numer 因 PerCpu 聚合為負 | 中 | 使用 saturating_sub，負值視為 0（最低 CV） |
| IAT_STATE LruHashMap 高流量鎖競爭 | 中 | 若成瓶頸可改 LruPerCpuHashMap（犧牲跨 CPU 精度） |
| 熱更新時 map 部分不一致 | 低 | disable → update all → enable 三步驟 |
| BPF verifier 拒絕 | 低 | 80 次迭代遠低於限制；必要時改二分搜尋減為 5×4=20 次 |

---

## 12. 分位桶切割方法（Quantile Bucket Cut Methods）

> **目前使用**: Equal-Frequency（N=2 時即 p50 中位數切割）  
> **狀態**: 日後探討，記錄於此供未來實驗參考

### 12.1 方法總覽

| # | 方法 | 切點邏輯 | 優點 | 缺點 | 適用場景 |
|---|------|---------|------|------|---------|
| 1 | Equal-Frequency | 每桶樣本數相同（p50 for N=2） | 簡單穩定、對離群值魯棒 | 切點不一定在分佈密度變化處 | 通用場景、首選基線 |
| 2 | Equal-Width | 等間距切割 `(max-min)/N` | 直覺、實作最簡 | 受離群值嚴重影響、桶分佈極不均 | 特徵分佈接近均勻時 |
| 3 | Optimal Threshold | 最大化 IF score 差異的切點（如 Youden's J） | 直接對齊異常偵測目標 | 需要 label 或 IF score 作為 proxy | 有明確異常/正常分群 |
| 4 | IF Score-Driven | 在 IF 的 per-feature 分數 g_j(x) 上找拐點 | 捕捉 IF 內部的非線性轉折 | 依賴 IF 模型品質、計算較複雜 | IF 蒸餾專用 |
| 5 | Decision Tree Split | 用深度-1 決策樹找最佳分割點 | 有理論基礎（Gini/Entropy） | 對 N=2 等價於 Optimal Threshold | 多桶場景 |
| 6 | KDE Valley | Kernel Density Estimation 找密度谷點 | 在多模態分佈中找自然分界 | 需調 bandwidth、不保證找到 N-1 個谷 | 已知多模態特徵 |

### 12.2 目前選擇：Equal-Frequency

Python 模型端的 `compute_quantile_boundaries()` 使用 `np.quantile` 計算等頻分位點。N=2 時只有一個切點即 p50（中位數），將樣本均分為兩半。

選擇原因：
- **穩定性**: 不受離群值影響，適合網路流量的長尾分佈
- **無需額外依賴**: 不需要 IF score 或 label 資訊
- **實驗驗證**: N=2 + equal-frequency 在當前資料集上 AUC 表現已足夠

### 12.3 未來探討方向

1. **Optimal Threshold (方法 3)**: 對每個特徵分別計算 IF score，找使正常/異常分群最分離的切點。預期能提升 N=2 的表達力，但需要 IF score 作為 proxy label。

2. **IF Score-Driven (方法 4)**: 計算 per-feature partial dependence `g_j(x_j)`，在曲線的最大曲率變化處切割。理論上最能保留 IF 的決策邊界，但實作複雜度較高。

3. **混合策略**: 不同特徵使用不同切割方法。例如 Protocol（離散值）用 equal-frequency，Pkt_CV（連續值）用 optimal threshold。

---

## 13. 驗證計劃

| 測試項目 | 方法 | 通過標準 |
|---------|------|---------|
| Verifier 通過 | `FirewallController::load()` 成功 | 無 verifier error |
| 模型禁用回退 | `MODEL_CONFIG.enabled=0`，送流量 | 所有封包 PASS，無效能退化 |
| 已知模型評分 | 載入固定權重+閾值，送已知特徵的合成封包 | score 值與 Python 離線計算一致 |
| 特徵正確性 | 比對 kernel 分位桶索引 vs Python 計算 | 桶索引完全一致 |
| 效能影響 | 啟用/禁用模型時測量 XDP throughput | 額外開銷 < 5% pps 下降 |
| 熱更新正確性 | 運行中更換模型檔 | 新舊模型切換無封包丟失（log-only 模式） |
