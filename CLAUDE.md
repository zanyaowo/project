# eBPF Firewall Project — CLAUDE.md

## 架構概覽（閉環控制系統）

架構設計文件：`docs/kernel_defense_architecture.md`（唯一架構依據）

### Tiered Offloading（分層卸載）

```
封包到達
   │
   ▼
[XDP]            ── 特徵提取（IAT、Bytes 等整數運算）
                 ── 黑名單比對（BLOCK_LIST BPF_MAP）
                 ── 明顯攻擊直接 XDP_DROP（LOIC-UDP，Sym_q 最大桶）
   │
   ▼ 未命中黑名單的封包
[TC]             ── 熵值計算（FixedPointLog BPF_MAP 查表）
                 ── 異常評分（分位桶索引 × 閾值比對，N=2）
                 ── token bucket 限流：R(t) = R_max × (1 − sigmoid(S − θ))
   │
   ▼ 邊緣案例 / 模型更新事件
[Rust Userspace] ── RingBuf 消費、特徵聚合
                 ── 邊緣案例送 Python（HOIC 需完整 log1p 特徵）
                 ── 重訓後將新權重 / 分位桶邊界下發回 BPF_MAP
   │
   ▼ 邊緣案例推論（非快速路徑）
[Python ML]      ── IsolationForest 全精度推論（AUC=0.9257）
                 ── 告警 → FirewallController → 寫入 BLOCK_LIST
                 ── model_store/ 儲存訓練產物
```

### 閉環角色對應

| 組件 | 角色 | 邏輯 |
|------|------|------|
| 感測層（XDP） | 流式熵值分析 | 提取 IAT、Bytes，識別非自然規律 |
| 決策層（TC） | 模型蒸餾內核化 | BPF_MAP 查表推論，分位桶 N=2 |
| 執行層（TC） | 自適應限流 | R(t) = R_max × (1 − sigmoid(S − θ))，減少誤殺 |

### 分層推論邊界

| 層 | 延遲 | 精度 | 適用場景 |
|----|------|------|---------|
| Kernel（目標）| < 1 µs | 超越 log1p 基準 | DDoS2019=0.9418，HOIC=0.9934，LOIC-HTTP=0.7941，LOIC-UDP=0.9961（N=2）|
| Userspace（現況）| 1–10 ms | 完整精度 | log1p 浮點推論（DDoS2019=0.9114） |

---

## 架構決策（不可更改，除非更新 kernel_defense_architecture.md）

- **分位桶 N=2**：Run 17 延伸驗證，N=2 全面超越 log1p 浮點基準（DDoS2019=0.9418、HOIC=0.9934、LOIC-HTTP=0.7941）；eBPF 每特徵只需 1 個邊界（BENIGN 中位數），3 次交叉乘法比較，零迴圈，verifier 負擔最低
- **分層推論**：Kernel 以分位桶（N=2）覆蓋所有主要攻擊類型，不再需要 userspace 備援；Userspace 僅負責模型更新與邊界下發
- **IF 蒸餾現況**：分位桶閾值比對已驗；線性蒸餾 Σw_j×q_j 待驗
- **Tiered Offloading**：XDP（最快路徑）→ TC（限流）→ Userspace（模型更新、Map 下發）
- **特徵集**：`schema.py` 的 `FEATURE_COLS`（26 個），以 Run 07 結果為基準（AUC=0.9257）

---

## eBPF 計算限制（寫 kernel 程式必讀）

| 限制 | 違反時的 verifier 報錯 | 繞過方式 |
|------|----------------------|---------|
| 無浮點運算 | `unknown opcode` | 定點數（位移 10 位）或 BPF_MAP 查表 |
| Stack 上限 512B | `combined stack size exceeds limit` | 大型陣列放 BPF_MAP |
| 無動態記憶體 | — | BPF_MAP 或 per-CPU stack |
| 迴圈必須有界 | `back-edge` | `#pragma unroll` 或固定 N 的 for loop |
| 單函式指令數上限 | `insns limit reached` | 拆分為多個 BPF 函式（tail call） |
| 無遞迴 | `unreachable insn` | 展開為迭代 |

---

## 關鍵命令

```bash
# Python 測試（快速，不需要真實資料）
uv run --project service/model pytest service/model/tests/ -m "not slow" -v

# 特徵選擇
uv run --project service/model python -m service.model.pipeline.feature_select \
    --data_dir service/model/dataset/parquet_clean/train \
    --val_dir  service/model/dataset/parquet_clean/test

# 訓練
uv run --project service/model python -m service.model.pipeline.train --model_type if

# Rust 編譯
cargo build --manifest-path service/firewall/Cargo.toml
```

---

## Python ML 約束（禁止事項）

- **不可** 在 `clean_and_save()` 之後再呼叫 `clean()`（資料已預處理，重複清洗會破壞結果）
- **不可** 修改 `FEATURE_COLS` 而不同步更新 `schema.py` 並重跑 `feature_select`
- **不可** 在 IsolationForest 訓練資料中混入 attack label（IF 只學 BENIGN 的正常行為）
- **訓練時序**：Train = `03-11`（2018-11-03，較早）/ Test = `01-12`（2018-12-01，較晚）；反轉即為資料洩漏

---

## 已知失敗記錄

> 每行對應一個歷史錯誤，用於防止重蹈覆轍。

- **2026-04-10**：Train/Test 時序顛倒（Train=01-12，Test=03-11）→ AUC 虛高 0.0192，Run 01–17 全部重跑修正
- **2026-04-11**：Run 11/12 單特徵 AUC 重跑時因記憶體不足（OOM，exit code 144）被 kernel 殺掉。原因：同時載入 train（30000）＋val（60000）＋IDS2018（15000）三份資料加上 7 個 IsolationForest（各 200 棵樹）導致 RAM 耗盡。對策：減少 val_sample_n（如 20000）、分批跑特徵、或逐特徵釋放前一個模型後再訓練下一個。
- **sample.py 拼字 silent failure**：`normal_label = "BEGIN"`（應為 `"BENIGN"`）導致 `get_normal_sample_from_files` 靜默回傳空 DataFrame；`transfrom` typo 導致 `transform` 參數靜默無效。現已修正，但新增抽樣函式時務必用實際資料跑一次確認 len > 0。
- **IF 訓練資料誤用 balanced sampling**：曾以 `get_balance_sample_from_files` 訓練 IsolationForest，破壞「異常是少數」的核心假設。IF 訓練只能用 `get_normal_sample_from_files`（BENIGN only）。
- **feature_select 嚴重不平衡**：曾以 `get_balance_sample_from_files` 做特徵選擇，產生 BENIGN 5,000 筆 vs 攻擊 ~82,000 筆的不平衡，分類器學到「哪類攻擊最多」而非「正常 vs 攻擊差異」。應改用 `get_binary_sample_from_files`（50/50）或 `get_balance_sample_from_files` 搭配 `min_samples` 過濾極少數 label。
- **Inbound 欄位 data leakage**：CIC-IDS 2019 的 `Inbound` 欄位幾乎只有 1，與攻擊 label 高度對應，導致其餘特徵 permutation importance 趨近 0。特徵選擇時必須排除 `Inbound`（已在 `feature_select.py` 中修正）。
- **Source Port 是 IP 特徵不可入模型**：`Source Port` IG 高達 39.6%，但屬於網路識別符（IP 特徵），納入 IF 等同讓模型記住特定 IP 的行為，泛化性差。已在 Run 03 人工移除，feature_select 不可自動保留。
- **feature_select random_state 未固定 → 特徵選擇不可重現**：`feature_select.py` 若未固定所有隨機來源，每次跑 permutation importance 結果不同，導致 FEATURE_COLS 不穩定。修改 feature_select.py 時確認三個隨機來源都有固定 seed（抽樣、分類器建樹、permutation importance）。
- **跨資料集泛化失敗（Distribution Shift）**：Run 08 在 CIC IDS 2018 的 LOIC-HTTP AUC=0.28（低於隨機基線）。根本原因：訓練集 BENIGN 來自反射攻擊高速環境，與一般辦公室流量統計特性截然不同。LOIC-HTTP 為應用層偽裝攻擊，Layer 4 特徵無法區分，非特徵工程問題。跨環境部署必須用目標環境的 BENIGN 重新訓練。

---

## 驗證 Checklist

### Python pipeline 修改後
```bash
# 1. import 無錯誤
uv run --project service/model python -c "import service.model.pipeline.infer"

# 2. 快速測試全綠
uv run --project service/model pytest service/model/tests/ -m "not slow" -q

# 3. 特徵數正確
uv run --project service/model python -c \
    "from service.model.schema import FEATURE_COLS; print(f'FEATURE_COLS: {len(FEATURE_COLS)} 個')"
```

### FEATURE_COLS 修改後
1. 重跑 `feature_select`，確認新 AUC ≥ 0.90（Run 07 基準：0.9257）
2. 更新 `schema.py` 的 `FEATURE_COLS`
3. 重新訓練並儲存 `model_store/`

### eBPF/Rust 修改後
```bash
cargo check --manifest-path service/firewall/Cargo.toml
# 確認無 verifier 相關錯誤（見上方限制清單）
```

---

## 待研究問題

- [ ] `LruCpuHashmap` 高流量下是否有 lock contention？→ 影響 Map 類型選擇
- [ ] IF 線性蒸餾（Σ w_j × q_j，q_j 為分位桶索引）的 AUC vs 純閾值比對
- [ ] 熵值定點數精度是否足以區分正常/攻擊流量？

---

## 資料路徑約定

| 用途 | 路徑 |
|------|------|
| 原始 CSV | `dataset/*/` |
| 清洗後 parquet | `service/model/dataset/parquet_clean/train/` 和 `test/` |
| 模型輸出 | `service/model/model_store/` |
| 架構文件 | `docs/kernel_defense_architecture.md` |
| 特徵實驗記錄 | `docs/feature_selection_log.md` |