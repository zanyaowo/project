# 已知失敗記錄

> 每則對應一個歷史錯誤，用於防止重蹈覆轍。

---

**2026-04-10 — Train/Test 時序顛倒**
Train=01-12，Test=03-11 → AUC 虛高 0.0192，Run 01–17 全部重跑修正。
正確時序：Train = `03-11`（2018-11-03）早於 Test = `01-12`（2018-12-01）。

---

**2026-04-11 — OOM（Run 11/12，exit code 144）**
同時載入 train（30000）＋val（60000）＋IDS2018（15000）＋7 個 IF（各 200 棵樹）→ RAM 耗盡被 kernel 殺掉。
對策：減少 val_sample_n（如 20000）、分批跑特徵、逐特徵釋放前一個模型。

---

**sample.py 拼字 silent failure**
`normal_label = "BEGIN"`（應為 `"BENIGN"`）→ `get_normal_sample_from_files` 靜默回傳空 DataFrame。
`transfrom` typo → `transform` 參數靜默無效。
對策：新增抽樣函式後必須用實際資料跑一次確認 len > 0。

---

**IF 訓練資料誤用 balanced sampling**
以 `get_balance_sample_from_files` 訓練 IsolationForest，破壞「異常是少數」的核心假設。
IF 訓練只能用 `get_normal_sample_from_files`（BENIGN only）。

---

**feature_select 嚴重不平衡**
以 `get_balance_sample_from_files` 做特徵選擇 → BENIGN 5,000 筆 vs 攻擊 ~82,000 筆，分類器學到「哪類攻擊最多」而非「正常 vs 攻擊差異」。
應改用 `get_binary_sample_from_files`（50/50）或搭配 `min_samples` 過濾極少數 label。

---

**Inbound 欄位 data leakage**
CIC-IDS 2019 的 `Inbound` 欄位幾乎只有 1，與攻擊 label 高度對應 → 其餘特徵 permutation importance 趨近 0。
特徵選擇時必須排除 `Inbound`（已在 `feature_select.py` 中修正）。

---

**Source Port 是 IP 特徵不可入模型**
`Source Port` IG 高達 39.6%，但屬於網路識別符 → 納入 IF 等同讓模型記住特定 IP，泛化性差。
已在 Run 03 人工移除，`feature_select` 不可自動保留。

---

**feature_select random_state 未固定 → 不可重現**
未固定所有隨機來源 → 每次跑 permutation importance 結果不同，FEATURE_COLS 不穩定。
修改 `feature_select.py` 時確認三個隨機來源都有固定 seed（抽樣、分類器建樹、permutation importance）。

---

**跨資料集泛化失敗（Distribution Shift）**
Run 08 在 CIC IDS 2018 的 LOIC-HTTP AUC=0.28（低於隨機基線）。
根本原因：訓練集 BENIGN 來自反射攻擊高速環境，與一般辦公室流量統計特性截然不同；LOIC-HTTP 為應用層偽裝攻擊，Layer 4 特徵無法區分。
跨環境部署必須用目標環境的 BENIGN 重新訓練。

---

**2026-04-17 — BigFlow-NIDS-V2 跨資料集驗證：CIC 分位桶邊界在新資料集完全失效**
用 CIC BENIGN 計算的 N=2 邊界在 BigFlow-NIDS-V2 上 AUC=0.3888（低於隨機基線，模型倒置）。根本原因：BF Benign 的 Shape_Ratio 中位數（1.00）遠高於 CIC BENIGN（0.32），導致 N=2 邊界對 BigFlow 無效。改用 BigFlow 自身 Benign 重算邊界後 N=4 達 AUC=0.9110。結論：分位桶邊界是環境相關參數（非通用常數），跨環境部署時 Rust Userspace 必須以目標環境 Benign 重算邊界並更新 BPF_MAP；同分布時 N=2 最優，跨資料集時 N=4 更穩健。