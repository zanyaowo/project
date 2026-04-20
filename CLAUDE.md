# eBPF Firewall Project — CLAUDE.md

## 架構

XDP（特徵提取、黑名單）→ TC（分位桶推論、限流）→ Rust Userspace（模型更新）→ Python ML（邊緣案例）

**唯一架構依據：** `docs/kernel_defense_architecture.md`
（eBPF verifier 限制、分位桶 N=2 決策、AUC 數字、數學模型均在此）

---

## 當前最優方案（Run 25，2026-04-18 確立）

**eBPF 分位桶特徵：FwdMax_q + Sym_q + Pkt_CV_q + Protocol + Packet Length Mean（5 個，N=2）**

| 特徵 | 公式 | 取代 |
|------|------|------|
| **FwdMax_q** | Fwd Pkt Length Max / Fwd Pkt Mean | Shape_q（Min/Mean，已棄用） |
| Sym_q | Total Fwd Pkts / Total Bwd Pkts | — |
| Pkt_CV_q | Packet Length Std / Packet Length Mean | — |

**訓練邊界來源：** Mixed BENIGN（CIC 15k + BigFlow 15k），N=2

**棄用 Shape_q 原因：** `Min Packet Length` 因 TCP ACK payload=0 退化為 Protocol 代理，跨環境無鑑別力

**最終 AUC-ROC（FwdMax_q Mixed N=2）：**

| DDoS2019 | LOIC-HTTP | HOIC | LOIC-UDP | BigFlow |
|:---:|:---:|:---:|:---:|:---:|
| 0.8888 | 0.4744 | 0.8125 | 0.9959 | 0.8769 |

---

## 絕對禁止（違反即為 bug）

- `FEATURE_COLS` 改動 → 必須同步 `schema.py` 並重跑 `feature_select`（目前 26 個，Run 07 基準）
- IF 訓練資料不可混入 attack label（BENIGN only，用 `get_normal_sample_from_files`）
- Train = `03-11`（2018-11-03）**必須早於** Test = `01-12`（2018-12-01）；反轉即為資料洩漏
- `clean_and_save()` 之後不可再呼叫 `clean()`（資料已預處理）
- 分位桶特徵不可再使用 `Shape_q`（Min/Fwd Mean）；一律改用 `FwdMax_q`（Max/Fwd Mean）
- 分位桶邊界必須以 **Mixed BENIGN** 計算（`get_mixed_normal_sample` 或等效）；純 CIC 邊界已知對 BigFlow 嚴重 overfit

---

## 快速參考

| 需要什麼 | 讀哪個檔案 |
|---------|-----------|
| 函式導覽、資料夾用途、抽樣方法選擇 | `docs/claude_ref/codebase_map.md` |
| 執行命令、驗證 checklist、資料路徑 | `docs/claude_ref/dev_commands.md` |
| 歷史失敗案例（9 則）| `docs/claude_ref/failure_records.md` |
| 架構決策、eBPF verifier 限制 | `docs/kernel_defense_architecture.md` |
| 特徵選擇實驗記錄（Run 01–25）| `docs/feature_selection_log.md` |

---

## Context 預算管理（防 Dumb Zone）

Context > 40% 輸出品質下降。完成工作單元（修改 → pytest 全綠 → commit）後開新對話。

**CLAUDE.md 自動恢復：** 架構決策、禁止事項、參考指針
**需手動帶入：** 當前 Run N 數字、debug 中的錯誤訊息、未 commit 的設計決策