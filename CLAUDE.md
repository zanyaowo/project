# eBPF Firewall Project — CLAUDE.md

## 架構

XDP（特徵提取、黑名單）→ TC（分位桶推論、限流）→ Rust Userspace（adaptive boundary 校準、Map 下發）→ ⟦Layer 2 Userspace 完整 IF：規劃中，未實作⟧

> 現況唯一推論層是 eBPF fast-path；Rust userspace 只做 logging + adaptive boundary，**無 runtime IF**。離線 IF 在 `service/model/`（訓練/蒸餾/實驗），未與 runtime 接通。Layer 2（邊緣案例完整 IF）為設計目標，集成計畫見 `docs/2_decision/layer2_integration_plan.md`（設計階段，未排程實作）。

**唯一架構依據：** `docs/_crosscut/kernel_defense_architecture.md`
（eBPF verifier 限制、分位桶 N=2 決策、AUC 數字、數學模型均在此）

---

## 當前部署 contract（5-bit all-binary，32-entry table）

**eBPF 實際 ship 的特徵：protocol_bit + pkt_len_mean_bit + FwdMax_q + Sym_q + Pkt_CV_sq（5 個全二值化，N=2，32-entry score table）**
產出腳本：`pipeline/distill_export.py` → `distilled_rules.json`

| 特徵 | 公式 | 取代 |
|------|------|------|
| **FwdMax_q** | Fwd Pkt Length Max / Fwd Pkt Mean | Shape_q（Min/Mean，已棄用） |
| Sym_q | Total Fwd Pkts / Total Bwd Pkts | — |
| Pkt_CV_sq | (Packet Length Std / Packet Length Mean)² | Pkt_CV_q（CV 未平方，僅存在於 Run 25 證據模型） |

**訓練邊界來源：** CIC-IDS-2019 BENIGN only（03-11 files，N=2）

> **評估範圍＝CIC-IDS-2019，且跨資料集泛化為明確「不跨越」的硬邊界**（2026-05-25 範圍決策、2026-06-07 確立為硬邊界）。不以跨環境（BigFlow / IDS2018 / HOIC）表現作為任何決策依據，亦不在文件中以泛化論述包裝結論。Mixed BENIGN 技術路徑（`get_mixed_normal_sample` + `build_features`）僅作預留，啟用＝未來明確決定解除此邊界時。
>
> **特徵集已定案：contract-5**（protocol + pkt_len_mean + FwdMax_q + Sym_q + Pkt_CV_sq）。Run 32（2026-06-07）確認其連續版 in-scope AUC≈Full25（0.845 vs 0.898）且 FPR 更低；不追求完整 25 維，亦不採純無量綱（CIC FPR 48% 不可用）。
>
> **最終 teacher＝Contract5 連續 IF**（5 連續特徵），不是 Full25/Abs20 絕對特徵 IF。理由：可由 eBPF SessionValue 重建、與 binarized student 同特徵空間、跨環境不崩。Abs20 in-scope AUC 略高（0.892 vs 0.845）但不可部署。成果對照（Table 1/2、per-attack、延遲）見 `docs/results_and_discussion.md`，腳本 `experiments/results_benchmark.py`。

**棄用 Shape_q 原因：** `Min Packet Length` 因 TCP ACK payload=0 退化為 Protocol 代理，跨環境無鑑別力

**AUC-ROC：證據模型 ≠ 部署 contract（Run 28/29 確認，2026-05-18）：**

| 模型 | Run 28 對應 | DDoS2019 | LOIC-HTTP | HOIC | LOIC-UDP | BigFlow | Avg |
|------|------|:---:|:---:|:---:|:---:|:---:|:---:|
| Run 25 證據（IF-direct；Protocol/PktLenMean raw、CV 未平方） | `A_run25_original` | 0.8888 | 0.4744 | 0.8125 | 0.9959 | 0.8769 | 0.8097 |
| **實際部署（5-bit all-binary，32-entry）** | `D_current_5bit_contract` | 0.8833 | 0.2647 | **0.0001** | 0.9969 | 0.8756 | **0.6041** |

> ⚠️ Run 25 那行**不是部署證據**。其 Protocol/PktLenMean 為 raw 連續值直接丟 IF（`table_size=None`），與實際全二值化 32-entry contract 是不同 model class（差異軸：Protocol/PktLenMean raw↔bit、CV↔CV²、BigFlow 正規化 +1e-6↔+1）。引用部署 AUC 必須用 `D` 那行——HOIC 已崩（0.0001），avg 僅 0.60。證據鏈見 `quantile_bucket_strategy_log.md` Run 28/29 與 `experiments/run28_contract_matrix.py:403`。

---

## 絕對禁止（違反即為 bug）

- `FEATURE_COLS` 改動 → 必須同步 `schema.py` 並重跑 `feature_select`（目前 26 個，Run 07 基準）
- IF 訓練資料不可混入 attack label（BENIGN only，用 `get_normal_sample_from_files`）
- Train = `03-11`（2018-11-03）**必須早於** Test = `01-12`（2018-12-01）；反轉即為資料洩漏
- `clean_and_save()` 之後不可再呼叫 `clean()`（資料已預處理）
- 分位桶特徵不可再使用 `Shape_q`（Min/Fwd Mean）；一律改用 `FwdMax_q`（Max/Fwd Mean）
- 分位桶邊界以 **CIC 2019 BENIGN**（`get_normal_sample_from_files`）計算；跨資料集泛化時需改用 `get_mixed_normal_sample`（CIC+BigFlow），純 CIC 邊界已知對 BigFlow 嚴重 overfit
- **資料檔案不可整份讀入記憶體**（`pl.read_parquet(big_file)` 無欄位篩選 = OOM crash）；必須擇一：(1) `columns=` 只讀需要的欄位、(2) `pl.scan_parquet` lazy 後 `.collect()`、(3) `get_normal_sample_from_files` / `get_balance_sample_from_files` 等 per-file 抽樣函式；IDS2018 / BigFlow 單檔有 80+ 欄，無條件 column-prune
- **跨資料集泛化是「不跨越」的硬邊界**：不得以跨環境（BigFlow / IDS2018 / HOIC）表現作為決策依據或文件主軸；HOIC 等為 eBPF fast-path 的**已凍結非目標**，非待解問題。要解除此邊界需明確的範圍決策（屆時才啟用 Mixed BENIGN 路徑）。跑跨環境腳本作參考可以，但結論一律以 CIC-2019 為準

---

## 快速參考

| 需要什麼 | 讀哪個檔案 |
|---------|-----------|
| 函式導覽、資料夾用途、抽樣方法選擇 | `docs/claude_ref/codebase_map.md` |
| 執行命令、驗證 checklist、資料路徑 | `docs/claude_ref/dev_commands.md` |
| 歷史失敗案例（10 則）| `docs/claude_ref/failure_records.md` |
| 架構決策、eBPF verifier 限制 | `docs/_crosscut/kernel_defense_architecture.md` |
| eBPF verifier × LLVM 踩坑 | `docs/_crosscut/issues/ebpf_verifier_pitfalls.md` |
| 效能量測踩坑（map update latency、自適應閘控 benign 觸發） | `docs/_crosscut/issues/adaptive_gate_benchmark_notes.md` |
| 特徵選擇實驗（Run 01–16,18、附錄 A-1～A-9） | `docs/1_sensing/feature_selection_log.md` |
| 分位桶策略/模型訓練（Run 17,19–29、A-10/11/12）；contract 不一致見 Run 28/29 | `docs/2_decision/quantile_bucket_strategy_log.md` |

---

## Context 預算管理（防 Dumb Zone）

Context > 40% 輸出品質下降。完成工作單元（修改 → pytest 全綠 → commit）後開新對話。

**CLAUDE.md 自動恢復：** 架構決策、禁止事項、參考指針
**需手動帶入：** 當前 Run N 數字、debug 中的錯誤訊息、未 commit 的設計決策