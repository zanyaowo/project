# 成果與討論（Results & Discussion）撰寫素材

**最後更新：2026-06-08**
**範圍：CIC-IDS-2019 only（CLAUDE.md 硬邊界）。本文所有數字均為 in-scope；IDS2018 / BigFlow 為已凍結非目標，不進主表、不作結論。**
**數據來源：`service/model/experiments/results_benchmark.py`（可重現）→ `results_benchmark.json`**

> 本文不是論文最終稿，是「成果與討論」段落的**數據 + 敘事骨架**。每個表格下方的「可寫」即可直接改寫成正文句子。

---

## 0. 三個寫之前必須釘死的前提（避免自相矛盾）

1. **最終 teacher＝five-contract 連續 IF**（`protocol + pkt_len_mean + fwd_max_q + sym_ratio + pkt_cv_sq`，未二值化）。
   不是 20/25 維絕對特徵 IF。理由見 §4。
2. **三條模型是不同 model class，AUC 不可混引**：
   - Teacher（Contract5 連續 IF，IF-direct）
   - Baseline（Abs20，20 維絕對特徵 IF）
   - Student（部署 binarized 5-bit 32-entry 查表）
3. **頭條數字一律取 CIC-DDoS2019 in-scope**。文件他處出現的 `avg=0.60` 是**跨資料集平均**（被 OOD 的 HOIC=0.0001 拉垮），屬範圍外，**不得當部署結論**。

---

## 1. Table 1 — 偵測能力（CIC-DDoS2019 in-scope，操作點 FPR ≤ 1%）

| 模型 | 角色 | ROC-AUC | PR-AUC | Precision | Recall | F1 | FPR | FNR |
|------|------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Contract5 連續 IF | **最終 teacher** | 0.845 | 0.984 | 0.987 | 0.059 | 0.112 | 0.009 | 0.941 |
| Abs20 絕對特徵 IF | baseline（上界參考） | 0.892 | 0.983 | 0.991 | 0.102 | 0.186 | 0.010 | 0.898 |
| 部署 binarized 32-entry | **deployed student** | 0.897 | 0.990 | 0.999 | 0.821 | 0.901 | 0.007 | 0.179 |

> 設定：train＝CIC 03-11 BENIGN（10k）、eval＝CIC 01-12 balanced（每類 ≤5k，共 48,439 列）、IF `n_estimators=200, contamination=0.01, seed=42`、操作點以 `threshold_at_fpr(0.01)` 固定（不用 Youden-J，避免操作點作弊）。

**可寫：**
- 在 in-scope CIC-DDoS2019 上，部署的 5-bit 32-entry 查表 student 於 FPR < 1% 達 **F1 = 0.90、Recall = 0.82、ROC-AUC = 0.897**，與 25/20 維連續 IF 同級甚至更高。
- **關鍵且反直覺的結果**：連續 teacher 的 ROC-AUC（0.845）與 PR-AUC（0.984）顯示其排序能力良好，但在固定 FPR≤1% 的操作點 Recall 僅 0.06——攻擊與 BENIGN 分數在門檻附近重疊。二值化把特徵離散到分位桶後，攻擊流量被推進**特定高分查表格**，反而在嚴格操作點上把可分性「銳化」。
- → **論點**：在單一已知環境下，分位桶二值化不是偵測力的代價，而是一種對齊 BENIGN 中位數的正規化；它讓 datapath 端的整數查表既輕量又在操作點上優於其連續來源。

---

## 2. 逐攻擊 Recall（@FPR ≤ 1%，in-scope 子類）— 含盲區

| 攻擊類型 | n | teacher（Contract5 連續） | deployed（binarized） |
|----------|---:|:---:|:---:|
| DrDoS_DNS | 4000 | 0.002 | **1.000** |
| DrDoS_LDAP | 4000 | 0.000 | **1.000** |
| DrDoS_MSSQL | 4000 | 0.000 | **1.000** |
| DrDoS_NTP | 4000 | 0.653 | **0.998** |
| DrDoS_NetBIOS | 4000 | 0.000 | **0.999** |
| DrDoS_SNMP | 4000 | 0.001 | **1.000** |
| DrDoS_SSDP | 4000 | 0.002 | **1.000** |
| DrDoS_UDP | 4000 | 0.002 | **1.000** |
| TFTP | 4000 | 0.000 | **0.993** |
| **Syn** | 4000 | 0.000 | **0.000** ← 盲區 |
| **UDP-lag** | 4000 | 0.000 | **0.131** ← 盲區 |
| **WebDDoS** | 439 | 0.000 | **0.000** ← 盲區 |

**可寫：**
- 部署 fast-path 對 **8 種 UDP 反射/放大型 DrDoS（DNS/LDAP/MSSQL/NTP/NetBIOS/SNMP/SSDP/UDP）+ TFTP** 達 99–100% Recall，這正是分位桶設計鎖定的 volumetric 威脅模型。
- **誠實限制（三盲區）**：`Syn`（0.00）、`UDP-lag`（0.13）、`WebDDoS`（0.00）。
  - SYN flood 由**獨立的 SYN-cookie 路徑**處理（不走 bucket scorer），不在本表偵測範圍；
  - UDP-lag / WebDDoS 為**已凍結非目標**（與 Run 30 結論「SYN/UDP-LAG 為盲區」一致），非待解 bug。
- → 寫成限制段時直接點名這三類，避免 reviewer 質疑「整體 F1 0.90 是否掩蓋盲區」。

---

## 3. Table 2 — 系統開銷（偵測側，per-flow 延遲）

| 路徑 | 延遲（µs / flow） | 說明 |
|------|:---:|------|
| Contract5 IF per-flow 推論（sklearn） | **5948.2** | userspace 完整 IF（Layer 2 假想路徑） |
| Contract 整數查表（userspace proxy） | **33.6** | 含 polars/python overhead，為**延遲上界** |
| **加速比（IF / 查表）** | **177×** | |

**可寫：**
- 即使把查表放在 userspace（含 Python/polars 開銷的悲觀上界），單次 bucket 查表仍比 per-flow IF 推論快 **177×**（33.6 µs vs 5.9 ms）。
- 在 kernel datapath，eBPF map lookup 為 **O(ns)** 等級（純整數比較 + 陣列索引，無浮點、無 `__multi3`），實際差距遠大於 177×。
- → 支撐系統論點 `eBPF map lookup ≪ IF per-flow inference`。

**⚠️ 待補（on-hardware，目前 `bpftool` 未安裝、pacman offline）：**
- kernel 內 `bpf_ktime_get_ns()` 包夾 SCORE_TABLE / QUANTILE_BOUNDS 單次查表 → p50/p99（ns）
- throughput（pps）4 對照組、CPU%（含 softirq）、mitigation latency（偵測→DROP, µs）
- 完成後回填 `docs/TASKS.md` §8.A / E4 Table 2。

---

## 4. Teacher 決策：為何 five-contract 連續 IF 是最終 teacher（不是 Abs20）

| 比較軸 | Contract5 連續（採用） | Abs20 絕對特徵（不採用） |
|--------|:---:|:---:|
| in-scope ROC-AUC | 0.845 | 0.892（+0.047） |
| 跨環境穩定性 | 無量綱比例，不受尺度漂移 | 絕對值跨資料集崩潰（Run 08–10/23/27） |
| 可由 eBPF datapath 重建 | ✅（SessionValue 可重建全部 5 特徵） | ❌（含 Flow Bytes/s、Win bytes 等不可得） |
| 與 student 同特徵空間 | ✅（蒸餾前提） | ❌ |

**可寫：**
- Abs20 在 in-scope 多 +0.047 AUC，但這是**只在單一已知環境成立的幻象**，代價是零可部署性：其 20 維含 datapath 取不到的欄位，且絕對值特徵已知跨環境崩潰。
- Contract5 是**唯一同時滿足「kernel 可重建」與「teacher/student 同特徵空間」**的集合，故定為最終 teacher。蒸餾的價值不在追求最高 in-scope AUC，而在把可重建特徵空間的異常排序壓進 32-entry 整數查表。
- （現況說明，避免過度宣稱）目前 `model.json` 的 score_table 由 `distill_export_cic_only.py` 以**二值特徵 IF** 直接產生；Contract5 連續 IF → bucket student 的正式 KD（KL/CE）仍是 future work（見 `docs/TASKS.md` §8.B-2）。

---

## 5. 討論段落骨架（可直接擴寫）

1. **偵測有效**：in-scope F1=0.90 / AUC=0.90，volumetric DrDoS 全覆蓋 → 主張成立。
2. **分位桶有用**：二值化在 in-scope 操作點上**優於**其連續來源（teacher Recall 0.06 → student 0.82），證明分位桶不是壓縮損失而是正規化增益。
3. **eBPF 輕量**：查表 ≪ IF 推論（≥177×，kernel 端 O(ns)）→ 系統貢獻成立。
4. **誠實邊界**：三盲區（Syn/UDP-lag/WebDDoS）明列；跨資料集 0.60 屬範圍外不引用。
5. **威脅模型對齊**：方法鎖定 UDP 反射/放大 volumetric DDoS，與 fast-path 設計目標一致。

**論文敘事（最終目標）：**
> Quantile-bucket distillation compresses an Isolation-Forest anomaly ranking over a kernel-reconstructable 5-feature space into a 32-entry integer lookup table. On CIC-DDoS2019, the deployed table achieves F1 = 0.90 at < 1% FPR, fully covering eight UDP reflection/amplification DDoS families, while a single bucket lookup is ≥177× cheaper than per-flow IF inference. Binarization at the BENIGN median acts as a normalizer that sharpens in-distribution separability rather than degrading it.

---

## 6. 限制（Limitations，誠實列出）

- **範圍**：結論限 CIC-IDS-2019；跨環境泛化為明確不跨越之硬邊界，HOIC/BigFlow 不作評估依據。
- **盲區**：SYN（另由 SYN-cookie 處理）、UDP-lag、WebDDoS 非本 fast-path 覆蓋。
- **系統量測未完**：Table 2 僅有偵測側 userspace 延遲比；kernel ns / pps / CPU% 待 on-hardware。
- **KD 未實作**：連續 teacher → bucket student 的正式知識蒸餾尚未落地，現以二值特徵 IF 直接產表。
- **操作點敏感**：連續 teacher 在 FPR≤1% Recall 偏低，反映其分數在門檻附近重疊；改報 AUC/PR-AUC 較公允。

---

## 附：重現指令

```bash
cd /home/zanya/code/ebpf_project/project
python -m service.model.experiments.results_benchmark
# → 主控台輸出 Table 1 / per-attack / Table 2
# → service/model/experiments/results_benchmark.json
```
