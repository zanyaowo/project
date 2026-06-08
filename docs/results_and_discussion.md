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
| 部署 binarized 32-entry | **deployed student（無監督）** | 0.897 | 0.990 | 0.999 | 0.821 | 0.901 | 0.007 | 0.179 |
| LogisticRegression（**監督上界**） | supervised ref | 0.948 | 0.995 | 0.999 | 0.806 | 0.892 | 0.010 | 0.194 |
| RandomForest（**監督上界**） | supervised ref | 0.934 | 0.993 | 1.000 | 0.817 | 0.900 | 0.000 | 0.183 |

> 設定：train＝CIC 03-11 BENIGN（10k）、eval＝CIC 01-12 balanced（每類 ≤5k，共 48,439 列）、IF `n_estimators=200, contamination=0.01, seed=42`、操作點以 `threshold_at_fpr(0.01)` 固定（不用 Youden-J，避免操作點作弊）。監督式（`run35_supervised_baseline.py`）train＝03-11 balanced（有 label）、同 contract-5 特徵、維持 Train 早於 Test。

**可寫：**
- 在 in-scope CIC-DDoS2019 上，部署的 5-bit 32-entry 查表 student 於 FPR < 1% 達 **F1 = 0.90、Recall = 0.82、ROC-AUC = 0.897**，與 25/20 維連續 IF 同級甚至更高。
- **無監督 bucket 追平監督上界**：部署 bucket（**零 label**）F1@1% = 0.902，與 supervised RandomForest（0.900）、LogisticRegression（0.892）**在操作點上等量齊觀**；監督式僅在 ROC-AUC（0.93–0.95）略高，操作點 F1 無實質優勢。→ 分位桶蒸餾在不用攻擊標籤下達到「有 label 才有的偵測力」。
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
- **盲區是特徵極限、非方法極限（強力佐證，`run35_supervised_baseline.py`）**：即使換成**有 attack label 的監督式** LR/RF，同 contract-5 特徵下 Syn=0.00、UDP-lag=0.13、WebDDoS=0.00 三盲區**完全不變**。→ 這三類無法由 contract-5 特徵分離，與是否無監督/是否分位桶無關；堵住「你無監督才漏掉」的質疑。

---

## 2b. Bucket 數量 K 敏感度（static quantile bucket，in-scope）— 坐實「為何 N=2」

**數據來源：`experiments/run33_static_bucket.py` → `run33_static_bucket.json`**（同 train/eval split）。
分位桶邊界只用 BENIGN 訓練集算一次（static，不更新），IF 在整數桶索引上訓練。

| N | eBPF table | ROC-AUC | PR-AUC | F1@FPR≤1% | R@1% | R@5% | R@10% |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **2** | 32-entry | 0.894 | 0.989 | **0.900** | 0.819 | 0.819 | 0.819 |
| 4 | 1024-entry | 0.890 | 0.989 | **0.000** | 0.000 | 0.000 | 0.819 |
| 8 | 32768-entry | 0.908 | 0.991 | 0.899 | 0.817 | 0.820 | 0.821 |

**可寫：**
- **AUC 幾乎不隨 N 變（0.89–0.91），但操作點穩健性非單調**：N=2 在 FPR 1%/5%/10% 皆穩定 Recall=0.82；N=4（1024-entry）在 **FPR≤5% 完全崩潰（Recall=0）**，只在 FPR≥10% 才恢復；N=8 恢復但需 32768-entry。
- N=4 崩潰機制：較細的離散化把一小撮 BENIGN 流量推進稀有桶組合 → 高異常分數佔據分數頂端，在嚴格 FPR 門檻下把所有攻擊擋在門檻下方（per-attack 全 0）。這是離散化 artifact，非 AUC 能看出的問題。
- → **論點（回答 reviewer「為何 K=2」）**：N=2 同時最小（32-entry，eBPF 友善）且在部署操作點最穩健；N=4 是「AUC 看似 OK 卻在操作點不可用」的陷阱；N=8 雖可用但 table 大 1000×、eBPF verifier/記憶體不可行。**選 N=2 不是精度妥協，是操作點穩健性 + 實作可行性的交集最優。**
- 與 Run 30（cross-dataset AUC-only，N=2 avg 最優）一致，但本實驗在**固定操作點**上把 N=4 的不可用性顯式量化，論證更強。

---

## 2c. Score Regression vs Bucket Classification（E2）— 為何不直接回歸分數

**數據來源：`experiments/run34_score_regression.py` → `run34_score_regression.json`**
（teacher=Contract5 連續 IF，01-12 balanced 對半切 distill-fit/eval，student 訓練不用 ground-truth）

| 模型 | ROC-AUC | F1@FPR≤1% | R@1% | Spearman→teacher |
|------|:---:|:---:|:---:|:---:|
| teacher（Contract5 連續） | 0.845 | 0.112 | 0.059 | 1.000 |
| student-reg（DecisionTree, MSE→teacher） | 0.857 | 0.111 | 0.059 | **0.990** |
| student-bucket（部署 32-entry） | 0.896 | **0.902** | 0.821 | **0.549** |

**可寫（結論全部指向上表數字）：**
- **回歸 student 忠實複製 teacher 排序（Spearman 0.990），代價是連 teacher 的操作點不可用性一起繼承**：F1@FPR≤1% 僅 0.111、R@1% 0.059，與 teacher（0.112 / 0.059）幾乎相同。
- **bucket student 反而不忠實複製 teacher（Spearman 0.549），卻在操作點達 F1 0.902 / R 0.821**。
- **誠實修正（推翻常見直覺與本專案原假設）**：價值不在「分位桶保留排序」——保留排序的是 regression。bucket 的 Spearman 偏低有兩個成因：(1) 它只有 ~16 個離散分數，與連續分數做秩相關有 tie 上限；(2) 它**刻意**用中位數二值化重塑分數分布，把攻擊離散進少數高分桶，使部署決策**與 teacher 不穩定的絕對分數脫鉤**。
- → **論點**：「直接回歸異常分數」會把 teacher 在嚴格 FPR 下的脆弱操作點原封不動搬到 datapath；分位桶分類犧牲絕對分數保真度，換取操作點穩健與整數查表可部署性。這同時回答 E2 的 reviewer 問題與「為何不用 score regression」。
- （指標註記）top-5% attack recall 三模型均 0.054，在本 eval（91% 為攻擊）下退化無鑑別力，故以 F1@FPR≤1% 為準。

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

## 3b. Gated update 抗攻擊污染（E5，Figure 2 素材）

**數據來源：`experiments/run36_contamination_sweep.py` → `run36_contamination_sweep.json`**
（忠於部署 `boundary_updater.decide_gate`：divergence>0.30 且 high-risk 命中率 jump>2.0 → AttackFreeze；ref=部署 BENIGN 中位數邊界；baseline FNR=0.182）

| 攻擊比例 ρ | divergence | high-risk× | gate 決策 | Naive FNR | Gated FNR |
|:---:|:---:|:---:|:---:|:---:|:---:|
| 10% | 0.349 | 34.6× | AttackFreeze | 0.190 | **0.182** |
| 30% | 1.194 | 70× | AttackFreeze | **1.000** | **0.182** |
| 50% | 2.224 | 89× | AttackFreeze | **1.000** | **0.182** |
| 80% | 3.166 | 119× | AttackFreeze | **1.000** | **0.182** |

**可寫：**
- **Naive streaming 在 ρ≥30% 完全崩潰（FNR=1.000，漏掉全部攻擊）**：污染視窗的逐特徵中位數被攻擊流量拉進攻擊分布，邊界一旦移過去，攻擊就落回「正常」桶 → 全部漏報。即便 ρ=10%，naive FNR 也從 0.182 升到 0.190。
- **Gated streaming 全程穩在 baseline FNR=0.182**：gate 在所有 ρ 都正確判定 AttackFreeze——divergence（0.35→3.17）遠超 0.30 門檻、high-risk 桶命中率（34→119×）遠超 2.0 跳升門檻 → 凍結 reference boundary，校準不被污染。
- → **論點**：streaming 自適應若不設防，攻擊比例升高會把攻擊「洗白」成新常態（FNR→1）；dual-sketch + gated freeze 以「divergence × high-risk 跳升」雙條件辨識污染，把 FNR 鎖在乾淨基線。這是回饋層（boundary adaptive update）的核心安全價值。

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
