# Layer 2 Userspace 完整 IF 集成計畫

> **狀態：擱置中的設計目標（parked design target）——目前無 in-scope 驅動力。**
> 本計畫唯一明確標的是 HOIC（§3），而 HOIC 屬跨資料集泛化；依 CLAUDE.md
> 「跨資料集泛化＝不跨越的硬邊界」決策（2026-06-07），**泛化為已凍結的非目標**，
> Layer 2 因此沒有 in-scope 驅動力，整體擱置。啟動條件＝未來明確決定解除該邊界。
> 在 CIC-2019 範圍內，fast-path（contract-5）即為唯一推論層，不需要 Layer 2。
> 本文保留作為「若將來解除邊界」的設計依據，並把架構文件對 Layer 2 的懸空引用補實。
>
> **唯一架構依據：** `docs/_crosscut/kernel_defense_architecture.md`
> （verifier 限制、分位桶 N=2 決策、AUC 數字、推論位置決策軸心均在此）

---

## 1. 目的與範圍

### 為什麼需要這份文件

`CLAUDE.md`、`kernel_defense_architecture.md` 多處將架構描述為「Layer 1 Kernel +
Layer 2 Userspace 分層」，但 Layer 2 從未有集成步驟說明，造成數處懸空引用
（見 `docs/README.md` 的死連結記錄）。本文補上這些步驟，使「Layer 2」從口號變成
可被審查、可被排程的設計。

### 範圍界定（誠實聲明）

- **本文是設計計畫，不是實作文件。** 現況 runtime 唯一推論層仍是 eBPF fast-path
  （`scorer.rs::score_session`）。離線 IF 在 `service/model/`，與 runtime **未接通**。
- **Layer 2 能解什麼、不能解什麼**，見 §3。特別是 **LOIC-HTTP 不在 Layer 2 的可解範圍**
  （它是 Layer 4 特徵本身的限制，userspace 用同樣 Layer 4 特徵亦無法救——
  見 `kernel_defense_architecture.md` 軸心一）。
- 啟動 Layer 2 等於把評估範圍擴出 CIC-2019；在那之前，本文凍結於設計階段。

---

## 2. 現況回顧（Layer 1 資料路徑）

```
封包 → XDP/TC parser → update_session（SessionValue 累積）
                          → score_session（5-bit bucket index → 32-entry SCORE_TABLE）
                          → action（XDP_DROP / PASS）
                          │
              ┌───────────┴────────────────┐
              ▼                             ▼
   EVENTS_POOL (SessionEvent)     STATS_RING_BUF (StatsEvent)
   key/timestamp/len/flag/score   numer[5]/denom[5]/score/flags
              │                             │
              ▼                             ▼
        logger.rs                  boundary_updater.rs
   （週期 metrics + 告警）        （S_ref/S_live dual-sketch
                                   → gated EMA → QUANTILE_BOUNDS
                                   double-buffer 熱切換）
```

**現有可重用資產（Layer 2 的天然掛載點）：**

| 資產 | 位置 | Layer 2 用途 |
|------|------|-------------|
| `StatsEvent`（含 `flags` gate bit）| `firewall-common/src/model.rs:53` | 升級候選的篩選訊號來源 |
| `STATS_RING_BUF` + `AsyncFd` 消費迴圈 | `boundary_updater.rs` | 升級事件的傳輸與非同步消費範式 |
| `controller.block_ip` → `BLOCK_LIST` | `controller.rs:89` | Layer 2 判決的**現成 enforcement 出口** |
| 離線 IF 推論 | `pipeline/infer.py::_infer_if` | Layer 2 IF sidecar 的推論核心 |
| IF bundle（model/scaler/meta）| `model_store/*.joblib` | Layer 2 載入的模型物件 |

---

## 3. Layer 2 定位：能解與不能解

| 案例 | Layer 1 現況 | Layer 2 是否可解 | 理由 |
|------|-------------|:----------------:|------|
| 一般 volumetric DDoS（DDoS2019 / LOIC-UDP）| 已可（AUC≈0.88 / 0.997）| 不需要 | fast-path 已足夠，升級只增延遲 |
| **HOIC** | 崩潰（contract AUC≈0）| **凍結非目標** | 屬跨資料集泛化（IDS2018），依硬邊界決策為已凍結非目標。技術上完整/無量綱 IF 可恢復部分鑑別力，但不在 in-scope 評估 |
| **LOIC-HTTP** | 崩潰（AUC≈0.26）| **不可解** | Layer 4 統計特徵本身無鑑別力；userspace 用同一批特徵亦無法救。需 L7 特徵，超出本架構 |

> **結論：Layer 2 的唯一潛在收益標的（HOIC）已被劃為凍結非目標，故 Layer 2 目前無 in-scope 收益。**
> 以下保留 HOIC 相關技術分析，僅供「未來若解除泛化邊界」時參考，非現行待解項。
> HOIC 另有低成本替代解（eBPF 端 `init_win_ratio` 硬規則），見
> `kernel_defense_architecture.md`「待研究問題」——若該硬規則足夠，可不需整個 Layer 2。
> Run 29 已確認：在 32-entry binary contract 內換特徵救不了 HOIC（換成 `init_win_bit`
> HOIC 仍 ≈0），故 HOIC 的解必然落在「跳出 binary contract」＝Layer 2 完整 IF
> 或 kernel 硬規則二選一。

---

## 4. 核心可行性問題：特徵重建（THE blocker）

完整 IF 的輸入是 CICFlowMeter 算出的 25 個 `FEATURE_COLS`。kernel datapath
**不**產生這些值——它只累積 `SessionValue` 的原始計數器。Layer 2 能否成立，
取決於能用 kernel 已有的量重建多少 IF 特徵。

### kernel 端已有的原始量

來自 `SessionValue`（`session.rs:65`）：
`orig_bytes` / `resp_bytes` / `orig_pkts` / `resp_pkts` / `start_ts` /
`last_seen_ts` / `pkt_sum_sq` / `max_pkt_len`。

來自 `StatsEvent`（5 個 contract 特徵的 numer/denom 近似）。

### 重建可行性分類（須在 M1 逐欄填表驗證）

| 類別 | 範例 IF 特徵 | 可重建？ |
|------|------------|:--------:|
| 直接可得 | Total Fwd/Bwd Pkts、Flow Duration（`last_seen-start`）、Fwd Pkt Len Max | ✓ |
| 由現有量推導 | Packet Length Mean（total_bytes/total_pkts）、Pkt Len Std（由 `pkt_sum_sq` 還原）、流量比率類 | ✓（需在 userspace 補算）|
| 需新增 kernel 欄位 | 方向別 byte/pkt 細分、IAT（封包間隔）統計、Init Win Bytes、Flag 計數 | △ 需擴 `SessionValue` |
| 無法重建 | 任何 L7 / payload 內容衍生特徵 | ✗ |

> **這張表是 Layer 2 的 go/no-go gate。** 若 IF 對 HOIC 的鑑別力主要來自「無法重建」
> 或「成本過高需大幅擴 `SessionValue`」的特徵，則 Layer 2 不划算，應退回 kernel 硬規則方案。
> M1 必須先用離線資料量化：**僅用可重建特徵子集**訓練的 IF 對比完整 25 維的表現。

### M1 結果（2026-06-07，CIC-2019，連續 IF-direct，訓練為 CIC BENIGN 03-11）

實驗：`experiments/run32_dimensionless_vs_full.py`。整體 AUC（BENIGN vs 全攻擊）：

| 特徵集 | 維度 | CIC 整體 AUC | CIC FPR | CIC macro-avg |
|--------|:---:|:---:|:---:|:---:|
| Full25（完整 CICFlowMeter）| 25 | 0.8976 | 0.108 | 0.8747 |
| Dim3（純無量綱 3 比例）| 3 | 0.6587 | **0.485** | 0.6514 |
| **Contract5_cont（可重建 5 特徵連續版）**| 5 | **0.8453** | **0.066** | 0.8038 |

**結論（CIC-2019 範圍內）：**
1. **純無量綱 3 比例不足以取代完整特徵**：AUC 0.66、FPR 48.5%（高 TPR 是假象，幾乎全判攻擊），不可用。
2. **可重建的 contract-5 連續版幾乎可取代 Full25**：整體 AUC 僅低 0.05、FPR 更低（0.066 vs 0.108），多項 DrDoS_* 甚至贏 Full25。兩個絕對特徵（protocol、pkt_len_mean）補上純比例缺口。
3. **代價集中在 Syn / UDP-lag / WebDDoS**（連線速率型/低速攻擊，Contract5 0.24–0.37 vs Full25 0.60–0.67）——但這些連 Full25 都偏弱，是**已知盲區（Run 30），非特徵覆蓋度問題**。

**對架構的關鍵推論：** 對照部署 contract（Run 28 D 二值化 avg≈0.60），Layer 2 可撿回的主要增益在「二值化 → 連續可重建 IF」（0.60→0.85），**非「可重建 → 完整 25 維」（0.85→0.90）**。userspace 連續 IF **不需要完整 25 維**，僅用可重建特徵就能拿回大部分損失。
go/no-go：**特徵覆蓋度不是 Layer 2 的阻塞點。**

> 跨環境（HOIC/IDS2018）的特徵集行為差異屬泛化議題，超出 CIC-2019 範圍，不在本文展開；
> `run32` 腳本含一個 out-of-scope HOIC 參考列，需要時自行執行查閱。

---

## 5. 架構設計：升級式（escalation）而非全量推論

完整 IF 單流推論 1–10 ms，不可能逐封包跑。Layer 2 採**選擇性升級**：
fast-path 處理全部流量，只把「不確定」的流量升級給 IF。

```
                       ┌─────────────── Layer 1（kernel fast-path，全量）────────────┐
封包 → score_session → │ 明確 BENIGN / 明確攻擊 → 直接 PASS / DROP（不升級）          │
                       │ 不確定（升級候選）→ 標記後經 ring buffer 上送                 │
                       └──────────────────────────┬─────────────────────────────────┘
                                                   ▼
                            ESCALATION_RING（新，或復用 StatsEvent 擴充）
                                                   ▼
                       ┌─────────────── Layer 2（userspace，選擇性）─────────────────┐
                       │ Rust dispatcher：特徵重建（§4）→ IPC → Python IF sidecar    │
                       │ IF 判決（anomaly_score > threshold）                          │
                       │   → 攻擊：controller.block_ip(src) 寫 BLOCK_LIST（enforcement）│
                       │   → 良性：記錄，不動作                                         │
                       └──────────────────────────────────────────────────────────────┘
```

**設計要點：**
1. **升級判準在 kernel**：以 `score` 落在 threshold 鄰域（near-boundary）或特定 bit pattern
   作為「不確定」訊號，沿用 `StatsEvent.flags` 的擴充位元，避免新增 hot-path 分支成本。
2. **IF 跑在 Python sidecar**：模型是 sklearn/joblib，必須 Python process。Rust firewall
   透過 IPC（Unix socket / stdin-stdout JSON）呼叫，重用 `infer.py::_infer_if` 的推論核心。
   符合架構文件「1–10 ms（ring buffer + IPC）」的延遲預算。
3. **enforcement 走現成出口**：Layer 2 判決 → `block_ip` → 後續封包由 XDP 直接 drop。
   不需新的 datapath 變更。
4. **升級預算**：每秒升級流數設上限（rate limit），避免攻擊以「大量 near-boundary 流」
   反向 DoS Layer 2（攻擊者可故意製造邊界附近流量灌爆 sidecar）。此為安全前提，非選配。

---

## 6. 元件變更清單（實作時的具體目標）

| 元件 | 檔案 | 變更 |
|------|------|------|
| 升級事件結構 | `firewall-common/src/model.rs` | 新增 `EscalationEvent`（SessionKey + 重建所需原始量），或擴充 `StatsEvent` 帶 key |
| 升級判準 | `firewall-ebpf/src/scorer.rs` | near-boundary 判定 → 設升級 flag + reserve 上送（沿用 sampling 範式，加預算上限）|
| `SessionValue` 擴欄（視 §4 M1 結果）| `firewall-common/src/session.rs` | 若 HOIC 關鍵特徵需 Init Win / 方向細分，補對應欄位（注意 512B stack 與 verifier）|
| 升級消費迴圈 | `firewall/src/lib/`（新檔 `escalator.rs`）| `AsyncFd` RingBuf 消費（仿 `boundary_updater.rs`）→ 特徵重建 → IPC |
| IF sidecar | `service/model/`（新 entrypoint，包 `infer.py::_infer_if`）| 常駐 process，stdin/socket 收特徵 → 回 anomaly_score |
| enforcement 串接 | `firewall/src/lib/escalator.rs` → `controller.block_ip` | IF 判攻擊 → 寫 BLOCK_LIST |
| 設定 | `firewall/src/lib/config.rs` | sidecar 路徑、升級預算、IF threshold、enforcement 開關 |

---

## 7. 分階段里程碑

| 階段 | 內容 | 退出條件 / go-no-go |
|------|------|--------------------|
| **M0** | 本設計文件、特徵重建欄位盤點 | 文件 review 通過（現階段到此為止）|
| **M1** | 特徵重建可行性實驗（離線）| **僅用可重建特徵子集的 IF 對 HOIC AUC ≥ 目標**；否則退回 kernel 硬規則，終止 Layer 2 |
| **M2** | Rust ↔ Python IF sidecar IPC PoC | 單流端到端延遲落在 1–10 ms 預算 |
| **M3** | 升級判準 + enforcement loop（kernel→sidecar→block_ip）| host-testable 整合測試（仿 `integration.rs`）|
| **M4** | 端到端評估（含升級預算下的攻擊抗壓）| HOIC 收益、誤升級率、legitimate drop、sidecar 抗 DoS |

> **M1 是真正的 gate。** 在 M1 量化 HOIC 收益前，不投入 M2 以後的工程。

---

## 8. 驗證與成功標準

- **偵測收益**：Layer 2 對 HOIC 的 AUC 相對 Layer 1（contract AUC≈0）的提升幅度，
  且須以**可重建特徵子集**衡量（非用完整 CICFlowMeter 25 維，那是理論上限非可達值）。
- **延遲**：升級流的端到端判決延遲 ≤ 10 ms（架構文件預算）；fast-path 全量延遲不受影響。
- **誤升級率**：被升級但實為 BENIGN 的比例（決定 sidecar 負載）。
- **安全**：升級預算上限下，攻擊者無法以 near-boundary 流灌爆 sidecar（M4 抗壓）。
- **legitimate drop**：Layer 2 enforcement 的正常封包誤丟比例。

---

## 9. 風險與已知限制

1. **特徵重建缺口（最高風險）**：若 HOIC 鑑別力依賴不可重建特徵，Layer 2 不成立。M1 先驗。
2. **scope 衝突**：HOIC 屬 IDS2018，與「CIC-2019 only」現行範圍衝突；啟動 Layer 2＝擴範圍決策。
3. **sidecar 成為新攻擊面**：IPC + Python process 引入延遲、單點與被灌爆風險（§5.4 升級預算為必要對策）。
4. **LOIC-HTTP 不在收益範圍**：勿把 Layer 2 宣傳為「補齊所有 fast-path 盲區」——它只可能補 HOIC。
5. **替代解可能更划算**：kernel 端 `init_win_ratio` 硬規則若能達標，Layer 2 整套可省。M1 應同時對照此替代解。

---

## 10. 關聯

- 解除懸空引用：`kernel_defense_architecture.md`（§Tiered Offloading、推論位置軸心、最終比較表）、
  `CLAUDE.md` 架構行、`docs/README.md` 死連結記錄。
- 前置：本文 M0 是 `TASKS.md` 實驗清單 Run 32（Layer 2 完整 IF 整合實驗）的設計依據。
- 證據鏈：HOIC 在 binary contract 內無解 → Run 28/29（`quantile_bucket_strategy_log.md`）。
