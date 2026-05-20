# docs/ 索引（資料流分層）

> 依 closed-loop 資料流分層：**感測 → 決策 → 執行 → 回饋**。跨層（架構總覽、Python↔Rust↔eBPF 契約）放在 `_crosscut/`。
> Canonical 與被 CLAUDE.md / `scripts/analyze_error.py` 依賴的路徑請見最後一節，**不要任意搬移**。

---

## `_crosscut/` — 跨層文件（架構總覽 / 契約）

| 檔案 | 角色 | 內容 |
|------|------|------|
| `_crosscut/kernel_defense_architecture.md` | **Canonical（CLAUDE.md 指定）** | 架構唯一依據：eBPF verifier 限制、分位桶決策、AUC 數字、數學模型、Tiered Offloading |
| `_crosscut/kernel_model_contract.md` | **Canonical** | P0 工程契約：Python 蒸餾 ↔ Rust loader ↔ eBPF scorer 對齊（5-feature N=2，32-entry，bit order，length unit） |
| `_crosscut/presentation_summary.md` | 報告 | 特徵工程研究總結（簡報用） |
| `_crosscut/architecture.dot` / `arch_control_plane.dot` / `arch_data_plane.dot` | 圖 | Graphviz 架構圖 |

---

## `1_sensing/` — 感測層：特徵抽取與選擇

> 對應：kernel 在 XDP/TC 計算 per-flow 特徵 + 離線從 26 特徵濃縮到 5 特徵的工程。

| 檔案 | 內容 |
|------|------|
| `1_sensing/feature_selection_log.md` | **Canonical（CLAUDE.md 指定）** 特徵選擇實驗（Run 01–16,18 + 附錄 A-1～A-9） |

---

## `2_decision/` — 決策層：蒸餾推論與評分

> 對應：分位桶邊界 → 5-bit 索引 → 32-entry score table → 與 threshold 比較。

| 檔案 | 內容 |
|------|------|
| `2_decision/quantile_bucket_strategy_log.md` | **Canonical（CLAUDE.md 指定）** 分位桶策略 / 模型訓練（Run 17,19–29 + A-10/11/12，含 contract Run 28/29） |
| `2_decision/iTree_training_report.md` | Isolation Forest 訓練報告（Run 25 證據鏈，論文交付物） |

---

## `3_actuation/` — 執行層：DROP / 限流 / userspace 控制面

> 對應：XDP_DROP、TC redirect + token bucket、BLOCK_LIST 動態管理、graceful shutdown、CLI。

| 檔案 | 狀態 | 內容 |
|------|------|------|
| `3_actuation/userspace_improvement_plan.md` | **活的（持續更新）** | userspace 品質追蹤（2026-02-21 起）：SYN cookie、TC attach、配置系統、CLI、metrics |

---

## `4_feedback/` — 回饋層：自適應邊界更新

> 對應：kernel 取樣 StatsEvent → userspace dual-sketch + gate state machine → versioned double-buffer 寫回 QUANTILE_BOUNDS。

| 檔案 | 狀態 | 內容 |
|------|------|------|
| `4_feedback/boundary_adaptive_update_plan.md` | **已落地（branch `feat/model_develope`）** | v2 dual-sketch + gated；§11 為實作落地與 CI 紀錄 |

---

## `claude_ref/` — Claude 專用參考

> ⚠️ 路徑被 `scripts/analyze_error.py:29`（寫入 `failure_records.md`）與 CLAUDE.md 硬鎖定，**勿改名/搬移**。

| 檔案 | 內容 |
|------|------|
| `claude_ref/codebase_map.md` | 函式導覽、資料夾用途、抽樣方法選擇 |
| `claude_ref/dev_commands.md` | 常用命令、驗證 checklist、資料路徑 |
| `claude_ref/failure_records.md` | 歷史失敗案例（`analyze_error.py` 會寫入此檔） |

---

## `archive/` — 已被實作取代或廢棄

| 檔案 | 為何歸檔 |
|------|---------|
| `archive/packetinfo_redesign_proposal.md` | 提案已由 `firewall-ebpf/src/parser.rs` 的 `PacketInfo` + `PacketContext` trait 實作取代 |

---

## 已知 doc 債

- **Layer 2（Userspace 完整 IF）集成計畫尚未撰寫**。原 4 處死連結（CLAUDE.md ×1、`_crosscut/kernel_defense_architecture.md` ×3 指向不存在的 `docs/layer2_integration_plan.md`）已改為「待撰寫」純文字。實際補寫後再把敘述接回連結。
- **執行層（`3_actuation/`）目前只有一份品質追蹤計畫**，限流器/token bucket 策略尚未獨立成文，仍散落於 `_crosscut/kernel_defense_architecture.md` 的「負反饋執行」段。

---

## 路徑硬鎖清單（搬移前務必檢查）

下列檔案被 CLAUDE.md 或程式碼直接引用路徑。**搬移時必須同步更新引用端**：

| 檔案 | 引用者 |
|------|--------|
| `_crosscut/kernel_defense_architecture.md` | CLAUDE.md（×2） |
| `1_sensing/feature_selection_log.md` | CLAUDE.md |
| `2_decision/quantile_bucket_strategy_log.md` | CLAUDE.md |
| `claude_ref/codebase_map.md` | CLAUDE.md |
| `claude_ref/dev_commands.md` | CLAUDE.md |
| `claude_ref/failure_records.md` | CLAUDE.md、`scripts/analyze_error.py:29`（寫入端） |
