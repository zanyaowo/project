# docs/ 索引

> 找文件先看這裡。分類依「角色」而非主題。canonical 與被程式/CLAUDE.md 依賴路徑的檔**不要任意搬移**（見最後一節）。

## Canonical（唯一依據，CLAUDE.md 指定）

| 檔案 | 內容 |
|------|------|
| `kernel_defense_architecture.md` | 架構唯一依據：eBPF verifier 限制、分位桶決策、AUC 數字、數學模型 |
| `kernel_model_contract.md` | P0 工程契約：Python 蒸餾 ↔ Rust loader ↔ eBPF scorer 對齊（5-feature N=2, 32-entry）|

## 進行中計畫

| 檔案 | 狀態 |
|------|------|
| `boundary_adaptive_update_plan.md` | v2 dual-sketch + gated；已實作落地（見其 §11）|
| `userspace_improvement_plan.md` | **活的**品質審查追蹤（2/21 起，持續更新）；非過時 |

## 實驗 / 報告（部分內容互有重疊）

| 檔案 | 內容 | 重疊關係 |
|------|------|---------|
| `feature_selection_log.md` | 特徵選擇實驗（Run 01–16,18 + 附錄 A-1～A-9） | 主來源；分位桶/訓練線已抽出 |
| `quantile_bucket_strategy_log.md` | 分位桶策略 / 模型訓練（Run 17,19–29 + A-10/11/12，含 contract Run 28/29） | 由 `feature_selection_log` 實體抽出；Run 編號連續共用 |
| `presentation_summary.md` | 特徵工程研究總結（簡報用） | 摘要橫跨上兩份 log |
| `iTree_training_report.md` | Isolation Forest 訓練報告（Run 25）| 屬論文交付物，刻意不合併 |

## 圖（Graphviz）

| 檔案 | 內容 |
|------|------|
| `architecture.dot` | 全系統架構圖 |
| `arch_control_plane.dot` | 控制平面 |
| `arch_data_plane.dot` | 資料平面 |

## 參考（`claude_ref/`）— 路徑被 `scripts/analyze_error.py` 與 CLAUDE.md 依賴，勿改名/搬移

| 檔案 | 內容 |
|------|------|
| `claude_ref/codebase_map.md` | 函式導覽、資料夾用途、抽樣方法選擇 |
| `claude_ref/dev_commands.md` | 常用命令、驗證 checklist、資料路徑 |
| `claude_ref/failure_records.md` | 歷史失敗案例（`analyze_error.py` 會寫入此檔）|

## `archive/`（已被實作取代或廢棄，保留供追溯）

| 檔案 | 為何歸檔 |
|------|---------|
| `archive/packetinfo_redesign_proposal.md` | 提案已由 `firewall-ebpf/src/parser.rs` 的 `PacketInfo` + `PacketContext` trait 實作取代 |

## 已知 doc 債

- **Layer 2 集成計畫尚未撰寫**。原本 4 處死連結（CLAUDE.md ×1、`kernel_defense_architecture.md` ×3 指向不存在的 `docs/layer2_integration_plan.md`）已改為「待撰寫」純文字，不再是 broken link。實際補寫該計畫文件後，再把這些敘述接回連結。
