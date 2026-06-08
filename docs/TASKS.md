# Project Task List

> 依閉環資料流分層：感測 → 決策 → 執行 → 回饋。標記說明：`[ ]` 待辦、`[x]` 完成、`[-]` 進行中。
> 嚴重度：🔴 阻塞性 / 🟡 重要 / 🟢 次要

---

## 1. 感測層（eBPF XDP — 特徵抽取）

| 狀態 | 嚴重 | 任務 | 位置 |
|------|------|------|------|
| `[x]` | 🔴 | 在 XDP per-flow struct 新增 `fwd_pkt_max` 欄位（`SessionValue.max_pkt_len: u32` 已存在） | `firewall-common/src/session.rs:46` |
| `[x]` | 🟡 | 移除 `ModelFeature` struct（已不存在於 `firewall-common/src/lib.rs`） | — |
| `[x]` | 🟢 | **(2026-05-31)** 實作 IPv6 封包解析：IPv4/IPv6 雙棧，位址統一為 `[u8;16]`（IPv4 走 IPv4-mapped `::ffff:a.b.c.d`）。`SessionKey`/`BLOCK_LIST`/`PacketInfo` 全鏈改 16-byte；IPv6 固定 40-byte header（不追 extension header）；SYN-cookie 以 `pkt.is_ipv6` gate 維持 IPv4-only。⚠️ kernel verifier 最終確認需 on-hardware load（`cargo build` 僅產 bytecode，不跑 verifier） | `firewall-ebpf/src/parser.rs`、`firewall-common/src/session.rs`、`blocker.rs`、`main.rs`、`controller.rs`、`logger.rs` |
| `[x]` | 🟢 | 補上 `unsafe` 程式碼的 safety invariant 說明（`parser.rs` 所有 `unsafe fn` 已有完整 SAFETY 說明）| `firewall-ebpf/src/parser.rs` |
| `[x]` | 🔴 | **(2026-05-23)** eBPF verifier 通過：6 個阻塞性修補（詳見 `docs/_crosscut/issues/ebpf_verifier_pitfalls.md`） | `firewall-ebpf/src/main.rs`、`syn_cookie.rs`、`scorer.rs`、`table.rs` |
| `[x]` | 🔴 | **(2026-05-23)** `tc_egress` 重構：body 移到 `tc_egress_impl(&ctx) -> i32` helper，回傳 scalar 隔離 register allocation；同時 inline 也消除 `Result<i32,()>` aggregate return | `firewall-ebpf/src/main.rs:31` |
| `[x]` | 🔴 | **(2026-05-23)** `update_checksum` while loop 改 2 次 unrolled fold（unbounded while 撞 verifier 1M insn limit）| `firewall-ebpf/src/syn_cookie.rs:51` |
| `[x]` | 🟠 | **(2026-05-23)** `scorer.rs` / `table.rs` 全面 `saturating_mul` → `wrapping_mul`（saturating 觸發 `__multi3` 在 BPF 缺 link）| `firewall-ebpf/src/scorer.rs`、`firewall-ebpf/src/table.rs` |

---

## 2. 決策層（eBPF TC scorer + ML pipeline）

| 狀態 | 嚴重 | 任務 | 位置 |
|------|------|------|------|
| `[x]` | 🔴 | **(2026-06-07) 不採用**：實跑 Run 29 32-entry contract 矩陣，無一 variant 改善 CIC-2019 範圍（E1 取代 protocol：DDoS2019 −0.16、LOIC-UDP −0.99 崩；E2 取代 mean：DDoS2019 −0.02、BigFlow −0.13；F 6-bit/64-entry：DDoS2019 −0.03、table 翻倍）。HOIC 在所有 variant 仍 ≈0（最佳 0.0057），證實單特徵 AUC=0.9995 是 IF-direct 而非 contract 路徑——HOIC 崩潰是二值化 contract 結構問題、非特徵選擇問題。保留 protocol_bit 與現有 5-bit contract | `firewall-ebpf/src/scorer.rs` + `distill_export.py` |
| `[x]` | 🟡 | 執行 Run 30 N-sweep（資料就緒後）：驗證多點分位桶對 HOIC / LOIC-HTTP 的改善效果（2026-05-23 完成） | `service/model/experiments/run30_n_sweep.py` |
| `[x]` | 🟡 | **(2026-05-25)** Run 30 決策：N=4 avg AUC=0.8806 < N=2 avg AUC=0.8943，N=4 無顯著改善；維持 N=2 32-entry contract，`distill_export.py` 無需調整 | `pipeline/distill_export.py` |
| `[x]` | 🔴 | **(2026-05-25)** `build_features` 實作 BigFlow→CIC 欄位映射（LONGEST_FLOW_PKT→FwdMax, IN_PKTS→TotalFwd, bucket→Std 等 7 欄）；CIC 路徑仍為 identity | `service/model/data/features.py` |
| `[x]` | 🟡 | **(2026-05-25)** `get_mixed_normal_sample` 加 `read_cols` 選項；BigFlow source 透過 `BIGFLOW_READ_COLS` column-prune，繞過 schema 衝突且防 OOM | `service/model/data/sample.py` |
| `[x]` | 🟡 | **(2026-05-23)** `service/firewall/firewall/src/data_format/model.json` 缺 contract 欄位且 `pkt_cv` 名稱錯誤；以 `distill_export_cic_only.py`（CIC-only stop-gap）重新產出 | `service/firewall/firewall/src/data_format/model.json` |
| `[-]` | 🟡 | **(2026-05-25 暫緩)** Mixed BENIGN model.json：BigFlow 載入技術路徑已修復，但範圍限定 CIC 2019，暫不啟用；恢復條件：決定跨資料集泛化時 | `service/model/pipeline/distill_export.py` |
| `[x]` | 🟡 | **(2026-06-07)** 撰寫 Layer 2 Userspace 完整 IF 集成計畫文件，並接回 CLAUDE.md ×1 / kernel_defense_architecture.md ×3 / README ×1 懸空引用。文件含特徵重建 go/no-go gate（M1）、升級式架構、元件變更清單、里程碑。標記為設計階段、未排程實作（依 CIC-2019 only） | `docs/2_decision/layer2_integration_plan.md` |
| `[ ]` | 🟢 | 更新 `docs/_crosscut/kernel_defense_architecture.md` 的 AUC 表：補入 Run 30 結果欄 | `docs/_crosscut/kernel_defense_architecture.md` |

---

## 3. 執行層（Rust Userspace — 控制面 / 限流）

| 狀態 | 嚴重 | 任務 | 位置 |
|------|------|------|------|
| `[x]` | 🔴 | 修復 `logger.rs`：RingBuf 讀取前大小驗證（`data.len() < size_of::<SessionEvent>()` 已修） | `firewall/src/lib/logger.rs:62` |
| `[x]` | 🔴 | 修復 `main.rs`：Per-CPU Map 查詢改用 `?` 而非 `expect()`（已修） | `firewall/src/main.rs` |
| `[x]` | 🔴 | 修復 `controller.rs`：`xdp_mode` match 改為窮舉（`Native` / `Skb` 均覆蓋）| `firewall/src/lib/controller.rs:51` |
| `[x]` | 🟡 | 實作 TC egress attach（`attach_tc` 已實作）並在 `main.rs` 呼叫 | `firewall/src/lib/controller.rs:60` |
| `[x]` | 🟡 | 實作 `BLOCK_LIST` 動態管理（`block_ip` / `unblock_ip` / `list_blocked`）| `firewall/src/lib/controller.rs:80` |
| `[x]` | 🟡 | 實作 SIGINT/SIGTERM graceful shutdown（`tokio::select!` + `shutdown_signal()`）| `firewall/src/main.rs` |
| `[x]` | 🟡 | 實作 CLI（`--config` / `--iface` / `--log-level` 覆蓋）| `firewall/src/main.rs` |
| `[x]` | 🔴 | **(2026-05-23)** 修補 TC clsact cleanup：aya 0.13.1 `qdisc_detach_program` 不清 qdisc，改用 `tc qdisc del dev <iface> clsact` 系統指令 | `firewall/src/lib/controller.rs:75` |
| `[x]` | 🟡 | **(2026-05-23)** aya 0.13.1 API 遷移：`Array::get(N, 0)` → `get(&N, 0)`；`qdisc_del_clsact` → `qdisc_detach_program` | `firewall/src/lib/model_loader.rs`、`boundary_updater.rs`、`controller.rs` |
| `[x]` | 🟡 | **(2026-05-23)** `tokio::try_join!` × `select!` 型別修正：Tokio 1.49 的 `try_join!` 已不是 Future，包進 `async {}` block | `firewall/src/main.rs:152` |
| `[x]` | 🟢 | **(2026-05-25)** 補齊 metrics 輸出：logger 每 60s 週期輸出 sessions count、ring_drops、drop_rate | `firewall/src/lib/logger.rs` |
| `[x]` | 🟡 | **(2026-05-25)** Runtime config 一致性：MapsConfig 加文件說明「需重新編譯才能生效」（build-time constant 無法 runtime 覆蓋） | `firewall/src/lib/config.rs` |

---

## 4. 回饋層（Boundary Adaptive Update v2）

> 依據 `docs/4_feedback/boundary_adaptive_update_plan.md`（v2 dual-sketch + gated）

| 狀態 | 嚴重 | 任務 | 位置 |
|------|------|------|------|
| `[x]` | 🔴 | 調整 `StatsEvent`：`flags: u32` 與 `STATS_FLAG_BENIGN_GATE = 0x01` 已定義 | `firewall-common/src/model.rs:45` |
| `[x]` | 🔴 | eBPF scorer 計算並寫入 `flags.bit0`（`score×2 < threshold`）已實作 | `firewall-ebpf/src/scorer.rs:158` |
| `[x]` | 🟡 | `BoundaryMeta` struct 及 `BOUNDARY_META` BPF map 已實作 | `firewall-common/src/model.rs:68` |
| `[x]` | 🟡 | `QUANTILE_BOUNDS` double-buffer layout + `active_bank_base()` 已實作 | `firewall-ebpf/src/scorer.rs:48` |
| `[x]` | 🟡 | `BoundaryUpdater` S_ref / S_live dual-sketch + `divergence()` 已實作 | `firewall/src/lib/boundary_updater.rs` |
| `[x]` | 🟡 | `GateState` 狀態機（`Normal` / `Uncertain` / `AttackFreeze`）已實作 | `firewall/src/lib/boundary_updater.rs:42` |
| `[x]` | 🟡 | Periodic calibration（EMA + `write_boundary_version` 原子切換）已實作 | `firewall/src/lib/boundary_updater.rs:233` |
| `[x]` | 🟢 | `expiry_ns` TTL 回退邏輯（`now > expiry_ns → bank 0`）已實作 | `firewall-ebpf/src/scorer.rs:53` |

---

## 5. 跨層 / 整合

| 狀態 | 嚴重 | 任務 | 位置 |
|------|------|------|------|
| `[x]` | 🟡 | **(2026-05-31)** 端到端整合測試（host 可測）：模擬 scorer `StatsEvent` → boundary updater gate 決策（Normal/AttackFreeze）→ double-buffer 熱切換不變式（bank 不重疊＝無 half-update）。on-hardware 完整 e2e 仍由 `test_session_tracking`（root+NIC）涵蓋 | `firewall/src/tests/integration.rs` |
| `[x]` | 🟢 | **(2026-05-31)** 更新 `docs/claude_ref/codebase_map.md`：補 `boundary_updater.rs` method 清單、IPv6 `[u8;16]` key、`integration.rs` 測試 | `docs/claude_ref/codebase_map.md` |
| `[x]` | 🔴 | **(2026-05-23)** 首次端對端 Linux 執行成功（wlp3s0 SKB mode、Logger ring buffer 持續讀取、graceful shutdown 完整清理） | `docs/linux_validation_checklist.md` |
| `[-]` | 🟡 | **(2026-06-07 腳本實作完成，待 on-hardware 執行)** 實際發送封包驗證：`make verify-packets IFACE=<iface>`（ping/hping3 過 XDP + `bpftool` dump SCORE_TABLE/QUANTILE_BOUNDS/SESSIONS） | `scripts/validate_runtime.sh packets`、`docs/linux_validation_checklist.md` P1 區 |
| `[-]` | 🟡 | **(2026-06-07 腳本實作完成，待 on-hardware 執行)** Adaptive boundary 觸發測試：`make verify-boundary`（低風險流量→`Normal`，flood→`AttackFreeze`，對照 `BOUNDARY_META.version` 凍結） | `scripts/validate_runtime.sh boundary`、`firewall/src/lib/boundary_updater.rs` |
| `[-]` | 🟡 | **(2026-06-07 腳本實作完成，待 on-hardware 執行)** BLOCK_LIST 行為驗證：`make verify-blocklist IFACE=<iface> IP=<addr>`（16-byte IPv4-mapped key 經 `bpftool map update` 寫入後 `hping3` 確認 DROP）。註：尚無 runtime CLI 呼叫 `block_ip`，暫以 bpftool 寫入 | `scripts/validate_runtime.sh blocklist`、`firewall/src/lib/controller.rs:89` |

---

## 7. Makefile / Dev Workflow（2026-05-23 新增）

| 狀態 | 嚴重 | 任務 | 位置 |
|------|------|------|------|
| `[x]` | 🟡 | Makefile 增 `make test` / `make run-firewall` / `make run-firewall-debug` / `make run-test` 並解決 `sudo` × nightly toolchain PATH 問題 | `Makefile` |
| `[x]` | 🟡 | 移除 Makefile 硬編碼 `/home/zanya/.cargo/bin/cargo`，改用 PATH 中的 `cargo` | `Makefile:2` |
| `[x]` | 🟢 | 增 `make clean-tc`（清理 `tc qdisc del dev <iface> clsact` 殘留）以便在強制 kill 後快速復原 | `Makefile` |
| `[x]` | 🟢 | 增 `make bpftool-maps`（dump SCORE_TABLE / QUANTILE_BOUNDS / BLOCK_LIST）| `Makefile` |

---

## 6. Code Review 修復清單（2026-05-20）

> 來源：全專案 code review。🔴 Critical / 🟠 Bug / 🟡 Design / 🟢 Minor

### eBPF Kernel（firewall-ebpf）

| 狀態 | 嚴重 | 任務 | 位置 |
|------|------|------|------|
| `[x]` | 🔴 | **SYN cookie ACK 驗證反向**：`if cookie != tcp.ack_seq + 1` 已改為 `if tcp.ack_seq.wrapping_sub(1) != cookie` | `firewall-ebpf/src/main.rs` |
| `[x]` | 🟠 | **BLOCK_LIST 對 SYN 封包無效**：`is_blocked` 已移至 SYN cookie 邏輯之前 | `firewall-ebpf/src/main.rs` |
| `[x]` | 🟠 | **TCP checksum data-offset nibble**：改為讀取 TCP offset 12-13 實際 16-bit word 再呼叫 `update_checksum`；移除 `SYN_FLAG`/`SYN_ACK_FLAG` 常數 | `firewall-ebpf/src/syn_cookie.rs` |
| `[x]` | 🟠 | **`pkt_sum_sq` overflow**：先 clamp `len` 到 65535（u16 max），`len²` ≤ 4.3B 不溢 u64；改 `saturating_add` 累加，完全無 `__multi3` | `firewall-ebpf/src/table.rs` |
| `[x]` | 🟡 | **(2026-05-23)** TC egress 改用 `SessionUpdateParams::from(&pkt)`：`tc_egress_impl` 不再手動 L4 match | `firewall-ebpf/src/main.rs:31` |
| `[x]` | 🟡 | **`DROP_EVENTS` 計數器**：Logger 加 `drop_events: PerCpuArray` 欄位，每 60s 讀取並記錄；main.rs 提取 DROP_EVENTS map 傳入 | `firewall/src/lib/logger.rs` |
| `[x]` | 🟢 | 多餘括號：`if ((*session).max_pkt_len < ...)` → 去括號 | `firewall-ebpf/src/table.rs` |
| `[x]` | 🟢 | 冗贅變數：`let mut is_close = false; is_close = ...` → `let is_close = ...` | `firewall-ebpf/src/table.rs` |
| `[x]` | 🟢 | 不必要 unsafe block：`unsafe { try_xdp_firewall(ctx) }` 中 `try_xdp_firewall` 為 safe fn | `firewall-ebpf/src/main.rs` |
| `[x]` | 🟢 | **(2026-05-23)** `XDP_PASS` import 已不使用、`PacketContext` import 已不使用，可移除 warning | `firewall-ebpf/src/main.rs`、`firewall-ebpf/src/syn_cookie.rs` |

### Userspace（firewall）

| 狀態 | 嚴重 | 任務 | 位置 |
|------|------|------|------|
| `[x]` | 🔴 | **`kill_old_sessions` 時鐘不相容**：改用 `libc::clock_gettime(CLOCK_BOOTTIME)` 與 `bpf_ktime_get_ns()` 對齊 | `firewall/src/lib/task.rs` |
| `[x]` | 🟡 | **`MapsConfig` 執行期值無作用**：已加文件說明「需重新編譯才能生效」 | `firewall/src/lib/config.rs` |
| `[x]` | 🟢 | 多餘括號：`if (config.security.enable_random_secret)` → 去括號 | `firewall/src/lib/controller.rs` |

### Python（service/model）

| 狀態 | 嚴重 | 任務 | 位置 |
|------|------|------|------|
| `[x]` | 🟡 | **`_feature_ratio_components` 靜默 fallback**：已加 `warnings.warn` 於 fallback 路徑 | `pipeline/distill.py` |
| `[x]` | 🟡 | **`get_mixed_normal_sample` 靜默降級為單一來源**：已加警告於 chunks 數量不足時 | `data/sample.py` |
| `[x]` | 🟢 | `RAW_COLS = []` 和 `NUMERIC_RAW_COLS = []` 空死欄位已移除 | `schema.py` |

---

## 實驗清單（特徵工程 Run 01–32）

> `[x]` 已完成並記錄、`[-]` 已寫腳本待跑、`[ ]` 規劃中

| 狀態 | Run | 主題 | 腳本 | 關鍵結論 |
|------|-----|------|------|---------|
| `[x]` | 01–07 | 特徵選擇基線（80→17 特徵，AUC=0.9257） | — | 絕對值特徵跨環境 AUC 0.28 |
| `[x]` | 08–10 | 跨資料集驗證：絕對值特徵在 LOIC-HTTP 崩潰 | — | 確認需無量綱特徵 |
| `[x]` | 11–16 | 比例特徵（Shape+Sym+Pkt_CV）+ log1p | — | HOIC 仍 ≈0；比例特徵未解決 |
| `[x]` | 17 | N=2 分位桶突破（BENIGN 中位數邊界） | `run17_quantile_ratio.py` | HOIC 0.002→0.993；核心突破 |
| `[x]` | 18 | Bytes sum 特徵實驗 | `run18_bytes_sum.py` | — |
| `[x]` | 19 | Mixed BENIGN 邊界（CIC+BigFlow） | `run19_mixed_benign.py` | 解決 CIC-only overfit |
| `[x]` | 20 | 移除 Shape_q 影響評估 | `run20_no_shape.py` | AUC −0.017，損失可接受但需替代 |
| `[x]` | 21 | Shape_q 替代特徵搜尋 | `run21_shape_alternatives.py` | FwdMax_ratio 為最佳替代（+0.031） |
| `[x]` | 22 | FwdMax_q N-scan（N=2/4/8/16） | `run22_fwdmax_n_scan.py` | N=2 最優；IF-direct（非 contract 路徑） |
| `[x]` | 23 | BigFlow OOD overfit 驗證 | `run23_bigflow_overfit_check.py` | Shape_q BigFlow AUC 0.40（反轉）|
| `[x]` | 24 | Mixed BENIGN 訓練：Shape_q vs FwdMax_q | `run24_mixed_benign_shape_fwdmax.py` | Mixed 後 FwdMax_q 均勝 Shape_q |
| `[x]` | 25 | 最終特徵確立 + N-scan（FwdMax+Sym+CV+Protocol+Mean） | `run25_final_fwdmax_n_scan.py` | 最終 5 特徵方案（IF-direct，非 contract）|
| `[x]` | 26 | 完整指標（AUC-PR, TPR@FPR）| `run26_extended_metrics.py` | AUC-PR DDoS2019=0.9895；BigFlow TPR@1%=0.0148 |
| `[x]` | 27 | Boundary overfit check（CIC vs BigFlow 邊界差異）| `run27_boundary_overfit_check.py` | 兩環境分布差異 2–4×；必須 Mixed 邊界 |
| `[x]` | 28 | Contract 對照矩陣（Run25 original vs 32-entry all-binary）| `run28_contract_matrix.py` | **部署 contract HOIC=0.0001，avg=0.60**；protocol 二值化是根本原因 |
| `[x]` | 29 | HOIC 特徵替換（init_win_bit 修復 HOIC）| `run29_hoic_feature_search.py` | `init_win_bit` 單特徵 HOIC AUC=0.9995；BigFlow 無此欄位不受影響 |
| `[x]` | **30** | N-sweep 多點分位桶（N=2/4/8，CIC-only）| `run30_n_sweep.py` | N=2 avg=0.8943 最優（N=4=0.8806、N=8=0.9125 但 32768-entry 不可行）；SYN/UDP-LAG 為盲區；維持 N=2 contract |
| `[x]` | 31 | **N=8 + Per-feature Additive Bucket Score（PAB-Score）驗證**：OLS fit additive model，同一 eval 切片三方對照 N=8 full / additive / N=2 全分位桶 contract（2026-05-31 完成）| `run31_additive_score.py` | **不採用**：additive avg AUC=0.7128 **連 N=2 contract（0.8943）都不如**；R²=0.66、max Δ=+0.39（SYN）、FPR 0.09→0.30。交叉項顯著，保留 N=2 contract |
| `[x]` | 34 | **Student score regression vs bucket（E2，in-scope FPR≤1%）** | `run34_score_regression.py` | regression 忠實複製 teacher（Spearman 0.99）→ 繼承 teacher 操作點不可用（F1@1%=0.11）；bucket 不複製（Spearman 0.55）卻 F1=0.90 → **推翻「分位桶保留排序」假設**，價值在與 teacher 絕對分數脫鉤 |
| `[x]` | 33 | **IF + static quantile bucket K 敏感度（E1/E6，in-scope FPR≤1%）** | `run33_static_bucket.py` | K=2 F1=0.900 全操作點穩健（32-entry）；**K=4 F1=0.000 操作點崩潰**（1024-entry，FPR≤5% R=0）；K=8 恢復但 32768-entry 不可行 → 坐實選 K=2 |
| `[-]` | 32 | Layer 2 完整 IF 整合實驗：userspace runtime IF 與 kernel fast-path 分流策略 | `run32_dimensionless_vs_full.py` | **M1 完成（2026-06-07，CIC-2019）**：可重建 contract-5 連續版 AUC=0.845（FPR 0.066）≈ Full25 的 0.898，純無量綱 3 比例崩（0.659/FPR 0.485）。關鍵：Layer 2 主增益在「二值化→連續 IF」(0.60→0.85)、非「可重建→25 維」；特徵覆蓋度非阻塞點。依 CIC-2019 only，M2+ 暫不啟動 |

---

## 8. 缺口收斂 → 可執行任務（2026-06-07）

> 由「實作程度盤點」轉出。三層 code 已完整可跑，缺口集中在**量測 / 對照 / 真機驗證**。
> 每列含：腳本（待建）、指令、驗收標準（DoD）、依賴。完成後回填對應 E#/Table 佔位表。
> 嚴重度沿用 🔴🟡🟢。`[ ]` 待辦、`[-]` 腳本就緒待跑。

### 8.A 系統效能量測（填 E4 / Table 2；目前整表空白＝從未量測）

| 狀態 | 嚴重 | 任務                                | 腳本 / 指令 | 驗收標準（DoD） | 依賴 |
|------|------|-----------------------------------|------------|----------------|------|
| `[ ]` | 🔴 | 建立 benchmark 測試平台（受測機 + 流量產生器）    | `scripts/bench/setup_testbed.sh`；`make bench-setup IFACE=<iface>` | 文件化拓樸（loopback / veth pair / 雙機）；`hping3` 或 `pktgen` 可發 ≥1 Mpps；可重現 | on-hardware（root + NIC） |
| `[ ]` | 🔴 | Packet throughput（pps）4 對照組       | `scripts/bench/throughput.sh`（no-mitigation / static-blocklist / userspace-IF / eBPF-bucket）| 產出 4 組 max sustained pps + drop 曲線；eBPF-bucket ≥ userspace-IF | 8.A-1 |
| `[ ]` | 🟡 | CPU usage（%）各對照組                  | 同上 harness + `mpstat`/`pidstat` | 同負載下 eBPF enforcement CPU% 表；含 softirq 佔比 | 8.A-1 |
| `[-]` | 🟡 | Map lookup latency（ns）            | kernel 內 `bpf_ktime_get_ns()` 包夾 scorer 查表段 → 直方圖 map；或 `bpftool prog profile` | SCORE_TABLE/QUANTILE_BOUNDS 單次查表 p50/p99（ns）。**userspace proxy 已測：33.6 µs/flow，比 IF 推論快 177×（`results_benchmark.py`）**；kernel ns 待 on-hardware | on-hardware |
| `[ ]` | 🟡 | Map update latency（µs）            | `boundary_updater.rs` 寫 map 前後 `Instant::now()` 包夾，logger 輸出 | `write_boundary_version` p50/p99（µs）| — |
| `[ ]` | 🟡 | Mitigation latency（µs，偵測→DROP e2e） | `scripts/bench/mitigation_latency.sh`（時間戳：攻擊封包進場 ↔ 首個 XDP_DROP）| 端到端延遲分布；含 SYN-cookie 路徑 | 8.A-1 |
| `[ ]` | 🟡 | Legitimate drop ratio（%）          | benign+attack 混流回放，比對 ground-truth | FPR-in-the-wild（誤丟正常封包比例）| 8.A-1 |

### 8.B 偵測對照矩陣（填 E1/E2/E3/E5/E6 — Table 1 + Figure 2）

| 狀態 | 嚴重 | 任務 | 腳本 / 指令 | 驗收標準（DoD） | 依賴 |
|------|------|------|------------|----------------|------|
| `[-]` | 🔴 | E1 Detection baseline：補齊 5 方法對照 | `service/model/experiments/results_benchmark.py`（已含 teacher/baseline/deployed 3 列）→ `run33_detection_baseline.py`（補餘 3 組）| **已測**：Contract5 teacher 0.845 / Abs20 0.892 / deployed binarized 0.897(F1 0.901)；**待補** IF-static-bucket / student-regression / **student-bucket-KD** / (LR\|RF) | student KD 需先實作（8.B-2）|
| `[ ]` | 🔴 | 實作 student quantile-bucket KD 訓練（目前只有 IF→bucket distill）| `pipeline/distill.py` 擴充 + `trainer/` | KL/CE distillation 產出 bucket policy；單元測試對齊 contract | — |
| `[ ]` | 🟡 | E2 Regression vs Classification 對照 | `run34_regression_vs_bucket.py` | Spearman(student vs IF score) + Top-k attack recall 兩軸數據 | 8.B-2 |
| `[ ]` | 🟡 | E3 漂移模擬器 + Static/Periodic/Gated 對照 | `run35_drift_eval.py`（或擴 `integration.rs` 驅動 Rust gate）| 人工 drift（pps 2×、攻擊 10%→50%）≥4 window 的 F1/FNR 折線 → Figure 2 | drift 注入器 |
| `[ ]` | 🟡 | E5 攻擊污染 sweep（ρ=10/30/50/80%）| `run36_contamination_sweep.py`（重用 `boundary_updater` gate 邏輯）| Naive vs Gated FNR 對照表；驗證 gate 凍結 reference boundary | 8.B-3 |
| `[-]` | 🟢 | E6 Bucket K 敏感度（K=2/4/8）| 部分已有 Run 30 數據（AUC/FPR）；補 F1/PR-AUC + table size 列 | 回填 E6 表（K=2 已知，K=4/8 從 Run 30 取）| 大致就緒 |

### 8.C 真機 eBPF 驗證 + 收尾（已有腳本，待 on-hardware 執行）

| 狀態 | 嚴重 | 任務 | 腳本 / 指令 | 驗收標準（DoD） | 依賴 |
|------|------|------|------------|----------------|------|
| `[x]` | 🔴 | **(2026-06-07) release artifact 通過**：kernel 6.12.90-1-MANJARO 上以 `lo`（SKB/`xdpgeneric`）實機 load，XDP+TC attach 成功、Logger ring buffer 即時讀到 loopback session、SIGTERM graceful shutdown 無 leak。⚠️ **debug build（`make run-firewall-debug` / `run-test`）verifier REJECT**：`last insn is not an exit or jmp`（debug bytecode 未最佳化，verifier-hostile）；正式 load 一律走 release。`make verify-load` 因 `bpftool` 未安裝（pacman offline）未跑 map dump 部分 | `make run-firewall IFACE=<iface>`、`make verify-load` |
| `[-]` | 🟡 | 封包驗證 `make verify-packets`（§5 已列）| `scripts/validate_runtime.sh packets` | bpftool dump SCORE_TABLE/SESSIONS 有預期變化 | on-hardware |
| `[-]` | 🟡 | Adaptive boundary 觸發 `make verify-boundary`（§5 已列）| `scripts/validate_runtime.sh boundary` | flood→`AttackFreeze`，`BOUNDARY_META.version` 凍結 | on-hardware |
| `[-]` | 🟡 | BLOCK_LIST 驗證 `make verify-blocklist`（§5 已列）| `scripts/validate_runtime.sh blocklist` | IPv4-mapped key 寫入後 hping3 確認 DROP | on-hardware |
| `[ ]` | 🟡 | 補 runtime CLI 呼叫 `block_ip`（目前僅 bpftool 手動寫入）| `firewall/src/main.rs` + `controller.rs:89` | CLI/signal 觸發 block/unblock；整合測試覆蓋 | — |
| `[x]` | 🟠 | **(2026-06-07 完成)** debug eBPF build verifier REJECT（`last insn is not an exit or jmp`）：根因＝workspace 無 `[profile.*]`，dev build `opt-level=0`。已加 `[profile.dev] opt-level=3`（+lto/codegen-units=1/panic=abort）+ `[profile.release] lto=true`。`make build-ebpf` / `build-ebpf-debug` 皆編過、`make test` 11 綠 | eBPF workspace `Cargo.toml` | nightly + bpf-linker |
| `[x]` | 🟠 | **(2026-06-07 發現+完成)** 上述 profile 修好後浮現新錯：`opt-level=3` 把 `#[inline(always)]` 的 `parse_packet` 折進 `xdp_firewall` entry frame，撞 512B BPF stack 上限。修法＝把 `parse_packet` 改 out-param + `bool` 回傳 + `#[inline(never)]`（沿用 `update_session`/`score_session` pattern，避開 bpf-linker aggregate-return 拒絕），並把 `parse_ipv4`/`parse_ipv6` 從回傳整個 `Ipv4Hdr`/`Ipv6Hdr`（20/40B copy）改為透過指標抽純量欄位回傳 `L3Fields`，移除主因的整 header stack copy | `firewall-ebpf/src/parser.rs`、`main.rs`、`firewall-common/src/protocol.rs`（`L4Info: Default`） | nightly + bpf-linker |
| `[ ]` | 🟢 | commit `feat/model_develope` 上未提交的 verifier fix 與實驗（git status 多檔 M/??）| `git add -p` + 分批 commit | 工作樹乾淨；commit message 對應 Run 30/31 與 verifier 修補 | — |
| `[ ]` | 🟢 | 補 `kernel_defense_architecture.md` AUC 表 Run 30 結果欄（§2 line 35 既列）| 編輯文件 | Run 30 N-sweep 數據入架構唯一依據 | — |

---

## 論文實驗計畫（IEEE 2-page / WiP）

> 目標敘事：Detection works ＋ Quantile bucket is useful ＋ eBPF mapping is lightweight
> 必做 4 個（P0/P1）＋ 加分 3 個（P2/P3）。兩頁 IEEE 放 **Table 1 + Table 2 + Figure 1 + Figure 2** 即可。

---

### 必做 E1 — 偵測能力 baseline（P0）

**目標：** 證明 teacher + student 有效，分位桶蒸餾不輸 IF teacher 太多。

**交付物：** `Table 1 — Detection Performance`

| 狀態 | 方法 | 說明 |
|------|------|------|
| `[x]` | IF + fixed threshold（Contract5 連續 teacher）| **最終 teacher**；FPR≤1% 操作點 |
| `[x]` | IF + static quantile bucket | **已測（`run33_static_bucket.py`）**：N=4(1024) F1@1%=0.000（FPR≤5% 崩潰，僅 FPR≥10% 恢復）；N=2(32) F1=0.900 全操作點穩健；N=8(32768) 恢復但不可行 |
| `[ ]` | Student score regression | Student 直接回歸 IF anomaly score（MSE loss）|
| `[-]` | **Student quantile bucket KD** | 你的方法；目前以二值特徵 IF 直接產 32-entry 表（非正式 KD），正式 KL/CE 蒸餾待實作（§8.B-2）|
| `[ ]` | Supervised baseline（選）| LR / RF，需 attack label，作為上限參考 |

**評估指標：** Precision、Recall、F1、ROC-AUC、PR-AUC、FPR、FNR
**Dataset：** CIC-DDoS2019 only（CLAUDE.md 硬邊界；不以 BigFlow 跨環境作結論）

**已實測（2026-06-08，`experiments/results_benchmark.py`；train=03-11 BENIGN、eval=01-12 balanced 48,439 列、FPR≤1% 操作點）：**

| 模型 | 角色 | ROC-AUC | PR-AUC | P | R | F1 | FPR | FNR |
|------|------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Contract5 連續 IF | 最終 teacher | 0.845 | 0.984 | 0.987 | 0.059 | 0.112 | 0.009 | 0.941 |
| Abs20 絕對特徵 IF | baseline 上界 | 0.892 | 0.983 | 0.991 | 0.102 | 0.186 | 0.010 | 0.898 |
| 部署 binarized 32-entry | deployed student | 0.897 | 0.990 | 0.999 | 0.821 | **0.901** | 0.007 | 0.179 |

> 完整逐攻擊 recall、Teacher 決策理由、討論骨架見 `docs/results_and_discussion.md`。
> 仍待補：IF static N=4 bucket、score regression、正式 KD、LR/RF supervised 四個對照組（§8.B-1/8.B-2）。

---

### 必做 E2 — Score Regression vs Quantile-Bucket Classification（P1）

**目標：** 回答 reviewer 必問：「為什麼不直接讓 student 回歸分數？」

**交付物：** 併入 Table 1 或獨立 Table 2（視頁面空間）

| 狀態 | 比較軸 | 說明 |
|------|--------|------|
| `[x]` | Student output type | **已測（`run34_score_regression.py`）**：regression vs bucket，數據如下 |
| `[x]` | Ranking preservation | Spearman(student vs teacher)：reg=0.990、bucket=0.549 |
| `[-]` | Loss function | 已比 MSE(reg) vs 二值化 bucket；正式 CE/KL 蒸餾待 §8.B-2 |
| `[x]` | Top-k attack recall | 三模型 top5%R 均 0.054（**退化指標**：eval 91% 為攻擊，top-5% 太小無鑑別力，改看 F1@1%）|

**已測（CIC-DDoS2019 in-scope，eval half，FPR≤1%）：**

| 模型 | AUC | F1@1% | R@1% | Spearman→teacher |
|------|:---:|:---:|:---:|:---:|
| teacher（Contract5 連續） | 0.845 | 0.112 | 0.059 | 1.000 |
| student-reg（DT, MSE→teacher） | 0.857 | 0.111 | 0.059 | **0.990** |
| student-bucket（32-entry） | 0.896 | **0.902** | 0.821 | **0.549** |

> **⚠️ 原假設被推翻（2026-06-08）：** 原寫「分位桶保留相對排序」。實測相反——**保留排序的是 regression（Spearman 0.99），不是 bucket（0.549）**。
>
> **修正後關鍵論點：** 忠實回歸 teacher 分數（Spearman 0.99）會**連 teacher 在嚴格操作點的不可用性一起繼承**（F1@1% 0.11，與 teacher 同）；分位桶**刻意不複製**絕對分數（Spearman 0.55，部分因 ~16 個離散分數的 tie 上限），透過中位數二值化把攻擊離散進高分桶、與 teacher 不穩定分數脫鉤，換得操作點穩健（F1@1% 0.90）。詳見 `docs/results_and_discussion.md` §2c。

---

### 必做 E3 — Static vs Streaming Bucket（drift robustness）（P1）

**目標：** 證明分位桶邊界獨立更新有價值（流量漂移下 static 邊界會退化）。

**交付物：** `Figure 2 — F1 / FNR over time under drift`

| 狀態 | 對照組 | 邊界更新方式 |
|------|--------|------------|
| `[ ]` | Static Quantile Bucket | 訓練集計算一次，不更新 |
| `[ ]` | Periodic Update Bucket | 每 T 秒以當前視窗重算 |
| `[ ]` | **Gated Streaming Bucket** | 你的方法：S_ref / S_live dual-sketch + GateState |

**Drift 場景（人工製造）：**
- 正常流量 packet rate 放大 2×（模擬業務高峰）
- 攻擊比例從 10% 增加到 50%（模擬攻擊持續）
- 切成至少 4 個 time window，折線圖呈現 F1 / FNR 變化

---

### 必做 E4 — eBPF 系統效能（P0）

**目標：** 證明這是系統論文，eBPF map lookup 遠快於 IF inference。

**交付物：** `Table 2 — System Overhead`

| 狀態 | 指標 | 說明 |
|------|------|------|
| `[ ]` | Packet throughput（pps）| 各方法能處理的最大封包率（待 on-hardware） |
| `[ ]` | CPU usage（%）| eBPF enforcement 對 CPU 的佔用（待 on-hardware） |
| `[-]` | Map lookup latency（ns）| kernel ns 待 `bpftool`/on-hardware；**userspace proxy 已測：查表 33.6 µs/flow** |
| `[ ]` | Map update latency（µs）| userspace 寫 BPF map 的成本 |
| `[ ]` | Mitigation latency（µs）| 從偵測到開始 DROP/RATE_LIMIT 的端到端延遲（待 on-hardware） |
| `[ ]` | Legitimate drop ratio（%）| 正常封包誤丟比例（in-scope FPR 已測：deployed 0.007） |

**已實測（偵測側 per-flow 延遲，userspace，`results_benchmark.py`）：**

| 路徑 | 延遲（µs/flow） | 說明 |
|------|:---:|------|
| Contract5 IF per-flow 推論 | 5948.2 | userspace 完整 IF |
| Contract 整數查表（proxy） | 33.6 | 含 polars/python overhead，延遲上界 |
| **加速比** | **177×** | kernel eBPF map lookup 為 O(ns)，實際差距更大 |

**對照組：**

| 方法 | 說明 |
|------|------|
| No mitigation | 純觀察，無 enforcement |
| eBPF static blocklist | 傳統 IP 黑名單查表 |
| IF per-flow inference（userspace）| 每封包跑一次 sklearn IF（已測 5.9 ms/flow）|
| **eBPF bucket policy map** | 你的方法（userspace proxy 33.6 µs/flow）|

**核心要證明：** `eBPF map lookup ≪ IF per-flow inference` ✅ 已驗證（≥177×，kernel ns 待補）

---

### 加分 E5 — Attack Contamination 實驗（P2）

**目標：** 展示 gated update 在 DDoS 攻擊比例高時的安全優勢。

**交付物：** `Figure 2` 的一部分，或單獨小 table

| 狀態 | 攻擊比例 ρ | Naive streaming FNR | Gated streaming FNR |
|------|-----------|:-------------------:|:-------------------:|
| `[ ]` | 10% | — | — |
| `[ ]` | 30% | — | — |
| `[ ]` | 50% | — | — |
| `[ ]` | 80% | — | — |

**關鍵論點：** Naive streaming 在 ρ 高時把攻擊流量校準為新常態（FNR 上升）；gated update 凍結 reference boundary，FNR 維持穩定。

---

### 加分 E6 — Bucket 數量 K 敏感度（P2）

**目標：** 回答「為什麼選 **K=2**」，同時呈現 eBPF table size 代價。
**（2026-06-08 修正：原假設 K=4 為目標，實測推翻——K=4 在操作點崩潰，K=2 才是最優。）**

**交付物：** 小 table 或 appendix。**已測（`run33_static_bucket.py`，CIC-DDoS2019 in-scope，FPR≤1%）：**

| 狀態 | K | F1@1% | PR-AUC | AUC | eBPF table size | 說明 |
|------|---|:---:|:---:|:---:|-----------------|------|
| `[x]` | **2** | **0.900** | 0.989 | 0.894 | 32-entry | **目前 contract；全操作點 R=0.82 穩健、table 最小** |
| `[x]` | 4 | 0.000 | 0.989 | 0.890 | 1024-entry | **FPR≤5% 崩潰（R=0），僅 FPR≥10% 恢復**；離散化 artifact |
| `[x]` | 8 | 0.899 | 0.991 | 0.908 | 32768-entry | 恢復可用但 table 大 1000×，eBPF verifier/記憶體不可行 |
| `[ ]` | 4-bucket policy | PASS / MONITOR / RATE_LIMIT / DROP | — | — | 1024-entry | 語意分級（與偵測力獨立，仍可設計）|

> 結論：選 K=2 非精度妥協，是「操作點穩健性 + eBPF 可行性」交集最優。詳見 `docs/results_and_discussion.md` §2b。

**Bucket 語意建議（K=4）：**

| Bucket | 意義 | Action |
|--------|------|--------|
| 0 | Normal | PASS |
| 1 | Low risk | PASS / MONITOR |
| 2 | Suspicious | RATE_LIMIT |
| 3 | Attack-like | DROP |

---

### 加分 E7 — BPF Map 熱更新一致性（P3）

**目標：** 證明 versioned double-buffer 更新不會讓 datapath 出現 half-update。

**交付物：** 小 table（若頁面空間允許）

| 狀態 | 測試場景 | 指標 |
|------|----------|------|
| `[ ]` | 高速封包通過時持續更新 boundary map | packet loss、inconsistent decision count |
| `[ ]` | Direct update（無 versioning）vs Versioned update | inconsistent decision per 1k updates |
| `[ ]` | TTL 開啟 vs 關閉 | stale policy duration（ms）|

---

### 論文交付物總覽

```
Figure 1  架構圖（Traffic → XDP → Feature Map → IF Teacher → Bucket Policy → eBPF → Action）
Table 1   Detection Performance（E1 + E2）
Table 2   System Overhead（E4）
Figure 2  Drift / Contamination robustness over time（E3 + E5）
```

**最小可行版（時間不夠時）：** Table 1 + Table 2 + 一張折線圖 = 兩頁站得住。

**論文敘事（最終目標）：**
> Quantile-bucket distillation preserves most of the Isolation Forest teacher's detection performance while reducing datapath decision cost to eBPF map lookups. Compared with fixed-threshold and score-regression baselines, streaming quantile-bucket calibration improves robustness under traffic drift. Gated updates further reduce attack-induced boundary contamination during DDoS bursts.
