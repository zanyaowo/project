# Codebase Map — 函式與資料夾導覽

> 目的：避免重複實作已有函式、使用錯誤抽樣方法。修改前先查此文件確認是否已有對應實作。

---

## service/model/schema.py — 常數定義（唯一來源）

| 常數 | 內容 |
|------|------|
| `FEATURE_COLS` | 26 個模型特徵名稱（順序固定，對應 Rust ModelFeature struct） |
| `ID_COLS` | 不可入模型的識別符欄位（Flow ID、IP、Timestamp 等） |
| `STRING_TO_FLOAT_COLS` | 需要從字串轉 float 的欄位（`Flow Bytes/s`、`Flow Packets/s`） |
| `PROTO_MOD`, `SERVICE_MOD` | Protocol/Service hash bucket 數 |
| `CLIP_UPPER_PERCENTILE` | inf cap 的百分位數（0.999） |

**禁止**：在其他地方硬編碼特徵名稱清單，一律 `from service.model.schema import FEATURE_COLS`。

---

## service/model/data/ — 資料層

### cleaner.py
**唯一公開函式：`clean(lf: LazyFrame) → LazyFrame`**
執行：strip 欄位名空白 → cap inf → fill null → cast STRING_TO_FLOAT_COLS。
- 只用於**原始 parquet/CSV**。`clean_and_save()` 產出的 parquet_clean 已預處理，**不可再呼叫 clean()**。

### loader.py
| 函式 | 用途 |
|------|------|
| `_load_features_parquet(path)` | 載入單一 parquet（或 glob 路徑）為 LazyFrame |
| `csv_to_parquet()` | 批次將 dataset/ 下 CSV 轉 parquet |
| `clean_and_save(src_dir, out_dir)` | 清洗 parquet → 寫入 parquet_clean/ |

### sample.py — 抽樣函式（三選一，用途嚴格區分）

| 函式 | 適用場景 | 禁止用於 |
|------|---------|---------|
| `get_normal_sample_from_files(paths, n, seed)` | **IF 訓練**（BENIGN only） | 任何需要攻擊樣本的場景 |
| `get_binary_sample_from_files(paths, n_per_class, seed)` | **特徵選擇**（50/50 BENIGN vs 攻擊） | IF 訓練 |
| `get_balance_sample_from_files(paths, sample_count_per_label, seed)` | **評估/測試**（各 label 等量） | IF 訓練、特徵選擇（除非搭配 min_samples 過濾） |
| `random_sample_lazyframe(lf, n, seed)` | 從已有 LazyFrame 隨機抽樣 | — |

### features.py
`build_features(df: pd.DataFrame) → pd.DataFrame`
衍生比率特徵（Shape_Ratio、Sym_Ratio、Pkt_CV 等）與 Protocol/Service 編碼。
用於 BigFlow 等欄位需要計算派生特徵的場景。

---

## service/model/pipeline/ — ML Pipeline

### schema 相依關係
```
schema.py → feature_select.py → trainer/ → infer.py
```

### feature_select.py
| 函式 | 用途 |
|------|------|
| `variance_select(benign_df, var_threshold, corr_threshold)` | 方案 B：用 BENIGN 資料做 variance + correlation filter |
| `if_auc_validate(benign_df, val_df, feature_names, ...)` | 方案 D：訓練 IF 並在含攻擊的驗證集上計算 AUC |
| `_numeric_matrix(df)` | 取出非 ID 數值欄位，回傳 (X: float32 ndarray, names) |

**CLI**：`python -m service.model.pipeline.feature_select --data_dir ... --val_dir ...`

### correlation_filter.py
`drop_correlated(X, feature_names, threshold=0.9) → (X, names)`
移除 Pearson |r| > threshold 的冗餘特徵。已被 `variance_select()` 內部呼叫，通常不需直接使用。

### trainer/
| 類別 | 用途 |
|------|------|
| `BaseTrainer` | 抽象基底，定義 `fit(df)` 和 `bundle()` 介面 |
| `IsolationForestTrainer` | 主要模型。`fit(df)` 接受含 Label 欄的 DataFrame（BENIGN only），`bundle()` 回傳含 scaler/model/meta 的 dict |
| `RandomForestTrainer` | 存在但非主力；分類器，需要 BENIGN + 攻擊資料 |

### train.py
CLI 入口，呼叫對應 Trainer 並儲存 bundle 至 `model_store/`。
**CLI**：`python -m service.model.pipeline.train --model_type if`

### infer.py — 推論（直接用，不要自己重寫）
| 函式 | 用途 |
|------|------|
| `_infer_if(df, bundle)` | IF 推論，輸入只含 FEATURE_COLS 的 DataFrame，回傳含 `anomaly_score`、`is_alert` 的 DataFrame |
| `_infer_rf(df, bundle)` | RF 推論（相同介面） |
| `_check_features(df, feature_cols)` | 確認 df 含所有必要欄位，缺少則 raise |

**CLI**：`python -m service.model.pipeline.infer --input ... --model ...`

---

## service/model/tests/ — 測試 Harness

| 檔案 | 測試內容 |
|------|---------|
| `conftest.py` | 共用 fixtures（`trained_if_bundle`、`make_benign_df`、`make_attack_df`、`feature_cols`） |
| `harness_pipeline_regression.py` | bundle 結構、joblib round-trip、FPR < 2%、AUC > 0.90（@slow） |
| `harness_feature_integrity.py` | clean() 後無 inf/NaN、FEATURE_COLS 存在且 numeric、資料洩漏防護 |
| `harness_inference_engine.py` | shape 契約（26 個）、邊界值、確定性、攻擊偵測 |
| `test_cleaner.py` | cleaner 單元測試 |
| `test_feature_select.py` | variance_select、if_auc_validate 單元測試 |
| `test_loader.py` | _load_features_parquet 單元測試 |
| `test_sample.py` | 抽樣函式單元測試 |

---

## service/model/experiments/ — 一次性實驗腳本（唯讀參考）

存放已執行完的分析腳本，**不應被 import**，只作為實驗記錄查閱。

| 檔案 | 對應實驗 |
|------|---------|
| `bigflow_run17_eval.py` | BigFlow-NIDS-V2 跨資料集驗證（N 值掃描） |
| `cross_dataset_validation.py` | 跨資料集泛化評估 |
| `info_gain.py` | Information Gain 特徵重要性分析 |
| `permutation_importance.py` | Permutation Importance 分析 |
| `rerun_all_correct_temporal.py` | 2026-04-10 時序修正後全面重跑 |
| `run17_quantile_ratio.py` | Run 17 分位桶比率實驗 |
| `run18_bytes_sum.py` | Run 18 Bytes sum 特徵實驗 |

---

## service/model/old_code/ — 已棄用（禁止使用）

舊版 monolithic 實作，已被 pipeline/ 取代。**不可 import，不可參考邏輯。**

---

## service/firewall/ — Rust 防火牆（eBPF datapath + userspace）

> 三個 crate：`firewall-common`（no_std 共用型別）、`firewall-ebpf`（XDP/TC datapath）、`firewall`（userspace 控制面）。修改前先查此節，勿重造已有 map/函式。

### firewall-common/（no_std 共用）

| 檔案 | 內容 |
|------|------|
| `src/model.rs` | `QuantileBound`（value/numer/denom）、`ModelConfig`（enabled/threshold/action）、`ScoreResult`、`StatsEvent`（numer[5]/denom[5]/score/`flags`；`STATS_FLAG_BENIGN_GATE` bit）、`BoundaryMeta`（version/active/expiry_ns，double-buffer 用）；`FEATURE_COUNT=5`、`BUCKET_COUNT=2`、`SCORE_TABLE_SIZE=32` |
| `src/constants.rs` | 協定常數；`STATS_BATCH_SIZE`、`STATS_SAMPLE_SHIFT`、`BOUNDARY_BANK_COUNT`；eBPF map size 由 `build.rs` 生成後 `include!` |
| `src/session.rs` | `SessionKey`、`SessionValue`、`SessionEvent`（RingBuf 事件，帶 `score`）|
| `src/protocol.rs` | `L4Info` 等 L4 解析型別 |
| `build.rs` | `parse_map_sizes()` 讀 `firewall/config.toml` `[maps]` → 生成 `*_SIZE` 常數（含 `STATS_RING_BUF_SIZE`、`BOUNDARY_META_SIZE`）|

### firewall-ebpf/（datapath，bpfel-unknown-none）

| 檔案 | 函式 / map | 作用 |
|------|-----------|------|
| `src/scorer.rs` | `score_session(val,key) -> Option<ScoreResult>` | 5 特徵各 1-bit 比較組 0..31 index → `SCORE_TABLE` 查分；`>= threshold` 則 action |
| | `active_bank_base()` | 讀 `BOUNDARY_META` 決定使用哪個 bank（雙緩衝），含 TTL 過期回退 bank 0 |
| | maps | `QUANTILE_BOUNDS`(2 bank)、`SCORE_TABLE`、`MODEL_CONFIG`、`BOUNDARY_META`、`STATS_RING_BUF`、`STATS_SAMPLE_CTR` |
| `src/parser.rs` | `PacketInfo` struct、`PacketContext` trait（`impl` for `XdpContext`/`TcContext`）、`parse_ipv4`/`parse_ipv6` | 統一 XDP/TC 封包解析（提案 `archive/packetinfo_redesign_proposal.md` 已由此實作）|
| `src/table.rs` | `SESSIONS`(LruPerCpuHashMap)、`update_session(SessionUpdateParams)` | 雙向 session 聚合、統計更新 |
| `src/collector.rs` | `EVENTS_POOL`(RingBuf)、`submit_event()`、`DROP_EVENTS` | 把 SessionEvent 送回 userspace；溢出計數 |
| `src/syn_cookie.rs` | SYN cookie ACK 驗證、`SECRET_KEY` | — |
| `src/blocker.rs` | `BLOCK_LIST` 查詢 | 黑名單命中 |
| `src/main.rs` | `xdp_firewall` / `tc_egress` 入口 | — |

### firewall/（userspace 控制面，tokio）

| 檔案 | 函式 / 型別 | 作用 |
|------|-----------|------|
| `src/lib/config.rs` | `Config`（network/security/log/maps/model/`adaptive`）、`BoundaryAdaptConfig`、`from_file()`/`default()` | TOML 設定 |
| `src/lib/controller.rs` | `FirewallController::load/attach_xdp/attach_tc/maps_mut` | 載入 bytecode、初始化 `SECRET_KEY`、附加程式 |
| `src/lib/model_loader.rs` | `load_model()`、`validate_model_contract()` | 讀 model.json（disable→寫 maps→enable）|
| | `write_boundary_version()` | 寫 inactive bank → 原子翻轉 `BoundaryMeta.active`（CLOCK_MONOTONIC TTL）|
| | `update_score_threshold()` | Path B：只改 `ModelConfig.threshold` |
| `src/lib/boundary_updater.rs` | `BoundaryUpdater`（dual-sketch + gate state machine）；`run()` 消費 `STATS_RING_BUF` | 自適應分位桶校準 |
| | 純函式：`batch_quantile`/`score_quantile`/`ema`/`drift_ratio`/`divergence`/`decide_gate`/`encode_bound`/`decode_bound`；`GateState{Normal,Uncertain,AttackFreeze}` | host 可測；S_ref/S_live 雙草圖判定 |
| `src/lib/logger.rs` | `Logger::start()` | 消費 EVENTS_POOL、跨 CPU 聚合、log |
| `src/lib/task.rs` | `kill_old_sessions()` | 依協定/時間清過期 session |
| `src/main.rs` | wiring | `tokio::try_join!(logger.start(), updater.run())` 併發 |

> 設計脈絡見 `docs/boundary_adaptive_update_plan.md`（v2 dual-sketch + gated，§11 落地紀錄）與 `docs/kernel_model_contract.md`（蒸餾↔loader↔scorer 契約）。

---

## docs/claude_ref/ — Claude 專用參考

| 檔案 | 內容 |
|------|------|
| `codebase_map.md` | 本文件 |
| `dev_commands.md` | 常用命令、驗證 checklist、資料路徑 |
| `failure_records.md` | 歷史失敗記錄（9+ 則） |

## docs/

> 完整角色分類索引見 `docs/README.md`。

| 檔案 | 內容 |
|------|------|
| `README.md` | docs 索引（canonical / 計畫 / 實驗報告 / 參考 / archive）|
| `kernel_defense_architecture.md` | 架構設計唯一依據（eBPF 限制、分位桶決策、AUC 數字）|
| `kernel_model_contract.md` | P0 工程契約：蒸餾 ↔ loader ↔ scorer 對齊 |
| `feature_selection_log.md` | 特徵選擇實驗（Run 01–16,18 + 附錄 A-1～A-9）|
| `quantile_bucket_strategy_log.md` | 分位桶策略 / 模型訓練（Run 17,19–29 + A-10/11/12，contract Run 28/29）|
| `boundary_adaptive_update_plan.md` | 分位桶自適應更新 v2（dual-sketch + gated）|
| `userspace_improvement_plan.md` | userspace 品質審查追蹤（持續更新）|
| `iTree_training_report.md` / `presentation_summary.md` | IF 訓練報告 / 研究總結（論文素材，與 log 部分重疊）|
| `archive/packetinfo_redesign_proposal.md` | 已被 `parser.rs` 實作取代（歷史）|
