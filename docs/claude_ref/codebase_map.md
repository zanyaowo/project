# Codebase Map — 函式與資料夾導覽

> 目的：避免重複實作已有函式、使用錯誤抽樣方法。修改前先查此文件確認是否已有對應實作。
> 範圍：所有非 `target/`、非 `old_code/`、非 `__pycache__/` 的 `.py` / `.rs`（最後同步：2026-05-20）。

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
**唯一公開函式：`clean(lf)`**
組合下列 4 個 private helper：
| 函式 | 作用 |
|------|------|
| `_strip_column_names` | 移除欄位名前後空白 |
| `_cap_infinite` | 用 `CLIP_UPPER_PERCENTILE` 蓋 inf 值 |
| `_fill_nulls` | 填補 numeric null = 0 |
| `_cast_types` | 將 `STRING_TO_FLOAT_COLS` 轉 float |

只用於**原始 parquet/CSV**。`clean_and_save` 產出的 parquet_clean 已預處理，**不可再呼叫 clean()**。

### loader.py
| 函式 | 用途 |
|------|------|
| `_load_features_parquet` | 載入單一 parquet（或 glob 路徑）為 LazyFrame |
| `_load_features_csv` | CSV → LazyFrame（內部用，正式流程走 parquet） |
| `csv_to_parquet` | 批次將 dataset/ 下 CSV 轉 parquet |
| `clean_and_save` | 清洗 parquet → 寫入 parquet_clean/ |

### sample.py — 抽樣函式（用途嚴格區分）

| 函式 | 適用場景 | 禁止用於 |
|------|---------|---------|
| `get_normal_sample_from_files` | **IF 訓練**（BENIGN only） | 任何需要攻擊樣本的場景 |
| `get_binary_sample_from_files` | **特徵選擇**（50/50 BENIGN vs 攻擊） | IF 訓練 |
| `get_balance_sample_from_files` | **評估/測試**（各 label 等量） | IF 訓練、特徵選擇（除非搭配 min_samples 過濾） |
| `get_mixed_normal_sample` | **跨資料集 BENIGN 混合**（CIC + BigFlow 等，邊界計算用） | 單資料集場景 |
| `random_sample_lazyframe` | 從已有 LazyFrame 隨機抽樣 | — |
| `_unique_labels` | 內部：掃 parquet 找 distinct label | — |

> ⚠️ 分位桶邊界**必須用** `get_mixed_normal_sample`（或等效混合）；純 CIC BENIGN 已知對 BigFlow overfit。

### features.py
| 函式 | 作用 |
|------|------|
| `build_features` | 公開入口：依序套用下列 4 個 helper |
| `_encode_proto` | Protocol hash bucket 編碼（用 `PROTO_MOD`） |
| `_encode_service` | Service hash bucket 編碼（用 `SERVICE_MOD`） |
| `_derive_ratio_features` | 衍生 Shape_Ratio、Sym_Ratio、Pkt_CV 等比率特徵 |
| `_derive_throughput_features` | 衍生 Bytes/s、Packets/s 等吞吐特徵 |

主要用於 BigFlow 等欄位需要計算派生特徵的場景。

---

## service/model/pipeline/ — ML Pipeline

### 依存關係
```
schema.py → feature_select.py → trainer/ → infer.py
                              ↘ distill.py → distill_export.py → distilled_rules.json
```

### feature_select.py
| 函式 | 用途 |
|------|------|
| `_numeric_matrix` | 取出非 ID 數值欄位，回傳 (X: float32 ndarray, names) |
| `variance_select` | 方案 B：BENIGN variance + correlation filter |
| `if_auc_validate` | 方案 D：訓練 IF 並在含攻擊驗證集上算 AUC |
| `run` / `parse_args` | CLI 入口 |

**CLI**：`python -m service.model.pipeline.feature_select --data_dir ... --val_dir ...`

### correlation_filter.py
`drop_correlated(X, feature_names, threshold=0.9) → (X, names)`
移除 Pearson |r| > threshold 的冗餘特徵。已被 `variance_select` 內部呼叫，通常不需直接使用。

### trainer/
| 類別 | 用途 |
|------|------|
| `BaseTrainer` | 抽象基底（`trainer/base.py`），定義 `fit(df)` 和 `bundle()` 介面 |
| `IsolationForestTrainer` | `trainer/if_.py`。主要模型；`fit(df)` 接受 BENIGN-only DataFrame，`bundle()` 回傳含 scaler/model/meta dict |
| `RandomForestTrainer` | `trainer/rf.py`。存在但非主力；需 BENIGN + 攻擊 |
| `get_trainer` | `trainer/__init__.py`。factory：`"if"` / `"rf"` 切換 |

### train.py
| 函式 | 用途 |
|------|------|
| `_load_data_for_if` | 載 BENIGN-only 訓練資料（呼叫 `get_normal_sample_from_files`） |
| `_load_data_for_rf` | 載 binary 訓練資料 |
| `_extra_kwargs` | 從 CLI args 萃取 trainer 額外參數 |
| `run` / `parse_args` | CLI 入口；呼叫對應 Trainer 並存 bundle 到 `model_store/` |

**CLI**：`python -m service.model.pipeline.train --model_type if`

### infer.py — 推論（直接用，不要自己重寫）
| 函式 | 用途 |
|------|------|
| `_infer_if` | IF 推論。輸入只含 FEATURE_COLS 的 df → `anomaly_score`、`is_alert` |
| `_infer_rf` | RF 推論（同介面） |
| `_check_features` | 確認 df 含所有必要欄位，缺少則 raise |
| `_load_input` | parquet / CSV 統一入口 |
| `_save_output` | 統一輸出 |
| `_print_report` | 推論結果摘要列印 |
| `run` / `parse_args` | CLI 入口 |

**CLI**：`python -m service.model.pipeline.infer --input ... --model ...`

### distill.py — 5-bit 規則蒸餾推論（Python 端對拍 eBPF）
| 物件 | 作用 |
|------|------|
| `CANONICAL_FEATURE_ORDER` | LSB→MSB 五特徵順序：`protocol, pkt_len_mean, fwd_max_q, sym_ratio, pkt_cv_sq` |
| `_FEATURE_COLUMN` | feature_name → (numer_col, denom_col 或 None) 對應表 |
| `DistilledClassifier` | 5-feature binary lookup-table 分類器 |
| ├ `__init__` | 載入規則（threshold、quantile_bounds、score_table） |
| ├ `_validate_contract` | 驗證 metadata v1、FEATURE_COUNT=5、SCORE_TABLE_SIZE=32 |
| ├ `from_json` | classmethod：讀 distilled_rules.json |
| ├ `_feature_ratio_components` | 取得 (numer, denom) 陣列；`pkt_cv_sq` 特例由 Sum/Sum Sq 推 CV² |
| ├ `_build_index` | 5 bit 位元拼出 0–31 索引 |
| ├ `score` / `predict` | 推論主入口（向量化） |
| ├ `explain_index` | debug：給定索引回傳每個 bit 的解釋 |
| └ `summary` | 列印規則摘要 |
| `_run_eval` | CLI：載規則 + 對資料集跑 AUC/FPR |

### distill_export.py — 將 IF 蒸餾為 5-bit 規則
| 函式 | 用途 |
|------|------|
| `_bucket_indices` | 依 quantile_bounds 把連續特徵轉 0/1 bit |
| `run` / `parse_args` | CLI：訓練 IF → 對 BENIGN+ATTACK 算每個 0–31 索引的平均分數 → 寫 `distilled_rules.json` |

**CLI**：產出 `distilled_rules.json`，eBPF 端唯一吃這個檔。

---

## service/model/tests/ — 測試 Harness

| 檔案 | 測試內容 |
|------|---------|
| `conftest.py` | 共用 fixtures：`feature_cols`、`make_benign_df`、`make_attack_df`、`trained_if_bundle`、`real_parquet_available` |
| `harness_pipeline_regression.py` | `TestBundleStructure` / `TestSerializationRoundTrip` / `TestFPRGate`（FPR < 2%）/ `TestAUCRegression`（AUC > 0.90，@slow） |
| `harness_feature_integrity.py` | `_make_raw_lf`；`TestFeatureColsPresence` / `TestNoInfNanAfterClean` / `TestDistributionSanity` / `TestDataLeakagePrevention` |
| `harness_inference_engine.py` | `_single_row_df`；`TestVectorShapeContract`（26 個）/ `TestEdgeCaseVectors` / `TestDeterminism` / `TestKnownAttackPatterns` |
| `test_schema.py` | `STRING_TO_FLOAT_COLS`、`ID_COLS`、`CLIP_UPPER_PERCENTILE` 常數契約 |
| `test_cleaner.py` | `TestStripColumnNames` / `TestCastTypes` / `TestCapInfinite` / `TestFillNulls` / `TestClean` |
| `test_loader.py` | `TestLoadFeaturesParquet`（含 `_write_parquet` helper） |
| `test_sample.py` | `_make_df`、`parquet_dir` fixture；測 4 個抽樣函式 |
| `test_feature_select.py` | `TestNumericMatrix` / `TestVarianceSelect` / `TestIfAucValidate` |
| `test_distill_contract.py` | `_base_rules` helper；驗證 LSB 順序、CICFlowMeter Std/Mean 推 CV²、v1 metadata 拒絕 |
| `test_data_quality_plots.py` | `_sample_lf`；`TestPlotMissingCounts` / `TestPlotLabelDistribution` / `TestPlotNumericStats` |

---

## service/model/view/ — 視覺化 / 分析腳本（CLI）

| 檔案 | 公開函式 | 用途 |
|------|---------|------|
| `data_overview.py` | `get_each_label_count` | 各 label 列數統計 |
| `data_quality_plots.py` | `plot_missing_counts` / `plot_label_distribution` / `plot_missing_matrix` / `plot_numeric_stats` | 缺失值矩陣、label 直方圖、numeric stats heatmap |
| `feature_stats.py` | `compute_stats` / `print_stats` + `_load_sample` / `_run` / `_parse_args` | 計算並列印特徵 mean/std/min/max/null 比率 |
| `entropy_plot.py` | `compute_entropy` / `plot_entropy_distribution` + `_load_df` / `_run` / `_parse_args` | 連續特徵的香農熵分佈圖 |
| `if_anomaly_plot.py` | `plot_if_anomaly` + `_run` / `_parse_args` | IF anomaly_score 分佈 vs 攻擊/良性 |
| `temporal_order_check.py` | `sample_df` / `load_ids` / `get_arrays` / `add_log1p` / `compute_bounds` / `apply_buckets` / `add_quantile` / `run_auc` / `eval_attack` / `run_scenario` / `print_comparison` / `main` | 驗證 train→test 時序正確 vs 反轉的 AUC 影響（資料洩漏防護工具） |

---

## service/model/experiments/ — 一次性實驗腳本（唯讀參考）

存放已執行完的分析腳本，**不應被 import**，只作為實驗記錄查閱。
共通工具函式（`compute_quantile_boundaries`、`ratio_to_bucket`、`load_ids2018`、`load_bigflow_val`、`fmt`、`main`）在多個檔內重複出現以保留實驗時的快照狀態，這是有意為之，不要去抽共用模組。

### Feature importance（一次性）
| 檔案 | 主要函式 | 對應 Run |
|------|---------|---------|
| `info_gain.py` | `_binary_entropy` / `_label_entropy` / `_conditional_entropy` / `information_gain` / `_load_balanced` / `compute_all_ig` | Information Gain 排序 |
| `permutation_importance.py` | `_sample_benign` / `_sample_balanced` / `_score` / `permutation_importance` | Permutation Importance 排序 |
| `cross_dataset_validation.py` | `map_cic_2019` / `map_bigflow` / `run_analysis` | 跨資料集泛化評估 |

### 分位桶 / 蒸餾相關 Run
| 檔案 | 主要函式 / 類別 | 對應 Run |
|------|---------------|---------|
| `rerun_r05_r11_r12.py` | `add_ratio_features` / `add_ratio_features_ids2018` / `single_feature_auc` / `run_05` / `run_11_12` | Run 05、11、12 時序修正重跑 |
| `rerun_r14_r17.py` | `add_ratios` / `auc_validate` / `print_sep` / `prepare_datasets` / `run_14` 到 `run_17` | Run 14–17 時序修正重跑 |
| `rerun_all_correct_temporal.py` | `sample_val` / `load_ids` / `fit_predict` / `per_attack` / `get_arr` / `add_log1p` / `mk_bounds` / `apply_q` / `add_q` / `add_ratio_raw` / `hdr_asym` | 2026-04-10 全面時序修正 |
| `run17_quantile_ratio.py` | `load_and_sample` / `load_ddos2019_test` / `apply_quantile_bucket` / `add_log1p_features` / `add_quantile_features` / `run_auc` / `eval_per_attack` | Run 17 分位桶比率 |
| `run18_bytes_sum.py` | `scalar_to_bucket` / `add_quantile_features` / `add_bytes_sum` / `auc_validate` | Run 18 Bytes sum |
| `bigflow_run17_eval.py` | `add_bigflow_features` / `apply_quantile_buckets` / `auc_validate` / `load_bigflow_sample` / `get_ratios` / `eval_n` | BigFlow N 值掃描 |
| `run19_mixed_benign.py` | `add_bigflow_features` / `compute_boundaries` / `ratio_bucket` / `apply_buckets` / `compute_bounds_from` / `auc_validate` / `load_bigflow_val` | Run 19 混合 BENIGN |
| `run20_no_shape.py` | `add_quantile_features` / `add_min_pkt_raw` / `auc_validate` | Run 20 拿掉 Shape_q |
| `run21_shape_alternatives.py` | `safe_ratio` / `build_features` / `auc_validate` | Run 21 Shape_q 替代品搜尋 |
| `run22_fwdmax_n_scan.py` | `add_features` / `auc_validate` | Run 22 FwdMax N 值掃描 |
| `run23_bigflow_overfit_check.py` | `add_cic_features` / `add_bigflow_features` / `auc_cic` / `auc_bigflow` | Run 23 邊界 overfit 檢查 |
| `run24_mixed_benign_shape_fwdmax.py` | `auc_score` / `to_normalized_cols` / `bigflow_to_normalized_cols` / `apply_buckets` | Run 24 Mixed BENIGN + Shape vs FwdMax |
| `run25_final_fwdmax_n_scan.py` | `apply_buckets_cic` / `apply_buckets_norm` / `auc_cic` / `auc_bigflow` / `to_norm` / `bigflow_to_norm` | Run 25 FwdMax 最終 N 掃描（IF-direct，**非部署 contract**，見 CLAUDE.md） |
| `run26_extended_metrics.py` | `Metrics` dataclass / `apply_buckets_norm` / `cic_to_norm` / `bigflow_to_norm` 及 evaluation 主流程 | Run 26 擴展指標 |
| `run27_boundary_overfit_check.py` | `Bounds` dataclass / `_ratio_bound` / `compute_bounds` / `_bit_ratio` / `bucketize` / `to_norm_cic` / `bigflow_to_norm` / `auc_eval` / `bucket_balance` | Run 27 邊界 overfit 二次檢查 |
| `run28_contract_matrix.py` | `RatioBounds` / `AbsoluteBounds` / `Variant` dataclass；`_finite` / `_ratio_bound` / `_quantile_bounds` / `_bucket` / `_bit_abs` / `_bit_ratio` / `compute_ratio_bounds` / `compute_abs_bounds` / `add_ratio_bucket_cols` / `protocol_category` / `bigflow_to_norm_run25` / `train_score_auc` | **Run 28 contract 矩陣**：證據模型 vs 部署 contract 差異拆解 |
| `run29_hoic_feature_search.py` | `Variant` dataclass / `_cic_norm_cols` / `cic_to_norm` / `bigflow_to_norm` / `_bit_ratio` / `add_all_features` / `compute_boundaries` / `train_score_auc` | Run 29 HOIC 崩潰特徵搜尋 |

---

## service/model/old_code/ — 已棄用（禁止使用）

舊版 monolithic 實作，已被 pipeline/ 取代。**不可 import，不可參考邏輯。**

---

## scripts/ — 工程腳本

| 檔案 | 函式 | 用途 |
|------|------|------|
| `analyze_error.py` | `_call_agent` / `_call_summarizer` / `_update_failure_records` / `_update_claude_md` / `main` | 用 Anthropic API 分析失敗 log → 自動寫入 `docs/claude_ref/failure_records.md`、必要時更新 `CLAUDE.md` 禁止事項 |

---

## service/firewall/ — Rust 防火牆（eBPF datapath + userspace）

> 三個 crate：`firewall-common`（no_std 共用型別）、`firewall-ebpf`（XDP/TC datapath）、`firewall`（userspace 控制面）。修改前先查此節，勿重造已有 map/函式。

### firewall-common/（no_std 共用）

| 檔案 | 內容 |
|------|------|
| `src/lib.rs` | crate root；re-export model/session/protocol/constants |
| `src/model.rs` | `QuantileBound`（value/numer/denom）、`ModelConfig`（enabled/threshold/action）、`ScoreResult`、`StatsEvent`（numer[5]/denom[5]/score/`flags`；`STATS_FLAG_BENIGN_GATE` bit）、`BoundaryMeta`（version/active/expiry_ns，double-buffer 用）；`FEATURE_COUNT=5`、`BUCKET_COUNT=2`、`SCORE_TABLE_SIZE=32` |
| `src/constants.rs` | 協定常數；`STATS_BATCH_SIZE`、`STATS_SAMPLE_SHIFT`、`BOUNDARY_BANK_COUNT`；eBPF map size 由 `build.rs` 生成後 `include!` |
| `src/session.rs` | `SessionKey`、`SessionValue`、`SessionEvent`（RingBuf 事件，帶 `score`） |
| `src/protocol.rs` | `L4Info` enum、`TcpInfo` / `UdpInfo` / `IcmpInfo` struct |
| `build.rs` | `main` 寫出 `OUT_DIR/map_sizes.rs`；`parse_map_sizes(contents) -> (u32×8)` 讀 `firewall/config.toml` `[maps]` → 生成 `*_SIZE` 常數（含 `STATS_RING_BUF_SIZE`、`BOUNDARY_META_SIZE`） |

### firewall-ebpf/（datapath，bpfel-unknown-none）

| 檔案 | 函式 / map | 作用 |
|------|-----------|------|
| `src/main.rs` | `xdp_firewall` / `tc_egress` 入口；`try_xdp_firewall`；`panic` handler | 程式入口與 panic handler |
| `src/scorer.rs` | `score_session(val, key) -> Option<ScoreResult>` | 5 特徵各 1-bit 比較組 0..31 index → `SCORE_TABLE` 查分；`>= threshold` 則 action |
| | `active_bank_base` | 讀 `BOUNDARY_META` 決定使用哪個 bank（雙緩衝），含 TTL 過期回退 bank 0 |
| | `sat_u32` | u64 → u32 飽和轉換（避免溢位） |
| | maps | `QUANTILE_BOUNDS`(2 bank)、`SCORE_TABLE`、`MODEL_CONFIG`、`BOUNDARY_META`、`STATS_RING_BUF`、`STATS_SAMPLE_CTR` |
| `src/parser.rs` | `PacketInfo` struct、`PacketContext` trait（`impl` for `XdpContext` / `TcContext`） | 統一 XDP/TC 封包解析（IPv4/IPv6；舊 PacketInfo 重構提案已由此實作並移除）|
| | `parse_eth` / `parse_ipv4` / `parse_ipv6` / `parse_tcp` / `parse_udp` / `parse_icmp` / `parse_packet` | L2→L4 分層解析（皆 `<C: PacketContext>` 泛型） |
| `src/table.rs` | `SESSIONS`(LruPerCpuHashMap)、`SessionUpdateParams` struct；`impl From<&PacketInfo>` / `impl From<&SessionUpdateParams> for SessionKey` | 雙向 session 聚合 key 推導 |
| | `update_session(params)` / `is_connection_closed(flag)` | 統計更新、TCP 連線狀態判斷 |
| `src/collector.rs` | `EVENTS_POOL`(RingBuf)、`DROP_EVENTS` map；`submit_event(params, score)` | 把 SessionEvent 送回 userspace；溢出計數 |
| `src/syn_cookie.rs` | `SECRET_KEY` map；`calculate_cookie(src, dst, sport, dport, proto)` / `update_checksum(old_csum, old_val, new_val)` / `send_syn_cookie(ctx)` | SYN cookie ACK 驗證 |
| `src/blocker.rs` | `BLOCK_LIST` map；`is_blocked(ip)` | 黑名單命中 |

### firewall/（userspace 控制面，tokio）

| 檔案 | 函式 / 型別 | 作用 |
|------|-----------|------|
| `src/main.rs` | `async fn main` | wiring：`tokio::try_join!(logger.start(), updater.run())` 併發 |
| `src/lib/mod.rs` | mod re-exports | userspace lib root |
| `src/lib/config.rs` | `Config` / `XdpMode` enum / `NetworkConfig` / `LogConfig` / `SecurityConfig` / `MapsConfig` / `ModelSetting` / `BoundaryAdaptConfig`；`impl Config { from_file, default }` | TOML 設定 |
| `src/lib/controller.rs` | `FirewallController` struct；`impl: load / attach_xdp / attach_tc / maps_mut` | 載入 bytecode、初始化 `SECRET_KEY`、附加程式 |
| `src/lib/model_loader.rs` | `QuantileBoundEntry` / `ModelFile` 資料模型；`validate_model_contract`；`load_model` | 讀 model.json → disable→寫 maps→enable |
| | `monotonic_ns`（兩個 cfg 變體：linux / fallback）；`write_boundary_version` | 寫 inactive bank → 原子翻轉 `BoundaryMeta.active`（CLOCK_MONOTONIC TTL） |
| | `update_score_threshold` | Path B：只改 `ModelConfig.threshold`（不重載 maps） |
| `src/lib/boundary_updater.rs` | `BoundaryUpdater<'a>` struct；`GateState` enum（Normal/Uncertain/AttackFreeze）；`is_absolute_feature` | 自適應分位桶校準（dual-sketch + gate state machine） |
| | 純函式：`batch_quantile` / `score_quantile` / `ema` / `drift_ratio` / `divergence` / `decide_gate` / `encode_bound` / `decode_bound` | host 可測；S_ref/S_live 雙草圖判定 |
| | `BoundaryUpdater::run` | 消費 `STATS_RING_BUF` 並執行狀態機 |
| `src/lib/logger.rs` | `SessionSummary` struct；`Logger<'a>` struct；`Logger::start` | 消費 `EVENTS_POOL`、跨 CPU 聚合、log |
| `src/lib/task.rs` | `kill_old_sessions` | 依協定/時間清過期 session |
| `src/tests/mod.rs` | tests mod root | — |
| `src/tests/test.rs` | `test_session_tracking` async | session 雙向聚合 e2e 測試 |

### xtask/（build orchestration）

| 檔案 | 函式 / 型別 | 作用 |
|------|-----------|------|
| `xtask/src/main.rs` | `Opts` struct / `Cmd` enum；`main` / `build_ebpf(release)` / `run(release)` | `cargo xtask build-ebpf` / `cargo xtask run` 工作流入口 |

> 設計脈絡見 `docs/4_feedback/boundary_adaptive_update_plan.md`（v2 dual-sketch + gated，§11 落地紀錄）與 `docs/_crosscut/kernel_model_contract.md`（蒸餾↔loader↔scorer 契約）。

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
| `boundary_adaptive_update_plan.md` | 分位桶自適應更新 v2（dual-sketch + gated；已落地，保留為設計與實作紀錄）|
| `iTree_training_report.md` / `presentation_summary.md` | IF 訓練報告 / 研究總結（論文素材，與 log 部分重疊）|
