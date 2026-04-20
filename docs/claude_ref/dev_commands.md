# Dev Commands & Verification

## 常用命令

```bash
# Python 測試（快速，不需要真實資料）
uv run --project service/model pytest service/model/tests/ -m "not slow" -v

# 特徵選擇
uv run --project service/model python -m service.model.pipeline.feature_select \
    --data_dir service/model/dataset/parquet_clean/train \
    --val_dir  service/model/dataset/parquet_clean/test

# 訓練
uv run --project service/model python -m service.model.pipeline.train --model_type if

# Rust 編譯
cargo build --manifest-path service/firewall/Cargo.toml
```

---

## 驗證 Checklist

### Python pipeline 修改後

```bash
# 1. import 無錯誤
uv run --project service/model python -c "import service.model.pipeline.infer"

# 2. 快速測試全綠
uv run --project service/model pytest service/model/tests/ -m "not slow" -q

# 3. 特徵數正確
uv run --project service/model python -c \
    "from service.model.schema import FEATURE_COLS; print(f'FEATURE_COLS: {len(FEATURE_COLS)} 個')"
```

### FEATURE_COLS 修改後

1. 重跑 `feature_select`，確認新 AUC ≥ 0.90（Run 07 基準：0.9257）
2. 更新 `schema.py` 的 `FEATURE_COLS`
3. 重新訓練並儲存 `model_store/`

### eBPF/Rust 修改後

```bash
cargo check --manifest-path service/firewall/Cargo.toml
# verifier 錯誤對照：docs/kernel_defense_architecture.md § eBPF 計算限制清單
```

---

## 資料路徑約定

| 用途 | 路徑 |
|------|------|
| 原始 CSV | `dataset/*/` |
| 清洗後 parquet | `service/model/dataset/parquet_clean/train/` 和 `test/` |
| 模型輸出 | `service/model/model_store/` |

---

## 待研究問題

- [ ] `LruCpuHashmap` 高流量下是否有 lock contention？→ 影響 Map 類型選擇
- [ ] IF 線性蒸餾（Σ w_j × q_j，q_j 為分位桶索引）的 AUC vs 純閾值比對
- [ ] 熵值定點數精度是否足以區分正常/攻擊流量？