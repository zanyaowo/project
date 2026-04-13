"""
Harness 2 — Feature Integrity

確保 clean() pipeline 的底層 invariant：
- 所有 FEATURE_COLS 存在且為 numeric
- clean() 後無 inf / NaN
- FEATURE_COLS 數量符合 Run 07 基準（26 個）
- 訓練資料無 label 洩漏

對應防護的已知失敗：
- Inbound 欄位 data leakage
- sample.py "BEGIN" → "BENIGN" 靜默失效
- Train/Test 時序顛倒（temporal leakage）
"""
import math

import numpy as np
import polars as pl
import pytest

from service.model.data.cleaner import clean
from service.model.schema import STRING_TO_FLOAT_COLS


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_raw_lf(feature_cols, n: int = 100, seed: int = 0) -> pl.LazyFrame:
    """模擬 clean() 前的原始資料：STRING_TO_FLOAT_COLS 為字串、含 inf/NaN。"""
    rng = np.random.default_rng(seed)
    data = {}
    for col in feature_cols:
        if col in STRING_TO_FLOAT_COLS:
            data[col] = [str(v) for v in rng.uniform(0, 1e6, n)]
        else:
            data[col] = rng.uniform(0.0, 1000.0, size=n).tolist()
    # 注入極端值
    data[feature_cols[0]] = [float("inf")] * 5 + data[feature_cols[0]][5:]
    data[feature_cols[1]] = [float("nan")] * 3 + data[feature_cols[1]][3:]
    data["Label"] = ["BENIGN"] * n
    return pl.DataFrame(data).lazy()


# ── FEATURE_COLS 存在性 ────────────────────────────────────────────────────────

@pytest.mark.harness
class TestFeatureColsPresence:
    def test_all_feature_cols_present_after_clean(self, feature_cols):
        """clean() 後所有 FEATURE_COLS 必須存在。"""
        lf = _make_raw_lf(feature_cols)
        result = clean(lf).collect()
        missing = [c for c in feature_cols if c not in result.columns]
        assert missing == [], f"clean() 後遺失 FEATURE_COLS：{missing}"

    def test_feature_cols_are_numeric_after_clean(self, feature_cols):
        """clean() 後所有 FEATURE_COLS 必須為 numeric dtype。
        STRING_TO_FLOAT_COLS 若 cast 失敗會殘留 String，導致 numpy 轉換炸掉。
        """
        lf = _make_raw_lf(feature_cols)
        result = clean(lf).collect()
        numeric_types = {
            pl.Float64, pl.Float32, pl.Int64, pl.Int32,
            pl.Int16, pl.Int8, pl.UInt64, pl.UInt32, pl.UInt16, pl.UInt8,
        }
        non_numeric = [
            c for c in feature_cols
            if c in result.columns and result[c].dtype not in numeric_types
        ]
        assert non_numeric == [], f"clean() 後仍為非 numeric：{non_numeric}"

    def test_feature_count_matches_run07_baseline(self, feature_cols):
        """FEATURE_COLS 數量門檻：Run 07 基準為 26 個。
        增減 FEATURE_COLS 後必須更新此斷言並重跑 feature_select。
        """
        assert len(feature_cols) == 26, (
            f"FEATURE_COLS 有 {len(feature_cols)} 個，Run 07 基準為 26。"
            "若有意修改，請同步更新此斷言並重跑 feature_select 確認 AUC ≥ 0.90。"
        )


# ── inf / NaN 消除 ────────────────────────────────────────────────────────────

@pytest.mark.harness
class TestNoInfNanAfterClean:
    def test_no_inf_in_feature_cols(self, feature_cols):
        """cap_infinite() 必須消除所有 inf。
        殘留 inf → StandardScaler 輸出 NaN → IF score 全為 NaN。
        """
        lf = _make_raw_lf(feature_cols)
        result = clean(lf).collect()
        for col in feature_cols:
            if col not in result.columns:
                continue
            has_inf = any(
                math.isinf(v) for v in result[col].to_list() if v is not None
            )
            assert not has_inf, f"clean() 後 '{col}' 仍有 inf"

    def test_no_nan_in_feature_cols(self, feature_cols):
        """fill_nulls() 必須消除所有 NaN。
        殘留 NaN 在 sklearn 中靜默傳播，不報錯但 score 全錯。
        """
        lf = _make_raw_lf(feature_cols)
        result = clean(lf).collect()
        for col in feature_cols:
            if col not in result.columns:
                continue
            has_nan = any(
                v is not None and math.isnan(v) for v in result[col].to_list()
            )
            assert not has_nan, f"clean() 後 '{col}' 仍有 NaN"


# ── 分布合理性 ────────────────────────────────────────────────────────────────

@pytest.mark.harness
class TestDistributionSanity:
    def test_variance_nonzero_for_all_feature_cols(self, make_benign_df, feature_cols):
        """所有 FEATURE_COLS 的 variance 必須 > 0。
        zero-variance 特徵經 StandardScaler 會產生 NaN（除以 0）。
        """
        df = make_benign_df(n=500)
        for col in feature_cols:
            if col not in df.columns:
                continue
            var = df[col].var()
            assert var is not None and var > 0.0, (
                f"'{col}' variance = 0，StandardScaler 將輸出 NaN"
            )


# ── 資料洩漏防護 ──────────────────────────────────────────────────────────────

@pytest.mark.harness
class TestDataLeakagePrevention:
    def test_benign_training_sample_has_no_attack_labels(self, make_benign_df):
        """IF 訓練資料不得包含非 BENIGN 的 label。
        對應失敗記錄：IF 訓練資料誤用 balanced sampling。
        """
        df = make_benign_df(n=300)
        labels = df["Label"].to_list()
        non_benign = [l for l in labels if l != "BENIGN"]
        assert non_benign == [], (
            f"訓練資料含 {len(non_benign)} 筆非 BENIGN label：{set(non_benign)}"
        )

    def test_temporal_order_train_before_test(self):
        """訓練集時間戳必須早於測試集。
        對應失敗記錄：Train/Test 時序顛倒（Train=01-12，Test=03-11）→ AUC 虛高 0.0192。
        """
        from datetime import date
        # 03-11 = 2018-11-03（train），01-12 = 2018-12-01（test）
        train_date = date(2018, 11, 3)
        test_date  = date(2018, 12, 1)
        assert train_date < test_date, (
            f"時序違反：train={train_date} 不早於 test={test_date}"
        )

    @pytest.mark.slow
    def test_real_parquet_temporal_no_overlap(self, real_parquet_available):
        """真實 parquet 檔名的時序約定不得有交集。
        03-11_* = train（Nov），01-12_* = test（Dec）。
        """
        if not real_parquet_available:
            pytest.skip("真實 parquet 不存在，跳過")
        import glob
        train_files = set(glob.glob("service/model/dataset/parquet_clean/train/03-11_*.parquet"))
        test_files  = set(glob.glob("service/model/dataset/parquet_clean/test/01-12_*.parquet"))
        overlap = train_files & test_files
        assert not overlap, f"Train/Test 檔案交集：{overlap}"
        assert train_files, "找不到 03-11_* train parquet"
        assert test_files,  "找不到 01-12_* test parquet"