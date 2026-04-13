"""
Harness 1 — ML Pipeline Regression

確保 train → save → load → score 整條流程的正確性：
- bundle 結構不被破壞
- joblib 序列化 round-trip 後 score 完全一致
- FPR < 2%（contamination=0.01 的生產標準）
- AUC > 0.90（需真實資料，@pytest.mark.slow）

對應防護的已知失敗：
- threshold 計算錯誤 → 所有流量觸發告警或完全無告警
- feature_cols 與 schema.py 不同步 → 推論時 KeyError
"""
import math

import numpy as np
import polars as pl
import pytest

from service.model.pipeline.infer import _infer_if
from service.model.schema import FEATURE_COLS


# ── Bundle 結構 ───────────────────────────────────────────────────────────────

@pytest.mark.harness
class TestBundleStructure:
    def test_bundle_has_required_keys(self, trained_if_bundle):
        """bundle dict 結構必須包含所有必要 key。"""
        assert "model_type" in trained_if_bundle
        assert "scaler"     in trained_if_bundle
        assert "model"      in trained_if_bundle
        assert "meta"       in trained_if_bundle
        meta = trained_if_bundle["meta"]
        assert "feature_cols"  in meta
        assert "threshold"     in meta
        assert "contamination" in meta

    def test_model_type_is_if(self, trained_if_bundle):
        assert trained_if_bundle["model_type"] == "if"

    def test_feature_cols_match_schema(self, trained_if_bundle):
        """bundle 內的 feature_cols 必須與 schema.FEATURE_COLS 完全一致。
        不同步時 → 推論時靜默使用錯誤特徵集。
        """
        saved = set(trained_if_bundle["meta"]["feature_cols"])
        schema = set(FEATURE_COLS)
        assert saved == schema, (
            f"bundle feature_cols 與 schema 不符。\n"
            f"  bundle 多出：{saved - schema}\n"
            f"  schema 多出：{schema - saved}"
        )

    def test_threshold_is_finite_positive(self, trained_if_bundle):
        """threshold 必須是有限正數。
        threshold ≤ 0 → 所有流量觸發告警；threshold = inf → 永不告警。
        """
        t = trained_if_bundle["meta"]["threshold"]
        assert isinstance(t, float)
        assert math.isfinite(t), f"threshold 非有限數：{t}"
        assert t > 0.0,          f"threshold ≤ 0：{t}"


# ── Serialization Round-trip ──────────────────────────────────────────────────

@pytest.mark.harness
class TestSerializationRoundTrip:
    def test_save_load_produces_identical_scores(
        self, trained_if_bundle, make_benign_df, tmp_path
    ):
        """joblib save → load 後 score 必須 bit-identical（rtol=1e-5）。
        float32 round-trip 允許 epsilon 差異。
        """
        from joblib import dump, load
        path = tmp_path / "model.joblib"
        dump(trained_if_bundle, str(path))
        loaded = load(str(path))

        df = make_benign_df(n=100, seed=99)
        r_orig   = _infer_if(df, trained_if_bundle)
        r_loaded = _infer_if(df, loaded)

        np.testing.assert_allclose(
            r_orig["anomaly_score"].to_numpy(),
            r_loaded["anomaly_score"].to_numpy(),
            rtol=1e-5,
            err_msg="joblib round-trip 後 score 不一致",
        )

    def test_threshold_survives_serialization(self, trained_if_bundle, tmp_path):
        """threshold 序列化後必須完全相同（不允許浮點漂移）。"""
        from joblib import dump, load
        path = tmp_path / "thresh.joblib"
        dump(trained_if_bundle, str(path))
        loaded = load(str(path))
        assert loaded["meta"]["threshold"] == trained_if_bundle["meta"]["threshold"]

    def test_feature_cols_survive_serialization(self, trained_if_bundle, tmp_path):
        """feature_cols list 序列化後順序與內容必須完全一致。"""
        from joblib import dump, load
        path = tmp_path / "cols.joblib"
        dump(trained_if_bundle, str(path))
        loaded = load(str(path))
        assert loaded["meta"]["feature_cols"] == trained_if_bundle["meta"]["feature_cols"]


# ── FPR 門檻 ──────────────────────────────────────────────────────────────────

@pytest.mark.harness
class TestFPRGate:
    def test_fpr_below_0_02_on_synthetic_benign(
        self, trained_if_bundle, make_benign_df
    ):
        """BENIGN 資料的 FPR 必須 < 2%。
        contamination=0.01 → 預期 ~1% FPR，2% 為保守上界（2× slack）。
        若 FPR 過高，threshold 計算或 scaler 有問題。
        """
        df = make_benign_df(n=1000, seed=77)
        result = _infer_if(df, trained_if_bundle)
        fpr = float(result["is_alert"].mean())
        assert fpr < 0.02, f"FPR={fpr:.4f} 超過門檻 0.02（contamination=0.01）"


# ── AUC 回歸（需真實資料）────────────────────────────────────────────────────

@pytest.mark.harness
@pytest.mark.slow
@pytest.mark.regression
class TestAUCRegression:
    def test_auc_above_0_90_on_real_data(self, real_parquet_available):
        """AUC 回歸門檻：0.90（Run 07 基準 0.9257 的保守下界）。
        任何模型改動導致 AUC 掉到 0.90 以下會被此測試攔截。
        """
        if not real_parquet_available:
            pytest.skip("真實 parquet 不存在，跳過 AUC 回歸測試")

        import glob
        from sklearn.metrics import roc_auc_score

        from service.model.data.sample import (
            get_balance_sample_from_files,
            get_normal_sample_from_files,
        )
        from service.model.pipeline.trainer.if_ import IsolationForestTrainer

        train_paths = glob.glob(
            "service/model/dataset/parquet_clean/train/03-11_*.parquet"
        )
        test_paths = glob.glob(
            "service/model/dataset/parquet_clean/test/01-12_*.parquet"
        )
        if not train_paths or not test_paths:
            pytest.skip("找不到正確時序的 parquet 檔案")

        train_df = get_normal_sample_from_files(train_paths, n=5000, seed=42)
        trainer = IsolationForestTrainer(n_estimators=100, contamination=0.01, seed=42)
        trainer.fit(train_df)

        test_df = get_balance_sample_from_files(
            test_paths, sample_count_per_label=500, seed=42
        )
        result = _infer_if(test_df, trainer.bundle())

        y_true = (test_df["Label"] != "BENIGN").cast(pl.Int8).to_numpy()
        scores = result["anomaly_score"].to_numpy()
        auc = float(roc_auc_score(y_true, scores))

        assert auc > 0.90, (
            f"AUC={auc:.4f} 低於回歸門檻 0.90（Run 07 基準：0.9257）"
        )