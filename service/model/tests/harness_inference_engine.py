"""
Harness 3 — Inference Engine（Socket-Ready）

測試 _infer_if() 作為 Rust → Python IPC 邊界時的行為：
- 形狀契約：26 個 float 對應 FEATURE_COLS（文件化 Rust ModelFeature 的契約）
- 邊界值：全零、極端大、負值不得 crash
- 確定性：相同輸入相同 score
- 一致性：is_alert 嚴格等於 score > threshold
- 已知攻擊型態：極端 IAT / 高 Bytes 必須觸發告警

對應防護的已知失敗：
- is_alert 與 threshold 不一致（若 _infer_if 邏輯被重構）
- 全零輸入（Rust 測量失敗）導致 crash 或 NaN score
"""
import math

import numpy as np
import polars as pl
import pytest

from service.model.pipeline.infer import _infer_if


# ── helpers ───────────────────────────────────────────────────────────────────

def _single_row_df(feature_cols: list[str], values: dict | float) -> pl.DataFrame:
    """建立單列 DataFrame。values 可為 dict（各欄指定）或 float（全欄同值）。"""
    if isinstance(values, (int, float)):
        data = {col: [float(values)] for col in feature_cols}
    else:
        data = {col: [float(values.get(col, 50.0))] for col in feature_cols}
    return pl.DataFrame(data)


# ── 形狀契約（文件化 Rust ModelFeature 的契約）────────────────────────────────

@pytest.mark.harness
class TestVectorShapeContract:
    def test_feature_cols_count_is_26(self, feature_cols):
        """FEATURE_COLS 必須是 26 個——這是 Rust ModelFeature struct 的欄位數契約。
        若 FEATURE_COLS 變動，Rust 端的 struct 定義也必須同步更新。
        """
        assert len(feature_cols) == 26, (
            f"FEATURE_COLS 有 {len(feature_cols)} 個，Rust ModelFeature 期望 26。"
            "請同步更新 firewall-common/src/lib.rs 的 ModelFeature struct。"
        )

    def test_infer_accepts_exact_feature_cols_dataframe(
        self, trained_if_bundle, feature_cols
    ):
        """_infer_if() 接受只含 FEATURE_COLS 的 DataFrame（無 Label 欄）。
        這是 Rust 送來的 feature vector 的最小合法形狀。
        """
        df = _single_row_df(feature_cols, 50.0)
        result = _infer_if(df, trained_if_bundle)
        assert "anomaly_score" in result.columns
        assert "is_alert"      in result.columns
        assert len(result) == 1


# ── 邊界值（Rust 可能送來的極端輸入）────────────────────────────────────────

@pytest.mark.harness
class TestEdgeCaseVectors:
    def test_all_zeros_produces_finite_score(
        self, trained_if_bundle, feature_cols
    ):
        """全零輸入（無流量 / Rust 測量失敗）不得 crash，score 必須有限。
        StandardScaler 將 0 映射為 -mean/std，是合法輸入。
        """
        df = _single_row_df(feature_cols, 0.0)
        result = _infer_if(df, trained_if_bundle)
        score = float(result["anomaly_score"][0])
        assert math.isfinite(score), f"全零輸入產生非有限 score：{score}"

    def test_extreme_large_values_produce_finite_score(
        self, trained_if_bundle, feature_cols
    ):
        """Rust u64 計數器飽和（~1e9）不得 crash 或產生 NaN。"""
        df = _single_row_df(feature_cols, 1e9)
        result = _infer_if(df, trained_if_bundle)
        score = float(result["anomaly_score"][0])
        assert math.isfinite(score), f"1e9 輸入產生非有限 score：{score}"

    def test_negative_values_produce_finite_score(
        self, trained_if_bundle, feature_cols
    ):
        """負值（Rust integer underflow）不得 crash。
        模型訓練時未見負值，但不應 panic。
        """
        df = _single_row_df(feature_cols, -1.0)
        result = _infer_if(df, trained_if_bundle)
        score = float(result["anomaly_score"][0])
        assert math.isfinite(score), f"負值輸入產生非有限 score：{score}"


# ── 確定性 ────────────────────────────────────────────────────────────────────

@pytest.mark.harness
class TestDeterminism:
    def test_same_input_same_score(self, trained_if_bundle, feature_cols):
        """相同輸入必須產生完全相同的 score（IsolationForest 推論無隨機性）。"""
        rng = np.random.default_rng(55)
        data = {col: rng.uniform(0, 100, size=50).tolist() for col in feature_cols}
        df = pl.DataFrame(data)
        r1 = _infer_if(df, trained_if_bundle)
        r2 = _infer_if(df, trained_if_bundle)
        np.testing.assert_array_equal(
            r1["anomaly_score"].to_numpy(),
            r2["anomaly_score"].to_numpy(),
            err_msg="相同輸入產生不同 score（非確定性）",
        )

    def test_is_alert_consistent_with_score_threshold(
        self, trained_if_bundle, make_benign_df
    ):
        """is_alert 必須嚴格等於 score > threshold，每一行都必須符合。
        對應 infer.py:44 的 `is_alert = scores > threshold`。
        若此行被重構為 >= 或讀取不同 meta key，此測試立即失敗。
        """
        df = make_benign_df(n=200)
        result = _infer_if(df, trained_if_bundle)
        threshold = trained_if_bundle["meta"]["threshold"]

        scores   = result["anomaly_score"].to_numpy()
        is_alert = result["is_alert"].to_numpy()
        expected = scores > threshold

        np.testing.assert_array_equal(
            is_alert, expected,
            err_msg="is_alert 與 (score > threshold) 不一致",
        )


# ── 已知攻擊型態（模型靈敏度回歸）──────────────────────────────────────────

@pytest.mark.harness
class TestKnownAttackPatterns:
    def test_attack_batch_has_high_alert_rate(
        self, trained_if_bundle, make_attack_df
    ):
        """攻擊批次（100 筆，9 個特徵極端）的告警率必須 > 50%。
        使用批次而非單點，減少 IF 高維隨機性的影響。
        make_attack_df 同時設定 IAT（7 個）、Bytes（1 個）、Down/Up（1 個）為極端值，
        模擬 Run 07 中 DDoS2019 最強鑑別特徵組合。
        """
        df = make_attack_df(n=100, seed=0)
        result = _infer_if(df, trained_if_bundle)
        alert_rate = float(result["is_alert"].mean())
        assert alert_rate > 0.50, (
            f"攻擊批次告警率={alert_rate:.2%}，低於 50%。"
            "模型對 DDoS 特徵型態的靈敏度不足。"
        )

    def test_normal_midrange_does_not_alert(self, trained_if_bundle, feature_cols):
        """中間值（50.0）不得觸發告警。
        若觸發，threshold 過低，正常流量會被誤殺。
        """
        df = _single_row_df(feature_cols, 50.0)
        result = _infer_if(df, trained_if_bundle)
        assert not bool(result["is_alert"][0]), (
            "中間值輸入觸發告警——threshold 可能過低，正常流量誤殺風險。"
        )