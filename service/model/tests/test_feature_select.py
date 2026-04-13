"""
Unit tests for service.model.pipeline.feature_select
"""
import numpy as np
import polars as pl
import pytest

from service.model.pipeline.feature_select import variance_select, _numeric_matrix, if_auc_validate


# ── _numeric_matrix ───────────────────────────────────────────────────────────

class TestNumericMatrix:
    def test_returns_ndarray_and_names(self):
        df = pl.DataFrame({"a": [1.0, 2.0], "b": [3.0, 4.0], "Label": ["BENIGN", "BENIGN"]})
        X, names = _numeric_matrix(df)
        assert isinstance(X, np.ndarray)
        assert isinstance(names, list)
        assert "Label" not in names

    def test_excludes_id_and_inbound_cols(self):
        from service.model.schema import ID_COLS
        data = {c: [1.0, 2.0] for c in ["feat_a", "feat_b"]}
        for c in list(ID_COLS)[:2]:
            data[c] = [1.0, 2.0]
        data["Inbound"] = [1.0, 2.0]
        df = pl.DataFrame(data)
        _, names = _numeric_matrix(df)
        assert "Inbound" not in names
        for c in list(ID_COLS)[:2]:
            assert c not in names

    def test_dtype_is_float32(self):
        df = pl.DataFrame({"x": [1.0, 2.0], "y": [3.0, 4.0]})
        X, _ = _numeric_matrix(df)
        assert X.dtype == np.float32


# ── variance_select ───────────────────────────────────────────────────────────

class TestVarianceSelect:
    def _make_benign_df(self, n=200, seed=0):
        rng = np.random.default_rng(seed)
        data = {f"feat_{i}": rng.uniform(0, 100, size=n).tolist() for i in range(10)}
        data["Label"] = ["BENIGN"] * n
        return pl.DataFrame(data)

    def test_returns_list_of_strings(self):
        df = self._make_benign_df()
        result = variance_select(df)
        assert isinstance(result, list)
        assert all(isinstance(c, str) for c in result)

    def test_zero_variance_cols_removed(self):
        rng = np.random.default_rng(0)
        df = pl.DataFrame({
            "constant": [5.0] * 100,
            "variable": rng.uniform(0, 100, 100).tolist(),
            "Label": ["BENIGN"] * 100,
        })
        result = variance_select(df, var_threshold=1e-4)
        assert "constant" not in result
        assert "variable" in result

    def test_high_corr_cols_reduced(self):
        rng = np.random.default_rng(0)
        base = rng.uniform(0, 100, 200)
        df = pl.DataFrame({
            "a": base.tolist(),
            "b": (base * 1.001).tolist(),   # near-perfect correlation
            "c": rng.uniform(0, 100, 200).tolist(),
            "Label": ["BENIGN"] * 200,
        })
        result = variance_select(df, corr_threshold=0.9)
        # 'a' and 'b' are nearly identical — one should be dropped
        assert len([x for x in result if x in ("a", "b")]) <= 1

    def test_result_subset_of_input_cols(self):
        df = self._make_benign_df()
        input_cols = set(df.columns) - {"Label"}
        result = variance_select(df)
        assert set(result).issubset(input_cols)


# ── if_auc_validate ───────────────────────────────────────────────────────────

class TestIfAucValidate:
    def _make_dfs(self, n_benign=300, n_attack=100, seed=0):
        rng = np.random.default_rng(seed)
        features = ["f1", "f2", "f3"]
        benign_data = {f: rng.normal(50, 5, n_benign).tolist() for f in features}
        benign_data["Label"] = ["BENIGN"] * n_benign
        benign_df = pl.DataFrame(benign_data)

        val_data = {f: rng.normal(50, 5, n_benign).tolist() for f in features}
        val_data["Label"] = ["BENIGN"] * n_benign
        attack_data = {f: rng.uniform(1e5, 1e7, n_attack).tolist() for f in features}
        attack_data["Label"] = ["DDoS"] * n_attack
        val_df = pl.concat([pl.DataFrame(val_data), pl.DataFrame(attack_data)])
        return benign_df, val_df

    def test_returns_float_auc(self):
        benign_df, val_df = self._make_dfs()
        auc = if_auc_validate(benign_df, val_df, ["f1", "f2", "f3"], n_estimators=20, seed=42)
        assert isinstance(auc, float)
        assert 0.0 <= auc <= 1.0

    def test_missing_feature_raises(self):
        benign_df, val_df = self._make_dfs()
        with pytest.raises(KeyError):
            if_auc_validate(benign_df, val_df, ["f1", "nonexistent"], n_estimators=20, seed=42)

    def test_extreme_attack_has_high_auc(self):
        benign_df, val_df = self._make_dfs(n_attack=200, seed=42)
        auc = if_auc_validate(benign_df, val_df, ["f1", "f2", "f3"], n_estimators=50, seed=42)
        assert auc > 0.70, f"AUC={auc:.4f} 過低，極端攻擊應易被 IF 識別"