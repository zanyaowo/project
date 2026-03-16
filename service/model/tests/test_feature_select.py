"""
Unit tests for service.model.pipeline.feature_select
"""
import numpy as np
import polars as pl
import pytest
from unittest.mock import patch

from service.model.pipeline.feature_select import _extract_label, _draw_feature_importance


# ── _extract_label ────────────────────────────────────────────────────────────

class TestExtractLabel:
    def test_benign_becomes_false(self):
        lf = pl.DataFrame({"Label": ["BENIGN", "BENIGN"]}).lazy()
        result = _extract_label(lf).collect()
        assert result["Label"].to_list() == [False, False]

    def test_attack_becomes_true(self):
        lf = pl.DataFrame({"Label": ["DDoS", "PortScan", "FTP-Patator"]}).lazy()
        result = _extract_label(lf).collect()
        assert result["Label"].to_list() == [True, True, True]

    def test_mixed_labels(self):
        lf = pl.DataFrame({"Label": ["BENIGN", "DDoS", "BENIGN", "PortScan"]}).lazy()
        result = _extract_label(lf).collect()
        assert result["Label"].to_list() == [False, True, False, True]

    def test_label_col_dtype_is_boolean(self):
        lf = pl.DataFrame({"Label": ["BENIGN", "DDoS"]}).lazy()
        result = _extract_label(lf).collect()
        assert result["Label"].dtype == pl.Boolean

    def test_other_cols_untouched(self):
        lf = pl.DataFrame({"Label": ["BENIGN", "DDoS"], "feat": [1.0, 2.0]}).lazy()
        result = _extract_label(lf).collect()
        assert result["feat"].to_list() == [1.0, 2.0]


# ── _draw_feature_importance ──────────────────────────────────────────────────

class TestDrawFeatureImportance:
    @patch("service.model.pipeline.feature_select.plt.savefig")
    @patch("service.model.pipeline.feature_select.plt.show")
    def test_does_not_raise(self, mock_show, mock_savefig, tmp_path):
        output = str(tmp_path / "importance.png")
        _draw_feature_importance(
            feature_names=["a", "b", "c"],
            importances=np.array([0.5, 0.3, 0.2]),
            std=np.array([0.05, 0.03, 0.02]),
            output=output,
        )
        mock_savefig.assert_called_once_with(output)

    @patch("service.model.pipeline.feature_select.plt.savefig")
    @patch("service.model.pipeline.feature_select.plt.show")
    def test_single_feature(self, mock_show, mock_savefig, tmp_path):
        output = str(tmp_path / "single.png")
        _draw_feature_importance(
            feature_names=["only_feat"],
            importances=np.array([1.0]),
            std=np.array([0.1]),
            output=output,
        )
        mock_savefig.assert_called_once()