"""
Unit tests for service.model.view.data_quality_plots
"""
import polars as pl
import pytest
from unittest.mock import patch, MagicMock

from service.model.view.data_quality_plots import (
    plot_missing_counts,
    plot_label_distribution,
    plot_numeric_stats,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _sample_lf(with_nulls: bool = False) -> pl.LazyFrame:
    data = {
        "Label": ["BENIGN"] * 5 + ["DDoS"] * 5,
        "feat_a": [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0],
        "feat_b": [10.0, None, 30.0, None, 50.0, 60.0, 70.0, None, 90.0, 100.0]
        if with_nulls
        else [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0],
    }
    return pl.DataFrame(data).lazy()


# ── plot_missing_counts ───────────────────────────────────────────────────────

class TestPlotMissingCounts:
    @patch("service.model.view.data_quality_plots.plt.show")
    def test_with_nulls_does_not_raise(self, mock_show):
        plot_missing_counts(_sample_lf(with_nulls=True))
        mock_show.assert_called_once()

    def test_no_nulls_prints_message(self, capsys):
        plot_missing_counts(_sample_lf(with_nulls=False))
        captured = capsys.readouterr()
        assert "缺失" in captured.out or "missing" in captured.out.lower() or captured.out != ""


# ── plot_label_distribution ───────────────────────────────────────────────────

class TestPlotLabelDistribution:
    @patch("service.model.view.data_quality_plots.plt.show")
    def test_does_not_raise(self, mock_show):
        plot_label_distribution(_sample_lf())
        mock_show.assert_called_once()

    @patch("service.model.view.data_quality_plots.plt.show")
    def test_custom_label_col(self, mock_show):
        lf = pl.DataFrame({
            "attack": ["normal", "ddos", "normal"],
            "feat": [1.0, 2.0, 3.0],
        }).lazy()
        plot_label_distribution(lf, label_col="attack")
        mock_show.assert_called_once()

    @patch("service.model.view.data_quality_plots.plt.show")
    def test_single_label(self, mock_show):
        lf = pl.DataFrame({"Label": ["BENIGN"] * 5, "feat": [1.0] * 5}).lazy()
        plot_label_distribution(lf)
        mock_show.assert_called_once()


# ── plot_numeric_stats ────────────────────────────────────────────────────────

class TestPlotNumericStats:
    def test_does_not_raise(self, capsys):
        plot_numeric_stats(_sample_lf())
        captured = capsys.readouterr()
        assert len(captured.out) > 0

    def test_prints_describe_output(self, capsys):
        plot_numeric_stats(_sample_lf())
        captured = capsys.readouterr()
        # polars describe 輸出含 "mean" 或 "count"
        assert "count" in captured.out or "mean" in captured.out