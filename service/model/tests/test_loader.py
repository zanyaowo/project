"""
Unit tests for service.model.data.loader
"""
import polars as pl
import pytest

from service.model.data.loader import _load_features_parquet as load_features_parquet


# ── helpers ───────────────────────────────────────────────────────────────────

def _write_parquet(path, data: dict) -> None:
    pl.DataFrame(data).write_parquet(path)


# ── load_features_parquet ─────────────────────────────────────────────────────

class TestLoadFeaturesParquet:
    def test_returns_lazyframe(self, tmp_path):
        p = tmp_path / "test.parquet"
        _write_parquet(p, {"a": [1.0, 2.0], "b": [3.0, 4.0]})
        result = load_features_parquet(str(p))
        assert isinstance(result, pl.LazyFrame)

    def test_columns_match(self, tmp_path):
        p = tmp_path / "test.parquet"
        _write_parquet(p, {"feat_x": [1.0], "feat_y": [2.0], "Label": ["BENIGN"]})
        lf = load_features_parquet(str(p))
        assert set(lf.collect_schema().names()) == {"feat_x", "feat_y", "Label"}

    def test_data_integrity(self, tmp_path):
        p = tmp_path / "test.parquet"
        _write_parquet(p, {"val": [10.0, 20.0, 30.0]})
        result = load_features_parquet(str(p)).collect()
        assert result["val"].to_list() == [10.0, 20.0, 30.0]

    def test_glob_pattern(self, tmp_path):
        for i in range(3):
            _write_parquet(tmp_path / f"file_{i}.parquet", {"val": [float(i)]})
        lf = load_features_parquet(str(tmp_path / "*.parquet"))
        result = lf.collect()
        assert result.height == 3

    def test_nonexistent_file_raises(self, tmp_path):
        with pytest.raises(Exception):
            load_features_parquet(str(tmp_path / "no_such_file.parquet")).collect()