"""
Unit tests for service.model.data.cleaner
"""
import math

import polars as pl
import pytest

from service.model.data.cleaner import (
    clean,
    _strip_column_names,
    _cast_types,
    _cap_infinite,
    _fill_nulls,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _lf(data: dict) -> pl.LazyFrame:
    return pl.DataFrame(data).lazy()


# ── _strip_column_names ───────────────────────────────────────────────────────

class TestStripColumnNames:
    def test_strips_leading_spaces(self):
        lf = _lf({" feat": [1.0], "  double": [2.0]})
        result = _strip_column_names(lf).collect_schema().names()
        assert "feat" in result
        assert "double" in result

    def test_strips_trailing_spaces(self):
        lf = _lf({"feat ": [1.0], "col  ": [2.0]})
        result = _strip_column_names(lf).collect_schema().names()
        assert "feat" in result
        assert "col" in result

    def test_no_change_when_already_clean(self):
        lf = _lf({"feat": [1.0], "col": [2.0]})
        result = _strip_column_names(lf).collect_schema().names()
        assert result == ["feat", "col"]


# ── _cast_types ───────────────────────────────────────────────────────────────

class TestCastTypes:
    def test_drops_unnamed_col(self):
        lf = _lf({"Unnamed: 0": [0, 1], "feat": [1.0, 2.0]})
        result = _cast_types(lf).collect_schema().names()
        assert "Unnamed: 0" not in result

    def test_no_error_without_unnamed_col(self):
        lf = _lf({"feat": [1.0, 2.0]})
        result = _cast_types(lf).collect()
        assert "feat" in result.columns

    def test_casts_flow_bytes_string_to_float(self):
        lf = _lf({"Flow Bytes/s": ["1.5", "2.3", None], "feat": [1.0, 2.0, 3.0]})
        result = _cast_types(lf).collect()
        assert result["Flow Bytes/s"].dtype == pl.Float64

    def test_casts_flow_packets_string_to_float(self):
        lf = _lf({"Flow Packets/s": ["10.0", "20.0"], "feat": [1.0, 2.0]})
        result = _cast_types(lf).collect()
        assert result["Flow Packets/s"].dtype == pl.Float64

    def test_invalid_string_becomes_null(self):
        lf = _lf({"Flow Bytes/s": ["not_a_number", "1.0"], "feat": [1.0, 2.0]})
        result = _cast_types(lf).collect()
        assert result["Flow Bytes/s"][0] is None


# ── _cap_infinite ─────────────────────────────────────────────────────────────

class TestCapInfinite:
    def test_replaces_pos_inf(self):
        lf = _lf({"val": [1.0, 2.0, 3.0, float("inf")]})
        result = _cap_infinite(lf).collect()
        assert not any(math.isinf(v) for v in result["val"].to_list())

    def test_replaces_neg_inf(self):
        lf = _lf({"val": [1.0, 2.0, 3.0, float("-inf")]})
        result = _cap_infinite(lf).collect()
        assert not any(math.isinf(v) for v in result["val"].to_list() if v is not None)

    def test_no_change_when_no_inf(self):
        lf = _lf({"val": [1.0, 2.0, 3.0]})
        before = lf.collect()["val"].to_list()
        after = _cap_infinite(lf).collect()["val"].to_list()
        assert before == after

    def test_finite_values_unchanged(self):
        lf = _lf({"val": [1.0, 2.0, 3.0, float("inf")]})
        result = _cap_infinite(lf).collect()["val"].to_list()
        assert result[0] == 1.0
        assert result[1] == 2.0
        assert result[2] == 3.0

    def test_multiple_inf_cols(self):
        lf = _lf({
            "a": [1.0, float("inf"), 3.0],
            "b": [float("inf"), 2.0, 3.0],
        })
        result = _cap_infinite(lf).collect()
        assert not any(math.isinf(v) for v in result["a"].to_list())
        assert not any(math.isinf(v) for v in result["b"].to_list())


# ── _fill_nulls ───────────────────────────────────────────────────────────────

class TestFillNulls:
    def test_fills_null_with_zero(self):
        lf = _lf({"val": [1.0, None, 3.0]})
        result = _fill_nulls(lf).collect()
        assert result["val"][1] == 0.0

    def test_fills_nan_with_zero(self):
        lf = pl.DataFrame({"val": [1.0, float("nan"), 3.0]}).lazy()
        result = _fill_nulls(lf).collect()
        assert result["val"][1] == 0.0

    def test_non_null_values_unchanged(self):
        lf = _lf({"val": [1.0, 2.0, 3.0]})
        result = _fill_nulls(lf).collect()
        assert result["val"].to_list() == [1.0, 2.0, 3.0]

    def test_string_col_not_affected(self):
        lf = _lf({"val": [1.0, None], "label": ["A", None]})
        result = _fill_nulls(lf).collect()
        # 字串欄位不應被填 0
        assert result["label"][1] is None


# ── clean (integration) ───────────────────────────────────────────────────────

class TestClean:
    def test_returns_lazyframe(self):
        lf = _lf({" Flow Bytes/s": ["1.0", "2.0"], "feat": [1.0, 2.0]})
        result = clean(lf)
        assert isinstance(result, pl.LazyFrame)

    def test_pipeline_strips_and_casts(self):
        lf = _lf({" Flow Bytes/s": ["1.5", "2.5"], "feat": [1.0, 2.0]})
        result = clean(lf).collect()
        assert "Flow Bytes/s" in result.columns
        assert result["Flow Bytes/s"].dtype == pl.Float64

    def test_pipeline_removes_unnamed(self):
        lf = _lf({"Unnamed: 0": [0, 1], "feat": [1.0, 2.0]})
        result = clean(lf).collect()
        assert "Unnamed: 0" not in result.columns

    def test_pipeline_removes_inf_and_nulls(self):
        lf = _lf({"feat": [1.0, float("inf"), None]})
        result = clean(lf).collect()
        vals = result["feat"].to_list()
        assert not any(v is None for v in vals)
        assert not any(math.isinf(v) for v in vals)