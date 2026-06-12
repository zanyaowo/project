"""
Unit tests for service.model.schema
"""
import service.model.schema as schema


def test_string_to_float_cols_is_list():
    assert isinstance(schema.STRING_TO_FLOAT_COLS, list)
    assert len(schema.STRING_TO_FLOAT_COLS) > 0


def test_string_to_float_cols_contains_expected():
    assert "Flow Bytes/s" in schema.STRING_TO_FLOAT_COLS
    assert "Flow Packets/s" in schema.STRING_TO_FLOAT_COLS


def test_clip_upper_percentile_range():
    assert 0.0 < schema.CLIP_UPPER_PERCENTILE < 1.0


def test_id_cols_contains_label():
    assert "Label" in schema.ID_COLS


def test_id_cols_is_list():
    assert isinstance(schema.ID_COLS, list)