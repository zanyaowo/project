import pytest
import polars as pl

from service.model.pipeline.distill import DistilledClassifier


CANONICAL_FEATURE_ORDER = [
    "protocol",
    "pkt_len_mean",
    "fwd_max_q",
    "sym_ratio",
    "pkt_cv_sq",
]


def _base_rules(**overrides):
    score_table = [0] * 32
    score_table[31] = 10
    rules = {
        "version": 1,
        "feature_order": CANONICAL_FEATURE_ORDER,
        "threshold_cmp": ">=",
        "score_scale": 10000,
        "length_unit": "packet_len",
        "threshold": 10,
        "quantile_bounds": [
            {"name": "protocol", "type": "absolute", "value": 6},
            {"name": "pkt_len_mean", "type": "absolute", "value": 100},
            {"name": "fwd_max_q", "type": "ratio", "numer": 2, "denom": 1},
            {"name": "sym_ratio", "type": "ratio", "numer": 3, "denom": 1},
            {"name": "pkt_cv_sq", "type": "ratio", "numer": 1, "denom": 10},
        ],
        "score_table": score_table,
    }
    rules.update(overrides)
    return rules


def test_contract_builds_index_with_canonical_lsb_feature_order_and_alerts_on_equal_threshold():
    """Contract v1: bit0..bit4 are protocol, mean, fwd_max, sym, pkt_cv_sq; score >= threshold alerts."""
    clf = DistilledClassifier(_base_rules())

    df = pl.DataFrame(
        {
            "Protocol": [17],
            "Packet Length Mean": [200],
            "Fwd Packet Length Max": [900],
            "Fwd Packet Length Mean": [300],
            "Total Fwd Packets": [10],
            "Total Bwd Packets": [2],
            # raw packet statistics used by the kernel contract for CV^2
            "Packet Length Sum": [1000],
            "Packet Length Sum Sq": [260000],
            "Total Packets": [5],
        }
    )

    assert clf._build_index(df).tolist() == [31]
    result = clf.predict(df)
    assert result["distill_score"].to_list() == [10]
    assert result["is_alert"].to_list() == [True]


def test_contract_builds_index_from_cicflowmeter_std_mean_when_packet_aggregates_are_unavailable():
    """Offline parquet validation may only have Packet Length Std/Mean; square CV to match kernel CV^2."""
    clf = DistilledClassifier(_base_rules())

    df = pl.DataFrame(
        {
            "Protocol": [17],
            "Packet Length Mean": [200],
            "Packet Length Std": [120],
            "Fwd Packet Length Max": [900],
            "Fwd Packet Length Mean": [300],
            "Total Fwd Packets": [10],
            "Total Bwd Packets": [2],
        }
    )

    assert clf._build_index(df).tolist() == [31]


@pytest.mark.parametrize(
    "bad_field,bad_value",
    [
        ("version", 2),
        ("feature_order", ["fwd_max_q", "sym_ratio", "pkt_cv_sq", "protocol", "pkt_len_mean"]),
        ("threshold_cmp", ">"),
        ("score_scale", 1),
        ("length_unit", "payload_len"),
    ],
)
def test_contract_rejects_rules_that_do_not_match_v1_metadata(bad_field, bad_value):
    rules = _base_rules(**{bad_field: bad_value})

    with pytest.raises(ValueError):
        DistilledClassifier(rules)
