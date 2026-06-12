import numpy as np
import pytest

from service.model.pipeline.distill import DistilledClassifier
from service.model.pipeline.distill_kd import (
    SCORE_SCALE,
    build_kd_score_table,
    kd_rules_from_deployed,
)


def test_per_bucket_mean_aggregation_scales_to_int_score_table():
    # bucket 0 has scores {0.4, 0.6} -> mean 0.5; bucket 1 has {0.7} -> 0.7.
    scores = np.array([0.4, 0.6, 0.7])
    idx = np.array([0, 0, 1])
    table, _ = build_kd_score_table(scores, idx, n_buckets=4, aggregate="mean")
    assert table[0] == int(round(0.5 * SCORE_SCALE))
    assert table[1] == int(round(0.7 * SCORE_SCALE))


def test_empty_buckets_fall_back_to_global_median_not_zero():
    scores = np.array([0.2, 0.8])  # median 0.5
    idx = np.array([0, 0])  # buckets 1..3 are empty
    table, empty = build_kd_score_table(scores, idx, n_buckets=4, aggregate="mean")
    assert empty == [1, 2, 3]
    fallback = int(round(0.5 * SCORE_SCALE))
    assert table[1] == table[2] == table[3] == fallback
    # empty buckets must not collapse to 0 (would mean "extremely benign")
    assert all(v != 0 for v in table)


def test_non_finite_teacher_scores_are_ignored_in_aggregation():
    scores = np.array([np.inf, 0.6, -np.inf, 0.4])
    idx = np.array([0, 0, 0, 0])
    table, _ = build_kd_score_table(scores, idx, n_buckets=2, aggregate="mean")
    assert table[0] == int(round(0.5 * SCORE_SCALE))  # only finite {0.6, 0.4}


def test_all_non_finite_raises():
    with pytest.raises(ValueError):
        build_kd_score_table(np.array([np.inf, -np.inf]), np.array([0, 0]), n_buckets=2)


def test_unknown_aggregate_raises():
    with pytest.raises(ValueError):
        build_kd_score_table(np.array([0.5]), np.array([0]), n_buckets=2, aggregate="max")


def _deployed_template():
    score_table = list(range(32))
    return {
        "version": 1,
        "feature_order": ["protocol", "pkt_len_mean", "fwd_max_q", "sym_ratio", "pkt_cv_sq"],
        "threshold_cmp": ">=",
        "score_scale": 10000,
        "length_unit": "packet_len",
        "threshold": 5,
        "quantile_bounds": [
            {"name": "protocol", "type": "absolute", "value": 6},
            {"name": "pkt_len_mean", "type": "absolute", "value": 100},
            {"name": "fwd_max_q", "type": "ratio", "numer": 2, "denom": 1},
            {"name": "sym_ratio", "type": "ratio", "numer": 3, "denom": 1},
            {"name": "pkt_cv_sq", "type": "ratio", "numer": 1, "denom": 10},
        ],
        "score_table": score_table,
    }


def test_kd_rules_preserve_bounds_and_pass_contract_validation():
    template = _deployed_template()
    new_table = [7000] * 32
    rules = kd_rules_from_deployed(template, new_table, threshold=6500)

    # bounds / metadata preserved, only score_table + threshold swapped
    assert rules["quantile_bounds"] == template["quantile_bounds"]
    assert rules["score_table"] == new_table
    assert rules["threshold"] == 6500
    # template must be untouched (deepcopy)
    assert template["score_table"] == list(range(32))
    # resulting rules must load as a valid v1 contract
    DistilledClassifier(rules)


def test_kd_rules_reject_wrong_length_score_table():
    with pytest.raises(ValueError):
        kd_rules_from_deployed(_deployed_template(), [0] * 16, threshold=1)
