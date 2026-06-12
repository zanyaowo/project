"""
Unit tests for service.model.data.sample
"""
import polars as pl
import pytest

from service.model.data.sample import get_balance_sample_from_files


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_df(label_counts: dict[str, int]) -> pl.DataFrame:
    rows = []
    for label, n in label_counts.items():
        for i in range(n):
            rows.append({"Label": label, "feat_a": float(i), "feat_b": float(i * 2)})
    return pl.DataFrame(rows)


@pytest.fixture
def parquet_dir(tmp_path):
    """三個 parquet 檔，各含不同 label 分布"""
    files = []
    for i, label_counts in enumerate([
        {"BENIGN": 200, "DDoS": 50},
        {"BENIGN": 300, "PortScan": 80},
        {"BENIGN": 150, "DDoS": 60, "PortScan": 30},
    ]):
        path = tmp_path / f"file_{i}.parquet"
        _make_df(label_counts).write_parquet(path)
        files.append(str(path))
    return files


# ── tests ─────────────────────────────────────────────────────────────────────

def test_returns_dataframe(parquet_dir):
    result = get_balance_sample_from_files(parquet_dir, sample_count_per_label=10)
    assert isinstance(result, pl.DataFrame)


def test_all_labels_present(parquet_dir):
    result = get_balance_sample_from_files(parquet_dir, sample_count_per_label=10)
    assert set(result["Label"].unique().to_list()) == {"BENIGN", "DDoS", "PortScan"}


def test_sample_count_capped_per_label(parquet_dir):
    n = 50
    result = get_balance_sample_from_files(parquet_dir, sample_count_per_label=n)
    for row in result.group_by("Label").len().iter_rows(named=True):
        assert row["len"] <= n


def test_exact_sample_count_when_data_sufficient(parquet_dir):
    # BENIGN 總共 650 筆，要 100 筆應剛好
    n = 100
    result = get_balance_sample_from_files(parquet_dir, sample_count_per_label=n)
    assert result.filter(pl.col("Label") == "BENIGN").height == n


def test_caps_at_available_when_insufficient(parquet_dir):
    # PortScan 總共 110 筆，要 200 筆 → 應最多回傳 110 筆
    result = get_balance_sample_from_files(parquet_dir, sample_count_per_label=200)
    portscan_count = result.filter(pl.col("Label") == "PortScan").height
    assert portscan_count == 110


def test_reproducible_with_same_seed(parquet_dir):
    r1 = get_balance_sample_from_files(parquet_dir, sample_count_per_label=20, seed=0)
    r2 = get_balance_sample_from_files(parquet_dir, sample_count_per_label=20, seed=0)
    assert r1.sort(["Label", "feat_a"]).equals(r2.sort(["Label", "feat_a"]))


def test_different_seed_gives_different_result(parquet_dir):
    r1 = get_balance_sample_from_files(parquet_dir, sample_count_per_label=20, seed=0)
    r2 = get_balance_sample_from_files(parquet_dir, sample_count_per_label=20, seed=999)
    assert not r1.sort(["Label", "feat_a"]).equals(r2.sort(["Label", "feat_a"]))


def test_single_file(tmp_path):
    path = tmp_path / "single.parquet"
    _make_df({"BENIGN": 100, "DDoS": 100}).write_parquet(path)
    result = get_balance_sample_from_files([str(path)], sample_count_per_label=30)
    assert result.height == 60


def test_empty_paths_raises():
    with pytest.raises(ValueError, match="paths 不能為空"):
        get_balance_sample_from_files([], sample_count_per_label=10)