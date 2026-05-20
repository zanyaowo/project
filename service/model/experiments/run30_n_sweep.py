"""Run 30 — N-sweep: 多點分位桶（非二值化）跨資料集 AUC 矩陣

目的：以 N=2/4/8 均勻分位桶量化全部 5 個特徵（Protocol 也用分位桶），
     觀察多桶是否改善 HOIC / LOIC-HTTP 失效，並量化 table size 代價。

⚠️  N=2 baseline 與 Run28 D 有微小差距：
    Run28 D 用整數交叉乘法（_bit_ratio），此處統一用浮點比值 + searchsorted。
    相對比較（N=2 vs N=4 vs N=8）有效；絕對值引用仍以 Run28 D 為準。

比較項（table_size = ∏ N_i）：
  D_n2_baseline:     N=2 all  →  2^5 = 32-entry              ← 對照（≈Run28 D）
  E_n4_all:          N=4 all  →  4^5 = 1024-entry
  E_n8_all:          N=8 all  →  8^5 = 32768-entry            ← 資訊上限，不宜直接 eBPF
  F_n4ratio_n2abs:   ratio × 3 N=4 + abs × 2 N=2  →  256-entry
  G_proto3_n4rest:   protocol 3-category + mean N=2 + ratio × 3 N=4  →  384-entry

執行：
  uv run --project service/model python -m service.model.experiments.run30_n_sweep
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

import numpy as np
import polars as pl
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import StandardScaler

from service.model.experiments.run27_boundary_overfit_check import (
    CONTAMINATION,
    IDS2018_D1,
    IDS2018_D2,
    N_ESTIMATORS,
    N_EVAL_PER_LABEL,
    N_TRAIN_PER_SOURCE,
    SEED,
    CIC_TEST_PATHS,
    CIC_TRAIN_PATHS,
    bigflow_to_norm as bigflow_to_norm_current,
    load_bigflow_samples,
    load_ids2018,
    to_norm_cic,
)
from service.model.data.sample import get_balance_sample_from_files, get_normal_sample_from_files

NORM_COLS = ["max_pkt", "fwd_mean", "fwd_pkts", "bwd_pkts", "pkt_std", "pkt_len_mean", "protocol"]

# N 值需要預先計算邊界；N=-1 代表 protocol 3-category special case
NS_TO_PRECOMPUTE = [2, 4, 8]

# ── Raw feature extractors ────────────────────────────────────────────────────

FEATURE_EXTRACTORS: dict[str, Callable[[pl.DataFrame], np.ndarray]] = {
    "protocol":     lambda df: df["protocol"].to_numpy().astype(np.float64),
    "pkt_len_mean": lambda df: df["pkt_len_mean"].to_numpy().astype(np.float64),
    "fwd_max_q":    lambda df: df["max_pkt"].to_numpy() / (df["fwd_mean"].to_numpy() + 1.0),
    "sym_ratio":    lambda df: df["fwd_pkts"].to_numpy() / (df["bwd_pkts"].to_numpy() + 1.0),
    "pkt_cv_sq":    lambda df: (df["pkt_std"].to_numpy() / (df["pkt_len_mean"].to_numpy() + 1.0)) ** 2,
}

# ── Bucketing helpers ─────────────────────────────────────────────────────────

def _finite(values: np.ndarray) -> np.ndarray:
    v = values.astype(np.float64)
    return v[np.isfinite(v)]


def _quantile_bounds(values: np.ndarray, n: int) -> np.ndarray:
    v = _finite(values)
    if len(v) == 0:
        raise ValueError("empty finite values")
    return np.percentile(v, np.linspace(0, 100, n + 1)[1:-1])


def _bucket(values: np.ndarray, bounds: np.ndarray) -> np.ndarray:
    return np.searchsorted(bounds, values.astype(np.float64), side="right").astype(np.float32)


def _protocol_cat3(values: np.ndarray) -> np.ndarray:
    """TCP=0, UDP=1, other=2."""
    v = values.astype(np.int64)
    return np.where(v == 6, 0, np.where(v == 17, 1, 2)).astype(np.float32)

# ── Bounds store ──────────────────────────────────────────────────────────────

@dataclass
class BoundsStore:
    """Per-feature quantile boundaries for each N value."""
    # feature → N → boundary array (length N-1)
    data: dict[str, dict[int, np.ndarray]] = field(default_factory=dict)

    def compute(self, mixed_train: pl.DataFrame, ns: list[int]) -> None:
        for feat, extractor in FEATURE_EXTRACTORS.items():
            raw = extractor(mixed_train)
            self.data[feat] = {n: _quantile_bounds(raw, n) for n in ns}

    def get(self, feat: str, n: int) -> np.ndarray:
        return self.data[feat][n]

# ── Feature builder ───────────────────────────────────────────────────────────

def add_bucket_features(df: pl.DataFrame, store: BoundsStore, n_map: dict[str, int]) -> pl.DataFrame:
    """Add bucketed columns to df according to n_map.

    n_map: feature → N  (N=-1 means 3-category for protocol)
    Column name: "{feat}_{N}b" or "protocol_cat3" for N=-1.
    """
    new_cols: list[pl.Series] = []
    for feat, n in n_map.items():
        raw = FEATURE_EXTRACTORS[feat](df)
        if feat == "protocol" and n == -1:
            new_cols.append(pl.Series("protocol_cat3", _protocol_cat3(raw)))
        else:
            bucketed = _bucket(raw, store.get(feat, n))
            new_cols.append(pl.Series(f"{feat}_{n}b", bucketed))
    return df.with_columns(new_cols)


def col_name(feat: str, n: int) -> str:
    return "protocol_cat3" if (feat == "protocol" and n == -1) else f"{feat}_{n}b"

# ── Variant definitions ───────────────────────────────────────────────────────

_ALL = ["protocol", "pkt_len_mean", "fwd_max_q", "sym_ratio", "pkt_cv_sq"]


@dataclass(frozen=True)
class Variant:
    name: str
    description: str
    n_map: dict[str, int]

    @property
    def table_size(self) -> int:
        size = 1
        for feat, n in self.n_map.items():
            size *= (3 if n == -1 else n)
        return size

    @property
    def feature_cols(self) -> list[str]:
        return [col_name(feat, n) for feat, n in self.n_map.items()]


VARIANTS: list[Variant] = [
    Variant(
        "D_n2_baseline",
        "N=2 all features; 32-entry (≈Run28 D)",
        {f: 2 for f in _ALL},
    ),
    Variant(
        "E_n4_all",
        "N=4 all features; 1024-entry",
        {f: 4 for f in _ALL},
    ),
    Variant(
        "E_n8_all",
        "N=8 all features; 32768-entry",
        {f: 8 for f in _ALL},
    ),
    Variant(
        "F_n4ratio_n2abs",
        "ratio × 3 N=4; abs × 2 N=2; 256-entry",
        {"protocol": 2, "pkt_len_mean": 2, "fwd_max_q": 4, "sym_ratio": 4, "pkt_cv_sq": 4},
    ),
    Variant(
        "G_proto3_n4rest",
        "protocol 3-cat; mean N=2; ratio × 3 N=4; 384-entry",
        {"protocol": -1, "pkt_len_mean": 2, "fwd_max_q": 4, "sym_ratio": 4, "pkt_cv_sq": 4},
    ),
]

# ── AUC ───────────────────────────────────────────────────────────────────────

def train_score_auc(
    train_df: pl.DataFrame,
    eval_df: pl.DataFrame,
    y: np.ndarray,
    feature_cols: list[str],
) -> float:
    x_train = train_df.select(feature_cols).to_numpy().astype(np.float32)
    x_eval = eval_df.select(feature_cols).to_numpy().astype(np.float32)
    x_train = x_train[np.isfinite(x_train).all(axis=1)]
    mask_eval = np.isfinite(x_eval).all(axis=1)
    x_eval = x_eval[mask_eval]
    y = y[mask_eval]
    if len(x_train) < 10 or y.sum() == 0 or y.sum() == len(y):
        raise ValueError("invalid split")
    scaler = StandardScaler()
    model = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination=CONTAMINATION,
        random_state=SEED,
        n_jobs=-1,
    )
    model.fit(scaler.fit_transform(x_train))
    score = -model.score_samples(scaler.transform(x_eval))
    return float(roc_auc_score(y, score))

# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 96)
    print("Run 30 — N-sweep: multi-level quantile buckets vs N=2 all-binary")
    print("=" * 96)

    # ── Data loading ──────────────────────────────────────────────────────────
    cic_train = to_norm_cic(get_normal_sample_from_files(CIC_TRAIN_PATHS, n=N_TRAIN_PER_SOURCE, seed=SEED))
    cic_eval = to_norm_cic(get_balance_sample_from_files(CIC_TEST_PATHS, sample_count_per_label=N_EVAL_PER_LABEL, seed=SEED))
    d1 = to_norm_cic(load_ids2018(IDS2018_D1), ids2018=True)
    d2 = to_norm_cic(load_ids2018(IDS2018_D2), ids2018=True)

    hoic_label = next((x for x in d2["Label"].unique().to_list() if "HOIC" in x), None)
    udp_label = next((x for x in d2["Label"].unique().to_list() if "UDP" in x), None)
    d2_hoic = d2.filter(pl.col("Label").is_in(["BENIGN", hoic_label])) if hoic_label else None
    d2_udp = d2.filter(pl.col("Label").is_in(["BENIGN", udp_label])) if udp_label else None

    bf_train_raw, bf_eval_raw = load_bigflow_samples()
    bf_train = bigflow_to_norm_current(bf_train_raw)
    bf_eval = bigflow_to_norm_current(bf_eval_raw)

    mixed_train = pl.concat([cic_train.select(NORM_COLS), bf_train.select(NORM_COLS)])
    print(f"Mixed BENIGN train: CIC={len(cic_train)} + BigFlow={len(bf_train)} = {len(mixed_train)}")

    # ── Compute quantile boundaries ───────────────────────────────────────────
    store = BoundsStore()
    store.compute(mixed_train, NS_TO_PRECOMPUTE)

    # Protocol 分布診斷（預測 N=4 邊界是否能分離 HOIC）
    proto_vals = mixed_train["protocol"].to_numpy()
    print("\nProtocol distribution in Mixed BENIGN:")
    for proto, name in [(6, "TCP"), (17, "UDP"), (1, "ICMP")]:
        pct = (proto_vals == proto).mean() * 100
        print(f"  {name} ({proto}): {pct:.1f}%")
    print(f"Protocol N=2 bounds: {[round(float(x), 1) for x in store.get('protocol', 2).tolist()]}")
    print(f"Protocol N=4 bounds: {[round(float(x), 1) for x in store.get('protocol', 4).tolist()]}")
    print(f"Protocol N=8 bounds: {[round(float(x), 1) for x in store.get('protocol', 8).tolist()]}")

    # ── Eval set registry ─────────────────────────────────────────────────────
    eval_dfs: dict[str, pl.DataFrame] = {
        "DDoS2019": cic_eval,
        "LOIC-HTTP": d1,
        "BigFlow": bf_eval,
    }
    if d2_hoic is not None:
        eval_dfs["HOIC"] = d2_hoic
    if d2_udp is not None:
        eval_dfs["LOIC-UDP"] = d2_udp

    eval_labels: dict[str, np.ndarray] = {
        "DDoS2019": (cic_eval["Label"] != "BENIGN").cast(pl.Int8).to_numpy(),
        "LOIC-HTTP": (d1["Label"] != "BENIGN").cast(pl.Int8).to_numpy(),
        "BigFlow": bf_eval["is_attack"].to_numpy(),
    }
    if d2_hoic is not None:
        eval_labels["HOIC"] = (d2_hoic["Label"] != "BENIGN").cast(pl.Int8).to_numpy()
    if d2_udp is not None:
        eval_labels["LOIC-UDP"] = (d2_udp["Label"] != "BENIGN").cast(pl.Int8).to_numpy()

    eval_order = [e for e in ["DDoS2019", "LOIC-HTTP", "HOIC", "LOIC-UDP", "BigFlow"] if e in eval_dfs]

    # ── Pre-compute bucketed features ─────────────────────────────────────────
    # Each variant has a unique n_map; cache by frozenset(n_map.items())
    train_feat: dict[frozenset, pl.DataFrame] = {}
    eval_feat: dict[frozenset, dict[str, pl.DataFrame]] = {}
    for v in VARIANTS:
        key = frozenset(v.n_map.items())
        if key not in train_feat:
            train_feat[key] = add_bucket_features(mixed_train, store, v.n_map)
            eval_feat[key] = {
                name: add_bucket_features(df, store, v.n_map) for name, df in eval_dfs.items()
            }

    # ── AUC-ROC matrix ────────────────────────────────────────────────────────
    print("\n[1] Variant definitions")
    for v in VARIANTS:
        print(f"  {v.name:<25} table={v.table_size:<6} {v.description}")

    print("\n[2] AUC-ROC matrix")
    header = f"{'Variant':<25}{'Table':>7}" + "".join(f"{n:>11}" for n in eval_order) + f"{'Avg':>9}"
    print(header)
    print("-" * len(header))

    all_results: dict[str, dict[str, float]] = {}
    for v in VARIANTS:
        key = frozenset(v.n_map.items())
        row_results: dict[str, float] = {}
        row = f"{v.name:<25}{v.table_size:>7}"
        for eval_name in eval_order:
            try:
                auc = train_score_auc(
                    train_feat[key],
                    eval_feat[key][eval_name],
                    eval_labels[eval_name],
                    v.feature_cols,
                )
                row_results[eval_name] = auc
                row += f"{auc:>11.4f}"
            except Exception as exc:
                row += f"{'ERR':>11}"
                print(f"\n[WARN] {v.name} on {eval_name}: {exc}")
        valid = list(row_results.values())
        avg = sum(valid) / len(valid) if valid else float("nan")
        row_results["Avg"] = avg
        row += f"{avg:>9.4f}"
        all_results[v.name] = row_results
        print(row)

    print("\n[3] Delta vs D_n2_baseline")
    baseline = all_results.get("D_n2_baseline", {})
    delta_header = f"{'Variant':<25}" + "".join(f"{n:>11}" for n in eval_order) + f"{'Avg':>9}"
    print(delta_header)
    print("-" * len(delta_header))
    for v in VARIANTS[1:]:
        row = f"{v.name:<25}"
        for eval_name in eval_order:
            d = all_results[v.name].get(eval_name, float("nan")) - baseline.get(eval_name, float("nan"))
            row += f"{d:>+11.4f}"
        d_avg = all_results[v.name].get("Avg", float("nan")) - baseline.get("Avg", float("nan"))
        row += f"{d_avg:>+9.4f}"
        print(row)

    # ── Protocol bucket distribution（HOIC 診斷）────────────────────────────
    if d2_hoic is not None:
        print("\n[4] Protocol bucket distribution — HOIC vs BENIGN in IDS2018-D2")
        hoic_only = d2_hoic.filter(pl.col("Label") != "BENIGN")
        ben_only = d2_hoic.filter(pl.col("Label") == "BENIGN")
        for n in [2, 4]:
            bounds_n = store.get("protocol", n)
            b_hoic = _bucket(FEATURE_EXTRACTORS["protocol"](hoic_only), bounds_n)
            b_ben = _bucket(FEATURE_EXTRACTORS["protocol"](ben_only), bounds_n)
            print(f"\n  Protocol N={n} (bounds={[round(float(x),1) for x in bounds_n.tolist()]}):")
            for buck in range(n):
                print(
                    f"    bucket {buck}: HOIC={100*(b_hoic == buck).mean():.1f}%"
                    f"  BENIGN={100*(b_ben == buck).mean():.1f}%"
                )

    print("\n[5] Interpretation hints")
    print("  - Protocol 在 Mixed BENIGN 以 TCP 為主；N=4 邊界預期叢集在 6 → HOIC 與 BENIGN 同桶，無法分離。")
    print("  - E_n4 vs D_n2 的 delta 顯示 ratio 特徵增加精度的邊際效益。")
    print("  - F（ratio N=4、abs N=2）是 eBPF 可接受的最大實用 table（256-entry）。")
    print("  - table_size > 1024 在 eBPF 需謹慎評估 BPF_MAP_TYPE_ARRAY 大小限制。")


if __name__ == "__main__":
    main()
