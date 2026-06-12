"""Run 28 — eBPF contract 對照實驗矩陣。

目的：把 Run 25 original model 與目前 32-entry all-binary contract，以及兩個
中間型 eBPF-compatible variant 放在同一份資料、同一個訓練/評估設定下比較。

比較項：
  A_run25_original:
    FwdMax_q + Sym_q + Pkt_CV_q + Protocol(raw) + Packet Length Mean(raw)

  B_protocol_bit_mean_raw:
    FwdMax_q + Sym_q + Pkt_CV_q + protocol_bit + Packet Length Mean(raw)

  C_larger_table_mean4 / C_larger_table_mean8:
    FwdMax_q + Sym_q + Pkt_CV_q + protocol_category + pkt_len_mean_bucket(N=4/8)
    理論 table size = 2^3 * 3 protocol categories * N

  D_current_5bit_contract:
    protocol_bit + pkt_len_mean_bit + FwdMax_q + Sym_q + Pkt_CV_sq
    理論 table size = 2^5 = 32

固定項：
  - BENIGN train = CIC 03-11 BENIGN + BigFlow BENIGN
  - Ratio boundaries = Mixed BENIGN median, N=2
  - IF hyperparameters = Run25/Run27 defaults
  - 評估：DDoS2019 / LOIC-HTTP / HOIC / LOIC-UDP / BigFlow

執行：
  uv run --project service/model python -m service.model.experiments.run28_contract_matrix
或：
  python -m service.model.experiments.run28_contract_matrix
"""
from __future__ import annotations

from dataclasses import dataclass
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
    SCALE,
    CIC_TEST_PATHS,
    CIC_TRAIN_PATHS,
    bigflow_to_norm as bigflow_to_norm_current,
    load_bigflow_samples,
    load_ids2018,
    to_norm_cic,
)
from service.model.data.sample import get_balance_sample_from_files, get_normal_sample_from_files


NORM_COLS = ["max_pkt", "fwd_mean", "fwd_pkts", "bwd_pkts", "pkt_std", "pkt_len_mean", "protocol"]
RATIO_FEATURES = ["fwd_max_q", "sym_ratio", "pkt_cv_q"]
CURRENT_CONTRACT_FEATURES = ["protocol", "pkt_len_mean", "fwd_max_q", "sym_ratio", "pkt_cv_sq"]


@dataclass(frozen=True)
class RatioBounds:
    fwd_max_q: tuple[int, int]
    sym_ratio: tuple[int, int]
    pkt_cv_q: tuple[int, int]
    pkt_cv_sq: tuple[int, int]


@dataclass(frozen=True)
class AbsoluteBounds:
    protocol: int
    pkt_len_mean: float


@dataclass(frozen=True)
class Variant:
    name: str
    description: str
    feature_cols: list[str]
    table_size: int | None
    builder: Callable[[pl.DataFrame], pl.DataFrame]


def _finite(values: np.ndarray) -> np.ndarray:
    values = values.astype(np.float64)
    return values[np.isfinite(values)]


def _ratio_bound(values: np.ndarray) -> tuple[int, int]:
    values = _finite(values)
    if len(values) == 0:
        raise ValueError("cannot compute ratio boundary from empty finite values")
    return max(0, int(np.median(values) * SCALE)), SCALE


def _quantile_bounds(values: np.ndarray, n: int) -> np.ndarray:
    values = _finite(values)
    if len(values) == 0:
        raise ValueError("cannot compute quantile boundaries from empty finite values")
    return np.percentile(values, np.linspace(0, 100, n + 1)[1:-1])


def _bucket(values: np.ndarray, bounds: np.ndarray) -> np.ndarray:
    values = values.astype(np.float64)
    return np.searchsorted(bounds, values, side="right").astype(np.float32)


def _bit_abs(values: np.ndarray, boundary: float) -> np.ndarray:
    return (values.astype(np.float64) > boundary).astype(np.float32)


def _bit_ratio(num: np.ndarray, den: np.ndarray, bound: tuple[int, int], den_add: float = 1.0) -> np.ndarray:
    numer, denom = bound
    return ((num.astype(np.float64) * denom) > ((den.astype(np.float64) + den_add) * numer)).astype(np.float32)


def compute_ratio_bounds(df: pl.DataFrame, den_add: float = 1.0) -> RatioBounds:
    max_pkt = df["max_pkt"].to_numpy()
    fwd_mean = df["fwd_mean"].to_numpy()
    fwd_pkts = df["fwd_pkts"].to_numpy()
    bwd_pkts = df["bwd_pkts"].to_numpy()
    pkt_std = df["pkt_std"].to_numpy()
    pkt_mean = df["pkt_len_mean"].to_numpy()
    return RatioBounds(
        fwd_max_q=_ratio_bound(max_pkt / (fwd_mean + den_add)),
        sym_ratio=_ratio_bound(fwd_pkts / (bwd_pkts + 1.0)),
        pkt_cv_q=_ratio_bound(pkt_std / (pkt_mean + den_add)),
        pkt_cv_sq=_ratio_bound((pkt_std / (pkt_mean + den_add)) ** 2),
    )


def compute_abs_bounds(df: pl.DataFrame) -> AbsoluteBounds:
    return AbsoluteBounds(
        protocol=int(np.median(df["protocol"].to_numpy())),
        pkt_len_mean=float(np.median(df["pkt_len_mean"].to_numpy())),
    )


def add_ratio_bucket_cols(df: pl.DataFrame, ratio_bounds: RatioBounds, suffix: str = "", den_add: float = 1.0) -> pl.DataFrame:
    return df.with_columns([
        pl.Series(f"fwd_max_q{suffix}", _bit_ratio(df["max_pkt"].to_numpy(), df["fwd_mean"].to_numpy(), ratio_bounds.fwd_max_q, den_add=den_add)),
        pl.Series(f"sym_ratio{suffix}", _bit_ratio(df["fwd_pkts"].to_numpy(), df["bwd_pkts"].to_numpy(), ratio_bounds.sym_ratio, den_add=1.0)),
        pl.Series(f"pkt_cv_q{suffix}", _bit_ratio(df["pkt_std"].to_numpy(), df["pkt_len_mean"].to_numpy(), ratio_bounds.pkt_cv_q, den_add=den_add)),
        pl.Series(
            f"pkt_cv_sq{suffix}",
            _bit_ratio(df["pkt_std"].to_numpy() ** 2, df["pkt_len_mean"].to_numpy() ** 2, ratio_bounds.pkt_cv_sq, den_add=0.0),
        ),
    ])


def protocol_category(values: np.ndarray) -> np.ndarray:
    """TCP=0, UDP=1, other=2. Keeps eBPF table categorical and bounded."""
    values = values.astype(np.int64)
    return np.where(values == 6, 0, np.where(values == 17, 1, 2)).astype(np.float32)


def bigflow_to_norm_run25(df: pl.DataFrame) -> pl.DataFrame:
    """Match Run25 BigFlow normalization exactly: denominators use 1e-6, not +1."""
    pkt_bucket_midpoints = {
        "NUM_PKTS_UP_TO_128_BYTES": 64,
        "NUM_PKTS_128_TO_256_BYTES": 192,
        "NUM_PKTS_256_TO_512_BYTES": 384,
        "NUM_PKTS_512_TO_1024_BYTES": 768,
        "NUM_PKTS_1024_TO_1514_BYTES": 1269,
    }
    total_pkts = pl.col("IN_PKTS").cast(pl.Float64) + pl.col("OUT_PKTS").cast(pl.Float64)
    total_bytes = pl.col("IN_BYTES").cast(pl.Float64) + pl.col("OUT_BYTES").cast(pl.Float64)
    fwd_mean = pl.col("IN_BYTES").cast(pl.Float64) / (pl.col("IN_PKTS").cast(pl.Float64) + 1e-6)
    pkt_len_mean = total_bytes / (total_pkts + 1e-6)
    ex2 = sum(pl.col(c).cast(pl.Float64) * float(m * m) for c, m in pkt_bucket_midpoints.items()) / (total_pkts + 1e-6)
    pkt_std = (ex2 - pkt_len_mean ** 2).clip(lower_bound=0.0).sqrt()
    return df.with_columns([
        pl.col("LONGEST_FLOW_PKT").cast(pl.Float64).alias("max_pkt"),
        fwd_mean.alias("fwd_mean"),
        pl.col("IN_PKTS").cast(pl.Float64).alias("fwd_pkts"),
        pl.col("OUT_PKTS").cast(pl.Float64).alias("bwd_pkts"),
        pkt_std.alias("pkt_std"),
        pkt_len_mean.alias("pkt_len_mean"),
        pl.col("PROTOCOL").cast(pl.Float64).alias("protocol"),
    ])


def train_score_auc(train_df: pl.DataFrame, eval_df: pl.DataFrame, y: np.ndarray, feature_cols: list[str]) -> float:
    x_train = train_df.select(feature_cols).to_numpy().astype(np.float32)
    x_eval = eval_df.select(feature_cols).to_numpy().astype(np.float32)
    finite_train = np.isfinite(x_train).all(axis=1)
    finite_eval = np.isfinite(x_eval).all(axis=1)
    x_train = x_train[finite_train]
    x_eval = x_eval[finite_eval]
    y = y[finite_eval]
    if len(x_train) < 10 or y.sum() == 0 or y.sum() == len(y):
        raise ValueError("invalid train/eval split for AUC")
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


def fmt(value: float | None) -> str:
    return "  nan " if value is None else f"{value:.4f}"


def main() -> dict[str, dict[str, float]]:
    print("=" * 92)
    print("Run 28 — Contract matrix: Run25 original vs eBPF-compatible distilled variants")
    print("=" * 92)
    print(f"CIC train files={len(CIC_TRAIN_PATHS)}; CIC test files={len(CIC_TEST_PATHS)}")
    print(f"N train/source={N_TRAIN_PER_SOURCE}; N eval/label={N_EVAL_PER_LABEL}; seed={SEED}")

    cic_train = to_norm_cic(get_normal_sample_from_files(CIC_TRAIN_PATHS, n=N_TRAIN_PER_SOURCE, seed=SEED))
    cic_eval = to_norm_cic(get_balance_sample_from_files(CIC_TEST_PATHS, sample_count_per_label=N_EVAL_PER_LABEL, seed=SEED))
    d1 = to_norm_cic(load_ids2018(IDS2018_D1), ids2018=True)
    d2 = to_norm_cic(load_ids2018(IDS2018_D2), ids2018=True)
    hoic_label = next((x for x in d2["Label"].unique().to_list() if "HOIC" in x), None)
    udp_label = next((x for x in d2["Label"].unique().to_list() if "UDP" in x), None)
    d2_hoic = d2.filter(pl.col("Label").is_in(["BENIGN", hoic_label])) if hoic_label else None
    d2_udp = d2.filter(pl.col("Label").is_in(["BENIGN", udp_label])) if udp_label else None

    bf_train_raw, bf_eval_raw = load_bigflow_samples()

    # Two normalized views are intentionally kept:
    # - Run25 view preserves the original experiment contract (+1e-6 for BigFlow means).
    # - Current view preserves the deployed/contract approximation (+1).
    bf_train_run25 = bigflow_to_norm_run25(bf_train_raw)
    bf_eval_run25 = bigflow_to_norm_run25(bf_eval_raw)
    bf_train_current = bigflow_to_norm_current(bf_train_raw)
    bf_eval_current = bigflow_to_norm_current(bf_eval_raw)

    mixed_train_run25 = pl.concat([cic_train.select(NORM_COLS), bf_train_run25.select(NORM_COLS)])
    mixed_train_current = pl.concat([cic_train.select(NORM_COLS), bf_train_current.select(NORM_COLS)])

    ratio_bounds_run25 = compute_ratio_bounds(mixed_train_run25, den_add=1e-6)
    ratio_bounds_current = compute_ratio_bounds(mixed_train_current, den_add=1.0)
    abs_bounds_run25 = compute_abs_bounds(mixed_train_run25)
    abs_bounds_current = compute_abs_bounds(mixed_train_current)
    pkt_mean_bounds_4 = _quantile_bounds(mixed_train_run25["pkt_len_mean"].to_numpy(), 4)
    pkt_mean_bounds_8 = _quantile_bounds(mixed_train_run25["pkt_len_mean"].to_numpy(), 8)

    print(f"CIC BENIGN train={len(cic_train)}; BigFlow BENIGN train={len(bf_train_run25)}; Mixed={len(mixed_train_run25)}")
    print(f"DDoS2019 eval={len(cic_eval)}; LOIC-HTTP eval={len(d1)}; BigFlow eval={len(bf_eval_run25)}")
    print("\nMixed boundaries:")
    print("  Run25-compatible (+1e-6 where Run25 used it):")
    print(f"    protocol median     = {abs_bounds_run25.protocol}")
    print(f"    pkt_len_mean median = {abs_bounds_run25.pkt_len_mean:.4f}")
    print(f"    fwd_max_q median    = {ratio_bounds_run25.fwd_max_q[0] / SCALE:.6f}")
    print(f"    sym_ratio median    = {ratio_bounds_run25.sym_ratio[0] / SCALE:.6f}")
    print(f"    pkt_cv_q median     = {ratio_bounds_run25.pkt_cv_q[0] / SCALE:.6f}")
    print(f"    pkt_len_mean q4     = {[round(float(x), 4) for x in pkt_mean_bounds_4.tolist()]}")
    print(f"    pkt_len_mean q8     = {[round(float(x), 4) for x in pkt_mean_bounds_8.tolist()]}")
    print("  Current contract (+1 / CV^2):")
    print(f"    protocol median     = {abs_bounds_current.protocol}")
    print(f"    pkt_len_mean median = {abs_bounds_current.pkt_len_mean:.4f}")
    print(f"    fwd_max_q median    = {ratio_bounds_current.fwd_max_q[0] / SCALE:.6f}")
    print(f"    sym_ratio median    = {ratio_bounds_current.sym_ratio[0] / SCALE:.6f}")
    print(f"    pkt_cv_sq median    = {ratio_bounds_current.pkt_cv_sq[0] / SCALE:.6f}")

    def run25_features(df: pl.DataFrame) -> pl.DataFrame:
        return add_ratio_bucket_cols(df, ratio_bounds_run25, suffix="_r25", den_add=1.0).with_columns([
            pl.col("protocol").cast(pl.Float32).alias("protocol_raw"),
            pl.col("pkt_len_mean").cast(pl.Float32).alias("pkt_len_mean_raw"),
            pl.Series("protocol_bit_r25", _bit_abs(df["protocol"].to_numpy(), abs_bounds_run25.protocol)),
            pl.Series("protocol_cat", protocol_category(df["protocol"].to_numpy())),
            pl.Series("pkt_len_mean_bucket4", _bucket(df["pkt_len_mean"].to_numpy(), pkt_mean_bounds_4)),
            pl.Series("pkt_len_mean_bucket8", _bucket(df["pkt_len_mean"].to_numpy(), pkt_mean_bounds_8)),
        ])

    def current_features(df: pl.DataFrame) -> pl.DataFrame:
        return add_ratio_bucket_cols(df, ratio_bounds_current, den_add=1.0).with_columns([
            pl.Series("protocol_bit", _bit_abs(df["protocol"].to_numpy(), abs_bounds_current.protocol)),
            pl.Series("pkt_len_mean_bit", _bit_abs(df["pkt_len_mean"].to_numpy(), abs_bounds_current.pkt_len_mean)),
        ])

    variants = [
        Variant(
            name="A_run25_original",
            description="3 ratio bits + Protocol raw + Packet Length Mean raw",
            feature_cols=["fwd_max_q_r25", "sym_ratio_r25", "pkt_cv_q_r25", "protocol_raw", "pkt_len_mean_raw"],
            table_size=None,
            builder=run25_features,
        ),
        Variant(
            name="B_protocol_bit_mean_raw",
            description="3 ratio bits + protocol bit + Packet Length Mean raw",
            feature_cols=["fwd_max_q_r25", "sym_ratio_r25", "pkt_cv_q_r25", "protocol_bit_r25", "pkt_len_mean_raw"],
            table_size=None,
            builder=run25_features,
        ),
        Variant(
            name="C_larger_table_mean4",
            description="3 ratio bits + protocol category + pkt mean bucket N=4",
            feature_cols=["fwd_max_q_r25", "sym_ratio_r25", "pkt_cv_q_r25", "protocol_cat", "pkt_len_mean_bucket4"],
            table_size=2**3 * 3 * 4,
            builder=run25_features,
        ),
        Variant(
            name="C_larger_table_mean8",
            description="3 ratio bits + protocol category + pkt mean bucket N=8",
            feature_cols=["fwd_max_q_r25", "sym_ratio_r25", "pkt_cv_q_r25", "protocol_cat", "pkt_len_mean_bucket8"],
            table_size=2**3 * 3 * 8,
            builder=run25_features,
        ),
        Variant(
            name="D_current_5bit_contract",
            description="protocol bit + pkt mean bit + FwdMax bit + Sym bit + CV^2 bit; 32-entry table",
            feature_cols=["protocol_bit", "pkt_len_mean_bit", "fwd_max_q", "sym_ratio", "pkt_cv_sq"],
            table_size=32,
            builder=current_features,
        ),
    ]

    eval_sets: list[tuple[str, pl.DataFrame, np.ndarray]] = [
        ("DDoS2019", cic_eval, (cic_eval["Label"] != "BENIGN").cast(pl.Int8).to_numpy()),
        ("LOIC-HTTP", d1, (d1["Label"] != "BENIGN").cast(pl.Int8).to_numpy()),
    ]
    if d2_hoic is not None:
        eval_sets.append(("HOIC", d2_hoic, (d2_hoic["Label"] != "BENIGN").cast(pl.Int8).to_numpy()))
    if d2_udp is not None:
        eval_sets.append(("LOIC-UDP", d2_udp, (d2_udp["Label"] != "BENIGN").cast(pl.Int8).to_numpy()))
    eval_sets.append(("BigFlow", bf_eval_run25, bf_eval_run25["is_attack"].to_numpy()))

    print("\n[1] Variant definitions")
    for variant in variants:
        table = "IF direct" if variant.table_size is None else f"table_size={variant.table_size}"
        print(f"  {variant.name:<28} {table:<16} {variant.description}")

    print("\n[2] AUC-ROC matrix")
    header = f"{'Variant':<28}{'Table':>8}" + "".join(f"{name:>11}" for name, _, _ in eval_sets) + f"{'Avg':>9}"
    print(header)
    print("-" * len(header))

    train_run25 = run25_features(mixed_train_run25)
    train_current = current_features(mixed_train_current)
    eval_feature_cache_run25 = {
        "DDoS2019": run25_features(cic_eval),
        "LOIC-HTTP": run25_features(d1),
        "BigFlow": run25_features(bf_eval_run25),
    }
    if d2_hoic is not None:
        eval_feature_cache_run25["HOIC"] = run25_features(d2_hoic)
    if d2_udp is not None:
        eval_feature_cache_run25["LOIC-UDP"] = run25_features(d2_udp)

    eval_feature_cache_current = {
        "DDoS2019": current_features(cic_eval),
        "LOIC-HTTP": current_features(d1),
        "BigFlow": current_features(bf_eval_current),
    }
    if d2_hoic is not None:
        eval_feature_cache_current["HOIC"] = current_features(d2_hoic)
    if d2_udp is not None:
        eval_feature_cache_current["LOIC-UDP"] = current_features(d2_udp)

    results: dict[str, dict[str, float]] = {}
    for variant in variants:
        row_results: dict[str, float] = {}
        row = f"{variant.name:<28}{(variant.table_size or 0):>8}"
        for eval_name, _eval_df, y in eval_sets:
            try:
                train_df = train_current if variant.name == "D_current_5bit_contract" else train_run25
                eval_cache = eval_feature_cache_current if variant.name == "D_current_5bit_contract" else eval_feature_cache_run25
                auc = train_score_auc(train_df, eval_cache[eval_name], y, variant.feature_cols)
                row_results[eval_name] = auc
                row += f"{auc:>11.4f}"
            except Exception as exc:
                row += f"{'ERR':>11}"
                print(f"\n[WARN] {variant.name} on {eval_name}: {exc}")
        valid = list(row_results.values())
        avg = sum(valid) / len(valid) if valid else float("nan")
        row_results["Avg"] = avg
        row += f"{avg:>9.4f}"
        results[variant.name] = row_results
        print(row)

    print("\n[3] Delta vs A_run25_original")
    baseline = results.get("A_run25_original", {})
    delta_header = f"{'Variant':<28}" + "".join(f"{name:>11}" for name, _, _ in eval_sets) + f"{'Avg':>9}"
    print(delta_header)
    print("-" * len(delta_header))
    for variant in variants[1:]:
        row = f"{variant.name:<28}"
        for eval_name, _, _ in eval_sets:
            delta = results[variant.name].get(eval_name, float("nan")) - baseline.get(eval_name, float("nan"))
            row += f"{delta:>+11.4f}"
        row += f"{(results[variant.name]['Avg'] - baseline.get('Avg', float('nan'))):>+9.4f}"
        print(row)

    print("\n[4] Interpretation hints")
    print("  - A 是 Run25 證據支持的模型；若 A 重現正常而 D 崩掉，代表問題在 contract distillation。")
    print("  - B 測 protocol 二值化的代價；若 B≈A，protocol raw 不是主要損失。")
    print("  - C 測較大 eBPF table 是否能救回 Packet Length Mean 的資訊。")
    print("  - D 是目前 32-entry all-binary contract；不可直接引用 A/Run25 的 AUC 作為部署證據。")

    return results


if __name__ == "__main__":
    main()
