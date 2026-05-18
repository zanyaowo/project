"""Run 27 — 分位桶邊界 overfit 驗證。

目的：驗證 5-feature N=2 distilled model 的 bucket boundaries 是否只貼合某一個
BENIGN 來源，導致跨資料集 benign bucket 分布崩塌或攻擊 AUC 下降。

固定項：
  - IF 訓練資料固定使用 Mixed BENIGN（CIC 03-11 + BigFlow BENIGN）
  - 只改變 boundary source：CIC-only / BigFlow-only / Mixed
  - 特徵使用目前 contract：FwdMax_q, Sym_q, Pkt_CV_sq, Protocol, Packet Length Mean

執行：
  uv run --project service/model python -m service.model.experiments.run27_boundary_overfit_check
或：
  python -m service.model.experiments.run27_boundary_overfit_check
"""
from __future__ import annotations

import glob
from dataclasses import dataclass

import numpy as np
import polars as pl
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import StandardScaler

from service.model.data.sample import get_balance_sample_from_files, get_normal_sample_from_files

BASE = "service/model/dataset/parquet_clean"
CIC_TRAIN_PATHS = sorted(glob.glob(f"{BASE}/03-11*.parquet"))
CIC_TEST_PATHS = sorted(glob.glob(f"{BASE}/01-12*.parquet"))
IDS2018_D1 = f"{BASE}/test/IDS-2018-DDOS/DDoS1-Tuesday-20-02-2018_TrafficForML_CICFlowMeter.parquet"
IDS2018_D2 = f"{BASE}/test/IDS-2018-DDOS/DDoS2-Wednesday-21-02-2018_TrafficForML_CICFlowMeter.parquet"
BIGFLOW_DIR = f"{BASE}/test/BigFlow-NIDS-V2-Merged-Parquet"

SEED = 42
N_TRAIN_PER_SOURCE = 10_000
N_EVAL_PER_LABEL = 4_000
N_ESTIMATORS = 200
CONTAMINATION = 0.01
SCALE = 1 << 20

FEATURES = ["protocol", "pkt_len_mean", "fwd_max_q", "sym_ratio", "pkt_cv_sq"]

PKT_BUCKET_MIDPOINTS = {
    "NUM_PKTS_UP_TO_128_BYTES": 64,
    "NUM_PKTS_128_TO_256_BYTES": 192,
    "NUM_PKTS_256_TO_512_BYTES": 384,
    "NUM_PKTS_512_TO_1024_BYTES": 768,
    "NUM_PKTS_1024_TO_1514_BYTES": 1269,
}


@dataclass(frozen=True)
class Bounds:
    protocol: int
    pkt_len_mean: int
    fwd_max_q: tuple[int, int]
    sym_ratio: tuple[int, int]
    pkt_cv_sq: tuple[int, int]


def _ratio_bound(values: np.ndarray) -> tuple[int, int]:
    values = values[np.isfinite(values)]
    if len(values) == 0:
        raise ValueError("cannot compute boundary from empty finite values")
    return max(0, int(np.median(values) * SCALE)), SCALE


def compute_bounds(df: pl.DataFrame) -> Bounds:
    return Bounds(
        protocol=int(np.median(df["protocol"].to_numpy())),
        pkt_len_mean=int(np.median(df["pkt_len_mean"].to_numpy())),
        fwd_max_q=_ratio_bound(df["max_pkt"].to_numpy() / (df["fwd_mean"].to_numpy() + 1.0)),
        sym_ratio=_ratio_bound(df["fwd_pkts"].to_numpy() / (df["bwd_pkts"].to_numpy() + 1.0)),
        pkt_cv_sq=_ratio_bound(
            (df["pkt_std"].to_numpy() / (df["pkt_len_mean"].to_numpy() + 1.0)) ** 2
        ),
    )


def _bit_ratio(num: np.ndarray, den: np.ndarray, bound: tuple[int, int]) -> np.ndarray:
    numer, denom = bound
    return (num.astype(np.float64) * denom) > ((den.astype(np.float64) + 1.0) * numer)


def bucketize(df: pl.DataFrame, bounds: Bounds) -> pl.DataFrame:
    protocol = (df["protocol"].to_numpy() > bounds.protocol).astype(np.float32)
    pkt_len_mean = (df["pkt_len_mean"].to_numpy() > bounds.pkt_len_mean).astype(np.float32)
    fwd_max_q = _bit_ratio(df["max_pkt"].to_numpy(), df["fwd_mean"].to_numpy(), bounds.fwd_max_q).astype(np.float32)
    sym_ratio = _bit_ratio(df["fwd_pkts"].to_numpy(), df["bwd_pkts"].to_numpy(), bounds.sym_ratio).astype(np.float32)
    pkt_cv_sq = _bit_ratio(
        df["pkt_std"].to_numpy() ** 2,
        df["pkt_len_mean"].to_numpy() ** 2,
        bounds.pkt_cv_sq,
    ).astype(np.float32)
    return df.with_columns([
        pl.Series("protocol", protocol),
        pl.Series("pkt_len_mean", pkt_len_mean),
        pl.Series("fwd_max_q", fwd_max_q),
        pl.Series("sym_ratio", sym_ratio),
        pl.Series("pkt_cv_sq", pkt_cv_sq),
    ])


def to_norm_cic(df: pl.DataFrame, ids2018: bool = False) -> pl.DataFrame:
    fwd_pkts_col = "Subflow Fwd Packets" if ids2018 and "Subflow Fwd Packets" in df.columns else "Total Fwd Packets"
    return df.with_columns([
        pl.col("Fwd Packet Length Max").cast(pl.Float64).alias("max_pkt"),
        pl.col("Fwd Packet Length Mean").cast(pl.Float64).alias("fwd_mean"),
        pl.col(fwd_pkts_col).cast(pl.Float64).alias("fwd_pkts"),
        pl.col("Total Backward Packets").cast(pl.Float64).alias("bwd_pkts"),
        pl.col("Packet Length Std").cast(pl.Float64).alias("pkt_std"),
        pl.col("Packet Length Mean").cast(pl.Float64).alias("pkt_len_mean"),
        pl.col("Protocol").cast(pl.Float64).alias("protocol"),
    ])


def bigflow_to_norm(df: pl.DataFrame) -> pl.DataFrame:
    total_pkts = pl.col("IN_PKTS").cast(pl.Float64) + pl.col("OUT_PKTS").cast(pl.Float64)
    total_bytes = pl.col("IN_BYTES").cast(pl.Float64) + pl.col("OUT_BYTES").cast(pl.Float64)
    pkt_len_mean = total_bytes / (total_pkts + 1.0)
    fwd_mean = pl.col("IN_BYTES").cast(pl.Float64) / (pl.col("IN_PKTS").cast(pl.Float64) + 1.0)
    ex2 = sum(pl.col(c).cast(pl.Float64) * float(m * m) for c, m in PKT_BUCKET_MIDPOINTS.items()) / (total_pkts + 1.0)
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


def load_ids2018(path: str) -> pl.DataFrame:
    df = pl.read_parquet(path).with_columns(pl.col("Label").cast(pl.String).str.to_uppercase().alias("Label"))
    chunks = []
    for label in df["Label"].unique().to_list():
        sub = df.filter(pl.col("Label") == label)
        if len(sub) > 0:
            chunks.append(sub.sample(min(N_EVAL_PER_LABEL, len(sub)), seed=SEED))
    return pl.concat(chunks)


def load_bigflow_samples() -> tuple[pl.DataFrame, pl.DataFrame]:
    parts = sorted(glob.glob(f"{BIGFLOW_DIR}/*.parquet"))
    rng = np.random.default_rng(SEED)
    benign_train, benign_eval, ddos_eval = [], [], []
    counts = {"train_b": 0, "eval_b": 0, "eval_d": 0}
    for path in parts:
        if all(v >= N_TRAIN_PER_SOURCE if k == "train_b" else v >= N_EVAL_PER_LABEL for k, v in counts.items()):
            break
        raw = pl.read_parquet(path)
        seed = int(rng.integers(1 << 31))
        b = raw.filter(pl.col("Attack") == "Benign")
        d = raw.filter(pl.col("Attack") == "DDoS")
        if len(b) and counts["train_b"] < N_TRAIN_PER_SOURCE:
            take = min(N_TRAIN_PER_SOURCE - counts["train_b"], len(b))
            benign_train.append(b.sample(take, seed=seed))
            counts["train_b"] += take
        if len(b) and counts["eval_b"] < N_EVAL_PER_LABEL:
            take = min(N_EVAL_PER_LABEL - counts["eval_b"], len(b))
            benign_eval.append(b.sample(take, seed=seed + 1))
            counts["eval_b"] += take
        if len(d) and counts["eval_d"] < N_EVAL_PER_LABEL:
            take = min(N_EVAL_PER_LABEL - counts["eval_d"], len(d))
            ddos_eval.append(d.sample(take, seed=seed + 2))
            counts["eval_d"] += take
    train = pl.concat(benign_train)
    eval_df = pl.concat([
        pl.concat(benign_eval).with_columns(pl.lit(0).cast(pl.Int8).alias("is_attack")),
        pl.concat(ddos_eval).with_columns(pl.lit(1).cast(pl.Int8).alias("is_attack")),
    ])
    return train, eval_df


def auc_eval(train_q: pl.DataFrame, eval_q: pl.DataFrame, y: np.ndarray) -> float:
    x_train = train_q.select(FEATURES).to_numpy().astype(np.float32)
    x_eval = eval_q.select(FEATURES).to_numpy().astype(np.float32)
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


def bucket_balance(df_q: pl.DataFrame) -> dict[str, float]:
    # p1: proportion in upper bucket. Median boundaries should yield ~0.5 on source-like benign.
    return {name: float(df_q[name].mean()) for name in FEATURES}


def fmt(x: float | None) -> str:
    return "  nan " if x is None else f"{x:.4f}"


def main() -> None:
    print("=" * 78)
    print("Run 27 — Boundary overfit check: CIC-only vs BigFlow-only vs Mixed")
    print("=" * 78)
    print(f"CIC train files: {len(CIC_TRAIN_PATHS)}; CIC test files: {len(CIC_TEST_PATHS)}")

    cic_train = to_norm_cic(get_normal_sample_from_files(CIC_TRAIN_PATHS, n=N_TRAIN_PER_SOURCE, seed=SEED))
    cic_eval = to_norm_cic(get_balance_sample_from_files(CIC_TEST_PATHS, sample_count_per_label=N_EVAL_PER_LABEL, seed=SEED))
    d1 = to_norm_cic(load_ids2018(IDS2018_D1), ids2018=True)
    d2 = to_norm_cic(load_ids2018(IDS2018_D2), ids2018=True)
    hoic_label = next((x for x in d2["Label"].unique().to_list() if "HOIC" in x), None)
    udp_label = next((x for x in d2["Label"].unique().to_list() if "UDP" in x), None)
    d2_hoic = d2.filter(pl.col("Label").is_in(["BENIGN", hoic_label])) if hoic_label else None
    d2_udp = d2.filter(pl.col("Label").is_in(["BENIGN", udp_label])) if udp_label else None

    bf_train_raw, bf_eval_raw = load_bigflow_samples()
    bf_train = bigflow_to_norm(bf_train_raw)
    bf_eval = bigflow_to_norm(bf_eval_raw)

    norm_cols = ["max_pkt", "fwd_mean", "fwd_pkts", "bwd_pkts", "pkt_std", "pkt_len_mean", "protocol"]
    mixed_train = pl.concat([cic_train.select(norm_cols), bf_train.select(norm_cols)])

    print(f"CIC BENIGN train={len(cic_train)}; BigFlow BENIGN train={len(bf_train)}; Mixed={len(mixed_train)}")
    print(f"DDoS2019 eval={len(cic_eval)}; LOIC-HTTP eval={len(d1)}; BigFlow eval={len(bf_eval)}")

    boundary_sources = {
        "CIC-only": cic_train,
        "BigFlow-only": bf_train,
        "Mixed": mixed_train,
    }

    eval_sets = [
        ("DDoS2019", cic_eval, (cic_eval["Label"] != "BENIGN").cast(pl.Int8).to_numpy()),
        ("LOIC-HTTP", d1, (d1["Label"] != "BENIGN").cast(pl.Int8).to_numpy()),
    ]
    if d2_hoic is not None:
        eval_sets.append(("HOIC", d2_hoic, (d2_hoic["Label"] != "BENIGN").cast(pl.Int8).to_numpy()))
    if d2_udp is not None:
        eval_sets.append(("LOIC-UDP", d2_udp, (d2_udp["Label"] != "BENIGN").cast(pl.Int8).to_numpy()))
    eval_sets.append(("BigFlow", bf_eval, bf_eval["is_attack"].to_numpy()))

    print("\n[1] AUC with IF train fixed to Mixed BENIGN; only boundary source changes")
    header = f"{'Boundary':<13}" + "".join(f"{name:>11}" for name, _, _ in eval_sets)
    print(header)
    print("-" * len(header))

    all_results: dict[str, dict[str, float]] = {}
    for source_name, source_df in boundary_sources.items():
        bounds = compute_bounds(source_df)
        train_q = bucketize(mixed_train, bounds)
        row_results = {}
        row = f"{source_name:<13}"
        for eval_name, eval_df, y in eval_sets:
            try:
                auc = auc_eval(train_q, bucketize(eval_df, bounds), y)
                row_results[eval_name] = auc
                row += f"{auc:>11.4f}"
            except Exception as exc:
                row_results[eval_name] = float("nan")
                row += f"{'ERR':>11}"
                print(f"[WARN] {source_name}/{eval_name}: {exc}")
        all_results[source_name] = row_results
        print(row)

    print("\n[2] BENIGN upper-bucket proportion; source-like should be near 0.5")
    print(f"{'Boundary':<13} {'BenignSet':<12} " + " ".join(f"{f:>12}" for f in FEATURES))
    print("-" * 92)
    benign_sets = {"CIC": cic_train, "BigFlow": bf_train, "Mixed": mixed_train}
    for source_name, source_df in boundary_sources.items():
        bounds = compute_bounds(source_df)
        for benign_name, benign_df in benign_sets.items():
            bal = bucket_balance(bucketize(benign_df, bounds))
            print(f"{source_name:<13} {benign_name:<12} " + " ".join(f"{bal[f]:>12.3f}" for f in FEATURES))

    print("\n[3] Boundary p50 values")
    print(f"{'Boundary':<13} {'proto':>7} {'mean':>8} {'fwdmax':>10} {'sym':>10} {'cv_sq':>10}")
    print("-" * 62)
    for source_name, source_df in boundary_sources.items():
        b = compute_bounds(source_df)
        print(
            f"{source_name:<13} {b.protocol:>7} {b.pkt_len_mean:>8} "
            f"{b.fwd_max_q[0] / SCALE:>10.4f} {b.sym_ratio[0] / SCALE:>10.4f} {b.pkt_cv_sq[0] / SCALE:>10.4f}"
        )

    print("\n[4] Quick interpretation rule")
    print("- 若 CIC-only 在 CIC AUC 高但 BigFlow AUC/BigFlow benign balance 崩掉，代表 CIC boundary overfit。")
    print("- 若 Mixed 同時維持 CIC 與 BigFlow，代表目前 Mixed boundary 能緩解 boundary overfit。")


if __name__ == "__main__":
    main()
