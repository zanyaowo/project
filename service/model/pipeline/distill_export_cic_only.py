"""
distill_export_cic_only — CIC-only variant of distill_export.

Why this exists (2026-05-23):
  The original `distill_export.py` requires Mixed BENIGN (CIC + BigFlow).
  BigFlow loading currently fails because:
    1. `features.build_features` is a stub (was returning None until 2026-05-23;
       now identity), so BigFlow→CIC schema conversion is not implemented.
    2. `pl.scan_parquet(dir)` on BigFlow merges parquet files with conflicting
       schemas (e.g. `SRC_TO_DST_SECOND_BYTES` Float64 vs Int64).

  This script bypasses those problems by training on CIC BENIGN alone,
  producing a model.json that conforms to the kernel's contract (version=1,
  feature_order, threshold_cmp, score_scale, length_unit). It is intended
  as a stop-gap for firewall runtime validation; the proper Mixed BENIGN
  model should be regenerated once BigFlow loading is fixed.
"""
import argparse
import json
import numpy as np
import polars as pl

from service.model.pipeline.distill import CANONICAL_FEATURE_ORDER, DistilledClassifier
from service.model.pipeline.trainer import get_trainer


def _bucket_indices(df: pl.DataFrame, bound: list[dict]) -> np.ndarray:
    tmp = DistilledClassifier.__new__(DistilledClassifier)
    tmp.bounds = bound
    return tmp._build_index(df)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True)
    p.add_argument("--cic-paths", nargs="+", required=True,
                   help="CIC parquet file paths (NOT directories)")
    p.add_argument("--n-samples", type=int, default=30000)
    p.add_argument("--n-estimators", type=int, default=200)
    p.add_argument("--contamination", type=float, default=0.01)
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()

    # CIC IDS 2019 column names (note: "Total Backward Packets", not "Total Bwd Packets")
    required_src = [
        "Protocol", "Packet Length Mean", "Packet Length Std",
        "Fwd Packet Length Max", "Fwd Packet Length Mean",
        "Total Fwd Packets", "Total Backward Packets",
    ]
    rename_map = {"Total Backward Packets": "Total Bwd Packets"}

    rng = np.random.default_rng(args.seed)
    chunks: list[pl.DataFrame] = []
    remaining = args.n_samples
    for path in args.cic_paths:
        if remaining <= 0:
            break
        df = pl.read_parquet(path).filter(pl.col("Label") == "BENIGN").select(required_src).rename(rename_map)
        if len(df) == 0:
            continue
        take = min(len(df), remaining)
        chunks.append(df.sample(take, seed=int(rng.integers(1 << 31))))
        remaining -= take
    if not chunks:
        raise SystemExit("No BENIGN samples loaded.")
    df_benign = pl.concat(chunks)
    print(f"BENIGN samples loaded: {len(df_benign)}")

    SCALE = 1 << 20
    p50_protocol     = float(np.median(df_benign["Protocol"].to_numpy()))
    p50_pkt_len_mean = float(np.median(df_benign["Packet Length Mean"].to_numpy()))
    p50_fwd_max_q    = df_benign.select(
        (pl.col("Fwd Packet Length Max") / (pl.col("Fwd Packet Length Mean") + 1))
        .median().alias("v")).item()
    p50_sym_ratio    = df_benign.select(
        (pl.col("Total Fwd Packets") / (pl.col("Total Bwd Packets") + 1))
        .median().alias("v")).item()
    p50_pkt_cv_sq    = df_benign.select(
        ((pl.col("Packet Length Std") / (pl.col("Packet Length Mean") + 1)) ** 2)
        .median().alias("v")).item()

    bound = [
        {"name": "protocol",     "type": "absolute", "value": int(p50_protocol)},
        {"name": "pkt_len_mean", "type": "absolute", "value": int(p50_pkt_len_mean)},
        {"name": "fwd_max_q",    "type": "ratio", "numer": int(p50_fwd_max_q * SCALE), "denom": SCALE},
        {"name": "sym_ratio",    "type": "ratio", "numer": int(p50_sym_ratio * SCALE), "denom": SCALE},
        {"name": "pkt_cv_sq",    "type": "ratio", "numer": int(p50_pkt_cv_sq * SCALE), "denom": SCALE},
    ]

    indices = _bucket_indices(df_benign, bound)
    df_bucket = pl.DataFrame(
        np.column_stack([(indices >> i) & 1 for i in range(5)]).astype(np.float32),
        schema=list(CANONICAL_FEATURE_ORDER),
    )

    trainer = get_trainer("if",
        n_estimators=args.n_estimators,
        contamination=args.contamination,
        seed=args.seed,
        feature_cols=list(CANONICAL_FEATURE_ORDER))
    trainer.fit(df_bucket)

    X_table = np.array(
        [[(idx >> i) & 1 for i in range(5)] for idx in range(32)],
        dtype=np.float32,
    )
    scores_float = -trainer._model.score_samples(trainer._scaler.transform(X_table))

    SCORE_SCALE = 10000
    score_table = [int(s * SCORE_SCALE) for s in scores_float]
    threshold = int(trainer._threshold * SCORE_SCALE)

    result = {
        "version": 1,
        "feature_order": list(CANONICAL_FEATURE_ORDER),
        "threshold_cmp": ">=",
        "score_scale": SCORE_SCALE,
        "length_unit": "packet_len",
        "threshold": threshold,
        "quantile_bounds": bound,
        "score_table": score_table,
    }
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)
    print(f"Wrote -> {args.output}  threshold={threshold}")


if __name__ == "__main__":
    main()
