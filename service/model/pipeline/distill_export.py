import json

import numpy as np
import polars as pl
import argparse

from service.model.data.sample import get_mixed_normal_sample
from service.model.data.features import build_features, BIGFLOW_READ_COLS
from service.model.pipeline.distill import CANONICAL_FEATURE_ORDER, DistilledClassifier
from service.model.pipeline.trainer import get_trainer


def _bucket_indices(df: pl.DataFrame, bound: list[dict]) -> np.ndarray:
    """各 row 的 5-bit bucket index，借用 DistilledClassifier._build_index。"""
    tmp = DistilledClassifier.__new__(DistilledClassifier)
    tmp.bounds = bound
    return tmp._build_index(df)

# bucket 特徵名稱，順序對應 kernel model contract bit 位置（bit0–bit4）
_BUCKET_FEATURE_COLS = CANONICAL_FEATURE_ORDER


def run(args: argparse.Namespace) -> None:
    REQUIRED_COLS = [
        "Protocol",
        "Packet Length Mean",
        "Packet Length Std",
        "Fwd Packet Length Max",
        "Fwd Packet Length Mean",
        "Total Fwd Packets",
        "Total Bwd Packets",
    ]

    # step 1: Mixed BENIGN（邊界計算與 IF 訓練來源）
    df_benign = get_mixed_normal_sample(
        sources=[
            {"paths": args.cic_dirs},
            {
                "paths": args.bf_dirs,
                "label_col": "Attack",
                "normal_label": "Benign",
                "read_cols": BIGFLOW_READ_COLS,
                "post_transform": build_features,
            },
        ],
        n_per_source=args.n_per_source,
        common_cols=REQUIRED_COLS,
    )

    # step 2: p50 邊界（kernel FEAT_* 順序）
    SCALE = 1 << 20

    p50_protocol     = float(np.median(df_benign["Protocol"].to_numpy()))
    p50_pkt_len_mean = float(np.median(df_benign["Packet Length Mean"].to_numpy()))
    p50_fwd_max_q    = df_benign.select(
        (pl.col("Fwd Packet Length Max") / (pl.col("Fwd Packet Length Mean") + 1))
        .median().alias("v")
    ).item()
    p50_sym_ratio    = df_benign.select(
        (pl.col("Total Fwd Packets") / (pl.col("Total Bwd Packets") + 1))
        .median().alias("v")
    ).item()
    p50_pkt_cv_sq    = df_benign.select(
        ((pl.col("Packet Length Std") / (pl.col("Packet Length Mean") + 1)) ** 2)
        .median().alias("v")
    ).item()

    bound = [
        {"name": "protocol",     "type": "absolute", "value": int(p50_protocol)},
        {"name": "pkt_len_mean", "type": "absolute", "value": int(p50_pkt_len_mean)},
        {"name": "fwd_max_q",    "type": "ratio", "numer": int(p50_fwd_max_q * SCALE),  "denom": SCALE},
        {"name": "sym_ratio",    "type": "ratio", "numer": int(p50_sym_ratio * SCALE),  "denom": SCALE},
        {"name": "pkt_cv_sq",    "type": "ratio", "numer": int(p50_pkt_cv_sq * SCALE), "denom": SCALE},
    ]

    # step 3: BENIGN → 5-bit bucket index → 5 個 0/1 特徵欄
    indices = _bucket_indices(df_benign, bound)
    df_bucket = pl.DataFrame(
        np.column_stack([(indices >> i) & 1 for i in range(5)]).astype(np.float32),
        schema=_BUCKET_FEATURE_COLS,
    )

    # step 4: 用 IsolationForestTrainer 訓練 5 個 bucket 特徵的 IF
    trainer = get_trainer(
        "if",
        n_estimators=args.n_estimators,
        contamination=args.contamination,
        seed=args.seed,
        feature_cols=_BUCKET_FEATURE_COLS,
    )
    trainer.fit(df_bucket)

    # step 5: 對 32 種 bit 組合算 IF score → score_table
    X_table = np.array(
        [[(idx >> i) & 1 for i in range(5)] for idx in range(32)],
        dtype=np.float32,
    )
    scores_float = -trainer._model.score_samples(trainer._scaler.transform(X_table))

    SCORE_SCALE = 10000
    score_table = [int(s * SCORE_SCALE) for s in scores_float]

    # step 6: threshold（trainer 在 fit() 已算好 1-contamination 分位）
    threshold = int(trainer._threshold * SCORE_SCALE)

    # step 7: 輸出 JSON
    result = {
        "version": 1,
        "feature_order": CANONICAL_FEATURE_ORDER,
        "threshold_cmp": ">=",
        "score_scale": SCORE_SCALE,
        "length_unit": "packet_len",
        "threshold": threshold,
        "quantile_bounds": bound,
        "score_table": score_table,
    }
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)
    print(f"已輸出 -> {args.output}  threshold={threshold}")

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="蒸餾規則產出（5 bucket 特徵 IF）")
    p.add_argument("--output",        required=True,       help="輸出 distilled_rules.json 路徑")
    p.add_argument("--cic-dirs",      nargs="+", required=True, help="CIC BENIGN parquet")
    p.add_argument("--bf-dirs",       nargs="+", required=True, help="BigFlow BENIGN parquet")
    p.add_argument("--n-per-source",  type=int, default=15000)
    p.add_argument("--n-estimators",  type=int, default=200)
    p.add_argument("--contamination", type=float, default=0.01)
    p.add_argument("--seed",          type=int, default=42)
    return p.parse_args()

if __name__ == "__main__":

    run(parse_args())

