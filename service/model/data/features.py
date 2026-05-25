"""
特徵工程：從清洗後的 DataFrame 衍生特徵欄位。

`build_features` 是 `get_mixed_normal_sample` 的 post_transform 接口：
  - 傳入 BigFlow DataFrame → 計算 7 個 CIC 相容欄位後返回
  - 傳入 CIC DataFrame（無 IN_PKTS）→ identity，直接返回
"""
import polars as pl

# BigFlow packet-size bucket 欄位 → 中值（bytes）
_PKT_BUCKET_MIDPOINTS: dict[str, int] = {
    "NUM_PKTS_UP_TO_128_BYTES":    64,
    "NUM_PKTS_128_TO_256_BYTES":  192,
    "NUM_PKTS_256_TO_512_BYTES":  384,
    "NUM_PKTS_512_TO_1024_BYTES": 768,
    "NUM_PKTS_1024_TO_1514_BYTES": 1269,
}

_BIGFLOW_MARKER = "IN_PKTS"  # only present in BigFlow

# Columns to read from BigFlow parquet (pass as read_cols in get_mixed_normal_sample).
# Keeps memory bounded; SRC_TO_DST_SECOND_BYTES (schema conflict) is excluded.
BIGFLOW_READ_COLS = [
    "Attack",
    "IN_PKTS", "OUT_PKTS", "IN_BYTES", "OUT_BYTES",
    "PROTOCOL", "LONGEST_FLOW_PKT",
] + list(_PKT_BUCKET_MIDPOINTS.keys())


def build_features(df: pl.DataFrame) -> pl.DataFrame:
    """Map BigFlow raw columns to CIC-compatible names for distill_export.py.

    Required output columns (CIC names):
      Protocol, Packet Length Mean, Packet Length Std,
      Fwd Packet Length Max, Fwd Packet Length Mean,
      Total Fwd Packets, Total Bwd Packets
    """
    if _BIGFLOW_MARKER not in df.columns:
        return df
    return _bigflow_to_cic(df)


def _bigflow_to_cic(df: pl.DataFrame) -> pl.DataFrame:
    """Derive CIC feature columns from BigFlow counters and bucket data."""
    total_pkts  = pl.col("IN_PKTS").cast(pl.Float64) + pl.col("OUT_PKTS").cast(pl.Float64)
    total_bytes = pl.col("IN_BYTES").cast(pl.Float64) + pl.col("OUT_BYTES").cast(pl.Float64)
    fwd_mean    = pl.col("IN_BYTES").cast(pl.Float64) / (pl.col("IN_PKTS").cast(pl.Float64) + 1e-6)
    pkt_mean    = total_bytes / (total_pkts + 1e-6)

    # Estimate E[X^2] from bucket midpoints to compute Packet Length Std
    bucket_cols = [c for c in _PKT_BUCKET_MIDPOINTS if c in df.columns]
    if bucket_cols:
        ex2_terms = [
            pl.col(c).cast(pl.Float64) * float(_PKT_BUCKET_MIDPOINTS[c] ** 2)
            for c in bucket_cols
        ]
        ex2 = sum(ex2_terms) / (total_pkts + 1e-6)
        pkt_std = (ex2 - pkt_mean ** 2).clip(lower_bound=0.0).sqrt()
    else:
        # Fallback: no bucket cols — set std to 0; boundary will be unreliable
        pkt_std = pl.lit(0.0)

    return df.with_columns([
        pl.col("LONGEST_FLOW_PKT").cast(pl.Float64).alias("Fwd Packet Length Max"),
        fwd_mean.alias("Fwd Packet Length Mean"),
        pl.col("IN_PKTS").cast(pl.Float64).alias("Total Fwd Packets"),
        pl.col("OUT_PKTS").cast(pl.Float64).alias("Total Bwd Packets"),
        pkt_mean.alias("Packet Length Mean"),
        pkt_std.alias("Packet Length Std"),
        pl.col("PROTOCOL").cast(pl.Float64).alias("Protocol"),
    ])
