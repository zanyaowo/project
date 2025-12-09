import numpy as np
import pandas as pd

NUM_COLS = [
    "duration","orig_bytes","resp_bytes","orig_ip_bytes","resp_ip_bytes",
    "orig_pkts","resp_pkts"
]

HASH_PROTO_MOD = 16
HASH_SERVICE_MOD = 128

def to_numeric(df: pd.DataFrame, cols):
    for c in cols:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)
    return df

def hash_bucket(series: pd.Series, mod: int):
    return series.fillna("").astype(str).apply(lambda x: hash(x) % mod)

def build_basic_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df = to_numeric(df, NUM_COLS)

    df["proto_h"]   = hash_bucket(df["proto"], mod=HASH_PROTO_MOD)
    df["service_h"] = hash_bucket(df["service"], mod=HASH_SERVICE_MOD)

    df["history_len"] = df["history"].fillna("").astype(str).str.len()

    df["bytes_sum"] = df["orig_bytes"] + df["resp_bytes"]
    df["pkts_sum"]  = df["orig_pkts"] + df["resp_pkts"]

    df["bytes_ratio"] = np.where(df["resp_bytes"]==0, 0, df["orig_bytes"]/df["resp_bytes"])
    df["pkts_ratio"]  = np.where(df["resp_pkts"]==0, 0, df["orig_pkts"]/df["resp_pkts"])

    df["bps_approx"]  = np.where(df["duration"]<=0, df["bytes_sum"], df["bytes_sum"]/df["duration"])

    keep_cols = ["ts","uid","src","sport","dst","dport","proto","service"] + [
        "duration","orig_bytes","resp_bytes","orig_ip_bytes","resp_ip_bytes",
        "orig_pkts","resp_pkts","history_len","bytes_sum","pkts_sum",
        "bytes_ratio","pkts_ratio","bps_approx","proto_h","service_h"
    ]
    return df[keep_cols]

FEATURE_COLS = [
    "duration","orig_bytes","resp_bytes","orig_ip_bytes","resp_ip_bytes",
    "orig_pkts","resp_pkts","history_len","bytes_sum","pkts_sum",
    "bytes_ratio","pkts_ratio","bps_approx","proto_h","service_h"
]
