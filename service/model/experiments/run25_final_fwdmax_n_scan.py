"""Run 25 — 最終方案：FwdMax_q × Mixed BENIGN × N 值掃描

確立最終 eBPF 特徵方案的完整 AUC-ROC 數字。

設定：
  特徵：FwdMax_q（Fwd Pkt Max / Fwd Pkt Mean）+ Sym_q + Pkt_CV_q + Protocol + Pkt_Mean
  訓練：CIC BENIGN 15,000 + BigFlow BENIGN 15,000 = 30,000（Mixed）
  N 值：{2, 4, 8, 16}
  驗證：DDoS2019、LOIC-HTTP、HOIC、LOIC-UDP、BigFlow DDoS

執行：
  uv run --project service/model python -m service.model.experiments.run25_final_fwdmax_n_scan
"""
import glob

import numpy as np
import polars as pl
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import StandardScaler

from service.model.data.sample import (
    get_balance_sample_from_files,
    get_normal_sample_from_files,
)

TRAIN_PATHS = sorted(glob.glob("service/model/dataset/parquet_clean/train/*.parquet"))
VAL_PATHS   = sorted(glob.glob("service/model/dataset/parquet_clean/test/*.parquet"))
IDS2018_D1  = "service/model/dataset/parquet_clean/test/IDS-2018-DDOS/DDoS1-Tuesday-20-02-2018_TrafficForML_CICFlowMeter.parquet"
IDS2018_D2  = "service/model/dataset/parquet_clean/test/IDS-2018-DDOS/DDoS2-Wednesday-21-02-2018_TrafficForML_CICFlowMeter.parquet"
BIGFLOW_DIR = "service/model/dataset/parquet_clean/test/BigFlow-NIDS-V2-Merged-Parquet"

SEED         = 42
N_ESTIMATORS = 200
CONTAMINATION = 0.01
N_TRAIN      = 15000
N_VALUES     = [2, 4, 8, 16]
FEATURES     = ["FwdMax_q", "Sym_q", "Pkt_CV_q", "Protocol", "Packet Length Mean"]

PKT_BUCKET_MIDPOINTS = {
    "NUM_PKTS_UP_TO_128_BYTES":    64,
    "NUM_PKTS_128_TO_256_BYTES":  192,
    "NUM_PKTS_256_TO_512_BYTES":  384,
    "NUM_PKTS_512_TO_1024_BYTES": 768,
    "NUM_PKTS_1024_TO_1514_BYTES": 1269,
}

RATIO_COLS_CIC = {
    "fwdmax": ("Fwd Packet Length Max", "Fwd Packet Length Mean"),
    "sym":    ("Total Fwd Packets",     "Total Backward Packets"),
    "cv":     ("Packet Length Std",     "Packet Length Mean"),
}
RATIO_COLS_IDS2018 = {
    "fwdmax": ("Fwd Packet Length Max", "Fwd Packet Length Mean"),
    "sym":    ("Subflow Fwd Packets",   "Total Backward Packets"),
    "cv":     ("Packet Length Std",     "Packet Length Mean"),
}


# ── 工具函式 ──────────────────────────────────────────────────

def compute_quantile_boundaries(values: np.ndarray, N: int) -> list[tuple[int, int]]:
    SCALE = 1 << 20
    values = values[np.isfinite(values)]
    percentiles = np.linspace(0, 100, N + 1)[1:-1]
    thresholds = np.percentile(values, percentiles)
    return [(max(0, int(t * SCALE)), SCALE) for t in thresholds]


def ratio_to_bucket(num: np.ndarray, den: np.ndarray,
                    bounds: list[tuple[int, int]]) -> np.ndarray:
    den = den.copy() + 1.0
    result = np.full(len(num), len(bounds), dtype=np.int32)
    for k in range(len(bounds) - 1, -1, -1):
        nk, dk = bounds[k]
        result[(num * dk) < (den * nk)] = k
    return result


def apply_buckets_cic(df: pl.DataFrame, col_map: dict,
                      fwdmax_b, sym_b, cv_b) -> pl.DataFrame | None:
    def bucket(key, bounds):
        nc, dc = col_map[key]
        if nc not in df.columns or dc not in df.columns:
            return None
        return ratio_to_bucket(df[nc].cast(pl.Float64).to_numpy(),
                               df[dc].cast(pl.Float64).to_numpy(), bounds)

    fq = bucket("fwdmax", fwdmax_b)
    sq = bucket("sym",    sym_b)
    cq = bucket("cv",     cv_b)
    if fq is None or sq is None or cq is None:
        return None
    return df.with_columns([
        pl.Series("FwdMax_q", fq.astype(np.float32)),
        pl.Series("Sym_q",    sq.astype(np.float32)),
        pl.Series("Pkt_CV_q", cq.astype(np.float32)),
    ])


def apply_buckets_norm(df: pl.DataFrame, fwdmax_b, sym_b, cv_b) -> pl.DataFrame | None:
    """統一欄位名的 DataFrame（Mixed BENIGN 或 BigFlow）"""
    for col in ("max_pkt", "fwd_mean", "fwd_pkts", "bwd_pkts", "pkt_std", "pkt_mean"):
        if col not in df.columns:
            return None
    fq = ratio_to_bucket(df["max_pkt"].to_numpy(), df["fwd_mean"].to_numpy(), fwdmax_b)
    sq = ratio_to_bucket(df["fwd_pkts"].to_numpy(), df["bwd_pkts"].to_numpy(), sym_b)
    cq = ratio_to_bucket(df["pkt_std"].to_numpy(), df["pkt_mean"].to_numpy(), cv_b)
    return df.with_columns([
        pl.Series("FwdMax_q", fq.astype(np.float32)),
        pl.Series("Sym_q",    sq.astype(np.float32)),
        pl.Series("Pkt_CV_q", cq.astype(np.float32)),
    ])


def auc_cic(benign_q: pl.DataFrame, val_q: pl.DataFrame) -> float | None:
    avail = [f for f in FEATURES if f in benign_q.columns and f in val_q.columns]
    if not avail:
        return None
    X_tr = benign_q.select(avail).to_numpy().astype(np.float32)
    X_v  = val_q.select(avail).to_numpy().astype(np.float32)
    mt, mv = np.isfinite(X_tr).all(1), np.isfinite(X_v).all(1)
    X_tr, X_v = X_tr[mt], X_v[mv]
    y = (val_q["Label"] != "BENIGN").cast(pl.Int8).to_numpy()[mv]
    if y.sum() == 0 or y.sum() == len(y) or len(X_tr) < 10:
        return None
    sc  = StandardScaler()
    iso = IsolationForest(n_estimators=N_ESTIMATORS, contamination=CONTAMINATION,
                          random_state=SEED, n_jobs=-1)
    iso.fit(sc.fit_transform(X_tr))
    return float(roc_auc_score(y, -iso.score_samples(sc.transform(X_v))))


def auc_bigflow(benign_q: pl.DataFrame, bf_q: pl.DataFrame) -> float | None:
    avail = [f for f in FEATURES if f in benign_q.columns and f in bf_q.columns]
    if not avail:
        return None
    X_tr = benign_q.select(avail).to_numpy().astype(np.float32)
    X_v  = bf_q.select(avail).to_numpy().astype(np.float32)
    mt, mv = np.isfinite(X_tr).all(1), np.isfinite(X_v).all(1)
    X_tr, X_v = X_tr[mt], X_v[mv]
    y = bf_q["is_attack"].to_numpy()[mv]
    if y.sum() == 0 or y.sum() == len(y) or len(X_tr) < 10:
        return None
    sc  = StandardScaler()
    iso = IsolationForest(n_estimators=N_ESTIMATORS, contamination=CONTAMINATION,
                          random_state=SEED, n_jobs=-1)
    iso.fit(sc.fit_transform(X_tr))
    return float(roc_auc_score(y, -iso.score_samples(sc.transform(X_v))))


def load_ids2018(path: str, sample_n: int = 5000) -> pl.DataFrame:
    df = pl.read_parquet(path)
    df = df.with_columns(pl.col("Label").cast(pl.String).str.to_uppercase().alias("Label"))
    chunks = [sub.sample(min(sample_n, len(sub)), seed=SEED)
              for lbl in df["Label"].unique().to_list()
              for sub in [df.filter(pl.col("Label") == lbl)] if len(sub) > 0]
    return pl.concat(chunks)


def load_bigflow_val(n_benign: int = 5000, n_ddos: int = 5000) -> pl.DataFrame:
    parts = sorted(glob.glob(f"{BIGFLOW_DIR}/*.parquet"))
    rng = np.random.default_rng(SEED)
    b_chunks, d_chunks, bc, dc = [], [], 0, 0
    for path in parts:
        if bc >= n_benign and dc >= n_ddos:
            break
        raw = pl.read_parquet(path)
        s = int(rng.integers(1 << 31))
        for chunks, col_val, collected, target in [
            (b_chunks, "Benign", bc, n_benign),
            (d_chunks, "DDoS",   dc, n_ddos),
        ]:
            sub = raw.filter(pl.col("Attack") == col_val)
            if len(sub) > 0 and collected < target:
                take = min(target - collected, len(sub))
                chunks.append(sub.sample(take, seed=s))
        bc = sum(len(c) for c in b_chunks)
        dc = sum(len(c) for c in d_chunks)
    bf = pl.concat(b_chunks).with_columns(pl.lit(0).cast(pl.Int8).alias("is_attack"))
    dd = pl.concat(d_chunks).with_columns(pl.lit(1).cast(pl.Int8).alias("is_attack"))
    return pl.concat([bf, dd])


def to_norm(df: pl.DataFrame) -> pl.DataFrame:
    """CIC DataFrame → 統一欄位名"""
    return df.with_columns([
        pl.col("Fwd Packet Length Max").cast(pl.Float64).alias("max_pkt"),
        pl.col("Fwd Packet Length Mean").cast(pl.Float64).alias("fwd_mean"),
        pl.col("Total Fwd Packets").cast(pl.Float64).alias("fwd_pkts"),
        pl.col("Total Backward Packets").cast(pl.Float64).alias("bwd_pkts"),
        pl.col("Packet Length Std").cast(pl.Float64).alias("pkt_std"),
        pl.col("Packet Length Mean").cast(pl.Float64).alias("pkt_mean"),
        pl.col("Protocol").cast(pl.Float64),
        pl.col("Packet Length Mean").cast(pl.Float64),
    ])


def bigflow_to_norm(df: pl.DataFrame) -> pl.DataFrame:
    """BigFlow DataFrame → 統一欄位名"""
    total_pkts  = pl.col("IN_PKTS").cast(pl.Float64) + pl.col("OUT_PKTS").cast(pl.Float64)
    total_bytes = pl.col("IN_BYTES").cast(pl.Float64) + pl.col("OUT_BYTES").cast(pl.Float64)
    fwd_mean    = pl.col("IN_BYTES").cast(pl.Float64) / (pl.col("IN_PKTS").cast(pl.Float64) + 1e-6)
    pkt_mean    = total_bytes / (total_pkts + 1e-6)
    ex2 = sum(pl.col(c).cast(pl.Float64) * float(m * m)
              for c, m in PKT_BUCKET_MIDPOINTS.items()) / (total_pkts + 1e-6)
    pkt_std = (ex2 - pkt_mean ** 2).clip(lower_bound=0.0).sqrt()
    return df.with_columns([
        pl.col("LONGEST_FLOW_PKT").cast(pl.Float64).alias("max_pkt"),
        fwd_mean.alias("fwd_mean"),
        pl.col("IN_PKTS").cast(pl.Float64).alias("fwd_pkts"),
        pl.col("OUT_PKTS").cast(pl.Float64).alias("bwd_pkts"),
        pkt_std.alias("pkt_std"),
        pkt_mean.alias("pkt_mean"),
        pl.col("PROTOCOL").cast(pl.Float64).alias("Protocol"),
        pkt_mean.alias("Packet Length Mean"),
    ])


def fmt(v) -> str:
    return f"{v:.4f}" if v is not None else "  nan "


# ── 主實驗 ────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("Run 25 — 最終方案：FwdMax_q × Mixed BENIGN × N 值掃描")
    print("=" * 70)
    print(f"特徵：{FEATURES}")

    # ── 1. 載入資料
    print("\n[1] 載入資料...")
    cic_benign = get_normal_sample_from_files(TRAIN_PATHS, n=N_TRAIN, seed=SEED)
    val_raw    = get_balance_sample_from_files(VAL_PATHS, sample_count_per_label=5000, seed=SEED)
    d1_raw     = load_ids2018(IDS2018_D1, sample_n=5000)
    d2_raw     = load_ids2018(IDS2018_D2, sample_n=5000)
    bf_val_raw = load_bigflow_val(n_benign=5000, n_ddos=5000)

    # BigFlow BENIGN 訓練樣本
    parts = sorted(glob.glob(f"{BIGFLOW_DIR}/*.parquet"))
    rng = np.random.default_rng(SEED)
    bf_b_chunks, count = [], 0
    for path in parts:
        if count >= N_TRAIN:
            break
        raw = pl.read_parquet(path)
        sub = raw.filter(pl.col("Attack") == "Benign")
        take = min(N_TRAIN - count, len(sub))
        if take > 0:
            bf_b_chunks.append(sub.sample(take, seed=int(rng.integers(1 << 31))))
            count += take
    bf_benign = pl.concat(bf_b_chunks)

    # 混合 BENIGN（統一欄位名）
    NORM_COLS = ["max_pkt", "fwd_mean", "fwd_pkts", "bwd_pkts",
                 "pkt_std", "pkt_mean", "Protocol", "Packet Length Mean"]
    mixed_benign = pl.concat([
        to_norm(cic_benign).select(NORM_COLS),
        bigflow_to_norm(bf_benign).select(NORM_COLS),
    ])
    print(f"  CIC BENIGN：{len(cic_benign)} 筆")
    print(f"  BigFlow BENIGN：{count} 筆")
    print(f"  Mixed BENIGN：{len(mixed_benign)} 筆")

    # IDS2018 子集
    hoic_lbl = next((l for l in d2_raw["Label"].unique().to_list() if "HOIC" in l), None)
    udp_lbl  = next((l for l in d2_raw["Label"].unique().to_list() if "UDP"  in l), None)
    d2_hoic  = d2_raw.filter(pl.col("Label").is_in(["BENIGN", hoic_lbl])) if hoic_lbl else None
    d2_udp   = d2_raw.filter(pl.col("Label").is_in(["BENIGN", udp_lbl]))  if udp_lbl  else None

    bf_val_norm = bigflow_to_norm(bf_val_raw)

    # ── 2. N 值掃描
    print(f"\n[2] AUC-ROC 結果（FwdMax_q，Mixed BENIGN 邊界）：\n")
    header = (f"  {'N':>3}  {'邊界 p50':>10}  "
              f"{'DDoS2019':>10} {'LOIC-HTTP':>10} {'HOIC':>8} {'LOIC-UDP':>10} {'BigFlow':>10}")
    print(header)
    print("  " + "─" * (len(header) - 2))

    results = {}
    for N in N_VALUES:
        # 以 Mixed BENIGN 計算邊界
        fwdmax_b = compute_quantile_boundaries(
            mixed_benign["max_pkt"].to_numpy() /
            (mixed_benign["fwd_mean"].to_numpy() + 1e-6), N)
        sym_b    = compute_quantile_boundaries(
            mixed_benign["fwd_pkts"].to_numpy() /
            (mixed_benign["bwd_pkts"].to_numpy() + 1.0), N)
        cv_b     = compute_quantile_boundaries(
            mixed_benign["pkt_std"].to_numpy() /
            (mixed_benign["pkt_mean"].to_numpy() + 1e-6), N)

        p50_fwdmax = fwdmax_b[0][0] / (1 << 20)

        bkw = dict(fwdmax_b=fwdmax_b, sym_b=sym_b, cv_b=cv_b)

        # 套用分位桶
        b_q   = apply_buckets_norm(mixed_benign, **bkw)
        val_q = apply_buckets_cic(val_raw,  RATIO_COLS_CIC,    **bkw)
        d1_q  = apply_buckets_cic(d1_raw,   RATIO_COLS_IDS2018, **bkw)
        d2h_q = apply_buckets_cic(d2_hoic,  RATIO_COLS_IDS2018, **bkw) if d2_hoic is not None else None
        d2u_q = apply_buckets_cic(d2_udp,   RATIO_COLS_IDS2018, **bkw) if d2_udp  is not None else None
        bf_q  = apply_buckets_norm(bf_val_norm, **bkw)

        a_d = auc_cic(b_q, val_q)  if b_q is not None and val_q is not None else None
        a_l = auc_cic(b_q, d1_q)   if b_q is not None and d1_q  is not None else None
        a_h = auc_cic(b_q, d2h_q)  if b_q is not None and d2h_q is not None else None
        a_u = auc_cic(b_q, d2u_q)  if b_q is not None and d2u_q is not None else None
        a_b = auc_bigflow(b_q, bf_q) if b_q is not None and bf_q is not None else None

        results[N] = (a_d, a_l, a_h, a_u, a_b)
        print(f"  {N:>3}  {p50_fwdmax:>10.4f}  "
              f"{fmt(a_d):>10} {fmt(a_l):>10} {fmt(a_h):>8} {fmt(a_u):>10} {fmt(a_b):>10}")

    # ── 3. 最佳 N 選擇建議
    print(f"\n[3] 綜合評分（各資料集 AUC 平均，以有效資料集計）：\n")
    print(f"  {'N':>3}  {'平均 AUC':>10}  {'BigFlow':>10}  {'DDoS2019':>10}  建議")
    print("  " + "─" * 55)
    for N, vals in results.items():
        valid = [v for v in vals if v is not None]
        avg = sum(valid) / len(valid) if valid else 0
        bf  = vals[4]
        d2  = vals[0]
        note = ""
        if N == 2:
            note = "← N=2 DDoS2019 最優"
        elif bf is not None and d2 is not None and bf > 0.84 and d2 > 0.84:
            note = "← 均衡"
        print(f"  {N:>3}  {avg:>10.4f}  {fmt(bf):>10}  {fmt(d2):>10}  {note}")

    # ── 4. 最終確認
    best_n = min(results, key=lambda n: -(results[n][0] or 0) - (results[n][4] or 0))
    r = results[best_n]
    print(f"\n[4] 最終方案確認（N={best_n}）：")
    print(f"  特徵：FwdMax_q + Sym_q + Pkt_CV_q + Protocol + Packet Length Mean")
    print(f"  邊界：Mixed BENIGN（CIC 15k + BigFlow 15k），N={best_n}")
    print(f"  DDoS2019  : {fmt(r[0])}")
    print(f"  LOIC-HTTP : {fmt(r[1])}")
    print(f"  HOIC      : {fmt(r[2])}")
    print(f"  LOIC-UDP  : {fmt(r[3])}")
    print(f"  BigFlow   : {fmt(r[4])}")

    return results


if __name__ == "__main__":
    main()
