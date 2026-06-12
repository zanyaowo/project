"""Run 23 — BigFlow 驗證：Shape_q vs FwdMax_q Overfitting 檢查

動機：
  Run 17/22 均以 CIC-IDS 資料（DDoS2019 + IDS2018）評估，
  兩者均在同分布上訓練並測試，無法排除對 CIC-IDS 分布 overfitting 的可能。
  BigFlow-NIDS-V2 是完全獨立的資料集（不同 sensor、不同 BENIGN 分布），
  作為 out-of-distribution 驗證，能揭示哪個特徵的泛化能力更好。

BigFlow 欄位映射：
  Shape_Ratio：SHORTEST_FLOW_PKT / (IN_BYTES/IN_PKTS)   ← 對應 Min / Fwd Mean
  FwdMax_ratio：LONGEST_FLOW_PKT  / (IN_BYTES/IN_PKTS)  ← 對應 Max / Fwd Mean（近似）
  Sym_Ratio：IN_PKTS / OUT_PKTS
  Pkt_CV：估算 Std / Mean（5 個封包大小桶加權方差）
  Protocol：PROTOCOL

執行：
  uv run --project service/model python -m service.model.experiments.run23_bigflow_overfit_check
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
N_VALUES     = [2, 4]

PKT_BUCKET_MIDPOINTS = {
    "NUM_PKTS_UP_TO_128_BYTES":    64,
    "NUM_PKTS_128_TO_256_BYTES":  192,
    "NUM_PKTS_256_TO_512_BYTES":  384,
    "NUM_PKTS_512_TO_1024_BYTES": 768,
    "NUM_PKTS_1024_TO_1514_BYTES": 1269,
}

# CIC-IDS 欄位對應
RATIO_COLS = {
    "ddos2019": {
        "shape":   ("Min Packet Length",     "Fwd Packet Length Mean"),
        "fwdmax":  ("Fwd Packet Length Max", "Fwd Packet Length Mean"),
        "sym":     ("Total Fwd Packets",     "Total Backward Packets"),
        "cv":      ("Packet Length Std",     "Packet Length Mean"),
    },
    "ids2018": {
        "shape":   ("Packet Length Min",     "Fwd Packet Length Mean"),
        "fwdmax":  ("Fwd Packet Length Max", "Fwd Packet Length Mean"),
        "sym":     ("Subflow Fwd Packets",   "Total Backward Packets"),
        "cv":      ("Packet Length Std",     "Packet Length Mean"),
    },
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


def add_cic_features(df: pl.DataFrame, dataset: str, variant: str,
                     shape_b, fwdmax_b, sym_b, cv_b) -> pl.DataFrame | None:
    rc = RATIO_COLS[dataset]

    def bucket(key, bounds):
        nc, dc = rc[key]
        if nc not in df.columns or dc not in df.columns:
            return None
        return ratio_to_bucket(
            df[nc].cast(pl.Float64).to_numpy(),
            df[dc].cast(pl.Float64).to_numpy(), bounds)

    sym_q = bucket("sym", sym_b)
    cv_q  = bucket("cv",  cv_b)
    if sym_q is None or cv_q is None:
        return None

    if variant == "shape":
        main_q = bucket("shape", shape_b)
        main_name = "Shape_q"
    else:
        main_q = bucket("fwdmax", fwdmax_b)
        main_name = "FwdMax_q"

    if main_q is None:
        return None

    return df.with_columns([
        pl.Series(main_name,  main_q.astype(np.float32)),
        pl.Series("Sym_q",    sym_q.astype(np.float32)),
        pl.Series("Pkt_CV_q", cv_q.astype(np.float32)),
    ])


def add_bigflow_features(df: pl.DataFrame, variant: str,
                         shape_b, fwdmax_b, sym_b, cv_b) -> pl.DataFrame | None:
    total_pkts  = (pl.col("IN_PKTS") + pl.col("OUT_PKTS")).cast(pl.Float64)
    total_bytes = (pl.col("IN_BYTES") + pl.col("OUT_BYTES")).cast(pl.Float64)
    fwd_mean    = pl.col("IN_BYTES").cast(pl.Float64) / (pl.col("IN_PKTS").cast(pl.Float64) + 1e-6)

    ex2 = sum(
        pl.col(c).cast(pl.Float64) * float(m * m)
        for c, m in PKT_BUCKET_MIDPOINTS.items()
    ) / (total_pkts + 1e-6)
    pkt_mean_expr = total_bytes / (total_pkts + 1e-6)
    pkt_std_expr  = (ex2 - pkt_mean_expr ** 2).clip(lower_bound=0.0).sqrt()

    feat = df.with_columns([
        pl.col("SHORTEST_FLOW_PKT").cast(pl.Float64).alias("min_pkt"),
        pl.col("LONGEST_FLOW_PKT").cast(pl.Float64).alias("max_pkt"),
        fwd_mean.alias("fwd_mean"),
        pl.col("IN_PKTS").cast(pl.Float64).alias("fwd_pkts"),
        pl.col("OUT_PKTS").cast(pl.Float64).alias("bwd_pkts"),
        pkt_std_expr.alias("pkt_std"),
        pkt_mean_expr.alias("pkt_mean"),
        pl.col("PROTOCOL").cast(pl.Float64).alias("Protocol"),
        pl.lit("BENIGN").alias("Label"),  # 佔位，auc_validate 會用 is_attack 覆蓋
    ])

    min_pkt  = feat["min_pkt"].to_numpy()
    max_pkt  = feat["max_pkt"].to_numpy()
    fwd_mean_v = feat["fwd_mean"].to_numpy()
    fwd_pkts = feat["fwd_pkts"].to_numpy()
    bwd_pkts = feat["bwd_pkts"].to_numpy()
    pkt_std  = feat["pkt_std"].to_numpy()
    pkt_mean = feat["pkt_mean"].to_numpy()

    sym_q = ratio_to_bucket(fwd_pkts, bwd_pkts, sym_b)
    cv_q  = ratio_to_bucket(pkt_std,  pkt_mean,  cv_b)

    if variant == "shape":
        main_q = ratio_to_bucket(min_pkt, fwd_mean_v, shape_b)
        main_name = "Shape_q"
    else:
        main_q = ratio_to_bucket(max_pkt, fwd_mean_v, fwdmax_b)
        main_name = "FwdMax_q"

    return feat.with_columns([
        pl.Series(main_name,  main_q.astype(np.float32)),
        pl.Series("Sym_q",    sym_q.astype(np.float32)),
        pl.Series("Pkt_CV_q", cv_q.astype(np.float32)),
        pl.col("pkt_mean").alias("Packet Length Mean"),
    ])


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
    print(f"  BigFlow 抽樣：Benign={bc}，DDoS={dc}")
    return pl.concat([bf, dd])


def auc_cic(benign_df: pl.DataFrame, val_df: pl.DataFrame,
            features: list[str]) -> float | None:
    avail = [f for f in features if f in benign_df.columns and f in val_df.columns]
    if not avail:
        return None
    X_tr = benign_df.select(avail).to_numpy().astype(np.float32)
    X_v  = val_df.select(avail).to_numpy().astype(np.float32)
    mt, mv = np.isfinite(X_tr).all(1), np.isfinite(X_v).all(1)
    X_tr, X_v = X_tr[mt], X_v[mv]
    y = (val_df["Label"] != "BENIGN").cast(pl.Int8).to_numpy()[mv]
    if y.sum() == 0 or y.sum() == len(y) or len(X_tr) < 10:
        return None
    sc  = StandardScaler()
    iso = IsolationForest(n_estimators=N_ESTIMATORS, contamination=CONTAMINATION,
                          random_state=SEED, n_jobs=-1)
    iso.fit(sc.fit_transform(X_tr))
    return float(roc_auc_score(y, -iso.score_samples(sc.transform(X_v))))


def auc_bigflow(benign_df: pl.DataFrame, bf_df: pl.DataFrame,
                features: list[str]) -> float | None:
    avail = [f for f in features if f in benign_df.columns and f in bf_df.columns]
    if not avail:
        return None
    X_tr = benign_df.select(avail).to_numpy().astype(np.float32)
    X_v  = bf_df.select(avail).to_numpy().astype(np.float32)
    mt, mv = np.isfinite(X_tr).all(1), np.isfinite(X_v).all(1)
    X_tr, X_v = X_tr[mt], X_v[mv]
    y = bf_df["is_attack"].to_numpy()[mv]
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


def fmt(v) -> str:
    return f"{v:.4f}" if v is not None else "  nan "


# ── 主實驗 ────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("Run 23 — BigFlow OOD 驗證：Shape_q vs FwdMax_q Overfitting 檢查")
    print("=" * 70)

    # ── 1. 載入資料
    print("\n[1] 載入資料...")
    benign_raw = get_normal_sample_from_files(TRAIN_PATHS, n=30000, seed=SEED)
    val_raw    = get_balance_sample_from_files(VAL_PATHS, sample_count_per_label=5000, seed=SEED)
    d1_raw     = load_ids2018(IDS2018_D1, sample_n=5000)
    d2_raw     = load_ids2018(IDS2018_D2, sample_n=5000)
    bf_raw     = load_bigflow_val(n_benign=5000, n_ddos=5000)

    hoic_lbl = next((l for l in d2_raw["Label"].unique().to_list() if "HOIC" in l), None)
    udp_lbl  = next((l for l in d2_raw["Label"].unique().to_list() if "UDP"  in l), None)
    d2_hoic  = d2_raw.filter(pl.col("Label").is_in(["BENIGN", hoic_lbl])) if hoic_lbl else None
    d2_udp   = d2_raw.filter(pl.col("Label").is_in(["BENIGN", udp_lbl]))  if udp_lbl  else None

    # ── 2. N 值掃描
    print(f"\n[2] 結果（各 N，CIC BENIGN 邊界）：")
    header = (f"  {'特徵':<14} {'N':>2}  {'DDoS2019':>10} {'LOIC-HTTP':>10}"
              f" {'HOIC':>8} {'LOIC-UDP':>10} {'BigFlow':>10}")
    print(header)
    print("  " + "-" * (len(header) - 2))

    all_results = {}
    for N in N_VALUES:
        b = benign_raw
        shape_b  = compute_quantile_boundaries(
            b["Min Packet Length"].cast(pl.Float64).to_numpy() /
            (b["Fwd Packet Length Mean"].cast(pl.Float64).to_numpy() + 1e-6), N)
        fwdmax_b = compute_quantile_boundaries(
            b["Fwd Packet Length Max"].cast(pl.Float64).to_numpy() /
            (b["Fwd Packet Length Mean"].cast(pl.Float64).to_numpy() + 1e-6), N)
        sym_b    = compute_quantile_boundaries(
            b["Total Fwd Packets"].cast(pl.Float64).to_numpy() /
            (b["Total Backward Packets"].cast(pl.Float64).to_numpy() + 1.0), N)
        cv_b     = compute_quantile_boundaries(
            b["Packet Length Std"].cast(pl.Float64).to_numpy() /
            (b["Packet Length Mean"].cast(pl.Float64).to_numpy() + 1e-6), N)

        kw = dict(shape_b=shape_b, fwdmax_b=fwdmax_b, sym_b=sym_b, cv_b=cv_b)

        for variant, main_feat, label in [
            ("shape",  "Shape_q",  "Shape_q  "),
            ("fwdmax", "FwdMax_q", "FwdMax_q "),
        ]:
            feats = [main_feat, "Sym_q", "Pkt_CV_q", "Protocol", "Packet Length Mean"]

            b_q   = add_cic_features(benign_raw, "ddos2019", variant, **kw)
            val_q = add_cic_features(val_raw,    "ddos2019", variant, **kw)
            d1_q  = add_cic_features(d1_raw,     "ids2018",  variant, **kw)
            d2h_q = add_cic_features(d2_hoic,    "ids2018",  variant, **kw) if d2_hoic is not None else None
            d2u_q = add_cic_features(d2_udp,     "ids2018",  variant, **kw) if d2_udp  is not None else None
            bf_q  = add_bigflow_features(bf_raw, variant, **kw)

            a_d = auc_cic(b_q, val_q,  feats) if b_q is not None and val_q  is not None else None
            a_l = auc_cic(b_q, d1_q,   feats) if b_q is not None and d1_q   is not None else None
            a_h = auc_cic(b_q, d2h_q,  feats) if b_q is not None and d2h_q  is not None else None
            a_u = auc_cic(b_q, d2u_q,  feats) if b_q is not None and d2u_q  is not None else None
            a_b = auc_bigflow(b_q, bf_q, feats) if b_q is not None and bf_q is not None else None

            all_results[(variant, N)] = (a_d, a_l, a_h, a_u, a_b)
            print(f"  {label:<14} {N:>2}  {fmt(a_d):>10} {fmt(a_l):>10} "
                  f"{fmt(a_h):>8} {fmt(a_u):>10} {fmt(a_b):>10}")

        print()

    # ── 3. Δ（FwdMax − Shape，同 N）
    print("[3] Δ（FwdMax_q − Shape_q，同 N）：")
    print(f"  {'N':>2}  {'DDoS2019':>10} {'LOIC-HTTP':>10} {'HOIC':>8} {'LOIC-UDP':>10} {'BigFlow':>10}")
    print("  " + "-" * 58)
    for N in N_VALUES:
        s = all_results.get(("shape",  N))
        f = all_results.get(("fwdmax", N))
        if s and f:
            def d_(i): return f"{(f[i] or 0)-(s[i] or 0):+.4f}" if s[i] and f[i] else "   N/A"
            print(f"  {N:>2}  {d_(0):>10} {d_(1):>10} {d_(2):>8} {d_(3):>10} {d_(4):>10}")

    # ── 4. CIC vs BigFlow 的 AUC 落差（overfitting 診斷）
    print(f"\n[4] CIC→BigFlow AUC 落差（大 = 對 CIC 過擬合）：")
    print(f"  {'特徵':<14} {'N':>2}  {'DDoS2019(CIC)':>15} {'BigFlow':>10} {'落差':>10}")
    print("  " + "-" * 55)
    for N in N_VALUES:
        for variant, label in [("shape", "Shape_q  "), ("fwdmax", "FwdMax_q ")]:
            r = all_results.get((variant, N))
            if r and r[0] is not None and r[4] is not None:
                drop = r[0] - r[4]
                print(f"  {label:<14} {N:>2}  {r[0]:>15.4f} {r[4]:>10.4f} {drop:>+10.4f}")

    return all_results


if __name__ == "__main__":
    main()
