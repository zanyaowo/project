"""Run 24 — 混合 BENIGN 訓練：Shape_q vs FwdMax_q × N 值掃描

目標：
  Run 23 確認兩個特徵均對 CIC-IDS 嚴重 overfit。
  本實驗以 CIC + BigFlow 混合 BENIGN 計算分位桶邊界，
  觀察混合訓練對 Shape_q 與 FwdMax_q 的 BigFlow 泛化能力影響，
  並掃描 N = {2, 4, 8} 觀察量化粒度效果。

邊界來源比較：
  CIC   — 純 CIC-IDS BENIGN（Run 17/22/23 設定，baseline）
  Mixed — CIC + BigFlow Benign 各半混合（共用 CIC 欄位交集）

評估資料集：DDoS2019、HOIC、LOIC-UDP、BigFlow DDoS
（LOIC-HTTP 需要欄位在 BigFlow 無法對應，略過）

BigFlow 欄位映射：
  Shape_Ratio：SHORTEST_FLOW_PKT / (IN_BYTES/IN_PKTS)
  FwdMax_ratio：LONGEST_FLOW_PKT  / (IN_BYTES/IN_PKTS)
  Sym_Ratio：IN_PKTS / OUT_PKTS
  Pkt_CV：估算 Std / Mean（5 個封包大小桶）

執行：
  uv run --project service/model python -m service.model.experiments.run24_mixed_benign_shape_fwdmax
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
IDS2018_D2  = "service/model/dataset/parquet_clean/test/IDS-2018-DDOS/DDoS2-Wednesday-21-02-2018_TrafficForML_CICFlowMeter.parquet"
BIGFLOW_DIR = "service/model/dataset/parquet_clean/test/BigFlow-NIDS-V2-Merged-Parquet"

SEED         = 42
N_ESTIMATORS = 200
CONTAMINATION = 0.01
N_VALUES     = [2, 4, 8]
N_TRAIN      = 15000   # 每個來源的 BENIGN 樣本數

PKT_BUCKET_MIDPOINTS = {
    "NUM_PKTS_UP_TO_128_BYTES":    64,
    "NUM_PKTS_128_TO_256_BYTES":  192,
    "NUM_PKTS_256_TO_512_BYTES":  384,
    "NUM_PKTS_512_TO_1024_BYTES": 768,
    "NUM_PKTS_1024_TO_1514_BYTES": 1269,
}

# 只有 Sym 有跨資料集欄位差異
RATIO_COLS_CIC = {
    "shape":  ("Min Packet Length",     "Fwd Packet Length Mean"),
    "fwdmax": ("Fwd Packet Length Max", "Fwd Packet Length Mean"),
    "sym":    ("Total Fwd Packets",     "Total Backward Packets"),
    "cv":     ("Packet Length Std",     "Packet Length Mean"),
}
RATIO_COLS_IDS2018 = {
    "shape":  ("Packet Length Min",     "Fwd Packet Length Mean"),
    "fwdmax": ("Fwd Packet Length Max", "Fwd Packet Length Mean"),
    "sym":    ("Subflow Fwd Packets",   "Total Backward Packets"),
    "cv":     ("Packet Length Std",     "Packet Length Mean"),
}

# 混合訓練時共用欄位（CIC 側）
COMMON_COLS = [
    "min_pkt", "max_pkt", "fwd_mean",
    "fwd_pkts", "bwd_pkts", "pkt_std", "pkt_mean",
    "Protocol", "Packet Length Mean",
]


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


def auc_score(benign_df: pl.DataFrame, val_df: pl.DataFrame,
              features: list[str], label_col: str,
              attack_condition) -> float | None:
    avail = [f for f in features if f in benign_df.columns and f in val_df.columns]
    if not avail:
        return None
    X_tr = benign_df.select(avail).to_numpy().astype(np.float32)
    X_v  = val_df.select(avail).to_numpy().astype(np.float32)
    mt, mv = np.isfinite(X_tr).all(1), np.isfinite(X_v).all(1)
    X_tr, X_v = X_tr[mt], X_v[mv]
    y = attack_condition(val_df)[mv]
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


def to_normalized_cols(df: pl.DataFrame) -> pl.DataFrame:
    """CIC DataFrame → 統一欄位名（供混合訓練用）"""
    return df.with_columns([
        pl.col("Min Packet Length").cast(pl.Float64).alias("min_pkt"),
        pl.col("Fwd Packet Length Max").cast(pl.Float64).alias("max_pkt"),
        pl.col("Fwd Packet Length Mean").cast(pl.Float64).alias("fwd_mean"),
        pl.col("Total Fwd Packets").cast(pl.Float64).alias("fwd_pkts"),
        pl.col("Total Backward Packets").cast(pl.Float64).alias("bwd_pkts"),
        pl.col("Packet Length Std").cast(pl.Float64).alias("pkt_std"),
        pl.col("Packet Length Mean").cast(pl.Float64).alias("pkt_mean"),
        pl.col("Protocol").cast(pl.Float64),
        pl.col("Packet Length Mean").cast(pl.Float64),
    ])


def bigflow_to_normalized_cols(df: pl.DataFrame) -> pl.DataFrame:
    """BigFlow DataFrame → 統一欄位名（供混合訓練用）"""
    total_pkts  = pl.col("IN_PKTS").cast(pl.Float64) + pl.col("OUT_PKTS").cast(pl.Float64)
    total_bytes = pl.col("IN_BYTES").cast(pl.Float64) + pl.col("OUT_BYTES").cast(pl.Float64)
    fwd_mean    = pl.col("IN_BYTES").cast(pl.Float64) / (pl.col("IN_PKTS").cast(pl.Float64) + 1e-6)
    pkt_mean    = total_bytes / (total_pkts + 1e-6)
    ex2 = sum(
        pl.col(c).cast(pl.Float64) * float(m * m)
        for c, m in PKT_BUCKET_MIDPOINTS.items()
    ) / (total_pkts + 1e-6)
    pkt_std = (ex2 - pkt_mean ** 2).clip(lower_bound=0.0).sqrt()
    return df.with_columns([
        pl.col("SHORTEST_FLOW_PKT").cast(pl.Float64).alias("min_pkt"),
        pl.col("LONGEST_FLOW_PKT").cast(pl.Float64).alias("max_pkt"),
        fwd_mean.alias("fwd_mean"),
        pl.col("IN_PKTS").cast(pl.Float64).alias("fwd_pkts"),
        pl.col("OUT_PKTS").cast(pl.Float64).alias("bwd_pkts"),
        pkt_std.alias("pkt_std"),
        pkt_mean.alias("pkt_mean"),
        pl.col("PROTOCOL").cast(pl.Float64).alias("Protocol"),
        pkt_mean.alias("Packet Length Mean"),
    ])


def apply_buckets(df: pl.DataFrame, variant: str,
                  shape_b, fwdmax_b, sym_b, cv_b,
                  col_map: dict | None = None) -> pl.DataFrame | None:
    """
    col_map: {"shape": (nc, dc), "fwdmax": ..., "sym": ..., "cv": ...}
             若 None，則使用統一欄位名（min_pkt, max_pkt, fwd_mean, ...）
    """
    if col_map is not None:
        def get(key): return (df[col_map[key][0]].cast(pl.Float64).to_numpy(),
                              df[col_map[key][1]].cast(pl.Float64).to_numpy())
    else:
        def get(key):
            mapping = {
                "shape":  ("min_pkt", "fwd_mean"),
                "fwdmax": ("max_pkt", "fwd_mean"),
                "sym":    ("fwd_pkts", "bwd_pkts"),
                "cv":     ("pkt_std", "pkt_mean"),
            }
            nc, dc = mapping[key]
            if nc not in df.columns or dc not in df.columns:
                return None, None
            return df[nc].to_numpy(), df[dc].to_numpy()

    sym_pair = get("sym")
    cv_pair  = get("cv")
    if sym_pair[0] is None or cv_pair[0] is None:
        return None

    sym_q = ratio_to_bucket(sym_pair[0], sym_pair[1], sym_b)
    cv_q  = ratio_to_bucket(cv_pair[0],  cv_pair[1],  cv_b)

    if variant == "shape":
        pair = get("shape")
        main_name = "Shape_q"
        bounds = shape_b
    else:
        pair = get("fwdmax")
        main_name = "FwdMax_q"
        bounds = fwdmax_b

    if pair[0] is None:
        return None
    main_q = ratio_to_bucket(pair[0], pair[1], bounds)

    return df.with_columns([
        pl.Series(main_name,  main_q.astype(np.float32)),
        pl.Series("Sym_q",    sym_q.astype(np.float32)),
        pl.Series("Pkt_CV_q", cv_q.astype(np.float32)),
    ])


def fmt(v) -> str:
    return f"{v:.4f}" if v is not None else "  nan "


# ── 主實驗 ────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("Run 24 — 混合 BENIGN 訓練：Shape_q vs FwdMax_q × N 值掃描")
    print("=" * 70)

    # ── 1. 載入資料
    print("\n[1] 載入資料...")
    cic_benign_raw = get_normal_sample_from_files(TRAIN_PATHS, n=N_TRAIN, seed=SEED)
    val_raw        = get_balance_sample_from_files(VAL_PATHS, sample_count_per_label=5000, seed=SEED)
    d2_raw         = load_ids2018(IDS2018_D2, sample_n=5000)
    bf_raw         = load_bigflow_val(n_benign=5000, n_ddos=5000)
    print(f"  CIC BENIGN：{len(cic_benign_raw)} 筆")

    # BigFlow BENIGN 訓練樣本
    parts = sorted(glob.glob(f"{BIGFLOW_DIR}/*.parquet"))
    bf_b_chunks, count = [], 0
    rng = np.random.default_rng(SEED)
    for path in parts:
        if count >= N_TRAIN:
            break
        raw = pl.read_parquet(path)
        sub = raw.filter(pl.col("Attack") == "Benign")
        take = min(N_TRAIN - count, len(sub))
        if take > 0:
            bf_b_chunks.append(sub.sample(take, seed=int(rng.integers(1 << 31))))
            count += take
    bf_benign_raw = pl.concat(bf_b_chunks)
    print(f"  BigFlow BENIGN：{count} 筆")

    # 統一欄位名
    cic_norm = to_normalized_cols(cic_benign_raw)
    bf_norm  = bigflow_to_normalized_cols(bf_benign_raw)
    mixed_benign = pl.concat([
        cic_norm.select(COMMON_COLS),
        bf_norm.select(COMMON_COLS),
    ])
    print(f"  Mixed BENIGN：{len(mixed_benign)} 筆（CIC+BigFlow）")

    # IDS2018 標籤
    hoic_lbl = next((l for l in d2_raw["Label"].unique().to_list() if "HOIC" in l), None)
    udp_lbl  = next((l for l in d2_raw["Label"].unique().to_list() if "UDP"  in l), None)
    d2_hoic  = d2_raw.filter(pl.col("Label").is_in(["BENIGN", hoic_lbl])) if hoic_lbl else None
    d2_udp   = d2_raw.filter(pl.col("Label").is_in(["BENIGN", udp_lbl]))  if udp_lbl  else None

    # ── 2. 掃描
    sources = {
        "CIC  ": cic_norm,
        "Mixed": mixed_benign,
    }

    print(f"\n[2] 結果矩陣（邊界來源 × 特徵 × N）：")
    header = (f"  {'來源':<7} {'特徵':<10} {'N':>2}  "
              f"{'DDoS2019':>10} {'HOIC':>8} {'LOIC-UDP':>10} {'BigFlow':>10}")
    print(header)
    print("  " + "-" * (len(header) - 2))

    all_results = {}
    for src_name, benign_df in sources.items():
        use_norm = "min_pkt" in benign_df.columns  # True = 統一欄位名
        for N in N_VALUES:
            # 從 benign_df 計算邊界
            def col(name): return benign_df[name].to_numpy()

            shape_b  = compute_quantile_boundaries(
                col("min_pkt") / (col("fwd_mean") + 1e-6), N)
            fwdmax_b = compute_quantile_boundaries(
                col("max_pkt") / (col("fwd_mean") + 1e-6), N)
            sym_b    = compute_quantile_boundaries(
                col("fwd_pkts") / (col("bwd_pkts") + 1.0), N)
            cv_b     = compute_quantile_boundaries(
                col("pkt_std") / (col("pkt_mean") + 1e-6), N)

            bkw = dict(shape_b=shape_b, fwdmax_b=fwdmax_b, sym_b=sym_b, cv_b=cv_b)

            for variant, main_feat in [("shape", "Shape_q"), ("fwdmax", "FwdMax_q")]:
                feats = [main_feat, "Sym_q", "Pkt_CV_q", "Protocol", "Packet Length Mean"]

                # 訓練集（統一欄位名 or CIC 原始欄位名）
                b_q = apply_buckets(benign_df, variant, **bkw)

                # 各驗證集
                val_q  = apply_buckets(val_raw,  variant, **bkw, col_map=RATIO_COLS_CIC)
                d2h_q  = apply_buckets(d2_hoic,  variant, **bkw, col_map=RATIO_COLS_IDS2018) if d2_hoic is not None else None
                d2u_q  = apply_buckets(d2_udp,   variant, **bkw, col_map=RATIO_COLS_IDS2018) if d2_udp  is not None else None
                bf_feat = bigflow_to_normalized_cols(bf_raw)
                bf_q   = apply_buckets(bf_feat,  variant, **bkw)

                def y_cic(df): return (df["Label"] != "BENIGN").cast(pl.Int8).to_numpy()
                def y_bf(df):  return df["is_attack"].to_numpy()

                a_d = auc_score(b_q, val_q,  feats, "Label",    y_cic) if b_q is not None and val_q is not None else None
                a_h = auc_score(b_q, d2h_q,  feats, "Label",    y_cic) if b_q is not None and d2h_q is not None else None
                a_u = auc_score(b_q, d2u_q,  feats, "Label",    y_cic) if b_q is not None and d2u_q is not None else None
                a_b = auc_score(b_q, bf_q,   feats, "is_attack", y_bf) if b_q is not None and bf_q  is not None else None

                key = (src_name.strip(), variant, N)
                all_results[key] = (a_d, a_h, a_u, a_b)
                print(f"  {src_name:<7} {main_feat:<10} {N:>2}  "
                      f"{fmt(a_d):>10} {fmt(a_h):>8} {fmt(a_u):>10} {fmt(a_b):>10}")

        print()

    # ── 3. Δ（Mixed − CIC，同特徵同 N）
    print("[3] Δ（Mixed − CIC，同特徵同 N）：")
    print(f"  {'特徵':<10} {'N':>2}  {'DDoS2019':>10} {'HOIC':>8} {'LOIC-UDP':>10} {'BigFlow':>10}")
    print("  " + "-" * 56)
    for variant, label in [("shape", "Shape_q"), ("fwdmax", "FwdMax_q")]:
        for N in N_VALUES:
            c = all_results.get(("CIC", variant, N))
            m = all_results.get(("Mixed", variant, N))
            if c and m:
                def d_(i): return f"{(m[i] or 0)-(c[i] or 0):+.4f}" if c[i] and m[i] else "   N/A"
                print(f"  {label:<10} {N:>2}  {d_(0):>10} {d_(1):>8} {d_(2):>10} {d_(3):>10}")
        print()

    # ── 4. BigFlow AUC 對比（CIC vs Mixed，各特徵各 N）
    print("[4] BigFlow AUC 改善（混合訓練 vs 純 CIC）：")
    print(f"  {'特徵':<10} {'N':>2}  {'CIC BigFlow':>12} {'Mixed BigFlow':>14} {'Δ':>8}")
    print("  " + "-" * 50)
    for variant, label in [("shape", "Shape_q"), ("fwdmax", "FwdMax_q")]:
        for N in N_VALUES:
            c = all_results.get(("CIC", variant, N))
            m = all_results.get(("Mixed", variant, N))
            if c and m and c[3] is not None and m[3] is not None:
                delta = m[3] - c[3]
                print(f"  {label:<10} {N:>2}  {c[3]:>12.4f} {m[3]:>14.4f} {delta:>+8.4f}")
        print()

    return all_results


if __name__ == "__main__":
    main()
