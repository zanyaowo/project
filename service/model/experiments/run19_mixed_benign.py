"""Run 19 — 混合 BENIGN 訓練（CIC-IDS + BigFlow）跨資料集效果

實驗比較三種邊界來源 × 兩種評估目標：

邊界來源：
  CIC    — 只用 CIC-IDS 2018 BENIGN（Run 17 原始設定）
  BF     — 只用 BigFlow Benign
  Mixed  — CIC + BigFlow Benign 各半混合

評估目標：
  CIC 測試集  — DDoS2019, HOIC, LOIC-UDP（同環境 & IDS2018 跨環境）
  BigFlow DDoS — 跨資料集

N 值掃描：{2, 4, 8}（只跑最有代表性的三個）

執行：
  uv run --project service/model python -m service.model.experiments.run19_mixed_benign
"""
import glob
import sys

import numpy as np
import polars as pl
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import StandardScaler

from service.model.data.sample import (
    get_balance_sample_from_files,
    get_mixed_normal_sample,
    get_normal_sample_from_files,
)

# ── 路徑 ──────────────────────────────────────────────────────
TRAIN_PATHS  = sorted(glob.glob("service/model/dataset/parquet_clean/train/*.parquet"))
VAL_PATHS    = sorted(glob.glob("service/model/dataset/parquet_clean/test/*.parquet"))
IDS2018_D2   = "service/model/dataset/parquet_clean/test/IDS-2018-DDOS/DDoS2-Wednesday-21-02-2018_TrafficForML_CICFlowMeter.parquet"
BIGFLOW_DIR  = "service/model/dataset/parquet_clean/test/BigFlow-NIDS-V2-Merged-Parquet"

SEED         = 42
N_ESTIMATORS = 200
CONTAMINATION = 0.01

# Run 17 的 5 個特徵（CIC 欄位名）
RUN17_FEATURES = ["Shape_q", "Sym_q", "Pkt_CV_q", "Protocol", "Packet Length Mean"]

# BigFlow 映射後需要的 CIC 對應欄位（計算前）
MAPPED_COLS = [
    "Min Packet Length", "Fwd Packet Length Mean",
    "Total Fwd Packets", "Total Backward Packets",
    "Packet Length Mean", "Packet Length Std", "Protocol",
]

# 封包大小桶中點
PKT_BUCKET_MIDPOINTS = {
    "NUM_PKTS_UP_TO_128_BYTES":    64,
    "NUM_PKTS_128_TO_256_BYTES":  192,
    "NUM_PKTS_256_TO_512_BYTES":  384,
    "NUM_PKTS_512_TO_1024_BYTES": 768,
    "NUM_PKTS_1024_TO_1514_BYTES": 1269,
}

RATIO_COLS_DDOS2019 = {
    "Shape_Ratio": ("Min Packet Length",      "Fwd Packet Length Mean"),
    "Sym_Ratio":   ("Total Fwd Packets",      "Total Backward Packets"),
    "Pkt_CV":      ("Packet Length Std",      "Packet Length Mean"),
}
RATIO_COLS_IDS2018 = {
    "Shape_Ratio": ("Packet Length Min",      "Fwd Packet Length Mean"),
    "Sym_Ratio":   ("Subflow Fwd Packets",    "Total Backward Packets"),
    "Pkt_CV":      ("Packet Length Std",      "Packet Length Mean"),
}


# ── BigFlow 欄位映射 ──────────────────────────────────────────

def add_bigflow_features(df: pl.DataFrame) -> pl.DataFrame:
    total_pkts  = pl.col("IN_PKTS") + pl.col("OUT_PKTS")
    total_bytes = pl.col("IN_BYTES") + pl.col("OUT_BYTES")
    pkt_mean = total_bytes.cast(pl.Float64) / (total_pkts.cast(pl.Float64) + 1e-6)
    ex2 = sum(
        pl.col(c).cast(pl.Float64) * float(m * m)
        for c, m in PKT_BUCKET_MIDPOINTS.items()
    ) / (total_pkts.cast(pl.Float64) + 1e-6)
    pkt_std = (ex2 - pkt_mean ** 2).clip(lower_bound=0.0).sqrt()
    return df.with_columns([
        pl.col("SHORTEST_FLOW_PKT").cast(pl.Float64).alias("Min Packet Length"),
        (pl.col("IN_BYTES").cast(pl.Float64) / (pl.col("IN_PKTS").cast(pl.Float64) + 1e-6))
            .alias("Fwd Packet Length Mean"),
        pl.col("IN_PKTS").cast(pl.Float64).alias("Total Fwd Packets"),
        pl.col("OUT_PKTS").cast(pl.Float64).alias("Total Backward Packets"),
        pkt_mean.alias("Packet Length Mean"),
        pkt_std.alias("Packet Length Std"),
        pl.col("PROTOCOL").cast(pl.Float64).alias("Protocol"),
    ])


# ── 分位桶工具 ────────────────────────────────────────────────

def compute_boundaries(values: np.ndarray, N: int) -> list[tuple[int, int]]:
    SCALE = 1 << 20
    v = values[np.isfinite(values)]
    pts = np.linspace(0, 100, N + 1)[1:-1]
    return [(max(0, int(t * SCALE)), SCALE) for t in np.percentile(v, pts)]


def ratio_bucket(num: np.ndarray, den: np.ndarray,
                 bounds: list[tuple[int, int]]) -> np.ndarray:
    d = den.copy() + 1.0
    r = np.full(len(num), len(bounds), dtype=np.int32)
    for k in range(len(bounds) - 1, -1, -1):
        nk, dk = bounds[k]
        r[(num * dk) < (d * nk)] = k
    return r


def apply_buckets(df: pl.DataFrame, col_map: dict,
                  sb, mb, cb) -> pl.DataFrame | None:
    ns, ds = col_map["Shape_Ratio"]
    nm, dm = col_map["Sym_Ratio"]
    nc, dc = col_map["Pkt_CV"]
    if any(c not in df.columns for c in [ns, ds, nm, dm, nc, dc]):
        return None
    sq = ratio_bucket(df[ns].cast(pl.Float64).to_numpy(),
                      df[ds].cast(pl.Float64).to_numpy(), sb)
    mq = ratio_bucket(df[nm].cast(pl.Float64).to_numpy(),
                      df[dm].cast(pl.Float64).to_numpy(), mb)
    cq = ratio_bucket(df[nc].cast(pl.Float64).to_numpy(),
                      df[dc].cast(pl.Float64).to_numpy(), cb)
    return df.with_columns([
        pl.Series("Shape_q",  sq.astype(np.float32)),
        pl.Series("Sym_q",    mq.astype(np.float32)),
        pl.Series("Pkt_CV_q", cq.astype(np.float32)),
    ])


def compute_bounds_from(benign: pl.DataFrame, col_map: dict,
                        N: int) -> tuple | None:
    ns, ds = col_map["Shape_Ratio"]
    nm, dm = col_map["Sym_Ratio"]
    nc, dc = col_map["Pkt_CV"]
    if any(c not in benign.columns for c in [ns, ds, nm, dm, nc, dc]):
        return None
    sb = compute_boundaries(
        benign[ns].cast(pl.Float64).to_numpy() /
        (benign[ds].cast(pl.Float64).to_numpy() + 1e-6), N)
    mb = compute_boundaries(
        benign[nm].cast(pl.Float64).to_numpy() /
        (benign[dm].cast(pl.Float64).to_numpy() + 1.0), N)
    cb = compute_boundaries(
        benign[nc].cast(pl.Float64).to_numpy() /
        (benign[dc].cast(pl.Float64).to_numpy() + 1e-6), N)
    return sb, mb, cb


# ── IF AUC 工具 ───────────────────────────────────────────────

def auc_validate(benign_df: pl.DataFrame, val_df: pl.DataFrame,
                 features: list[str], label_col: str = "Label",
                 benign_label: str = "BENIGN") -> float | None:
    avail = [f for f in features if f in benign_df.columns and f in val_df.columns]
    if not avail:
        return None
    X_tr = benign_df.select(avail).to_numpy().astype(np.float32)
    X_v  = val_df.select(avail).to_numpy().astype(np.float32)
    mt   = np.isfinite(X_tr).all(axis=1)
    mv   = np.isfinite(X_v).all(axis=1)
    X_tr, X_v = X_tr[mt], X_v[mv]
    y = (val_df[label_col] != benign_label).cast(pl.Int8).to_numpy()[mv]
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
    if not parts:
        sys.exit(f"找不到 BigFlow：{BIGFLOW_DIR}")
    b_chunks, d_chunks, bc, dc = [], [], 0, 0
    rng = np.random.default_rng(SEED)
    for path in parts:
        if bc >= n_benign and dc >= n_ddos:
            break
        df = pl.read_parquet(path)
        s  = int(rng.integers(1 << 31))
        for chunks, col_val, collected, target in [
            (b_chunks, "Benign", bc, n_benign),
            (d_chunks, "DDoS",   dc, n_ddos),
        ]:
            sub = df.filter(pl.col("Attack") == col_val)
            if len(sub) > 0 and collected < target:
                take = min(target - collected, len(sub))
                chunks.append(sub.sample(take, seed=s))
        bc = sum(len(c) for c in b_chunks)
        dc = sum(len(c) for c in d_chunks)
    bf = (pl.concat(b_chunks)
          .with_columns(pl.lit(0).cast(pl.Int8).alias("is_attack")))
    dd = (pl.concat(d_chunks)
          .with_columns(pl.lit(1).cast(pl.Int8).alias("is_attack")))
    raw = pl.concat([bf, dd])
    feat = add_bigflow_features(raw)
    print(f"  BigFlow 抽樣：Benign={bc}，DDoS={dc}")
    return feat


def fmt(v) -> str:
    return f"{v:.4f}" if v is not None else "  nan "


# ── 主實驗 ────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("Run 19 — 混合 BENIGN 訓練比較（CIC / BF / Mixed）")
    print("=" * 70)

    # ── 1. 載入三種 BENIGN 訓練集
    print("\n[1] 載入各 BENIGN 來源...")
    cic_benign = get_normal_sample_from_files(TRAIN_PATHS, n=15000, seed=SEED)
    print(f"  CIC BENIGN：{len(cic_benign)} 筆")

    parts = sorted(glob.glob(f"{BIGFLOW_DIR}/*.parquet"))
    bf_b_chunks, count = [], 0
    for path in parts:
        if count >= 15000:
            break
        sub = pl.read_parquet(path).filter(pl.col("Attack") == "Benign")
        take = min(15000 - count, len(sub))
        if take > 0:
            bf_b_chunks.append(sub.sample(take, seed=SEED))
            count += take
    bf_benign_feat = add_bigflow_features(pl.concat(bf_b_chunks))
    print(f"  BigFlow Benign：{len(bf_benign_feat)} 筆（欄位映射後）")

    mixed_benign = get_mixed_normal_sample(
        sources=[
            {"paths": TRAIN_PATHS},
            {
                "paths": parts,
                "label_col": "Attack",
                "normal_label": "Benign",
                "post_transform": add_bigflow_features,
            },
        ],
        n_per_source=15000,
        common_cols=MAPPED_COLS,
        seed=SEED,
    )
    print(f"  Mixed BENIGN：{len(mixed_benign)} 筆（CIC + BF 對齊至 {len(MAPPED_COLS)} 欄）")

    # ── 2. 載入驗證集
    print("\n[2] 載入驗證集...")
    val_cic = get_balance_sample_from_files(VAL_PATHS, sample_count_per_label=5000, seed=SEED)
    d2_raw  = load_ids2018(IDS2018_D2, sample_n=5000)
    hoic_lbl = next((l for l in d2_raw["Label"].unique().to_list() if "HOIC" in l), None)
    udp_lbl  = next((l for l in d2_raw["Label"].unique().to_list() if "UDP"  in l), None)
    d2_hoic  = d2_raw.filter(pl.col("Label").is_in(["BENIGN", hoic_lbl])) if hoic_lbl else None
    d2_udp   = d2_raw.filter(pl.col("Label").is_in(["BENIGN", udp_lbl]))  if udp_lbl  else None

    bf_val = load_bigflow_val(n_benign=5000, n_ddos=5000)

    # ── 3. N 值掃描
    N_values = [2, 4, 8]

    benign_sources = {
        "CIC   ": (cic_benign,    RATIO_COLS_DDOS2019),
        "BF    ": (bf_benign_feat, RATIO_COLS_DDOS2019),
        "Mixed ": (mixed_benign,   RATIO_COLS_DDOS2019),
    }

    print(f"\n[3] 結果矩陣：")
    header = f"  {'來源':<10} {'N':>3}  {'DDoS2019':>10} {'HOIC':>8} {'LOIC-UDP':>10} {'BigFlow DDoS':>14}"
    print(header)
    print("  " + "-" * (len(header) - 2))

    all_results = {}
    for src_name, (benign_df, col_map) in benign_sources.items():
        for N in N_values:
            bounds = compute_bounds_from(benign_df, col_map, N)
            if bounds is None:
                print(f"  {src_name} N={N}: 欄位不足，跳過")
                continue
            sb, mb, cb = bounds

            # 套用分位桶
            b_q     = apply_buckets(benign_df, col_map,       sb, mb, cb)
            val_q   = apply_buckets(val_cic,   RATIO_COLS_DDOS2019, sb, mb, cb)
            hoic_q  = apply_buckets(d2_hoic,   RATIO_COLS_IDS2018,  sb, mb, cb) if d2_hoic is not None else None
            udp_q   = apply_buckets(d2_udp,    RATIO_COLS_IDS2018,  sb, mb, cb) if d2_udp  is not None else None
            bf_q    = apply_buckets(bf_val,    RATIO_COLS_DDOS2019, sb, mb, cb)

            # BigFlow 的 "Label" 是 is_attack (0/1)，benign=0
            def bf_auc(bq, vq):
                if bq is None or vq is None:
                    return None
                avail = [f for f in RUN17_FEATURES if f in bq.columns and f in vq.columns]
                if not avail:
                    return None
                X_tr = bq.select(avail).to_numpy().astype(np.float32)
                X_v  = vq.select(avail).to_numpy().astype(np.float32)
                mt, mv = np.isfinite(X_tr).all(1), np.isfinite(X_v).all(1)
                X_tr, X_v = X_tr[mt], X_v[mv]
                y = vq["is_attack"].to_numpy()[mv]
                if y.sum() == 0 or y.sum() == len(y):
                    return None
                sc  = StandardScaler()
                iso = IsolationForest(n_estimators=N_ESTIMATORS, contamination=CONTAMINATION,
                                      random_state=SEED, n_jobs=-1)
                iso.fit(sc.fit_transform(X_tr))
                return float(roc_auc_score(y, -iso.score_samples(sc.transform(X_v))))

            a_d2019 = auc_validate(b_q, val_q,  RUN17_FEATURES) if b_q is not None and val_q is not None else None
            a_hoic  = auc_validate(b_q, hoic_q, RUN17_FEATURES) if b_q is not None and hoic_q is not None else None
            a_udp   = auc_validate(b_q, udp_q,  RUN17_FEATURES) if b_q is not None and udp_q  is not None else None
            a_bf    = bf_auc(b_q, bf_q)

            key = (src_name.strip(), N)
            all_results[key] = (a_d2019, a_hoic, a_udp, a_bf)
            print(f"  {src_name} N={N}  {fmt(a_d2019):>10} {fmt(a_hoic):>8} "
                  f"{fmt(a_udp):>10} {fmt(a_bf):>14}")

        print()

    # ── 4. 摘要：各 N 下 Mixed vs CIC 的 Δ
    print("[4] Δ（Mixed − CIC，同 N）：")
    print(f"  {'N':>3}  {'DDoS2019':>10} {'HOIC':>8} {'LOIC-UDP':>10} {'BigFlow':>10}")
    print("  " + "-" * 50)
    for N in N_values:
        cic_r = all_results.get(("CIC", N))
        mix_r = all_results.get(("Mixed", N))
        if cic_r and mix_r:
            def d_(i): return f"{(mix_r[i] or 0)-(cic_r[i] or 0):+.4f}" if cic_r[i] and mix_r[i] else "   N/A"
            print(f"  {N:>3}  {d_(0):>10} {d_(1):>8} {d_(2):>10} {d_(3):>10}")

    return all_results


if __name__ == "__main__":
    main()