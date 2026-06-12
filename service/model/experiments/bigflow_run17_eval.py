"""BigFlow DDoS 資料集上驗證 Run 17 N=2 分位桶方案

欄位映射（BigFlow → CIC-IDS 語義）：
  SHORTEST_FLOW_PKT          → Min Packet Length     (Shape_q 分子)
  IN_BYTES / IN_PKTS         → Fwd Packet Length Mean (Shape_q 分母)
  IN_PKTS                    → Total Fwd Packets      (Sym_q 分子)
  OUT_PKTS                   → Total Backward Packets (Sym_q 分母)
  (IN_BYTES+OUT_BYTES)/(IN_PKTS+OUT_PKTS) → Packet Length Mean
  加權桶估算 std              → Packet Length Std      (Pkt_CV_q 分子)
  PROTOCOL                   → Protocol

執行：
  uv run --project service/model python -m service.model.view.bigflow_run17_eval
"""
import glob
import sys

import numpy as np
import polars as pl
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import StandardScaler

from service.model.data.sample import get_normal_sample_from_files

TRAIN_PATHS = sorted(glob.glob("service/model/dataset/parquet_clean/train/*.parquet"))
BIGFLOW_DIR = "service/model/dataset/parquet_clean/test/BigFlow-NIDS-V2-Merged-Parquet"

SEED = 42
N_ESTIMATORS = 200
CONTAMINATION = 0.01
N_QUANTILE = 2          # Run 17 最佳結果

# 封包大小桶中點（用於估算 Packet Length Std）
PKT_BUCKET_MIDPOINTS = {
    "NUM_PKTS_UP_TO_128_BYTES":    64,
    "NUM_PKTS_128_TO_256_BYTES":  192,
    "NUM_PKTS_256_TO_512_BYTES":  384,
    "NUM_PKTS_512_TO_1024_BYTES": 768,
    "NUM_PKTS_1024_TO_1514_BYTES": 1269,
}


def add_bigflow_features(df: pl.DataFrame) -> pl.DataFrame:
    """將 BigFlow 原始欄位轉換為對應 Run 17 的 CIC-IDS 語義欄位"""
    total_pkts = pl.col("IN_PKTS") + pl.col("OUT_PKTS")
    total_bytes = pl.col("IN_BYTES") + pl.col("OUT_BYTES")
    pkt_mean = total_bytes.cast(pl.Float64) / (total_pkts.cast(pl.Float64) + 1e-6)

    # 加權桶估算 Packet Length Std
    # E[X] ≈ pkt_mean（用精確計算值）
    # E[X^2] ≈ Σ midpoint_i^2 * count_i / total_pkts
    # Std ≈ sqrt(E[X^2] - E[X]^2)
    ex2_terms = []
    for col, mid in PKT_BUCKET_MIDPOINTS.items():
        ex2_terms.append(
            (pl.col(col).cast(pl.Float64) * float(mid * mid))
        )
    ex2 = sum(ex2_terms) / (total_pkts.cast(pl.Float64) + 1e-6)
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
        numer_k, denom_k = bounds[k]
        cond = (num * denom_k) < (den * numer_k)
        result[cond] = k
    return result


def apply_quantile_buckets(df: pl.DataFrame,
                            shape_bounds, sym_bounds, cv_bounds) -> pl.DataFrame:
    shape_q = ratio_to_bucket(
        df["Min Packet Length"].to_numpy(),
        df["Fwd Packet Length Mean"].to_numpy(),
        shape_bounds,
    )
    sym_q = ratio_to_bucket(
        df["Total Fwd Packets"].to_numpy(),
        df["Total Backward Packets"].to_numpy(),
        sym_bounds,
    )
    cv_q = ratio_to_bucket(
        df["Packet Length Std"].to_numpy(),
        df["Packet Length Mean"].to_numpy(),
        cv_bounds,
    )
    return df.with_columns([
        pl.Series("Shape_q",   shape_q.astype(np.float32)),
        pl.Series("Sym_q",     sym_q.astype(np.float32)),
        pl.Series("Pkt_CV_q",  cv_q.astype(np.float32)),
    ])


def auc_validate(benign_df: pl.DataFrame, val_df: pl.DataFrame,
                 features: list[str], label_col: str = "Label") -> float | None:
    avail = [f for f in features if f in benign_df.columns and f in val_df.columns]
    if not avail:
        return None
    X_train = benign_df.select(avail).to_numpy().astype(np.float32)
    X_val   = val_df.select(avail).to_numpy().astype(np.float32)
    mask_t  = np.isfinite(X_train).all(axis=1)
    mask_v  = np.isfinite(X_val).all(axis=1)
    X_train, X_val = X_train[mask_t], X_val[mask_v]
    y_val = val_df[label_col].to_numpy()[mask_v]
    if y_val.sum() == 0 or y_val.sum() == len(y_val) or len(X_train) < 10:
        return None
    scaler = StandardScaler()
    iso = IsolationForest(n_estimators=N_ESTIMATORS, contamination=CONTAMINATION,
                          random_state=SEED, n_jobs=-1)
    iso.fit(scaler.fit_transform(X_train))
    scores = -iso.score_samples(scaler.transform(X_val))
    return float(roc_auc_score(y_val, scores))


def load_bigflow_sample(n_benign: int = 5000, n_ddos: int = 5000,
                         seed: int = SEED) -> pl.DataFrame:
    """讀取所有 part 並抽樣 Benign + DDoS"""
    parts = sorted(glob.glob(f"{BIGFLOW_DIR}/*.parquet"))
    if not parts:
        sys.exit(f"找不到 BigFlow parquet 檔案：{BIGFLOW_DIR}")

    # 先掃描每個 part，累積直到蒐集到足夠樣本
    benign_chunks, ddos_chunks = [], []
    benign_collected, ddos_collected = 0, 0

    rng = np.random.default_rng(seed)
    for path in parts:
        if benign_collected >= n_benign and ddos_collected >= n_ddos:
            break
        df = pl.read_parquet(path)
        b = df.filter(pl.col("Attack") == "Benign")
        d = df.filter(pl.col("Attack") == "DDoS")
        if len(b) > 0 and benign_collected < n_benign:
            take = min(n_benign - benign_collected, len(b))
            benign_chunks.append(b.sample(take, seed=int(rng.integers(1 << 31))))
            benign_collected += take
        if len(d) > 0 and ddos_collected < n_ddos:
            take = min(n_ddos - ddos_collected, len(d))
            ddos_chunks.append(d.sample(take, seed=int(rng.integers(1 << 31))))
            ddos_collected += take

    print(f"BigFlow 抽樣：Benign={benign_collected}，DDoS={ddos_collected}")
    benign_df = pl.concat(benign_chunks).with_columns(pl.lit(0).cast(pl.Int8).alias("is_attack"))
    ddos_df   = pl.concat(ddos_chunks).with_columns(pl.lit(1).cast(pl.Int8).alias("is_attack"))
    return pl.concat([benign_df, ddos_df])


def get_ratios(df: pl.DataFrame) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    shape = (df["Min Packet Length"].cast(pl.Float64).to_numpy() /
             (df["Fwd Packet Length Mean"].cast(pl.Float64).to_numpy() + 1e-6))
    sym   = (df["Total Fwd Packets"].cast(pl.Float64).to_numpy() /
             (df["Total Backward Packets"].cast(pl.Float64).to_numpy() + 1.0))
    cv    = (df["Packet Length Std"].cast(pl.Float64).to_numpy() /
             (df["Packet Length Mean"].cast(pl.Float64).to_numpy() + 1e-6))
    return shape, sym, cv


def eval_n(benign_src: pl.DataFrame, bigflow_feat: pl.DataFrame, N: int) -> float | None:
    """給定邊界來源 benign_src，以 N 個分位桶評估 BigFlow DDoS AUC"""
    shape_r, sym_r, cv_r = get_ratios(benign_src)
    shape_bounds = compute_quantile_boundaries(shape_r, N)
    sym_bounds   = compute_quantile_boundaries(sym_r,   N)
    cv_bounds    = compute_quantile_boundaries(cv_r,    N)

    benign_q  = apply_quantile_buckets(benign_src,   shape_bounds, sym_bounds, cv_bounds)
    bigflow_q = apply_quantile_buckets(bigflow_feat, shape_bounds, sym_bounds, cv_bounds)

    q_feats = ["Shape_q", "Sym_q", "Pkt_CV_q", "Protocol", "Packet Length Mean"]
    return auc_validate(benign_q, bigflow_q, q_feats, label_col="is_attack")


def main():
    print("=" * 65)
    print("BigFlow DDoS 驗證 — Run 17 分位桶 N 值掃描")
    print("=" * 65)

    # ── 1. 載入 CIC-IDS 2018 BENIGN
    print("\n[1] 載入 CIC-IDS 2018 訓練集 BENIGN（30000 筆）...")
    cic_benign = get_normal_sample_from_files(TRAIN_PATHS, n=30000, seed=SEED)

    # ── 2. 載入 BigFlow
    print("[2] 載入 BigFlow 資料（Benign + DDoS 各 5000 筆）...")
    bigflow_raw  = load_bigflow_sample(n_benign=5000, n_ddos=5000)
    bigflow_feat = add_bigflow_features(bigflow_raw)

    # BigFlow Benign（用於重訓邊界版本）
    bf_benign_feat = bigflow_feat.filter(pl.col("is_attack") == 0)

    # ── 3. 特徵分布概覽
    print("\n[3] 原始比率特徵中位數比較（理解 distribution shift）：")
    cic_s, cic_sym, cic_cv = get_ratios(cic_benign)
    bf_s,  bf_sym,  bf_cv  = get_ratios(bf_benign_feat)
    ddos_feat = bigflow_feat.filter(pl.col("is_attack") == 1)
    dd_s,  dd_sym,  dd_cv  = get_ratios(ddos_feat)
    print(f"  {'特徵':<12} {'CIC BENIGN':>12} {'BF Benign':>12} {'BF DDoS':>12}")
    print(f"  {'-'*50}")
    for name, a, b, c in [("Shape_Ratio", np.nanmedian(cic_s), np.nanmedian(bf_s), np.nanmedian(dd_s)),
                           ("Sym_Ratio",   np.nanmedian(cic_sym), np.nanmedian(bf_sym), np.nanmedian(dd_sym)),
                           ("Pkt_CV",      np.nanmedian(cic_cv), np.nanmedian(bf_cv), np.nanmedian(dd_cv))]:
        print(f"  {name:<12} {a:>12.4f} {b:>12.4f} {c:>12.4f}")

    # ── 4. N 值掃描
    N_values = [2, 4, 8, 16, 64, 256]
    print(f"\n[4] N 值掃描（各 N 分別評估 AUC）：")
    print(f"\n  {'N':>5}  {'邊界來源:CIC':>14}  {'邊界來源:BigFlow':>17}")
    print(f"  {'-'*42}")

    results = {}
    for N in N_values:
        auc_cic = eval_n(cic_benign,   bigflow_feat, N)
        auc_bf  = eval_n(bf_benign_feat, bigflow_feat, N)
        results[N] = (auc_cic, auc_bf)
        s_cic = f"{auc_cic:.4f}" if auc_cic is not None else "  nan "
        s_bf  = f"{auc_bf:.4f}"  if auc_bf  is not None else "  nan "
        print(f"  {N:>5}  {s_cic:>14}  {s_bf:>17}")

    # ── 5. 摘要
    print(f"\n[5] 結論：")
    best_cic_n, best_cic_auc = max(
        ((n, v[0]) for n, v in results.items() if v[0] is not None), key=lambda x: x[1])
    best_bf_n, best_bf_auc = max(
        ((n, v[1]) for n, v in results.items() if v[1] is not None), key=lambda x: x[1])
    print(f"  CIC 邊界最佳：N={best_cic_n}  AUC={best_cic_auc:.4f}")
    print(f"  BF  邊界最佳：N={best_bf_n}   AUC={best_bf_auc:.4f}")

    return results


if __name__ == "__main__":
    main()