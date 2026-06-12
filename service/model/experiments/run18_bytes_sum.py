"""Run 18 — 加入 Bytes_Sum 特徵，驗證其對 Run 17 N=2 分位桶的增益

Bytes_Sum = Total Length of Fwd Packets + Total Length of Bwd Packets
（IDS2018 對應：Fwd Packets Length Total + Bwd Packets Length Total）

實驗矩陣（以 Run 17 N=2 為基準）：
  A. Run 17 基準（Shape_q + Sym_q + Pkt_CV_q + Protocol + Pkt_Mean）
  B. A + raw Bytes_Sum
  C. A + log1p(Bytes_Sum)
  D. A + Bytes_Sum_q（分位桶）

執行：
  uv run --project service/model python -m service.model.experiments.run18_bytes_sum
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

SEED = 42
N_ESTIMATORS = 200
CONTAMINATION = 0.01
N_QUANTILE = 2

# 欄位對應
BYTES_SUM_COLS = {
    "ddos2019": ("Total Length of Fwd Packets", "Total Length of Bwd Packets"),
    "ids2018":  ("Fwd Packets Length Total",    "Bwd Packets Length Total"),
}

RATIO_COLS_DDOS2019 = {
    "Shape_Ratio": ("Min Packet Length",        "Fwd Packet Length Mean"),
    "Sym_Ratio":   ("Total Fwd Packets",        "Total Backward Packets"),
    "Pkt_CV":      ("Packet Length Std",        "Packet Length Mean"),
}
RATIO_COLS_IDS2018 = {
    "Shape_Ratio": ("Packet Length Min",        "Fwd Packet Length Mean"),
    "Sym_Ratio":   ("Subflow Fwd Packets",      "Total Backward Packets"),
    "Pkt_CV":      ("Packet Length Std",        "Packet Length Mean"),
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
        numer_k, denom_k = bounds[k]
        cond = (num * denom_k) < (den * numer_k)
        result[cond] = k
    return result


def scalar_to_bucket(values: np.ndarray,
                     bounds: list[tuple[int, int]]) -> np.ndarray:
    """純量特徵的分位桶（不做除法）"""
    SCALE = 1 << 20
    result = np.full(len(values), len(bounds), dtype=np.int32)
    for k in range(len(bounds) - 1, -1, -1):
        numer_k, _ = bounds[k]
        threshold = numer_k / SCALE
        result[values < threshold] = k
    return result


def add_quantile_features(df: pl.DataFrame, col_map: dict,
                           shape_b, sym_b, cv_b) -> pl.DataFrame | None:
    num_s, den_s = col_map["Shape_Ratio"]
    num_m, den_m = col_map["Sym_Ratio"]
    num_c, den_c = col_map["Pkt_CV"]
    if any(c not in df.columns for c in [num_s, den_s, num_m, den_m, num_c, den_c]):
        return None
    shape_q = ratio_to_bucket(df[num_s].cast(pl.Float64).to_numpy(),
                               df[den_s].cast(pl.Float64).to_numpy(), shape_b)
    sym_q   = ratio_to_bucket(df[num_m].cast(pl.Float64).to_numpy(),
                               df[den_m].cast(pl.Float64).to_numpy(), sym_b)
    cv_q    = ratio_to_bucket(df[num_c].cast(pl.Float64).to_numpy(),
                               df[den_c].cast(pl.Float64).to_numpy(), cv_b)
    return df.with_columns([
        pl.Series("Shape_q",  shape_q.astype(np.float32)),
        pl.Series("Sym_q",    sym_q.astype(np.float32)),
        pl.Series("Pkt_CV_q", cv_q.astype(np.float32)),
    ])


def add_bytes_sum(df: pl.DataFrame, dataset: str, log1p_: bool = False) -> pl.DataFrame:
    fwd_col, bwd_col = BYTES_SUM_COLS[dataset]
    if fwd_col not in df.columns or bwd_col not in df.columns:
        return df
    bs = pl.col(fwd_col).cast(pl.Float64) + pl.col(bwd_col).cast(pl.Float64)
    if log1p_:
        bs = (bs.clip(lower_bound=0) + 1.0).log()
    return df.with_columns(bs.alias("Bytes_Sum"))


def auc_validate(benign_df: pl.DataFrame, val_df: pl.DataFrame,
                 features: list[str], label_col: str = "Label",
                 benign_label: str = "BENIGN") -> float | None:
    avail = [f for f in features if f in benign_df.columns and f in val_df.columns]
    if not avail:
        return None
    X_train = benign_df.select(avail).to_numpy().astype(np.float32)
    X_val   = val_df.select(avail).to_numpy().astype(np.float32)
    mask_t  = np.isfinite(X_train).all(axis=1)
    mask_v  = np.isfinite(X_val).all(axis=1)
    X_train, X_val = X_train[mask_t], X_val[mask_v]
    y_val = (val_df[label_col] != benign_label).cast(pl.Int8).to_numpy()[mask_v]
    if y_val.sum() == 0 or y_val.sum() == len(y_val) or len(X_train) < 10:
        return None
    scaler = StandardScaler()
    iso = IsolationForest(n_estimators=N_ESTIMATORS, contamination=CONTAMINATION,
                          random_state=SEED, n_jobs=-1)
    iso.fit(scaler.fit_transform(X_train))
    scores = -iso.score_samples(scaler.transform(X_val))
    return float(roc_auc_score(y_val, scores))


def load_ids2018(path: str, sample_n: int = 5000, seed: int = SEED) -> pl.DataFrame:
    df = pl.read_parquet(path)
    df = df.with_columns(pl.col("Label").cast(pl.String).str.to_uppercase().alias("Label"))
    chunks = []
    for lbl in df["Label"].unique().to_list():
        sub = df.filter(pl.col("Label") == lbl)
        chunks.append(sub.sample(min(sample_n, len(sub)), seed=seed))
    return pl.concat(chunks)


def fmt(v) -> str:
    return f"{v:.4f}" if v is not None else "  nan "


def main():
    print("=" * 70)
    print("Run 18 — Bytes_Sum 特徵增益驗證（基準：Run 17 N=2 分位桶）")
    print("=" * 70)

    # ── 1. 載入原始資料
    print("\n[1] 載入資料...")
    benign_raw = get_normal_sample_from_files(TRAIN_PATHS, n=30000, seed=SEED)
    val_raw    = get_balance_sample_from_files(VAL_PATHS, sample_count_per_label=5000, seed=SEED)
    d1_raw     = load_ids2018(IDS2018_D1, sample_n=5000)
    d2_raw     = load_ids2018(IDS2018_D2, sample_n=5000)

    # ── 2. 計算 Run 17 N=2 分位桶邊界（以 CIC BENIGN）
    print("[2] 計算 N=2 分位桶邊界...")
    b_shape = benign_raw["Min Packet Length"].cast(pl.Float64).to_numpy()
    b_fwdm  = benign_raw["Fwd Packet Length Mean"].cast(pl.Float64).to_numpy()
    b_fwd   = benign_raw["Total Fwd Packets"].cast(pl.Float64).to_numpy()
    b_bwd   = benign_raw["Total Backward Packets"].cast(pl.Float64).to_numpy()
    b_std   = benign_raw["Packet Length Std"].cast(pl.Float64).to_numpy()
    b_mean  = benign_raw["Packet Length Mean"].cast(pl.Float64).to_numpy()

    shape_b = compute_quantile_boundaries(b_shape / (b_fwdm + 1e-6), N_QUANTILE)
    sym_b   = compute_quantile_boundaries(b_fwd   / (b_bwd   + 1.0),  N_QUANTILE)
    cv_b    = compute_quantile_boundaries(b_std   / (b_mean  + 1e-6), N_QUANTILE)

    # Bytes_Sum 分位桶邊界（原始 & log1p 兩種）
    bs_raw = benign_raw["Total Length of Fwd Packets"].cast(pl.Float64).to_numpy() + \
             benign_raw["Total Length of Bwd Packets"].cast(pl.Float64).to_numpy()
    bs_log = np.log1p(np.clip(bs_raw, 0, None))
    bs_raw_b = compute_quantile_boundaries(bs_raw, N_QUANTILE)
    bs_log_b = compute_quantile_boundaries(bs_log, N_QUANTILE)

    # Bytes_Sum 分布診斷
    print(f"\n[3] Bytes_Sum 分布（訓練 BENIGN）：")
    val_bs_raw = (val_raw["Total Length of Fwd Packets"].cast(pl.Float64) +
                  val_raw["Total Length of Bwd Packets"].cast(pl.Float64))
    bm_raw = np.nanmedian(bs_raw)
    bm_log = np.nanmedian(bs_log)
    vm_raw = float(val_bs_raw.median())
    print(f"  BENIGN 中位數（raw）: {bm_raw:.1f}   BENIGN 中位數（log1p）: {bm_log:.4f}")
    print(f"  DDoS2019 val 整體中位數（raw）: {vm_raw:.1f}")

    # IDS2018 Bytes_Sum 診斷
    d2_bs = (d2_raw["Fwd Packets Length Total"].cast(pl.Float64) +
             d2_raw["Bwd Packets Length Total"].cast(pl.Float64))
    hoic_lbl = next((l for l in d2_raw["Label"].unique().to_list() if "HOIC" in l), None)
    udp_lbl  = next((l for l in d2_raw["Label"].unique().to_list() if "UDP"  in l), None)
    for lbl in [hoic_lbl, udp_lbl, "BENIGN"]:
        if lbl:
            med = float(d2_raw.filter(pl.col("Label") == lbl)
                        .select((pl.col("Fwd Packets Length Total").cast(pl.Float64) +
                                 pl.col("Bwd Packets Length Total").cast(pl.Float64)))
                        .to_series().median())
            print(f"  IDS2018 {lbl:<35}: Bytes_Sum 中位數 = {med:.1f}")

    # ── 4. 套用所有特徵組合
    def prep(df: pl.DataFrame, col_map: dict, bs_log1p: bool, bs_q: bool) -> pl.DataFrame | None:
        out = add_quantile_features(df, col_map, shape_b, sym_b, cv_b)
        if out is None:
            return None
        dataset = "ddos2019" if col_map is RATIO_COLS_DDOS2019 else "ids2018"
        out = add_bytes_sum(out, dataset, log1p_=bs_log1p)
        if bs_q and "Bytes_Sum" in out.columns:
            bounds = bs_log_b if bs_log1p else bs_raw_b
            bsq = scalar_to_bucket(out["Bytes_Sum"].to_numpy(), bounds)
            out = out.with_columns(pl.Series("Bytes_Sum_q", bsq.astype(np.float32)))
        return out

    base_feats = ["Shape_q", "Sym_q", "Pkt_CV_q", "Protocol", "Packet Length Mean"]

    configs = [
        ("A  Run17 基準",                  base_feats,                              False, False),
        ("B  + raw Bytes_Sum",             base_feats + ["Bytes_Sum"],              False, False),
        ("C  + log1p(Bytes_Sum)",          base_feats + ["Bytes_Sum"],              True,  False),
        ("D  + Bytes_Sum_q（N=2）",        base_feats + ["Bytes_Sum_q"],            False, True),
        ("E  + log1p(Bytes_Sum)_q（N=2）", base_feats + ["Bytes_Sum_q"],            True,  True),
    ]

    # 準備各資料集
    d2_hoic = d2_raw.filter(pl.col("Label").is_in(["BENIGN", hoic_lbl])) if hoic_lbl else None
    d2_udp  = d2_raw.filter(pl.col("Label").is_in(["BENIGN", udp_lbl]))  if udp_lbl  else None

    print(f"\n[4] 實驗結果：")
    print(f"\n  {'方案':<30} {'DDoS2019':>10} {'LOIC-HTTP':>10} {'HOIC':>8} {'LOIC-UDP':>10}")
    print(f"  {'-'*72}")

    results = {}
    for name, feats, bs_log1p, bs_q in configs:
        benign_q = prep(benign_raw, RATIO_COLS_DDOS2019, bs_log1p, bs_q)
        val_q    = prep(val_raw,    RATIO_COLS_DDOS2019, bs_log1p, bs_q)
        d1_q     = prep(d1_raw,     RATIO_COLS_IDS2018,  bs_log1p, bs_q)
        d2h_q    = prep(d2_hoic,    RATIO_COLS_IDS2018,  bs_log1p, bs_q) if d2_hoic is not None else None
        d2u_q    = prep(d2_udp,     RATIO_COLS_IDS2018,  bs_log1p, bs_q) if d2_udp  is not None else None

        auc_d2019 = auc_validate(benign_q, val_q,  feats) if benign_q is not None and val_q is not None else None
        auc_loic  = auc_validate(benign_q, d1_q,  feats) if benign_q is not None and d1_q  is not None else None
        auc_hoic  = auc_validate(benign_q, d2h_q, feats) if benign_q is not None and d2h_q is not None else None
        auc_udp   = auc_validate(benign_q, d2u_q, feats) if benign_q is not None and d2u_q is not None else None
        results[name] = (auc_d2019, auc_loic, auc_hoic, auc_udp)
        print(f"  {name:<30} {fmt(auc_d2019):>10} {fmt(auc_loic):>10} "
              f"{fmt(auc_hoic):>8} {fmt(auc_udp):>10}")

    # ── 5. Δ vs Run17 基準
    base = results["A  Run17 基準"]
    print(f"\n  Δ（相對 Run17 基準）：")
    print(f"  {'方案':<30} {'DDoS2019':>10} {'LOIC-HTTP':>10} {'HOIC':>8} {'LOIC-UDP':>10}")
    print(f"  {'-'*72}")
    for name, (d, l, h, u) in results.items():
        if name == "A  Run17 基準":
            continue
        def d_(a, b): return f"{a-b:+.4f}" if a is not None and b is not None else "   N/A"
        print(f"  {name:<30} {d_(d,base[0]):>10} {d_(l,base[1]):>10} "
              f"{d_(h,base[2]):>8} {d_(u,base[3]):>10}")

    print(f"\n[5] 結論：")
    best_name = max(results, key=lambda k: sum(v or 0 for v in results[k]))
    print(f"  綜合最佳方案：{best_name}")
    return results


if __name__ == "__main__":
    main()
