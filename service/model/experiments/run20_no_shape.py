"""Run 20 — 移除 Shape_q 特徵實驗

背景：Shape_Ratio 在 N=2 邊界 ≈ 0，實際上是 Protocol 的代理特徵（
TCP ACK 封包 payload = 0 → Min Pkt Length = 0 → 全落桶 0）。
IDS18 所有流量的 Shape_q 幾乎全為 0，對跨資料集無鑑別力。

實驗矩陣（固定 N=2，CIC BENIGN 訓練）：
  A. Run 17 基準（Shape_q + Sym_q + Pkt_CV_q + Protocol + Pkt_Mean）5 個特徵
  B. 移除 Shape_q   （Sym_q + Pkt_CV_q + Protocol + Pkt_Mean）4 個特徵
  C. 移除 Shape_q + 加回 raw Min Packet Length（驗證原始值是否補回鑑別力）

執行：
  uv run --project service/model python -m service.model.experiments.run20_no_shape
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

SEED         = 42
N_ESTIMATORS = 200
CONTAMINATION = 0.01
N_QUANTILE   = 2

RATIO_COLS_DDOS2019 = {
    "Shape_Ratio": ("Min Packet Length",   "Fwd Packet Length Mean"),
    "Sym_Ratio":   ("Total Fwd Packets",   "Total Backward Packets"),
    "Pkt_CV":      ("Packet Length Std",   "Packet Length Mean"),
}
RATIO_COLS_IDS2018 = {
    "Shape_Ratio": ("Packet Length Min",   "Fwd Packet Length Mean"),
    "Sym_Ratio":   ("Subflow Fwd Packets", "Total Backward Packets"),
    "Pkt_CV":      ("Packet Length Std",   "Packet Length Mean"),
}

MIN_PKT_COL = {
    "ddos2019": "Min Packet Length",
    "ids2018":  "Packet Length Min",
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
        result[(num * denom_k) < (den * numer_k)] = k
    return result


def add_quantile_features(df: pl.DataFrame, col_map: dict,
                           shape_b, sym_b, cv_b) -> pl.DataFrame | None:
    ns, ds = col_map["Shape_Ratio"]
    nm, dm = col_map["Sym_Ratio"]
    nc, dc = col_map["Pkt_CV"]
    if any(c not in df.columns for c in [ns, ds, nm, dm, nc, dc]):
        return None
    sq = ratio_to_bucket(df[ns].cast(pl.Float64).to_numpy(),
                         df[ds].cast(pl.Float64).to_numpy(), shape_b)
    mq = ratio_to_bucket(df[nm].cast(pl.Float64).to_numpy(),
                         df[dm].cast(pl.Float64).to_numpy(), sym_b)
    cq = ratio_to_bucket(df[nc].cast(pl.Float64).to_numpy(),
                         df[dc].cast(pl.Float64).to_numpy(), cv_b)
    return df.with_columns([
        pl.Series("Shape_q",  sq.astype(np.float32)),
        pl.Series("Sym_q",    mq.astype(np.float32)),
        pl.Series("Pkt_CV_q", cq.astype(np.float32)),
    ])


def add_min_pkt_raw(df: pl.DataFrame, dataset: str) -> pl.DataFrame:
    col = MIN_PKT_COL.get(dataset)
    if col and col in df.columns:
        return df.with_columns(
            pl.col(col).cast(pl.Float64).alias("Min_Pkt_raw")
        )
    return df


def auc_validate(benign_df: pl.DataFrame, val_df: pl.DataFrame,
                 features: list[str], label_col: str = "Label",
                 benign_label: str = "BENIGN") -> float | None:
    avail = [f for f in features if f in benign_df.columns and f in val_df.columns]
    if not avail:
        return None
    X_tr = benign_df.select(avail).to_numpy().astype(np.float32)
    X_v  = val_df.select(avail).to_numpy().astype(np.float32)
    mt, mv = np.isfinite(X_tr).all(axis=1), np.isfinite(X_v).all(axis=1)
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


def fmt(v) -> str:
    return f"{v:.4f}" if v is not None else "  nan "


# ── 主實驗 ────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("Run 20 — 移除 Shape_q 特徵（基準：Run 17 N=2）")
    print("=" * 70)

    # ── 1. 載入資料
    print("\n[1] 載入資料...")
    benign_raw = get_normal_sample_from_files(TRAIN_PATHS, n=30000, seed=SEED)
    val_raw    = get_balance_sample_from_files(VAL_PATHS, sample_count_per_label=5000, seed=SEED)
    d1_raw     = load_ids2018(IDS2018_D1, sample_n=5000)
    d2_raw     = load_ids2018(IDS2018_D2, sample_n=5000)
    print(f"  BENIGN 訓練：{len(benign_raw)} 筆")

    hoic_lbl = next((l for l in d2_raw["Label"].unique().to_list() if "HOIC" in l), None)
    udp_lbl  = next((l for l in d2_raw["Label"].unique().to_list() if "UDP"  in l), None)
    d2_hoic  = d2_raw.filter(pl.col("Label").is_in(["BENIGN", hoic_lbl])) if hoic_lbl else None
    d2_udp   = d2_raw.filter(pl.col("Label").is_in(["BENIGN", udp_lbl]))  if udp_lbl  else None

    # ── 2. 計算 N=2 分位桶邊界
    print("[2] 計算 N=2 分位桶邊界...")
    b_shape = benign_raw["Min Packet Length"].cast(pl.Float64).to_numpy()
    b_fwdm  = benign_raw["Fwd Packet Length Mean"].cast(pl.Float64).to_numpy()
    b_fwd   = benign_raw["Total Fwd Packets"].cast(pl.Float64).to_numpy()
    b_bwd   = benign_raw["Total Backward Packets"].cast(pl.Float64).to_numpy()
    b_std   = benign_raw["Packet Length Std"].cast(pl.Float64).to_numpy()
    b_mean  = benign_raw["Packet Length Mean"].cast(pl.Float64).to_numpy()

    shape_b = compute_quantile_boundaries(b_shape / (b_fwdm + 1e-6), N_QUANTILE)
    sym_b   = compute_quantile_boundaries(b_fwd   / (b_bwd  + 1.0),  N_QUANTILE)
    cv_b    = compute_quantile_boundaries(b_std   / (b_mean + 1e-6), N_QUANTILE)

    print(f"  Shape_q 邊界：{shape_b}")
    print(f"  Sym_q   邊界：{sym_b}")
    print(f"  Pkt_CV_q邊界：{cv_b}")

    # Shape_q 邊界 = 0 意味著 benign 中位數為 0（TCP ACK 問題）
    shape_boundary_zero = shape_b[0][0] == 0 if shape_b else True
    if shape_boundary_zero:
        print("  [!] Shape_q N=2 邊界 numer=0：確認退化為 Protocol 代理")

    # ── 3. 套用分位桶 + raw Min Pkt
    def prep(df: pl.DataFrame, col_map: dict, dataset: str,
             with_min_pkt: bool = False) -> pl.DataFrame | None:
        out = add_quantile_features(df, col_map, shape_b, sym_b, cv_b)
        if out is None:
            return None
        if with_min_pkt:
            out = add_min_pkt_raw(out, dataset)
        return out

    benign_q   = prep(benign_raw, RATIO_COLS_DDOS2019, "ddos2019", with_min_pkt=True)
    val_q      = prep(val_raw,    RATIO_COLS_DDOS2019, "ddos2019", with_min_pkt=True)
    d1_q       = prep(d1_raw,     RATIO_COLS_IDS2018,  "ids2018",  with_min_pkt=True)
    d2h_q      = prep(d2_hoic,    RATIO_COLS_IDS2018,  "ids2018",  with_min_pkt=True) if d2_hoic is not None else None
    d2u_q      = prep(d2_udp,     RATIO_COLS_IDS2018,  "ids2018",  with_min_pkt=True) if d2_udp  is not None else None

    # ── 4. 特徵組合比較
    BASE_FEATS    = ["Shape_q", "Sym_q", "Pkt_CV_q", "Protocol", "Packet Length Mean"]
    NO_SHAPE_FEATS = ["Sym_q", "Pkt_CV_q", "Protocol", "Packet Length Mean"]
    RAW_MIN_FEATS  = ["Sym_q", "Pkt_CV_q", "Protocol", "Packet Length Mean", "Min_Pkt_raw"]

    configs = [
        ("A  Run17 基準（含 Shape_q）",     BASE_FEATS),
        ("B  移除 Shape_q",                NO_SHAPE_FEATS),
        ("C  移除 Shape_q + raw Min Pkt",  RAW_MIN_FEATS),
    ]

    print(f"\n[3] 實驗結果（N=2）：")
    print(f"\n  {'方案':<35} {'特徵數':>5} {'DDoS2019':>10} {'LOIC-HTTP':>10} {'HOIC':>8} {'LOIC-UDP':>10}")
    print(f"  {'-'*83}")

    results = {}
    for name, feats in configs:
        a_d2019 = auc_validate(benign_q, val_q,  feats) if benign_q is not None and val_q  is not None else None
        a_loic  = auc_validate(benign_q, d1_q,   feats) if benign_q is not None and d1_q   is not None else None
        a_hoic  = auc_validate(benign_q, d2h_q,  feats) if benign_q is not None and d2h_q  is not None else None
        a_udp   = auc_validate(benign_q, d2u_q,  feats) if benign_q is not None and d2u_q  is not None else None
        results[name] = (a_d2019, a_loic, a_hoic, a_udp)
        print(f"  {name:<35} {len(feats):>5} {fmt(a_d2019):>10} {fmt(a_loic):>10} "
              f"{fmt(a_hoic):>8} {fmt(a_udp):>10}")

    # ── 5. Δ vs Run17 基準
    base_name = "A  Run17 基準（含 Shape_q）"
    base = results[base_name]
    print(f"\n  Δ（相對 Run17 基準）：")
    print(f"  {'方案':<35} {'DDoS2019':>10} {'LOIC-HTTP':>10} {'HOIC':>8} {'LOIC-UDP':>10}")
    print(f"  {'-'*75}")
    for name, (d, l, h, u) in results.items():
        if name == base_name:
            continue
        def d_(a, b): return f"{a-b:+.4f}" if a is not None and b is not None else "   N/A"
        print(f"  {name:<35} {d_(d,base[0]):>10} {d_(l,base[1]):>10} "
              f"{d_(h,base[2]):>8} {d_(u,base[3]):>10}")

    return results


if __name__ == "__main__":
    main()
