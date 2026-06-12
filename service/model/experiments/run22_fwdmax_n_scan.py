"""Run 22 — FwdMax_ratio 替換 Shape_q，N 值掃描

背景：
  Shape_q 與 Protocol 語意高度重疊（N=2 時均在區分 TCP vs UDP），
  IF 建樹時兩個冗餘特徵共享同一分割信號，N=2 二分化放大此效果導致 AUC 虛高。
  Run 21 原始模型 AUC 顯示 FwdMax_ratio（Fwd Max / Fwd Mean）是語意最獨立、
  鑑別力最強的替代（DDoS2019 +0.03、LOIC-HTTP +0.10、HOIC +0.10）。

實驗設計：
  以 FwdMax_q 替換 Shape_q，掃描 N = {2, 4, 8, 16}，
  與 Run 17（Shape_q，同 N）比較，觀察 N 對 AUC 的影響是否因語意不重疊而改變。

執行：
  uv run --project service/model python -m service.model.experiments.run22_fwdmax_n_scan
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
N_VALUES     = [2, 4, 8, 16]

# 欄位對應（只有 Shape/Sym 有跨資料集差異）
RATIO_COLS = {
    "ddos2019": {
        "shape":   ("Min Packet Length",     "Fwd Packet Length Mean"),
        "sym":     ("Total Fwd Packets",     "Total Backward Packets"),
        "cv":      ("Packet Length Std",     "Packet Length Mean"),
        "fwdmax":  ("Fwd Packet Length Max", "Fwd Packet Length Mean"),
    },
    "ids2018": {
        "shape":   ("Packet Length Min",     "Fwd Packet Length Mean"),
        "sym":     ("Subflow Fwd Packets",   "Total Backward Packets"),
        "cv":      ("Packet Length Std",     "Packet Length Mean"),
        "fwdmax":  ("Fwd Packet Length Max", "Fwd Packet Length Mean"),
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


def add_features(df: pl.DataFrame, dataset: str, variant: str,
                 shape_b, sym_b, cv_b, fwdmax_b) -> pl.DataFrame | None:
    """variant: 'shape17' = Run17 組合（含 Shape_q），'fwdmax' = FwdMax_q 替換"""
    rc = RATIO_COLS[dataset]

    def bucket(key, bounds):
        nc, dc = rc[key]
        if nc not in df.columns or dc not in df.columns:
            return None
        return ratio_to_bucket(
            df[nc].cast(pl.Float64).to_numpy(),
            df[dc].cast(pl.Float64).to_numpy(), bounds
        )

    sym_q = bucket("sym", sym_b)
    cv_q  = bucket("cv",  cv_b)
    if sym_q is None or cv_q is None:
        return None

    cols = [
        pl.Series("Sym_q",    sym_q.astype(np.float32)),
        pl.Series("Pkt_CV_q", cv_q.astype(np.float32)),
    ]

    if variant == "shape17":
        q = bucket("shape", shape_b)
        if q is None:
            return None
        cols.append(pl.Series("Shape_q", q.astype(np.float32)))
    else:
        q = bucket("fwdmax", fwdmax_b)
        if q is None:
            return None
        cols.append(pl.Series("FwdMax_q", q.astype(np.float32)))

    return df.with_columns(cols)


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
    print("Run 22 — FwdMax_q vs Shape_q，N 值掃描（N=2/4/8/16）")
    print("=" * 70)

    # ── 1. 載入資料
    print("\n[1] 載入資料...")
    benign_raw = get_normal_sample_from_files(TRAIN_PATHS, n=30000, seed=SEED)
    val_raw    = get_balance_sample_from_files(VAL_PATHS, sample_count_per_label=5000, seed=SEED)
    d1_raw     = load_ids2018(IDS2018_D1, sample_n=5000)
    d2_raw     = load_ids2018(IDS2018_D2, sample_n=5000)

    hoic_lbl = next((l for l in d2_raw["Label"].unique().to_list() if "HOIC" in l), None)
    udp_lbl  = next((l for l in d2_raw["Label"].unique().to_list() if "UDP"  in l), None)
    d2_hoic  = d2_raw.filter(pl.col("Label").is_in(["BENIGN", hoic_lbl])) if hoic_lbl else None
    d2_udp   = d2_raw.filter(pl.col("Label").is_in(["BENIGN", udp_lbl]))  if udp_lbl  else None

    # ── 2. N 值掃描
    FEATS_SHAPE  = ["Shape_q",  "Sym_q", "Pkt_CV_q", "Protocol", "Packet Length Mean"]
    FEATS_FWDMAX = ["FwdMax_q", "Sym_q", "Pkt_CV_q", "Protocol", "Packet Length Mean"]

    print(f"\n[2] N 值掃描結果：")
    header = f"  {'組合':<22} {'N':>3}  {'DDoS2019':>10} {'LOIC-HTTP':>10} {'HOIC':>8} {'LOIC-UDP':>10}"
    print(header)
    print("  " + "-" * (len(header) - 2))

    all_results = {}
    for N in N_VALUES:
        # 計算各比率的分位桶邊界
        b = benign_raw
        shape_b  = compute_quantile_boundaries(
            b["Min Packet Length"].cast(pl.Float64).to_numpy() /
            (b["Fwd Packet Length Mean"].cast(pl.Float64).to_numpy() + 1e-6), N)
        sym_b    = compute_quantile_boundaries(
            b["Total Fwd Packets"].cast(pl.Float64).to_numpy() /
            (b["Total Backward Packets"].cast(pl.Float64).to_numpy() + 1.0), N)
        cv_b     = compute_quantile_boundaries(
            b["Packet Length Std"].cast(pl.Float64).to_numpy() /
            (b["Packet Length Mean"].cast(pl.Float64).to_numpy() + 1e-6), N)
        fwdmax_b = compute_quantile_boundaries(
            b["Fwd Packet Length Max"].cast(pl.Float64).to_numpy() /
            (b["Fwd Packet Length Mean"].cast(pl.Float64).to_numpy() + 1e-6), N)

        for variant, feats, label in [
            ("shape17", FEATS_SHAPE,  "Shape_q（Run17）"),
            ("fwdmax",  FEATS_FWDMAX, "FwdMax_q（Run22）"),
        ]:
            kw = dict(shape_b=shape_b, sym_b=sym_b, cv_b=cv_b, fwdmax_b=fwdmax_b)
            b_q   = add_features(benign_raw, "ddos2019", variant, **kw)
            val_q = add_features(val_raw,    "ddos2019", variant, **kw)
            d1_q  = add_features(d1_raw,     "ids2018",  variant, **kw)
            d2h_q = add_features(d2_hoic,    "ids2018",  variant, **kw) if d2_hoic is not None else None
            d2u_q = add_features(d2_udp,     "ids2018",  variant, **kw) if d2_udp  is not None else None

            a_d = auc_validate(b_q, val_q,  feats) if b_q is not None and val_q  is not None else None
            a_l = auc_validate(b_q, d1_q,   feats) if b_q is not None and d1_q   is not None else None
            a_h = auc_validate(b_q, d2h_q,  feats) if b_q is not None and d2h_q  is not None else None
            a_u = auc_validate(b_q, d2u_q,  feats) if b_q is not None and d2u_q  is not None else None
            all_results[(variant, N)] = (a_d, a_l, a_h, a_u)
            print(f"  {label:<22} {N:>3}  {fmt(a_d):>10} {fmt(a_l):>10} "
                  f"{fmt(a_h):>8} {fmt(a_u):>10}")

        print()

    # ── 3. Δ（FwdMax − Shape，同 N）
    print("[3] Δ（FwdMax_q − Shape_q，同 N）：")
    print(f"  {'N':>3}  {'DDoS2019':>10} {'LOIC-HTTP':>10} {'HOIC':>8} {'LOIC-UDP':>10}")
    print("  " + "-" * 50)
    for N in N_VALUES:
        s = all_results.get(("shape17", N))
        f = all_results.get(("fwdmax",  N))
        if s and f:
            def d_(i): return f"{(f[i] or 0)-(s[i] or 0):+.4f}" if s[i] and f[i] else "   N/A"
            print(f"  {N:>3}  {d_(0):>10} {d_(1):>10} {d_(2):>8} {d_(3):>10}")

    return all_results


if __name__ == "__main__":
    main()
