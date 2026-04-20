"""Run 21 — Shape_Ratio 替代特徵實驗（以原始模型 AUC 為主）

Shape_q 問題：Min Packet Length 因 TCP ACK 封包（payload=0）退化，
IDS2018 所有 TCP 流幾乎全落桶 0，跨資料集無鑑別力。

本實驗改用原始特徵值（不做分位桶）訓練完整 IF 模型，評估各候選特徵的
真實鑑別力，再決定哪個特徵值得進一步 eBPF 量化。

實驗矩陣（完整 IF 模型，原始特徵值）：
  A. Run 17 類比基準（Shape_Ratio + Sym_Ratio + Pkt_CV + Protocol + Pkt_Mean）
  B. PktVar 替換 Shape_Ratio（Packet Length Variance）
  C. BwdMean 替換 Shape_Ratio（Bwd Packet Length Mean）
  D. FwdMax_ratio 替換 Shape_Ratio（Fwd Max / Fwd Mean）
  E. PktVar + BwdMean 雙替換（同時替換 Shape_Ratio + Pkt_CV）

欄位處理：
  - 比率特徵（Shape_Ratio, Sym_Ratio, Pkt_CV, FwdMax_ratio）計算後以 log1p 縮放
  - BwdMean, PktVar 以 log1p 縮放
  - 兩個資料集欄位名稱差異僅在 Shape_Ratio 和 Sym_Ratio

執行：
  uv run --project service/model python -m service.model.experiments.run21_shape_alternatives
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

# 欄位名稱（僅 Shape 和 Sym 有跨資料集差異）
COLS = {
    "ddos2019": {
        "shape_num":  "Min Packet Length",
        "shape_den":  "Fwd Packet Length Mean",
        "sym_num":    "Total Fwd Packets",
        "sym_den":    "Total Backward Packets",
        "cv_num":     "Packet Length Std",
        "cv_den":     "Packet Length Mean",
        "fwdmax_num": "Fwd Packet Length Max",
        "fwdmax_den": "Fwd Packet Length Mean",
        "pktvar":     "Packet Length Variance",
        "bwdmean":    "Bwd Packet Length Mean",
        "pkt_mean":   "Packet Length Mean",
        "protocol":   "Protocol",
    },
    "ids2018": {
        "shape_num":  "Packet Length Min",
        "shape_den":  "Fwd Packet Length Mean",
        "sym_num":    "Subflow Fwd Packets",
        "sym_den":    "Total Backward Packets",
        "cv_num":     "Packet Length Std",
        "cv_den":     "Packet Length Mean",
        "fwdmax_num": "Fwd Packet Length Max",
        "fwdmax_den": "Fwd Packet Length Mean",
        "pktvar":     "Packet Length Variance",
        "bwdmean":    "Bwd Packet Length Mean",
        "pkt_mean":   "Packet Length Mean",
        "protocol":   "Protocol",
    },
}


# ── 工具函式 ──────────────────────────────────────────────────

def safe_ratio(num: np.ndarray, den: np.ndarray, add: float = 1e-6) -> np.ndarray:
    return num / (den + add)


def build_features(df: pl.DataFrame, dataset: str,
                   scheme: str) -> pl.DataFrame | None:
    """根據方案計算所有原始特徵，回傳帶有計算欄位的 DataFrame。"""
    c = COLS[dataset]
    needed_base = [c["sym_num"], c["sym_den"], c["cv_num"], c["cv_den"],
                   c["pkt_mean"], c["protocol"]]
    if any(col not in df.columns for col in needed_base):
        return None

    out = df.clone()
    sym = safe_ratio(df[c["sym_num"]].cast(pl.Float64).to_numpy(),
                     df[c["sym_den"]].cast(pl.Float64).to_numpy(), add=1.0)
    cv  = safe_ratio(df[c["cv_num"]].cast(pl.Float64).to_numpy(),
                     df[c["cv_den"]].cast(pl.Float64).to_numpy())
    out = out.with_columns([
        pl.Series("Sym_Ratio",  np.log1p(np.clip(sym, 0, None)).astype(np.float32)),
        pl.Series("Pkt_CV",     np.log1p(np.clip(cv,  0, None)).astype(np.float32)),
    ])

    if scheme == "A":
        if c["shape_num"] not in df.columns or c["shape_den"] not in df.columns:
            return None
        shape = safe_ratio(df[c["shape_num"]].cast(pl.Float64).to_numpy(),
                           df[c["shape_den"]].cast(pl.Float64).to_numpy())
        out = out.with_columns(
            pl.Series("Shape_Ratio", np.log1p(np.clip(shape, 0, None)).astype(np.float32))
        )

    if scheme in ("B", "E"):
        if c["pktvar"] not in df.columns:
            return None
        pv = df[c["pktvar"]].cast(pl.Float64).to_numpy()
        out = out.with_columns(
            pl.Series("PktVar", np.log1p(np.clip(pv, 0, None)).astype(np.float32))
        )

    if scheme in ("C", "E"):
        if c["bwdmean"] not in df.columns:
            return None
        bm = df[c["bwdmean"]].cast(pl.Float64).to_numpy()
        out = out.with_columns(
            pl.Series("BwdMean", np.log1p(np.clip(bm, 0, None)).astype(np.float32))
        )

    if scheme == "D":
        if c["fwdmax_num"] not in df.columns or c["fwdmax_den"] not in df.columns:
            return None
        fwdmax = safe_ratio(df[c["fwdmax_num"]].cast(pl.Float64).to_numpy(),
                            df[c["fwdmax_den"]].cast(pl.Float64).to_numpy())
        out = out.with_columns(
            pl.Series("FwdMax_ratio", np.log1p(np.clip(fwdmax, 0, None)).astype(np.float32))
        )

    return out


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
    print("Run 21 — Shape_Ratio 替代特徵（原始模型 AUC，無分位桶）")
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

    # ── 2. 特徵方案配置
    BASE_FEATS = ["Sym_Ratio", "Pkt_CV", "Protocol", "Packet Length Mean"]
    configs = [
        ("A  Shape_Ratio 基準",       "A", ["Shape_Ratio"]  + BASE_FEATS),
        ("B  PktVar 替換",             "B", ["PktVar"]       + BASE_FEATS),
        ("C  BwdMean 替換",            "C", ["BwdMean"]      + BASE_FEATS),
        ("D  FwdMax_ratio 替換",       "D", ["FwdMax_ratio"] + BASE_FEATS),
        ("E  PktVar+BwdMean 雙替",     "E", ["PktVar", "BwdMean", "Sym_Ratio", "Protocol", "Packet Length Mean"]),
    ]

    print(f"\n[2] 實驗結果（原始特徵，log1p 縮放）：")
    print(f"\n  {'方案':<30} {'特徵數':>5} {'DDoS2019':>10} {'LOIC-HTTP':>10} {'HOIC':>8} {'LOIC-UDP':>10}")
    print(f"  {'-'*80}")

    results = {}
    for name, scheme, feats in configs:
        b_q   = build_features(benign_raw, "ddos2019", scheme)
        val_q = build_features(val_raw,    "ddos2019", scheme)
        d1_q  = build_features(d1_raw,     "ids2018",  scheme)
        d2h_q = build_features(d2_hoic,    "ids2018",  scheme) if d2_hoic is not None else None
        d2u_q = build_features(d2_udp,     "ids2018",  scheme) if d2_udp  is not None else None

        a_d = auc_validate(b_q, val_q,  feats) if b_q is not None and val_q  is not None else None
        a_l = auc_validate(b_q, d1_q,   feats) if b_q is not None and d1_q   is not None else None
        a_h = auc_validate(b_q, d2h_q,  feats) if b_q is not None and d2h_q  is not None else None
        a_u = auc_validate(b_q, d2u_q,  feats) if b_q is not None and d2u_q  is not None else None
        results[name] = (a_d, a_l, a_h, a_u)
        print(f"  {name:<30} {len(feats):>5} {fmt(a_d):>10} {fmt(a_l):>10} "
              f"{fmt(a_h):>8} {fmt(a_u):>10}")

    # ── 3. Δ vs 基準
    base_name = "A  Shape_Ratio 基準"
    base = results[base_name]
    print(f"\n  Δ（相對 Shape_Ratio 基準）：")
    print(f"  {'方案':<30} {'DDoS2019':>10} {'LOIC-HTTP':>10} {'HOIC':>8} {'LOIC-UDP':>10}")
    print(f"  {'-'*70}")
    for name, (d, l, h, u) in results.items():
        if name == base_name:
            continue
        def d_(a, b): return f"{a-b:+.4f}" if a is not None and b is not None else "   N/A"
        print(f"  {name:<30} {d_(d,base[0]):>10} {d_(l,base[1]):>10} "
              f"{d_(h,base[2]):>8} {d_(u,base[3]):>10}")

    return results


if __name__ == "__main__":
    main()
