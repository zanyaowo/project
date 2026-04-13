"""重跑 Run 14–17 — 以 Run 11（Shape+Sym+Pkt_CV）為正確基準

Run 14：Shape+Sym+Pkt_CV 在 DDoS2（HOIC/LOIC-UDP）的跨資料集驗證
Run 15：log1p 轉換效果驗證（原始 vs log1p，三資料集全面比較）
Run 16：整合特徵（絕對值 + 比例）AUC 驗證
Run 17：分位桶整數化（N=16/64/256，eBPF 可行性）

執行：
  uv run --project service/model python -m service.model.view.rerun_r14_r17
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

# ── 資料路徑 ──────────────────────────────────────────────────
TRAIN_PATHS = sorted(glob.glob("service/model/dataset/parquet_clean/train/*.parquet"))  # 03-11 訓練集
VAL_PATHS   = sorted(glob.glob("service/model/dataset/parquet_clean/test/*.parquet"))   # 01-12 測試集
IDS2018_D1  = "service/model/dataset/parquet_clean/test/IDS-2018-DDOS/DDoS1-Tuesday-20-02-2018_TrafficForML_CICFlowMeter.parquet"
IDS2018_D2  = "service/model/dataset/parquet_clean/test/IDS-2018-DDOS/DDoS2-Wednesday-21-02-2018_TrafficForML_CICFlowMeter.parquet"

SEED = 42
N_ESTIMATORS = 200
CONTAMINATION = 0.01

# ── 特徵定義 ──────────────────────────────────────────────────
# Run 11 基準：3 個比例特徵（DDoS2019 欄位名）
RATIO_COLS_DDOS2019 = {
    "Shape_Ratio": ("Min Packet Length",           "Fwd Packet Length Mean"),
    "Sym_Ratio":   ("Total Fwd Packets",            "Total Backward Packets"),
    "Pkt_CV":      ("Packet Length Std",            "Packet Length Mean"),
}
# IDS2018 欄位對應
RATIO_COLS_IDS2018 = {
    "Shape_Ratio": ("Packet Length Min",            "Fwd Packet Length Mean"),
    "Sym_Ratio":   ("Subflow Fwd Packets",          "Total Backward Packets"),
    "Pkt_CV":      ("Packet Length Std",            "Packet Length Mean"),
}

# Run 16 額外加入的絕對值特徵（跨資料集通用）
ABS_FEATURES_COMMON  = ["Protocol", "Packet Length Mean"]
ABS_FEATURES_DDOS    = ["Destination Port"]   # 僅 DDoS2019 有此欄位


# ── 特徵計算 ──────────────────────────────────────────────────

def add_ratios(df: pl.DataFrame, col_map: dict, log1p: bool = False) -> pl.DataFrame:
    exprs = []
    for name, (num_col, den_col) in col_map.items():
        if num_col not in df.columns or den_col not in df.columns:
            continue
        ratio = pl.col(num_col).cast(pl.Float64) / (pl.col(den_col).cast(pl.Float64) + 1e-6)
        if log1p:
            ratio = (ratio.clip(lower_bound=0) + 1.0).log()
        exprs.append(ratio.alias(name))
    return df.with_columns(exprs)


# ── IF AUC 工具 ───────────────────────────────────────────────

def auc_validate(
    benign_df: pl.DataFrame,
    val_df: pl.DataFrame,
    features: list[str],
    label_col: str = "Label",
    benign_label: str = "BENIGN",
) -> float | None:
    available = [f for f in features if f in benign_df.columns and f in val_df.columns]
    if not available:
        return None
    X_train = benign_df.select(available).to_numpy().astype(np.float32)
    X_val   = val_df.select(available).to_numpy().astype(np.float32)
    # 清理 NaN/Inf
    mask_t = np.isfinite(X_train).all(axis=1)
    mask_v = np.isfinite(X_val).all(axis=1)
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
    labels = df["Label"].unique().to_list()
    chunks = []
    for lbl in labels:
        sub = df.filter(pl.col("Label") == lbl)
        n = min(sample_n, len(sub))
        chunks.append(sub.sample(n, seed=seed))
    return pl.concat(chunks)


def print_sep(title: str) -> None:
    print(f"\n{'=' * 60}\n{title}\n{'=' * 60}")


# ═══════════════════════════════════════════════════════════════
# 載入並準備各資料集
# ═══════════════════════════════════════════════════════════════

def prepare_datasets(log1p: bool = False):
    benign_raw = get_normal_sample_from_files(TRAIN_PATHS, n=10000, seed=SEED)
    val_raw    = get_balance_sample_from_files(VAL_PATHS,  sample_count_per_label=3000, seed=SEED)
    d1_raw     = load_ids2018(IDS2018_D1, sample_n=5000)
    d2_raw     = load_ids2018(IDS2018_D2, sample_n=5000)

    benign = add_ratios(benign_raw, RATIO_COLS_DDOS2019, log1p=log1p)
    val    = add_ratios(val_raw,    RATIO_COLS_DDOS2019, log1p=log1p)
    d1     = add_ratios(d1_raw,     RATIO_COLS_IDS2018,  log1p=log1p)
    d2     = add_ratios(d2_raw,     RATIO_COLS_IDS2018,  log1p=log1p)
    return benign, val, d1, d2


# ═══════════════════════════════════════════════════════════════
# Run 14：DDoS2 跨資料集驗證（Shape+Sym+Pkt_CV，原始比值）
# ═══════════════════════════════════════════════════════════════

def run_14():
    print_sep("Run 14 重跑 — DDoS2 跨資料集驗證（Run11 基準：Shape+Sym+Pkt_CV）")
    benign, val_ddos2019, d1, d2 = prepare_datasets(log1p=False)

    ratio_feats = ["Shape_Ratio", "Sym_Ratio", "Pkt_CV"]

    # ── DDoS2019 整體 AUC
    auc_d2019 = auc_validate(benign, val_ddos2019, ratio_feats)
    print(f"\nDDoS2019（01-12 整體）AUC = {auc_d2019:.4f}")

    # ── DDoS2 per-label
    print(f"\n{'攻擊類型':<30} {'AUC':>8}")
    print("-" * 42)
    for lbl in sorted(d2["Label"].unique().to_list()):
        if lbl == "BENIGN":
            continue
        sub = pl.concat([
            d2.filter(pl.col("Label") == "BENIGN"),
            d2.filter(pl.col("Label") == lbl),
        ])
        auc = auc_validate(benign, sub, ratio_feats)
        auc_str = f"{auc:.4f}" if auc is not None else "nan"
        print(f"  {lbl:<28} {auc_str:>8}")

    # ── LOIC-HTTP（DDoS1）
    auc_loic = auc_validate(benign, d1, ratio_feats)
    print(f"  {'LOIC-HTTP (DDoS1)':<28} {auc_loic:.4f}")

    # ── 特徵分布中位數表
    print("\n特徵分布中位數（Train BENIGN / IDS18 BENIGN / HOIC / LOIC-UDP）：")
    for feat in ratio_feats:
        def med(df, lbl=None):
            sub = df.filter(pl.col("Label") == lbl) if lbl else df
            if feat not in sub.columns:
                return "N/A"
            v = sub[feat].drop_nulls()
            return f"{float(v.median()):.4f}" if len(v) > 0 else "N/A"
        hoic_lbl   = next((l for l in d2["Label"].unique().to_list() if "HOIC" in l), None)
        udp_lbl    = next((l for l in d2["Label"].unique().to_list() if "UDP" in l), None)
        ids_benign = d2.filter(pl.col("Label") == "BENIGN")
        ids_benign_with_feats = add_ratios(
            pl.read_parquet(IDS2018_D2).with_columns(
                pl.col("Label").cast(pl.String).str.to_uppercase().alias("Label")
            ).filter(pl.col("Label") == "BENIGN").sample(min(2000, 10000), seed=SEED),
            RATIO_COLS_IDS2018, log1p=False
        )
        b_med = f"{float(benign[feat].drop_nulls().median()):.4f}" if feat in benign.columns else "N/A"
        ids_med = f"{float(ids_benign_with_feats[feat].drop_nulls().median()):.4f}" if feat in ids_benign_with_feats.columns else "N/A"
        hoic_med = med(d2, hoic_lbl) if hoic_lbl else "N/A"
        udp_med  = med(d2, udp_lbl)  if udp_lbl  else "N/A"
        print(f"  {feat:<14} Train={b_med}  IDS18={ids_med}  HOIC={hoic_med}  LOIC-UDP={udp_med}")

    return auc_d2019


# ═══════════════════════════════════════════════════════════════
# Run 15：log1p 轉換效果驗證
# ═══════════════════════════════════════════════════════════════

def run_15():
    print_sep("Run 15 重跑 — log1p 轉換效果驗證（Shape+Sym+Pkt_CV）")
    benign_raw, val_raw, d1_raw, d2_raw = prepare_datasets(log1p=False)
    benign_log, val_log, d1_log, d2_log = prepare_datasets(log1p=True)

    ratio_feats = ["Shape_Ratio", "Sym_Ratio", "Pkt_CV"]

    datasets = [
        ("DDoS2019（01-12 整體）",  val_raw,    val_log,    RATIO_COLS_DDOS2019),
        ("LOIC-HTTP（DDoS1）",      d1_raw,     d1_log,     RATIO_COLS_IDS2018),
        ("HOIC（DDoS2）",           None,       None,       RATIO_COLS_IDS2018),
        ("LOIC-UDP（DDoS2）",       None,       None,       RATIO_COLS_IDS2018),
    ]

    # per-label DDoS2
    hoic_lbl = next((l for l in d2_raw["Label"].unique().to_list() if "HOIC" in l), None)
    udp_lbl  = next((l for l in d2_raw["Label"].unique().to_list() if "UDP"  in l), None)
    if hoic_lbl:
        d2_hoic_raw = pl.concat([d2_raw.filter(pl.col("Label") == "BENIGN"),
                                  d2_raw.filter(pl.col("Label") == hoic_lbl)])
        d2_hoic_log = pl.concat([d2_log.filter(pl.col("Label") == "BENIGN"),
                                  d2_log.filter(pl.col("Label") == hoic_lbl)])
        datasets[2] = ("HOIC（DDoS2）", d2_hoic_raw, d2_hoic_log, RATIO_COLS_IDS2018)
    if udp_lbl:
        d2_udp_raw  = pl.concat([d2_raw.filter(pl.col("Label") == "BENIGN"),
                                  d2_raw.filter(pl.col("Label") == udp_lbl)])
        d2_udp_log  = pl.concat([d2_log.filter(pl.col("Label") == "BENIGN"),
                                  d2_log.filter(pl.col("Label") == udp_lbl)])
        datasets[3] = ("LOIC-UDP（DDoS2）", d2_udp_raw, d2_udp_log, RATIO_COLS_IDS2018)

    print(f"\n{'資料集 / 攻擊類型':<25} {'原始':>8} {'log1p':>8} {'差異':>8}")
    print("-" * 55)
    results = {}
    for name, val_r, val_l, col_map in datasets:
        if val_r is None:
            continue
        benign_r = benign_raw if col_map == RATIO_COLS_DDOS2019 else \
                   add_ratios(get_normal_sample_from_files(TRAIN_PATHS, n=10000, seed=SEED),
                              RATIO_COLS_IDS2018, log1p=False)
        benign_l = benign_log if col_map == RATIO_COLS_DDOS2019 else \
                   add_ratios(get_normal_sample_from_files(TRAIN_PATHS, n=10000, seed=SEED),
                              RATIO_COLS_IDS2018, log1p=True)
        auc_r = auc_validate(benign_r, val_r, ratio_feats)
        auc_l = auc_validate(benign_l, val_l, ratio_feats)
        diff = (auc_l - auc_r) if (auc_r and auc_l) else None
        r_s = f"{auc_r:.4f}" if auc_r else "nan"
        l_s = f"{auc_l:.4f}" if auc_l else "nan"
        d_s = f"{diff:+.4f}" if diff else "—"
        print(f"  {name:<23} {r_s:>8} {l_s:>8} {d_s:>8}")
        results[name] = (auc_r, auc_l)
    return results


# ═══════════════════════════════════════════════════════════════
# Run 16：整合特徵（絕對值 + 比例）
# ═══════════════════════════════════════════════════════════════

def run_16():
    print_sep("Run 16 重跑 — 整合特徵（Protocol + Pkt_Mean + Shape+Sym+Pkt_CV，log1p）")

    benign_raw = get_normal_sample_from_files(TRAIN_PATHS, n=10000, seed=SEED)
    val_raw    = get_balance_sample_from_files(VAL_PATHS, sample_count_per_label=3000, seed=SEED)
    d1_raw     = load_ids2018(IDS2018_D1, sample_n=5000)
    d2_raw     = load_ids2018(IDS2018_D2, sample_n=5000)

    def prep(df, col_map, log1p):
        return add_ratios(df, col_map, log1p=log1p)

    ratio_feats = ["Shape_Ratio", "Sym_Ratio", "Pkt_CV"]
    abs_common  = ["Protocol", "Packet Length Mean"]
    # Destination Port 在 IDS2018 中對應欄位不同，不列入跨資料集共用特徵
    feat_5 = ratio_feats + abs_common           # 5 個（跨資料集通用）

    print(f"\n{'資料集 / 攻擊類型':<25} {'原始 5個':>10} {'log1p 5個':>10}")
    print("-" * 50)

    configs = [
        ("DDoS2019（整體）",   val_raw,  RATIO_COLS_DDOS2019),
        ("LOIC-HTTP（DDoS1）", d1_raw,   RATIO_COLS_IDS2018),
    ]
    hoic_lbl = next((l for l in d2_raw["Label"].unique().to_list() if "HOIC" in l), None)
    udp_lbl  = next((l for l in d2_raw["Label"].unique().to_list() if "UDP" in l), None)
    if hoic_lbl:
        configs.append(("HOIC（DDoS2）",
                         pl.concat([d2_raw.filter(pl.col("Label") == "BENIGN"),
                                    d2_raw.filter(pl.col("Label") == hoic_lbl)]),
                         RATIO_COLS_IDS2018))
    if udp_lbl:
        configs.append(("LOIC-UDP（DDoS2）",
                         pl.concat([d2_raw.filter(pl.col("Label") == "BENIGN"),
                                    d2_raw.filter(pl.col("Label") == udp_lbl)]),
                         RATIO_COLS_IDS2018))

    results = {}
    for name, val_df, col_map in configs:
        is_ids = (col_map == RATIO_COLS_IDS2018)
        benign_r = prep(benign_raw, col_map, log1p=False)
        benign_l = prep(benign_raw, col_map, log1p=True)
        val_r    = prep(val_df,    col_map, log1p=False)
        val_l    = prep(val_df,    col_map, log1p=True)

        auc_r = auc_validate(benign_r, val_r, feat_5)
        auc_l = auc_validate(benign_l, val_l, feat_5)
        r_s = f"{auc_r:.4f}" if auc_r else "nan"
        l_s = f"{auc_l:.4f}" if auc_l else "nan"
        print(f"  {name:<23} {r_s:>10} {l_s:>10}")
        results[name] = (auc_r, auc_l)

    return results


# ═══════════════════════════════════════════════════════════════
# Run 17：分位桶整數化（Shape+Sym+Pkt_CV，N=16/64/256）
# ═══════════════════════════════════════════════════════════════

def compute_quantile_boundaries(values: np.ndarray, N: int) -> list[tuple[int, int]]:
    SCALE = 1 << 20
    values = values[np.isfinite(values)]
    percentiles = np.linspace(0, 100, N + 1)[1:-1]
    thresholds = np.percentile(values, percentiles)
    return [(max(0, int(t * SCALE)), SCALE) for t in thresholds]


def ratio_to_bucket(num: np.ndarray, den: np.ndarray,
                    bounds: list[tuple[int, int]]) -> np.ndarray:
    """a/b < numer_k/denom_k  ↔  a * denom_k < b * numer_k (交叉乘法)"""
    den = den + 1   # avoid divide-by-zero
    result = np.full(len(num), len(bounds), dtype=np.int32)
    for k in range(len(bounds) - 1, -1, -1):
        numer_k, denom_k = bounds[k]
        cond = (num * denom_k) < (den * numer_k)
        result[cond] = k
    return result


def run_17():
    print_sep("Run 17 重跑 — 分位桶整數化（Shape+Sym+Pkt_CV）")

    benign_raw = get_normal_sample_from_files(TRAIN_PATHS, n=30000, seed=SEED)
    val_raw    = get_balance_sample_from_files(VAL_PATHS, sample_count_per_label=5000, seed=SEED)
    d1_raw     = load_ids2018(IDS2018_D1, sample_n=5000)
    d2_raw     = load_ids2018(IDS2018_D2, sample_n=5000)

    # ── log1p 基準（Run 15/16 的浮點參考）
    def make_log1p_features(benign, val, col_map):
        b = add_ratios(benign, col_map, log1p=True)
        v = add_ratios(val,    col_map, log1p=True)
        return b, v

    def eval_quantile(N: int):
        # 以 BENIGN 計算三個比例特徵的分位桶邊界
        b_num_shape = benign_raw["Min Packet Length"].cast(pl.Float64).to_numpy()
        b_den_shape = benign_raw["Fwd Packet Length Mean"].cast(pl.Float64).to_numpy()
        b_num_sym   = benign_raw["Total Fwd Packets"].cast(pl.Float64).to_numpy()
        b_den_sym   = benign_raw["Total Backward Packets"].cast(pl.Float64).to_numpy()
        b_num_cv    = benign_raw["Packet Length Std"].cast(pl.Float64).to_numpy()
        b_den_cv    = benign_raw["Packet Length Mean"].cast(pl.Float64).to_numpy()

        shape_bounds = compute_quantile_boundaries(b_num_shape / (b_den_shape + 1e-6), N)
        sym_bounds   = compute_quantile_boundaries(b_num_sym   / (b_den_sym   + 1.0),  N)
        cv_bounds    = compute_quantile_boundaries(b_num_cv    / (b_den_cv    + 1e-6), N)

        def apply_buckets(df: pl.DataFrame, col_map: dict) -> pl.DataFrame:
            num_s_col, den_s_col = col_map["Shape_Ratio"]
            num_m_col, den_m_col = col_map["Sym_Ratio"]
            num_c_col, den_c_col = col_map["Pkt_CV"]
            if any(c not in df.columns for c in [num_s_col, den_s_col, num_m_col,
                                                   den_m_col, num_c_col, den_c_col]):
                return None
            shape_q = ratio_to_bucket(
                df[num_s_col].cast(pl.Float64).to_numpy(),
                df[den_s_col].cast(pl.Float64).to_numpy(), shape_bounds)
            sym_q   = ratio_to_bucket(
                df[num_m_col].cast(pl.Float64).to_numpy(),
                df[den_m_col].cast(pl.Float64).to_numpy(), sym_bounds)
            cv_q    = ratio_to_bucket(
                df[num_c_col].cast(pl.Float64).to_numpy(),
                df[den_c_col].cast(pl.Float64).to_numpy(), cv_bounds)
            return df.with_columns([
                pl.Series("Shape_q", shape_q.astype(np.float32)),
                pl.Series("Sym_q",   sym_q.astype(np.float32)),
                pl.Series("Pkt_CV_q", cv_q.astype(np.float32)),
            ])

        q_feats = ["Shape_q", "Sym_q", "Pkt_CV_q", "Protocol", "Packet Length Mean"]

        benign_q = apply_buckets(benign_raw, RATIO_COLS_DDOS2019)
        val_q    = apply_buckets(val_raw,    RATIO_COLS_DDOS2019)
        d1_q     = apply_buckets(d1_raw,     RATIO_COLS_IDS2018)
        d2_q     = apply_buckets(d2_raw,     RATIO_COLS_IDS2018)

        hoic_lbl = next((l for l in d2_raw["Label"].unique().to_list() if "HOIC" in l), None)
        udp_lbl  = next((l for l in d2_raw["Label"].unique().to_list() if "UDP"  in l), None)

        aucs = {}
        aucs["DDoS2019"] = auc_validate(benign_q, val_q, q_feats)
        aucs["LOIC-HTTP"] = auc_validate(benign_q, d1_q, q_feats) if d1_q is not None else None
        if hoic_lbl and d2_q is not None:
            sub = pl.concat([d2_q.filter(pl.col("Label") == "BENIGN"),
                             d2_q.filter(pl.col("Label") == hoic_lbl)])
            aucs["HOIC"] = auc_validate(benign_q, sub, q_feats)
        if udp_lbl and d2_q is not None:
            sub = pl.concat([d2_q.filter(pl.col("Label") == "BENIGN"),
                             d2_q.filter(pl.col("Label") == udp_lbl)])
            aucs["LOIC-UDP"] = auc_validate(benign_q, sub, q_feats)
        return aucs

    # ── 先跑 log1p 浮點基準
    print("\n計算 log1p 浮點基準（Run 15/16 參考）...")
    b_log = add_ratios(benign_raw, RATIO_COLS_DDOS2019, log1p=True)
    v_log = add_ratios(val_raw,    RATIO_COLS_DDOS2019, log1p=True)
    d1_log = add_ratios(d1_raw,    RATIO_COLS_IDS2018,  log1p=True)
    d2_log = add_ratios(d2_raw,    RATIO_COLS_IDS2018,  log1p=True)
    ratio_feats = ["Shape_Ratio", "Sym_Ratio", "Pkt_CV"]
    hoic_lbl = next((l for l in d2_raw["Label"].unique().to_list() if "HOIC" in l), None)
    udp_lbl  = next((l for l in d2_raw["Label"].unique().to_list() if "UDP"  in l), None)
    b_log_ids = add_ratios(get_normal_sample_from_files(TRAIN_PATHS, n=10000, seed=SEED),
                            RATIO_COLS_IDS2018, log1p=True)
    baseline = {
        "DDoS2019":  auc_validate(b_log, v_log,  ratio_feats + ["Protocol", "Packet Length Mean"]),
        "LOIC-HTTP": auc_validate(b_log_ids, d1_log, ratio_feats + ["Protocol", "Packet Length Mean"]),
        "HOIC":      auc_validate(b_log_ids,
                                   pl.concat([d2_log.filter(pl.col("Label") == "BENIGN"),
                                              d2_log.filter(pl.col("Label") == hoic_lbl)]),
                                   ratio_feats + ["Protocol", "Packet Length Mean"]) if hoic_lbl else None,
        "LOIC-UDP":  auc_validate(b_log_ids,
                                   pl.concat([d2_log.filter(pl.col("Label") == "BENIGN"),
                                              d2_log.filter(pl.col("Label") == udp_lbl)]),
                                   ratio_feats + ["Protocol", "Packet Length Mean"]) if udp_lbl else None,
    }

    # ── 分位桶結果
    print(f"\n{'特徵組合':<25} {'DDoS2019':>10} {'LOIC-HTTP':>10} {'HOIC':>8} {'LOIC-UDP':>10}")
    print("-" * 70)
    b_str = "  ".join(f"{v:.4f}" if v else " nan  " for v in [
        baseline["DDoS2019"], baseline["LOIC-HTTP"], baseline["HOIC"], baseline["LOIC-UDP"]])
    print(f"  {'log1p 基準（浮點）':<23} {baseline['DDoS2019'] or 0:.4f}  "
          f"{baseline['LOIC-HTTP'] or 0:.4f}  {baseline['HOIC'] or 0:.4f}  "
          f"{baseline['LOIC-UDP'] or 0:.4f}")

    all_results = {"baseline": baseline}
    for N in [2, 4, 8, 16, 64, 256]:
        print(f"  計算 N={N}...", end="", flush=True)
        aucs = eval_quantile(N)
        all_results[N] = aucs
        d2019  = f"{aucs['DDoS2019']:.4f}"  if aucs.get("DDoS2019")  else " nan "
        loic   = f"{aucs['LOIC-HTTP']:.4f}" if aucs.get("LOIC-HTTP") else " nan "
        hoic   = f"{aucs['HOIC']:.4f}"      if aucs.get("HOIC")      else " nan "
        ludp   = f"{aucs['LOIC-UDP']:.4f}"  if aucs.get("LOIC-UDP")  else " nan "
        print(f"\r  {'分位桶 N='+str(N):<23} {d2019:>10} {loic:>10} {hoic:>8} {ludp:>10}")

    print("\nΔ（相對 log1p 基準）：")
    print(f"{'N':>5} {'DDoS2019':>10} {'LOIC-HTTP':>10} {'HOIC':>8} {'LOIC-UDP':>10}")
    for N in [2, 4, 8, 16, 64, 256]:
        aucs = all_results[N]
        def delta(k):
            if aucs.get(k) and baseline.get(k):
                return f"{aucs[k]-baseline[k]:+.4f}"
            return "   N/A"
        print(f"  {N:>3}  {delta('DDoS2019'):>10} {delta('LOIC-HTTP'):>10} "
              f"{delta('HOIC'):>8} {delta('LOIC-UDP'):>10}")

    return all_results


if __name__ == "__main__":
    r14 = run_14()
    r15 = run_15()
    r16 = run_16()
    r17 = run_17()
    print("\n\n✅ Run 14–17 全部重跑完成")