"""Run 26 — 擴充指標評估：AUC-ROC / AUC-PR / TPR@FPR

動機：
  現有實驗只回報 AUC-ROC，但：
  - 驗證集為人工平衡（50/50），真實網路攻擊比例極低
  - AUC-ROC 在不平衡資料下高估實際效能
  - eBPF 防火牆需要在固定誤殺率（FPR）下確認偵測率

新增指標：
  AUC-PR  — Precision-Recall AUC，不平衡資料下更真實
  TPR@1%  — FPR=1% 時的 True Positive Rate（最大容忍誤殺率下的偵測率）
  TPR@5%  — FPR=5% 時的 True Positive Rate（較寬鬆容忍下的偵測率）

實驗對象：
  A. Shape_q  + CIC BENIGN  N=2（Run 17 基準，已棄用）
  B. FwdMax_q + Mixed BENIGN N=2（Run 25 最終方案）

驗證集：DDoS2019、LOIC-HTTP、HOIC、LOIC-UDP、BigFlow DDoS

執行：
  uv run --project service/model python -m service.model.experiments.run26_extended_metrics
"""
import glob
from dataclasses import dataclass

import numpy as np
import polars as pl
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    average_precision_score,
    roc_auc_score,
    roc_curve,
)
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

PKT_BUCKET_MIDPOINTS = {
    "NUM_PKTS_UP_TO_128_BYTES":    64,
    "NUM_PKTS_128_TO_256_BYTES":  192,
    "NUM_PKTS_256_TO_512_BYTES":  384,
    "NUM_PKTS_512_TO_1024_BYTES": 768,
    "NUM_PKTS_1024_TO_1514_BYTES": 1269,
}

RATIO_COLS_SHAPE_CIC    = {"main": ("Min Packet Length",     "Fwd Packet Length Mean"),
                            "sym":  ("Total Fwd Packets",     "Total Backward Packets"),
                            "cv":   ("Packet Length Std",     "Packet Length Mean")}
RATIO_COLS_FWDMAX_CIC   = {"main": ("Fwd Packet Length Max", "Fwd Packet Length Mean"),
                            "sym":  ("Total Fwd Packets",     "Total Backward Packets"),
                            "cv":   ("Packet Length Std",     "Packet Length Mean")}
RATIO_COLS_SHAPE_IDS    = {"main": ("Packet Length Min",     "Fwd Packet Length Mean"),
                            "sym":  ("Subflow Fwd Packets",   "Total Backward Packets"),
                            "cv":   ("Packet Length Std",     "Packet Length Mean")}
RATIO_COLS_FWDMAX_IDS   = {"main": ("Fwd Packet Length Max", "Fwd Packet Length Mean"),
                            "sym":  ("Subflow Fwd Packets",   "Total Backward Packets"),
                            "cv":   ("Packet Length Std",     "Packet Length Mean")}


# ── 指標結構 ──────────────────────────────────────────────────

@dataclass
class Metrics:
    auc_roc:  float | None = None
    auc_pr:   float | None = None
    tpr_1pct: float | None = None
    tpr_5pct: float | None = None

    def fmt_row(self) -> str:
        def f(v): return f"{v:.4f}" if v is not None else "  nan "
        return f"{f(self.auc_roc):>8} {f(self.auc_pr):>8} {f(self.tpr_1pct):>9} {f(self.tpr_5pct):>9}"


# ── 工具函式 ──────────────────────────────────────────────────

def compute_quantile_boundaries(values: np.ndarray, N: int) -> list[tuple[int, int]]:
    SCALE = 1 << 20
    values = values[np.isfinite(values)]
    thresholds = np.percentile(values, np.linspace(0, 100, N + 1)[1:-1])
    return [(max(0, int(t * SCALE)), SCALE) for t in thresholds]


def ratio_to_bucket(num: np.ndarray, den: np.ndarray,
                    bounds: list[tuple[int, int]]) -> np.ndarray:
    den = den.copy() + 1.0
    result = np.full(len(num), len(bounds), dtype=np.int32)
    for k in range(len(bounds) - 1, -1, -1):
        nk, dk = bounds[k]
        result[(num * dk) < (den * nk)] = k
    return result


def apply_buckets(df: pl.DataFrame, col_map: dict,
                  main_b, sym_b, cv_b,
                  main_name: str) -> pl.DataFrame | None:
    def bucket(key, bounds):
        nc, dc = col_map[key]
        if nc not in df.columns or dc not in df.columns:
            return None
        return ratio_to_bucket(df[nc].cast(pl.Float64).to_numpy(),
                               df[dc].cast(pl.Float64).to_numpy(), bounds)

    mq = bucket("main", main_b)
    sq = bucket("sym",  sym_b)
    cq = bucket("cv",   cv_b)
    if mq is None or sq is None or cq is None:
        return None
    return df.with_columns([
        pl.Series(main_name,  mq.astype(np.float32)),
        pl.Series("Sym_q",    sq.astype(np.float32)),
        pl.Series("Pkt_CV_q", cq.astype(np.float32)),
    ])


def apply_buckets_norm(df: pl.DataFrame, main_b, sym_b, cv_b,
                       main_name: str) -> pl.DataFrame | None:
    for col in ("main_pkt", "ref_pkt", "fwd_pkts", "bwd_pkts", "pkt_std", "pkt_mean"):
        if col not in df.columns:
            return None
    mq = ratio_to_bucket(df["main_pkt"].to_numpy(), df["ref_pkt"].to_numpy(), main_b)
    sq = ratio_to_bucket(df["fwd_pkts"].to_numpy(), df["bwd_pkts"].to_numpy(), sym_b)
    cq = ratio_to_bucket(df["pkt_std"].to_numpy(),  df["pkt_mean"].to_numpy(), cv_b)
    return df.with_columns([
        pl.Series(main_name,  mq.astype(np.float32)),
        pl.Series("Sym_q",    sq.astype(np.float32)),
        pl.Series("Pkt_CV_q", cq.astype(np.float32)),
    ])


def evaluate(benign_q: pl.DataFrame, val_q: pl.DataFrame,
             features: list[str], y: np.ndarray) -> Metrics:
    avail = [f for f in features if f in benign_q.columns and f in val_q.columns]
    if not avail:
        return Metrics()
    X_tr = benign_q.select(avail).to_numpy().astype(np.float32)
    X_v  = val_q.select(avail).to_numpy().astype(np.float32)
    mt, mv = np.isfinite(X_tr).all(1), np.isfinite(X_v).all(1)
    X_tr, X_v = X_tr[mt], X_v[mv]
    y_v = y[mv]
    if y_v.sum() == 0 or y_v.sum() == len(y_v) or len(X_tr) < 10:
        return Metrics()
    sc  = StandardScaler()
    iso = IsolationForest(n_estimators=N_ESTIMATORS, contamination=CONTAMINATION,
                          random_state=SEED, n_jobs=-1)
    iso.fit(sc.fit_transform(X_tr))
    scores = -iso.score_samples(sc.transform(X_v))

    auc_roc = float(roc_auc_score(y_v, scores))
    auc_pr  = float(average_precision_score(y_v, scores))
    fpr_arr, tpr_arr, _ = roc_curve(y_v, scores)
    tpr_1pct = float(tpr_arr[np.searchsorted(fpr_arr, 0.01)])
    tpr_5pct = float(tpr_arr[np.searchsorted(fpr_arr, 0.05)])
    return Metrics(auc_roc=auc_roc, auc_pr=auc_pr,
                   tpr_1pct=tpr_1pct, tpr_5pct=tpr_5pct)


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


def cic_to_norm(df: pl.DataFrame, main_col: str) -> pl.DataFrame:
    return df.with_columns([
        pl.col(main_col).cast(pl.Float64).alias("main_pkt"),
        pl.col("Fwd Packet Length Mean").cast(pl.Float64).alias("ref_pkt"),
        pl.col("Total Fwd Packets").cast(pl.Float64).alias("fwd_pkts"),
        pl.col("Total Backward Packets").cast(pl.Float64).alias("bwd_pkts"),
        pl.col("Packet Length Std").cast(pl.Float64).alias("pkt_std"),
        pl.col("Packet Length Mean").cast(pl.Float64).alias("pkt_mean"),
        pl.col("Protocol").cast(pl.Float64),
        pl.col("Packet Length Mean").cast(pl.Float64),
    ])


def bigflow_to_norm(df: pl.DataFrame, use_max: bool) -> pl.DataFrame:
    total_pkts  = pl.col("IN_PKTS").cast(pl.Float64) + pl.col("OUT_PKTS").cast(pl.Float64)
    total_bytes = pl.col("IN_BYTES").cast(pl.Float64) + pl.col("OUT_BYTES").cast(pl.Float64)
    fwd_mean    = pl.col("IN_BYTES").cast(pl.Float64) / (pl.col("IN_PKTS").cast(pl.Float64) + 1e-6)
    pkt_mean    = total_bytes / (total_pkts + 1e-6)
    ex2 = sum(pl.col(c).cast(pl.Float64) * float(m * m)
              for c, m in PKT_BUCKET_MIDPOINTS.items()) / (total_pkts + 1e-6)
    pkt_std = (ex2 - pkt_mean ** 2).clip(lower_bound=0.0).sqrt()
    main_src = pl.col("LONGEST_FLOW_PKT" if use_max else "SHORTEST_FLOW_PKT").cast(pl.Float64)
    return df.with_columns([
        main_src.alias("main_pkt"),
        fwd_mean.alias("ref_pkt"),
        pl.col("IN_PKTS").cast(pl.Float64).alias("fwd_pkts"),
        pl.col("OUT_PKTS").cast(pl.Float64).alias("bwd_pkts"),
        pkt_std.alias("pkt_std"),
        pkt_mean.alias("pkt_mean"),
        pl.col("PROTOCOL").cast(pl.Float64).alias("Protocol"),
        pkt_mean.alias("Packet Length Mean"),
    ])


# ── 主實驗 ────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("Run 26 — 擴充指標評估（AUC-ROC / AUC-PR / TPR@FPR）")
    print("=" * 70)

    # ── 1. 載入原始資料
    print("\n[1] 載入資料...")
    cic_benign = get_normal_sample_from_files(TRAIN_PATHS, n=N_TRAIN, seed=SEED)
    val_raw    = get_balance_sample_from_files(VAL_PATHS, sample_count_per_label=5000, seed=SEED)
    d1_raw     = load_ids2018(IDS2018_D1, sample_n=5000)
    d2_raw     = load_ids2018(IDS2018_D2, sample_n=5000)
    bf_val_raw = load_bigflow_val(n_benign=5000, n_ddos=5000)

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
    print(f"  CIC BENIGN：{len(cic_benign)} 筆，BigFlow BENIGN：{count} 筆")

    # IDS2018 子集
    hoic_lbl = next((l for l in d2_raw["Label"].unique().to_list() if "HOIC" in l), None)
    udp_lbl  = next((l for l in d2_raw["Label"].unique().to_list() if "UDP"  in l), None)
    d2_hoic  = d2_raw.filter(pl.col("Label").is_in(["BENIGN", hoic_lbl])) if hoic_lbl else None
    d2_udp   = d2_raw.filter(pl.col("Label").is_in(["BENIGN", udp_lbl]))  if udp_lbl  else None

    # ── 2. 建立兩個方案的訓練資料與邊界
    NORM_COLS = ["main_pkt", "ref_pkt", "fwd_pkts", "bwd_pkts",
                 "pkt_std", "pkt_mean", "Protocol", "Packet Length Mean"]

    # 方案 A：Shape_q + CIC（Run 17 基準）
    cic_norm_shape = cic_to_norm(cic_benign, "Min Packet Length")
    shape_b = compute_quantile_boundaries(
        cic_norm_shape["main_pkt"].to_numpy() / (cic_norm_shape["ref_pkt"].to_numpy() + 1e-6), 2)
    sym_b_cic = compute_quantile_boundaries(
        cic_norm_shape["fwd_pkts"].to_numpy() / (cic_norm_shape["bwd_pkts"].to_numpy() + 1.0), 2)
    cv_b_cic = compute_quantile_boundaries(
        cic_norm_shape["pkt_std"].to_numpy() / (cic_norm_shape["pkt_mean"].to_numpy() + 1e-6), 2)

    # 方案 B：FwdMax_q + Mixed（Run 25 最終方案）
    cic_norm_fwdmax = cic_to_norm(cic_benign, "Fwd Packet Length Max")
    bf_norm_fwdmax  = bigflow_to_norm(bf_benign, use_max=True)
    mixed_norm = pl.concat([
        cic_norm_fwdmax.select(NORM_COLS),
        bf_norm_fwdmax.select(NORM_COLS),
    ])
    fwdmax_b = compute_quantile_boundaries(
        mixed_norm["main_pkt"].to_numpy() / (mixed_norm["ref_pkt"].to_numpy() + 1e-6), 2)
    sym_b_mix = compute_quantile_boundaries(
        mixed_norm["fwd_pkts"].to_numpy() / (mixed_norm["bwd_pkts"].to_numpy() + 1.0), 2)
    cv_b_mix = compute_quantile_boundaries(
        mixed_norm["pkt_std"].to_numpy() / (mixed_norm["pkt_mean"].to_numpy() + 1e-6), 2)

    print(f"  Shape_q  邊界 p50 = {shape_b[0][0]/(1<<20):.4f}")
    print(f"  FwdMax_q 邊界 p50 = {fwdmax_b[0][0]/(1<<20):.4f}")

    # ── 3. 套用分位桶
    def make_val_sets(main_name, col_map_cic, col_map_ids, mb, sb, cb, norm_use_max):
        b_q   = apply_buckets_norm(cic_norm_shape if not norm_use_max else mixed_norm,
                                   mb, sb, cb, main_name)
        val_q = apply_buckets(val_raw, col_map_cic, mb, sb, cb, main_name)
        d1_q  = apply_buckets(d1_raw,  col_map_ids, mb, sb, cb, main_name)
        d2h_q = apply_buckets(d2_hoic, col_map_ids, mb, sb, cb, main_name) if d2_hoic is not None else None
        d2u_q = apply_buckets(d2_udp,  col_map_ids, mb, sb, cb, main_name) if d2_udp  is not None else None
        bf_norm = bigflow_to_norm(bf_val_raw, use_max=norm_use_max)
        bf_q  = apply_buckets_norm(bf_norm,  mb, sb, cb, main_name)
        return b_q, val_q, d1_q, d2h_q, d2u_q, bf_q

    FEATS_SHAPE  = ["Shape_q",  "Sym_q", "Pkt_CV_q", "Protocol", "Packet Length Mean"]
    FEATS_FWDMAX = ["FwdMax_q", "Sym_q", "Pkt_CV_q", "Protocol", "Packet Length Mean"]

    b_s, val_s, d1_s, d2h_s, d2u_s, bf_s = make_val_sets(
        "Shape_q", RATIO_COLS_SHAPE_CIC, RATIO_COLS_SHAPE_IDS,
        shape_b, sym_b_cic, cv_b_cic, norm_use_max=False)

    b_f, val_f, d1_f, d2h_f, d2u_f, bf_f = make_val_sets(
        "FwdMax_q", RATIO_COLS_FWDMAX_CIC, RATIO_COLS_FWDMAX_IDS,
        fwdmax_b, sym_b_mix, cv_b_mix, norm_use_max=True)

    def y_cic(df): return (df["Label"] != "BENIGN").cast(pl.Int8).to_numpy()
    def y_bf(df):  return df["is_attack"].to_numpy()

    # ── 4. 計算所有指標
    datasets = [
        ("DDoS2019",  val_s,  val_f,  y_cic),
        ("LOIC-HTTP", d1_s,   d1_f,   y_cic),
        ("HOIC",      d2h_s,  d2h_f,  y_cic),
        ("LOIC-UDP",  d2u_s,  d2u_f,  y_cic),
        ("BigFlow",   bf_s,   bf_f,   y_bf),
    ]

    print(f"\n[2] 完整指標比較（A = Shape_q CIC N=2，B = FwdMax_q Mixed N=2）：\n")
    header = (f"  {'資料集':<12} {'方案':<3}"
              f" {'AUC-ROC':>8} {'AUC-PR':>8} {'TPR@1%':>9} {'TPR@5%':>9}")
    print(header)
    print("  " + "─" * (len(header) - 2))

    all_metrics: dict[str, dict[str, Metrics]] = {}
    for ds_name, val_s_i, val_f_i, y_fn in datasets:
        all_metrics[ds_name] = {}
        for label, b_q, val_q, feats in [
            ("A", b_s, val_s_i, FEATS_SHAPE),
            ("B", b_f, val_f_i, FEATS_FWDMAX),
        ]:
            if b_q is None or val_q is None:
                m = Metrics()
            else:
                y = y_fn(val_q)
                m = evaluate(b_q, val_q, feats, y)
            all_metrics[ds_name][label] = m
            print(f"  {ds_name:<12} {label:<3} {m.fmt_row()}")
        print()

    # ── 5. Δ（B − A）
    print("[3] Δ（FwdMax_q Mixed − Shape_q CIC）：\n")
    header2 = f"  {'資料集':<12} {'ΔAUC-ROC':>10} {'ΔAUC-PR':>10} {'ΔTPR@1%':>10} {'ΔTPR@5%':>10}"
    print(header2)
    print("  " + "─" * (len(header2) - 2))
    for ds_name in all_metrics:
        a = all_metrics[ds_name]["A"]
        b = all_metrics[ds_name]["B"]
        def d_(va, vb): return f"{vb-va:+.4f}" if va is not None and vb is not None else "   N/A"
        print(f"  {ds_name:<12} {d_(a.auc_roc,b.auc_roc):>10} {d_(a.auc_pr,b.auc_pr):>10}"
              f" {d_(a.tpr_1pct,b.tpr_1pct):>10} {d_(a.tpr_5pct,b.tpr_5pct):>10}")

    # ── 6. 各指標摘要
    print(f"\n[4] 各指標一致性檢查（方案 B，FwdMax_q Mixed N=2）：\n")
    print(f"  {'資料集':<12} {'AUC-ROC':>8} {'AUC-PR':>8} {'TPR@1%':>9} {'TPR@5%':>9}  一致性")
    print("  " + "─" * 65)
    for ds_name in all_metrics:
        m = all_metrics[ds_name]["B"]
        if m.auc_roc is None:
            continue
        # 一致性：AUC-PR 與 AUC-ROC 方向是否一致
        gap = (m.auc_roc or 0) - (m.auc_pr or 0)
        note = f"PR gap={gap:+.3f}" if gap > 0.2 else "一致"
        print(f"  {ds_name:<12} {m.fmt_row()}  {note}")

    return all_metrics


if __name__ == "__main__":
    main()
