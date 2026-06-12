"""Run 29 — HOIC-aware feature replacement for 32-entry contract.

問題：D_current_5bit_contract 的 protocol_bit 對 HOIC 無鑑別力。
HOIC 全為 TCP（protocol=6），與 BENIGN TCP 相同，binary threshold 無法分離。

關鍵發現（前置分析）：
  Init Fwd Win Bytes / (Init Bwd Win Bytes + 1) 在 HOIC vs BENIGN TCP 的單特徵 AUC=0.9995
  HOIC 工具廣播極小的 Bwd Window，BENIGN TCP median FwdWin/BwdWin ≈ 5
  此特徵是攻擊工具行為（非環境分布），不受 Mixed BENIGN 分布偏移影響
  BigFlow 為 NetFlow 格式無 TCP handshake 欄位，BigFlow 攻擊為 UDP DDoS 不需此特徵

比較項（全部 ≤ 32-entry，F 除外作為上限參考）：
  D_current_5bit:      protocol_bit + pkt_mean_bit + fwd_max_q + sym_ratio + pkt_cv_sq  (baseline, 32)
  E1_init_win_r_proto: init_win_bit + pkt_mean_bit + fwd_max_q + sym_ratio + pkt_cv_sq  (取代 protocol, 32)
  E2_init_win_r_mean:  protocol_bit + init_win_bit + fwd_max_q + sym_ratio + pkt_cv_sq  (取代 mean, 32)
  F_6bit_ceiling:      init_win_bit + protocol_bit + pkt_mean_bit + 3 ratio bits         (64-entry 上限)
  G_4bit_floor:        pkt_mean_bit + fwd_max_q + sym_ratio + pkt_cv_sq                  (16-entry 下限)

執行：
  uv run --project service/model python -m service.model.experiments.run29_hoic_feature_search
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import polars as pl
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import StandardScaler

from service.model.experiments.run27_boundary_overfit_check import (
    CONTAMINATION,
    IDS2018_D1,
    IDS2018_D2,
    N_ESTIMATORS,
    N_EVAL_PER_LABEL,
    N_TRAIN_PER_SOURCE,
    SEED,
    SCALE,
    CIC_TEST_PATHS,
    CIC_TRAIN_PATHS,
    load_bigflow_samples,
    load_ids2018,
)
from service.model.data.sample import get_balance_sample_from_files, get_normal_sample_from_files

# ── Constants ────────────────────────────────────────────────────────────────

PKT_BUCKET_MIDPOINTS = {
    "NUM_PKTS_UP_TO_128_BYTES": 64,
    "NUM_PKTS_128_TO_256_BYTES": 192,
    "NUM_PKTS_256_TO_512_BYTES": 384,
    "NUM_PKTS_512_TO_1024_BYTES": 768,
    "NUM_PKTS_1024_TO_1514_BYTES": 1269,
}

# Columns kept after normalisation (raw intermediates needed for bucketing)
_NORM_COLS = ["max_pkt", "fwd_mean", "fwd_pkts", "bwd_pkts", "pkt_std", "pkt_len_mean", "protocol"]

# Columns from CIC/IDS2018 needed for init_win_bit
_CIC_WIN_FWD = "Init_Win_bytes_forward"
_CIC_WIN_BWD = "Init_Win_bytes_backward"
_IDS_WIN_FWD = "Init Fwd Win Bytes"
_IDS_WIN_BWD = "Init Bwd Win Bytes"


@dataclass(frozen=True)
class Variant:
    name: str
    description: str
    feature_cols: list[str]
    table_size: int


# ── Normalisation helpers ─────────────────────────────────────────────────────

def _cic_norm_cols(df: pl.DataFrame, ids2018: bool = False) -> list[str]:
    fwd_pkts_col = (
        "Subflow Fwd Packets"
        if ids2018 and "Subflow Fwd Packets" in df.columns
        else "Total Fwd Packets"
    )
    return [fwd_pkts_col]


def cic_to_norm(df: pl.DataFrame, ids2018: bool = False) -> pl.DataFrame:
    """Return a DataFrame with only _NORM_COLS + init_win columns if present."""
    fwd_pkts_col = (
        "Subflow Fwd Packets"
        if ids2018 and "Subflow Fwd Packets" in df.columns
        else "Total Fwd Packets"
    )
    out = df.select([
        pl.col("Fwd Packet Length Max").cast(pl.Float32).alias("max_pkt"),
        pl.col("Fwd Packet Length Mean").cast(pl.Float32).alias("fwd_mean"),
        pl.col(fwd_pkts_col).cast(pl.Float32).alias("fwd_pkts"),
        pl.col("Total Backward Packets").cast(pl.Float32).alias("bwd_pkts"),
        pl.col("Packet Length Std").cast(pl.Float32).alias("pkt_std"),
        pl.col("Packet Length Mean").cast(pl.Float32).alias("pkt_len_mean"),
        pl.col("Protocol").cast(pl.Float32).alias("protocol"),
    ])
    # Carry init_win columns through if present (CIC uses underscore; IDS2018 uses spaces)
    for fwd_col, bwd_col in [(_CIC_WIN_FWD, _CIC_WIN_BWD), (_IDS_WIN_FWD, _IDS_WIN_BWD)]:
        if fwd_col in df.columns and bwd_col in df.columns:
            out = out.with_columns([
                df[fwd_col].cast(pl.Float32).alias("win_fwd"),
                df[bwd_col].cast(pl.Float32).alias("win_bwd"),
            ])
            break
    # Carry Label if present
    if "Label" in df.columns:
        out = out.with_columns(df["Label"].alias("Label"))
    return out


def bigflow_to_norm(df: pl.DataFrame) -> pl.DataFrame:
    total_pkts  = pl.col("IN_PKTS").cast(pl.Float32)  + pl.col("OUT_PKTS").cast(pl.Float32)
    total_bytes = pl.col("IN_BYTES").cast(pl.Float32) + pl.col("OUT_BYTES").cast(pl.Float32)
    fwd_mean    = pl.col("IN_BYTES").cast(pl.Float32)  / (pl.col("IN_PKTS").cast(pl.Float32) + 1.0)
    pkt_len_mean = total_bytes / (total_pkts + 1.0)
    ex2 = sum(
        pl.col(c).cast(pl.Float32) * float(m * m)
        for c, m in PKT_BUCKET_MIDPOINTS.items()
    ) / (total_pkts + 1.0)
    pkt_std = (ex2 - pkt_len_mean ** 2).clip(lower_bound=0.0).sqrt()
    out = df.select([
        pl.col("LONGEST_FLOW_PKT").cast(pl.Float32).alias("max_pkt"),
        fwd_mean.alias("fwd_mean"),
        pl.col("IN_PKTS").cast(pl.Float32).alias("fwd_pkts"),
        pl.col("OUT_PKTS").cast(pl.Float32).alias("bwd_pkts"),
        pkt_std.alias("pkt_std"),
        pkt_len_mean.alias("pkt_len_mean"),
        pl.col("PROTOCOL").cast(pl.Float32).alias("protocol"),
    ])
    # BigFlow has no TCP handshake info → win_fwd/win_bwd absent (handled in add_all_features)
    if "Attack" in df.columns:
        out = out.with_columns(df["Attack"].alias("Attack"))
    if "is_attack" in df.columns:
        out = out.with_columns(df["is_attack"].alias("is_attack"))
    return out


# ── Feature computation ───────────────────────────────────────────────────────

def _bit_ratio(num: np.ndarray, den: np.ndarray, numer: int, denom: int) -> np.ndarray:
    return ((num.astype(np.float64) * denom) > ((den.astype(np.float64) + 1.0) * numer)).astype(np.float32)


def add_all_features(
    df: pl.DataFrame,
    *,
    abs_proto: float,
    abs_mean: float,
    fwd_max_q: tuple[int, int],
    sym_ratio: tuple[int, int],
    pkt_cv_sq: tuple[int, int],
    init_win_boundary: float,
) -> pl.DataFrame:
    """Compute all binary features in one pass; returns df with added feature columns."""
    proto   = df["protocol"].to_numpy().astype(np.float64)
    mean    = df["pkt_len_mean"].to_numpy().astype(np.float64)
    max_pkt = df["max_pkt"].to_numpy().astype(np.float64)
    fwd_m   = df["fwd_mean"].to_numpy().astype(np.float64)
    fwd_p   = df["fwd_pkts"].to_numpy().astype(np.float64)
    bwd_p   = df["bwd_pkts"].to_numpy().astype(np.float64)
    pkt_std = df["pkt_std"].to_numpy().astype(np.float64)

    protocol_bit  = (proto > abs_proto).astype(np.float32)
    pkt_mean_bit  = (mean > abs_mean).astype(np.float32)
    fwdmax_q_bit  = _bit_ratio(max_pkt, fwd_m, fwd_max_q[0], fwd_max_q[1])
    sym_ratio_bit = _bit_ratio(fwd_p,   bwd_p, sym_ratio[0],  sym_ratio[1])
    cv_sq_bit     = _bit_ratio(pkt_std ** 2, mean ** 2, pkt_cv_sq[0], pkt_cv_sq[1])

    # init_win_bit: 1 if FwdWin/(BwdWin+1) > boundary; 0 for non-TCP/BigFlow
    if "win_fwd" in df.columns:
        win_f = df["win_fwd"].to_numpy().astype(np.float64)
        win_b = df["win_bwd"].to_numpy().astype(np.float64)
        ratio = win_f / (win_b + 1.0)
        # -1 sentinel (non-TCP in CICFlowMeter) → 0
        init_win_bit = np.where((win_b >= 0) & (ratio > init_win_boundary), 1.0, 0.0).astype(np.float32)
    else:
        init_win_bit = np.zeros(len(df), dtype=np.float32)

    return df.with_columns([
        pl.Series("protocol_bit",  protocol_bit),
        pl.Series("pkt_len_mean_bit", pkt_mean_bit),
        pl.Series("fwd_max_q",     fwdmax_q_bit),
        pl.Series("sym_ratio",     sym_ratio_bit),
        pl.Series("pkt_cv_sq",     cv_sq_bit),
        pl.Series("init_win_bit",  init_win_bit),
    ])


# ── Boundary computation ─────────────────────────────────────────────────────

def compute_boundaries(mixed_train: pl.DataFrame, cic_train: pl.DataFrame) -> dict:
    """mixed_train and cic_train are already norm-columns DataFrames."""
    proto = np.median(mixed_train["protocol"].to_numpy())
    mean  = np.median(mixed_train["pkt_len_mean"].to_numpy())

    def ratio_bound(num: np.ndarray, den: np.ndarray) -> tuple[int, int]:
        vals = (num / (den + 1.0)).astype(np.float64)
        vals = vals[np.isfinite(vals)]
        return max(0, int(np.median(vals) * SCALE)), SCALE

    fwd_max_q = ratio_bound(mixed_train["max_pkt"].to_numpy(), mixed_train["fwd_mean"].to_numpy())
    sym_ratio = ratio_bound(mixed_train["fwd_pkts"].to_numpy(), mixed_train["bwd_pkts"].to_numpy())
    pkt_std_  = mixed_train["pkt_std"].to_numpy()
    mean_      = mixed_train["pkt_len_mean"].to_numpy()
    cv_sq      = ratio_bound(pkt_std_ ** 2, mean_ ** 2)

    # init_win boundary: CIC BENIGN TCP only (BigFlow has no win columns)
    if "win_fwd" in cic_train.columns:
        win_f = cic_train["win_fwd"].to_numpy().astype(np.float64)
        win_b = cic_train["win_bwd"].to_numpy().astype(np.float64)
        ratio = win_f / (win_b + 1.0)
        valid = ratio[(win_b >= 0) & np.isfinite(ratio)]
        init_win_boundary = float(np.median(valid)) if len(valid) > 0 else 5.0
    else:
        init_win_boundary = 5.0  # fallback

    return dict(
        abs_proto=float(proto),
        abs_mean=float(mean),
        fwd_max_q=fwd_max_q,
        sym_ratio=sym_ratio,
        pkt_cv_sq=cv_sq,
        init_win_boundary=init_win_boundary,
    )


# ── AUC helper ────────────────────────────────────────────────────────────────

def train_score_auc(
    train_df: pl.DataFrame,
    eval_df: pl.DataFrame,
    y: np.ndarray,
    feature_cols: list[str],
) -> float:
    x_tr = train_df.select(feature_cols).to_numpy().astype(np.float32)
    x_ev = eval_df.select(feature_cols).to_numpy().astype(np.float32)
    mask_tr = np.isfinite(x_tr).all(axis=1)
    mask_ev = np.isfinite(x_ev).all(axis=1)
    x_tr, x_ev, y = x_tr[mask_tr], x_ev[mask_ev], y[mask_ev]
    if len(x_tr) < 10 or y.sum() == 0 or y.sum() == len(y):
        raise ValueError("invalid split")
    sc = StandardScaler()
    m  = IsolationForest(n_estimators=N_ESTIMATORS, contamination=CONTAMINATION,
                         random_state=SEED, n_jobs=-1)
    m.fit(sc.fit_transform(x_tr))
    return float(roc_auc_score(y, -m.score_samples(sc.transform(x_ev))))


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> dict[str, dict[str, float]]:
    print("=" * 92)
    print("Run 29 — HOIC-aware feature replacement: init_win_bit as protocol_bit substitute")
    print("=" * 92)

    # ── Load CIC train (keep win columns via cic_to_norm) ─────────────────────
    print("Loading CIC BENIGN train...")
    cic_train_raw = get_normal_sample_from_files(CIC_TRAIN_PATHS, n=N_TRAIN_PER_SOURCE, seed=SEED)
    cic_train = cic_to_norm(cic_train_raw)
    del cic_train_raw

    # ── Load BigFlow (train + eval) ───────────────────────────────────────────
    print("Loading BigFlow...")
    bf_train_raw, bf_eval_raw = load_bigflow_samples()
    bf_train = bigflow_to_norm(bf_train_raw);  del bf_train_raw

    # Concat mixed train (norm cols only, no win cols for BigFlow)
    shared_cols = _NORM_COLS
    mixed_train_norm = pl.concat([
        cic_train.select(shared_cols),
        bf_train.select(shared_cols),
    ])

    # ── Compute boundaries ────────────────────────────────────────────────────
    print("Computing boundaries...")
    bounds = compute_boundaries(mixed_train_norm, cic_train)
    print(f"  protocol median      = {bounds['abs_proto']}")
    print(f"  pkt_len_mean median  = {bounds['abs_mean']:.4f}")
    print(f"  fwd_max_q            = {bounds['fwd_max_q'][0] / SCALE:.6f}")
    print(f"  sym_ratio            = {bounds['sym_ratio'][0] / SCALE:.6f}")
    print(f"  pkt_cv_sq            = {bounds['pkt_cv_sq'][0] / SCALE:.6f}")
    print(f"  init_win_boundary    = {bounds['init_win_boundary']:.4f}  (CIC BENIGN TCP FwdWin/BwdWin median)")
    del mixed_train_norm

    def featurize(df: pl.DataFrame) -> pl.DataFrame:
        return add_all_features(df, **bounds)

    # ── Build mixed train features ────────────────────────────────────────────
    # CIC: has init_win; BigFlow: no init_win (zeros added by featurize)
    cic_train_feat = featurize(cic_train);  del cic_train
    bf_train_feat  = featurize(bf_train);   del bf_train

    feature_cols_all = ["protocol_bit", "pkt_len_mean_bit", "fwd_max_q",
                        "sym_ratio", "pkt_cv_sq", "init_win_bit"]
    train_feat = pl.concat([
        cic_train_feat.select(feature_cols_all),
        bf_train_feat.select(feature_cols_all),
    ])
    del cic_train_feat, bf_train_feat

    # ── Load + featurize eval sets ────────────────────────────────────────────
    print("Loading eval sets...")

    cic_eval_raw = get_balance_sample_from_files(
        CIC_TEST_PATHS, sample_count_per_label=N_EVAL_PER_LABEL, seed=SEED
    )
    cic_eval = featurize(cic_to_norm(cic_eval_raw))
    cic_y    = (cic_eval_raw["Label"] != "BENIGN").cast(pl.Int8).to_numpy()
    del cic_eval_raw

    d1_raw = load_ids2018(IDS2018_D1)
    d1     = featurize(cic_to_norm(d1_raw, ids2018=True))
    d1_y   = (d1_raw["Label"].cast(pl.String).str.to_uppercase() != "BENIGN").cast(pl.Int8).to_numpy()
    del d1_raw

    d2_raw = load_ids2018(IDS2018_D2)
    d2_raw = d2_raw.with_columns(pl.col("Label").cast(pl.String).str.to_uppercase().alias("Label"))
    hoic_label = next((x for x in d2_raw["Label"].unique() if "HOIC" in x), None)
    udp_label  = next((x for x in d2_raw["Label"].unique() if "UDP"  in x), None)

    eval_sets: list[tuple[str, pl.DataFrame, np.ndarray]] = [
        ("DDoS2019",  cic_eval, cic_y),
        ("LOIC-HTTP", d1,       d1_y),
    ]

    if hoic_label:
        d2_hoic_raw = d2_raw.filter(pl.col("Label").is_in(["BENIGN", hoic_label]))
        d2_hoic     = featurize(cic_to_norm(d2_hoic_raw, ids2018=True))
        d2_hoic_y   = (d2_hoic_raw["Label"] != "BENIGN").cast(pl.Int8).to_numpy()
        del d2_hoic_raw
        eval_sets.append(("HOIC", d2_hoic, d2_hoic_y))

    if udp_label:
        d2_udp_raw = d2_raw.filter(pl.col("Label").is_in(["BENIGN", udp_label]))
        d2_udp     = featurize(cic_to_norm(d2_udp_raw, ids2018=True))
        d2_udp_y   = (d2_udp_raw["Label"] != "BENIGN").cast(pl.Int8).to_numpy()
        del d2_udp_raw
        eval_sets.append(("LOIC-UDP", d2_udp, d2_udp_y))

    del d2_raw

    bf_eval = featurize(bigflow_to_norm(bf_eval_raw))
    bf_y    = bf_eval_raw["is_attack"].to_numpy()
    del bf_eval_raw
    eval_sets.append(("BigFlow", bf_eval, bf_y))

    # ── init_win_bit sanity check ─────────────────────────────────────────────
    print("\n[0] init_win_bit mean (BENIGN≈0, HOIC→1 expected)")
    for name, df, y in eval_sets:
        iw = df["init_win_bit"].to_numpy()
        ben_iw  = float(iw[y == 0].mean()) if np.any(y == 0) else float("nan")
        atk_iw  = float(iw[y == 1].mean()) if np.any(y == 1) else float("nan")
        print(f"  {name:<12} benign={ben_iw:.3f}  attack={atk_iw:.3f}")

    # ── Variants ──────────────────────────────────────────────────────────────
    variants = [
        Variant("D_current_5bit",      "protocol_bit+pkt_mean_bit+3 ratio (baseline)",
                ["protocol_bit","pkt_len_mean_bit","fwd_max_q","sym_ratio","pkt_cv_sq"], 32),
        Variant("E1_init_win_r_proto",  "init_win replaces protocol_bit",
                ["init_win_bit","pkt_len_mean_bit","fwd_max_q","sym_ratio","pkt_cv_sq"], 32),
        Variant("E2_init_win_r_mean",   "init_win replaces pkt_mean_bit",
                ["protocol_bit","init_win_bit","fwd_max_q","sym_ratio","pkt_cv_sq"],    32),
        Variant("F_6bit_ceiling",       "add init_win to current 5-bit (64-entry)",
                ["init_win_bit","protocol_bit","pkt_len_mean_bit","fwd_max_q","sym_ratio","pkt_cv_sq"], 64),
        Variant("G_4bit_floor",         "drop protocol entirely (16-entry)",
                ["pkt_len_mean_bit","fwd_max_q","sym_ratio","pkt_cv_sq"], 16),
    ]

    print("\n[1] Variant definitions")
    for v in variants:
        print(f"  {v.name:<26} table={v.table_size:<5} {v.description}")

    # ── AUC matrix ────────────────────────────────────────────────────────────
    eval_names = [n for n, _, _ in eval_sets]
    print("\n[2] AUC-ROC matrix")
    header = f"{'Variant':<26}{'Table':>7}" + "".join(f"{n:>11}" for n in eval_names) + f"{'Avg':>9}"
    print(header)
    print("-" * len(header))

    results: dict[str, dict[str, float]] = {}
    for v in variants:
        row = f"{v.name:<26}{v.table_size:>7}"
        row_res: dict[str, float] = {}
        for name, df, y in eval_sets:
            try:
                auc = train_score_auc(train_feat, df, y, v.feature_cols)
                row_res[name] = auc
                row += f"{auc:>11.4f}"
            except Exception as exc:
                row += f"{'ERR':>11}"
                print(f"\n  [WARN] {v.name}/{name}: {exc}")
        valid = list(row_res.values())
        avg = sum(valid) / len(valid) if valid else float("nan")
        row_res["Avg"] = avg
        row += f"{avg:>9.4f}"
        results[v.name] = row_res
        print(row)

    # ── Delta vs baseline ─────────────────────────────────────────────────────
    print("\n[3] Delta vs D_current_5bit")
    base = results.get("D_current_5bit", {})
    print(f"{'Variant':<26}" + "".join(f"{n:>11}" for n in eval_names) + f"{'Avg':>9}")
    print("-" * (26 + 11 * len(eval_names) + 9))
    for v in variants[1:]:
        row = f"{v.name:<26}"
        for n in eval_names:
            d = results[v.name].get(n, float("nan")) - base.get(n, float("nan"))
            row += f"{d:>+11.4f}"
        row += f"{(results[v.name]['Avg'] - base.get('Avg', float('nan'))):>+9.4f}"
        print(row)

    print("\n[4] Interpretation")
    print("  E1/E2: 若 HOIC 大幅提升且其他維持，代表對應欄位可以替換。")
    print("  F:     64-entry 上限，確認 6-bit 是否值得額外複雜度。")
    print("  G:     16-entry 下限，確認 protocol bit 的邊際貢獻。")
    print("  BigFlow init_win_bit 固定為 0；BigFlow AUC 變化反映其他 4 個特徵的穩定性。")

    return results


if __name__ == "__main__":
    main()
