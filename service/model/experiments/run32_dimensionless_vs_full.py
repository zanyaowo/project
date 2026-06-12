"""Run 32 (Layer 2 M1) — 無量綱特徵 IF vs 全 25 維特徵 IF（CIC-2019，連續 IF-direct）。

問題：Layer 2 userspace 完整 IF 的輸入理論上是 CICFlowMeter 的 25 個 FEATURE_COLS，
但 kernel datapath 只能供應 SessionValue 重建的無量綱（比例）特徵子集。
userspace 推論不受 eBPF 整數/verifier 限制（可浮點、可完整 IF），因此瓶頸不是運算
能力而是**特徵覆蓋度**：只用可重建的無量綱特徵訓練的 IF，能否逼近完整 25 維 IF？

本實驗在 CIC-2019（現行評估範圍）上做 apples-to-apples 對照，連續特徵（IF-direct，
非部署 contract 的二值化路徑），逐攻擊 AUC + FPR/FNR/F1：

  Full25         : 25 個 FEATURE_COLS（含絕對值特徵；原始 pipeline baseline）
  Dim3           : 純無量綱比例 fwd_max_q / sym_ratio / pkt_cv_sq（皆可由 SessionValue 重建）
  Contract5_cont : 合約 5 特徵連續版 protocol + pkt_len_mean + 3 比例（Layer 2 可重建集，未二值化）

注意：無量綱特徵的真正優勢在**跨環境泛化**（Run 08–10/23/27：絕對值特徵跨資料集崩潰）。
CIC-2019 為同環境 in-distribution，預期 Full25 在此佔優；本實驗回答的是「同環境下
放棄絕對值特徵要付多少代價」，跨環境優勢另見既有跨資料集實驗。

執行：
  uv run --project service/model python -m service.model.experiments.run32_dimensionless_vs_full
"""
from __future__ import annotations

import numpy as np
import polars as pl
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from service.model.schema import FEATURE_COLS
from service.model.metrics import detection_metrics
from service.model.data.sample import (
    get_balance_sample_from_files,
    get_normal_sample_from_files,
)
from service.model.experiments.run27_boundary_overfit_check import (
    CIC_TRAIN_PATHS,
    CIC_TEST_PATHS,
    CONTAMINATION,
    IDS2018_D2,
    N_ESTIMATORS,
    N_EVAL_PER_LABEL,
    N_TRAIN_PER_SOURCE,
    SEED,
    load_ids2018,
)

# IDS2018 → CIC FEATURE_COLS 名稱對應（HOIC 跨環境評估用）。
# "Destination Port" 在 IDS2018 不存在 → Full25 補 0（略低估，已標 caveat）。
_IDS_RENAME = {
    "Fwd Packets Length Total": "Total Length of Fwd Packets",
    "Init Fwd Win Bytes": "Init_Win_bytes_forward",
    "Init Bwd Win Bytes": "Init_Win_bytes_backward",
    "Fwd Act Data Packets": "act_data_pkt_fwd",
}


def ids2018_to_cic(df: pl.DataFrame) -> pl.DataFrame:
    """Rename IDS2018 columns to CIC FEATURE_COLS names so the CIC-trained
    models can score them. Adds a constant Destination Port (absent in IDS2018)."""
    df = df.rename({k: v for k, v in _IDS_RENAME.items() if k in df.columns})
    if "Destination Port" not in df.columns:
        df = df.with_columns(pl.lit(0.0).alias("Destination Port"))
    return df

# Raw columns needed to reconstruct the dimensionless ratios (some overlap FEATURE_COLS).
_RATIO_RAW = [
    "Fwd Packet Length Max",
    "Fwd Packet Length Mean",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Packet Length Std",
    "Packet Length Mean",
    "Protocol",
]
TRAIN_COLS = sorted(set(FEATURE_COLS) | set(_RATIO_RAW))
EVAL_COLS = sorted(set(TRAIN_COLS) | {"Label"})


def _select(cols: list[str]):
    """Lazy column-prune transform (CIC files have ~87 cols → must prune to avoid OOM)."""
    return lambda lf: lf.select(cols)


def _f64(df: pl.DataFrame, col: str) -> np.ndarray:
    return df[col].cast(pl.Float64, strict=False).to_numpy()


# ── Feature builders (continuous) ─────────────────────────────────────────────

def x_full25(df: pl.DataFrame) -> np.ndarray:
    return df.select(
        [pl.col(c).cast(pl.Float64, strict=False) for c in FEATURE_COLS]
    ).to_numpy()


def _ratios(df: pl.DataFrame) -> dict[str, np.ndarray]:
    max_pkt = _f64(df, "Fwd Packet Length Max")
    fwd_mean = _f64(df, "Fwd Packet Length Mean")
    fwd_p = _f64(df, "Total Fwd Packets")
    bwd_p = _f64(df, "Total Backward Packets")
    pkt_std = _f64(df, "Packet Length Std")
    pkt_mean = _f64(df, "Packet Length Mean")
    return {
        "fwd_max_q": max_pkt / (fwd_mean + 1.0),
        "sym_ratio": fwd_p / (bwd_p + 1.0),
        "pkt_cv_sq": (pkt_std / (pkt_mean + 1.0)) ** 2,
    }


def x_dim3(df: pl.DataFrame) -> np.ndarray:
    r = _ratios(df)
    return np.column_stack([r["fwd_max_q"], r["sym_ratio"], r["pkt_cv_sq"]])


def x_contract5_cont(df: pl.DataFrame) -> np.ndarray:
    r = _ratios(df)
    proto = _f64(df, "Protocol")
    pkt_mean = _f64(df, "Packet Length Mean")
    return np.column_stack([proto, pkt_mean, r["fwd_max_q"], r["sym_ratio"], r["pkt_cv_sq"]])


FEATURE_SETS = {
    "Full25":         (x_full25, 25),
    "Dim3":           (x_dim3, 3),
    "Contract5_cont": (x_contract5_cont, 5),
}


def _fit(x_train: np.ndarray) -> tuple[StandardScaler, IsolationForest]:
    mask = np.isfinite(x_train).all(axis=1)
    x = x_train[mask]
    sc = StandardScaler()
    m = IsolationForest(
        n_estimators=N_ESTIMATORS, contamination=CONTAMINATION,
        random_state=SEED, n_jobs=-1,
    )
    m.fit(sc.fit_transform(x))
    return sc, m


def _score(sc: StandardScaler, m: IsolationForest, x: np.ndarray) -> np.ndarray:
    """anomaly score (higher = more anomalous); non-finite rows → -inf so they rank benign."""
    out = np.full(len(x), -np.inf)
    mask = np.isfinite(x).all(axis=1)
    if mask.any():
        out[mask] = -m.score_samples(sc.transform(x[mask]))
    return out


def main() -> None:
    print("=" * 96)
    print("Run 32 (Layer 2 M1) — 無量綱特徵 vs 全 25 維特徵 IF（CIC-2019，連續 IF-direct）")
    print("=" * 96)

    print("Loading CIC BENIGN train (03-11)...")
    train = get_normal_sample_from_files(
        CIC_TRAIN_PATHS, n=N_TRAIN_PER_SOURCE, seed=SEED, transform=_select(TRAIN_COLS)
    )
    print(f"  train rows = {len(train)}")

    print("Loading CIC eval (01-12, balanced per label)...")
    ev = get_balance_sample_from_files(
        CIC_TEST_PATHS, sample_count_per_label=N_EVAL_PER_LABEL, seed=SEED,
        transform=_select(EVAL_COLS),
    )
    labels = ev["Label"].to_numpy()
    is_benign = labels == "BENIGN"
    attack_types = sorted({l for l in labels if l != "BENIGN"})
    print(f"  eval rows = {len(ev)}；BENIGN={int(is_benign.sum())}；攻擊類型 {len(attack_types)} 種")

    # Fit each model once on its feature set.
    models = {}
    for name, (builder, _) in FEATURE_SETS.items():
        sc, m = _fit(builder(train))
        models[name] = (sc, m, builder)

    # ── Overall AUC (BENIGN vs all attacks) + at-threshold metrics ────────────
    y_all = (~is_benign).astype(int)
    print("\n[1] 整體（BENIGN vs 全攻擊）")
    hdr = f"{'FeatureSet':<16}{'dim':>5}{'AUC':>9}{'F1':>8}{'FPR':>8}{'FNR':>8}{'TPR':>8}"
    print(hdr)
    print("-" * len(hdr))
    overall = {}
    for name, (_, ndim) in FEATURE_SETS.items():
        sc, m, builder = models[name]
        s = _score(sc, m, builder(ev))
        met = detection_metrics(y_all, s)
        overall[name] = met
        print(f"{name:<16}{ndim:>5}{met['auc']:>9.4f}{met['f1']:>8.3f}"
              f"{met['fpr']:>8.3f}{met['fnr']:>8.3f}{met['tpr']:>8.3f}")

    # ── Per-attack AUC ─────────────────────────────────────────────────────────
    print("\n[2] 逐攻擊類型 AUC（BENIGN vs 單一攻擊）")
    hdr2 = f"{'Attack':<24}" + "".join(f"{n:>16}" for n in FEATURE_SETS)
    print(hdr2)
    print("-" * len(hdr2))
    benign_scores = {}
    for name in FEATURE_SETS:
        sc, m, builder = models[name]
        benign_scores[name] = _score(sc, m, builder(ev))[is_benign]
    per_attack: dict[str, dict[str, float]] = {n: {} for n in FEATURE_SETS}
    for atk in attack_types:
        atk_mask = labels == atk
        row = f"{atk:<24}"
        for name in FEATURE_SETS:
            sc, m, builder = models[name]
            atk_scores = _score(sc, m, builder(ev))[atk_mask]
            y = np.concatenate([np.zeros(is_benign.sum()), np.ones(atk_mask.sum())])
            s = np.concatenate([benign_scores[name], atk_scores])
            finite = np.isfinite(s)
            try:
                auc = detection_metrics(y[finite], s[finite])["auc"]
            except Exception:
                auc = float("nan")
            per_attack[name][atk] = auc
            row += f"{auc:>16.4f}"
        print(row)

    # macro avg across attack types
    print("-" * len(hdr2))
    row = f"{'macro-avg':<24}"
    for name in FEATURE_SETS:
        vals = [v for v in per_attack[name].values() if np.isfinite(v)]
        row += f"{(sum(vals) / len(vals) if vals else float('nan')):>16.4f}"
    print(row)

    # ── Cross-env reference: HOIC (IDS2018 D2) ─────────────────────────────────
    # 跨環境：模型仍用 CIC BENIGN 訓練，評估 IDS2018 HOIC。out-of-scope（CIC-2019 only），
    # 僅作 Layer 2 對 HOIC 的「連續可重建 IF 上限」參考。
    print("\n[3] 跨環境參考：HOIC（IDS2018 D2；訓練仍為 CIC BENIGN，out-of-scope）")
    print("    註：Full25 的 Destination Port 在 IDS2018 缺失，補 0，HOIC 數字略低估")
    ids = load_ids2018(IDS2018_D2)
    ids = ids.with_columns(pl.col("Label").cast(pl.String).str.to_uppercase().alias("Label"))
    ids = ids2018_to_cic(ids)
    hmask = ids["Label"].to_numpy()
    h_benign = hmask == "BENIGN"
    h_attack = np.array(["HOIC" in str(x) for x in hmask])
    hdr3 = f"{'Eval':<16}" + "".join(f"{n:>16}" for n in FEATURE_SETS)
    print(hdr3)
    print("-" * len(hdr3))
    row = f"{'HOIC':<16}"
    hoic_auc: dict[str, float] = {}
    for name in FEATURE_SETS:
        sc, m, builder = models[name]
        s_all = _score(sc, m, builder(ids))
        y = np.concatenate([np.zeros(int(h_benign.sum())), np.ones(int(h_attack.sum()))])
        s = np.concatenate([s_all[h_benign], s_all[h_attack]])
        finite = np.isfinite(s)
        try:
            auc = detection_metrics(y[finite], s[finite])["auc"]
        except Exception:
            auc = float("nan")
        hoic_auc[name] = auc
        row += f"{auc:>16.4f}"
    print(row)

    # ── Judgement helper ───────────────────────────────────────────────────────
    print("\n[4] 判斷（以 Full25 為基準）")
    base = overall["Full25"]["auc"]
    for name in ("Dim3", "Contract5_cont"):
        d = overall[name]["auc"] - base
        print(f"  {name:<16} CIC 整體 AUC Δ = {d:+.4f}  "
              f"(FPR {overall[name]['fpr']:.3f} vs Full25 {overall['Full25']['fpr']:.3f})"
              f"  | HOIC AUC = {hoic_auc.get(name, float('nan')):.4f}")
    print(f"  {'Full25':<16} HOIC AUC = {hoic_auc.get('Full25', float('nan')):.4f}（Dst Port 補 0）")


if __name__ == "__main__":
    main()
