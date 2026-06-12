"""Run 37 — Static vs Periodic vs Gated bucket under drift（E3，Figure 2 主圖）。

漂移場景（人工，CIC-DDoS2019 in-scope）：5 個時間視窗，攻擊比例由 10% 漸增到 50%，
並疊加溫和良性漂移（pkt_len_mean 隨業務高峰上移）。比較三種邊界更新策略，逐視窗 F1/FNR：

  Static   ：訓練集邊界算一次，永不更新（= 部署 model.json BENIGN 中位數）
  Periodic ：每視窗以「當前視窗中位數」重算邊界（無 gate，= naive streaming）
  Gated    ：dual-sketch + decide_gate（boundary_updater）——僅 gate=Normal（良性漂移、
             無 high-risk 跳升）才 EMA 更新 reference；偵測到攻擊污染則 AttackFreeze 凍結

門檻採部署預設 divergence_threshold=0.30、high_risk_rate_jump=2.0、EMA alpha=0.30。

預期（誠實）：無量綱比例特徵對良性 rate 漂移不敏感 → Static 穩健；Periodic 被攻擊污染
逐視窗退化；Gated 凍結 reference 維持穩定。結論一律指向逐視窗實測。

執行：python -m service.model.experiments.run37_drift_eval
"""
from __future__ import annotations

import copy
import json

import numpy as np
import polars as pl

from service.model.data.sample import get_balance_sample_from_files
from service.model.pipeline.distill import DistilledClassifier
from service.model.experiments.results_benchmark import (
    CIC_TEST_PATHS,
    CONTRACT_PATH,
    N_EVAL_PER_LABEL,
    RATIO_RAW,
    SEED,
    x_contract5,
)

EVAL_COLS = sorted(set(RATIO_RAW) | {"Label"})
DIV_THRESHOLD = 0.30
HIGH_RISK_JUMP = 2.0
EMA_ALPHA = 0.30
ATTACK_FRACS = (0.10, 0.20, 0.30, 0.40, 0.50)   # 10% → 50%
BENIGN_DRIFT = (0.0, 0.15, 0.30, 0.45, 0.60)    # pkt_len_mean 良性上移比例（業務高峰）
RENAME = {"Total Backward Packets": "Total Bwd Packets"}


def _select(cols):
    return lambda lf: lf.select(cols)


def _spec_with_bounds(base: dict, vals: np.ndarray) -> dict:
    spec = copy.deepcopy(base)
    for i, b in enumerate(spec["quantile_bounds"]):
        v = float(max(vals[i], 0.0))
        if b["type"] == "absolute":
            b["value"] = int(round(v))
        else:
            b["numer"] = int(round(v * b["denom"]))
    return spec


def _clf(spec: dict) -> DistilledClassifier:
    clf = DistilledClassifier.__new__(DistilledClassifier)
    clf.bounds = spec["quantile_bounds"]
    clf.score_table = np.asarray(spec["score_table"])
    clf.threshold = spec["threshold"]
    return clf


def _vals(spec: dict) -> np.ndarray:
    return np.array([b["value"] if b["type"] == "absolute" else b["numer"] / b["denom"]
                     for b in spec["quantile_bounds"]])


def f1_fnr(clf: DistilledClassifier, win: pl.DataFrame, y: np.ndarray) -> tuple[float, float, float]:
    s = clf.score(win.rename(RENAME))
    pred = (s >= clf.threshold).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    fnr = fn / (fn + tp) if fn + tp else 0.0
    fpr = fp / (fp + ((pred == 0) & (y == 0)).sum()) if (y == 0).sum() else 0.0
    return f1, fnr, fpr


def drift_pkt_len(df: pl.DataFrame, frac: float) -> pl.DataFrame:
    """良性漂移：BENIGN 列 pkt_len_mean 上移 frac（模擬封包變大的業務高峰）。"""
    if frac == 0:
        return df
    is_b = df["Label"] == "BENIGN"
    return df.with_columns(
        pl.when(is_b)
        .then(pl.col("Packet Length Mean") * (1.0 + frac))
        .otherwise(pl.col("Packet Length Mean"))
        .alias("Packet Length Mean"))


def main() -> None:
    base = json.load(open(CONTRACT_PATH))
    ref_vals = _vals(base)
    static_clf = _clf(base)

    pool = get_balance_sample_from_files(
        CIC_TEST_PATHS, sample_count_per_label=N_EVAL_PER_LABEL, seed=SEED,
        transform=_select(EVAL_COLS))
    is_b = pool["Label"].to_numpy() == "BENIGN"
    benign = pool.filter(pl.Series(is_b)); attack = pool.filter(pl.Series(~is_b))
    benign_base_alert = float((static_clf.score(benign.rename(RENAME)) >= static_clf.threshold).mean())

    gated_vals = ref_vals.copy()
    W = 6000

    print("漂移場景：5 視窗，攻擊 10%→50%，BENIGN pkt_len_mean 漸增")
    print(f"benign baseline high-risk rate={benign_base_alert:.3f}\n")
    hdr = (f"{'win':>4}{'atk%':>6}{'drift':>7} | "
           f"{'StaticF1':>9}{'StatFNR':>8} | {'PeriF1':>8}{'PeriFNR':>8}{'gate':>13} | "
           f"{'GateF1':>8}{'GateFNR':>8}{'g.gate':>13}")
    print(hdr)
    out = {"scope": "CIC-DDoS2019 only", "windows": []}

    for w, (af, bd) in enumerate(zip(ATTACK_FRACS, BENIGN_DRIFT)):
        n_atk = int(W * af); n_ben = W - n_atk
        win = pl.concat([
            benign.sample(min(n_ben, len(benign)), with_replacement=n_ben > len(benign), seed=SEED + w),
            attack.sample(min(n_atk, len(attack)), with_replacement=n_atk > len(attack), seed=SEED + w),
        ])
        win = drift_pkt_len(win, bd)
        y = (win["Label"].to_numpy() != "BENIGN").astype(int)
        med = np.nanmedian(x_contract5(win), axis=0)

        # Static
        s_f1, s_fnr, _ = f1_fnr(static_clf, win, y)
        # Periodic（每視窗重算）
        peri_clf = _clf(_spec_with_bounds(base, med))
        p_f1, p_fnr, _ = f1_fnr(peri_clf, win, y)
        peri_div = float(np.mean(np.abs(med - ref_vals) / (np.abs(ref_vals) + 1e-9)))
        # Gated（dual-sketch + decide_gate，以當前 gated_vals 為 reference）
        divg = float(np.mean(np.abs(med - gated_vals) / (np.abs(gated_vals) + 1e-9)))
        hr_ratio = float((static_clf.score(win.rename(RENAME)) >= static_clf.threshold).mean()) / (benign_base_alert + 1e-9)
        jump = hr_ratio > HIGH_RISK_JUMP
        if divg > DIV_THRESHOLD:
            g_gate = "AttackFreeze" if jump else "Normal"
        else:
            g_gate = "Uncertain"
        if g_gate == "Normal":
            gated_vals = EMA_ALPHA * med + (1 - EMA_ALPHA) * gated_vals
        gated_clf = _clf(_spec_with_bounds(base, gated_vals))
        g_f1, g_fnr, _ = f1_fnr(gated_clf, win, y)
        peri_gate = "AttackFreeze" if (peri_div > DIV_THRESHOLD and jump) else (
            "Normal" if peri_div > DIV_THRESHOLD else "Uncertain")

        print(f"{w:>4}{int(af*100):>6}{bd:>7.2f} | "
              f"{s_f1:>9.3f}{s_fnr:>8.3f} | {p_f1:>8.3f}{p_fnr:>8.3f}{peri_gate:>13} | "
              f"{g_f1:>8.3f}{g_fnr:>8.3f}{g_gate:>13}")
        out["windows"].append({
            "win": w, "attack_frac": af, "benign_drift": bd,
            "static": {"f1": s_f1, "fnr": s_fnr},
            "periodic": {"f1": p_f1, "fnr": p_fnr},
            "gated": {"f1": g_f1, "fnr": g_fnr, "gate": g_gate}})

    with open("service/model/experiments/run37_drift_eval.json", "w") as f:
        json.dump(out, f, indent=2, default=float)
    print("\nWrote -> service/model/experiments/run37_drift_eval.json")


if __name__ == "__main__":
    main()
