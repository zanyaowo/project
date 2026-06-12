"""Run 35 — Supervised LR/RF 上界（E1 Table 1 最後一列，CIC-DDoS2019 in-scope）。

目的：給 E1 一個「有 attack label 的監督式上限參考」。我們的方法是無監督 IF + 分位桶
（不用 label）；本實驗量化「若允許用 label」在同 contract-5 特徵空間能到多高，作為上界。

時序限制（CLAUDE.md，違反即資料洩漏）：
  train = 03-11（較早，BENIGN + 攻擊 balanced，有 label）
  eval  = 01-12（較晚，balanced）
→ 監督式仍需跨日泛化（03-11 攻擊類型 ≠ 01-12 全部類型），是誠實的 in-scope 上界。

特徵：contract-5（與部署同空間，公平對照）。模型：LogisticRegression / RandomForest。
評估：ROC-AUC / PR-AUC / F1 / R @FPR≤1%（用 predict_proba 排序）。

範圍：CIC-DDoS2019 only。執行：
  python -m service.model.experiments.run35_supervised_baseline
"""
from __future__ import annotations

import json

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from service.model.data.sample import get_balance_sample_from_files
from service.model.experiments.results_benchmark import (
    CIC_TRAIN_PATHS,
    CIC_TEST_PATHS,
    N_EVAL_PER_LABEL,
    RATIO_RAW,
    SEED,
    TARGET_FPR,
    metrics_at_fpr,
    x_contract5,
)

EVAL_COLS = sorted(set(RATIO_RAW) | {"Label"})
N_TRAIN_PER_LABEL = 4000


def _select(cols):
    return lambda lf: lf.select(cols)


def _finite_xy(X: np.ndarray, y: np.ndarray):
    m = np.isfinite(X).all(axis=1)
    return X[m], y[m]


def main() -> None:
    # 監督式訓練集：03-11 balanced（含攻擊 label）
    tr = get_balance_sample_from_files(
        CIC_TRAIN_PATHS, sample_count_per_label=N_TRAIN_PER_LABEL, seed=SEED,
        transform=_select(EVAL_COLS))
    ev = get_balance_sample_from_files(
        CIC_TEST_PATHS, sample_count_per_label=N_EVAL_PER_LABEL, seed=SEED,
        transform=_select(EVAL_COLS))
    ytr = (tr["Label"].to_numpy() != "BENIGN").astype(int)
    yev = (ev["Label"].to_numpy() != "BENIGN").astype(int)
    Xtr, ytr = _finite_xy(x_contract5(tr), ytr)
    Xev = x_contract5(ev)
    mev = np.isfinite(Xev).all(axis=1)
    print(f"train(03-11)={len(Xtr)} (attack={int(ytr.sum())})  "
          f"eval(01-12)={int(mev.sum())} (attack={int(yev[mev].sum())})")

    scaler = StandardScaler().fit(Xtr)
    models = {
        "LogisticRegression": LogisticRegression(max_iter=1000, class_weight="balanced"),
        "RandomForest": RandomForestClassifier(
            n_estimators=200, random_state=SEED, n_jobs=-1, class_weight="balanced"),
    }

    print("\n===== Supervised 上界 (CIC-DDoS2019 in-scope, contract-5, FPR≤1%) =====")
    hdr = f"{'model':<22}{'AUC':>8}{'PR-AUC':>8}{'P':>7}{'R':>7}{'F1':>7}{'FPR':>7}{'FNR':>7}"
    print(hdr)
    out = {"scope": "CIC-DDoS2019 only", "op_point": f"FPR<={TARGET_FPR}",
           "feature_space": "contract-5", "supervised": {}}
    s_full = {}
    for name, clf in models.items():
        Xt = scaler.transform(Xtr) if name == "LogisticRegression" else Xtr
        clf.fit(Xt, ytr)
        Xe = scaler.transform(Xev[mev]) if name == "LogisticRegression" else Xev[mev]
        proba = clf.predict_proba(Xe)[:, 1]
        s = np.full(len(Xev), -np.inf)
        s[mev] = proba
        met = metrics_at_fpr(yev, s, TARGET_FPR)
        s_full[name] = s
        print(f"{name:<22}{met['roc_auc']:>8.3f}{met['pr_auc']:>8.3f}{met['precision']:>7.3f}"
              f"{met['recall']:>7.3f}{met['f1']:>7.3f}{met['fpr']:>7.3f}{met['fnr']:>7.3f}")
        out["supervised"][name] = met

    print("\n--- per-attack recall @FPR≤1% ---")
    from service.model.metrics import threshold_at_fpr
    labels = ev["Label"].to_numpy()
    thr = {n: threshold_at_fpr(yev[np.isfinite(s)], s[np.isfinite(s)], TARGET_FPR)
           for n, s in s_full.items()}
    print(f"  {'attack':<22}" + "".join(f"{n[:10]:>12}" for n in models))
    for lab in sorted(set(labels.tolist())):
        if lab == "BENIGN":
            continue
        mk = labels == lab
        print(f"  {lab:<22}" + "".join(
            f"{(s_full[n][mk] >= thr[n]).mean():>12.3f}" for n in models))

    with open("service/model/experiments/run35_supervised_baseline.json", "w") as f:
        json.dump(out, f, indent=2, default=float)
    print("\nWrote -> service/model/experiments/run35_supervised_baseline.json")


if __name__ == "__main__":
    main()
