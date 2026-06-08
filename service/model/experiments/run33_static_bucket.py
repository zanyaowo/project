"""Run 33 — IF + static quantile bucket baseline（E1 對照組，CIC-DDoS2019 in-scope）。

E1 Table 1 需要「IF + static quantile bucket」baseline：分位桶邊界只用訓練集 BENIGN
算一次（不更新），IF 在桶索引上訓練。本腳本對照 N=2 / N=4，並與 results_benchmark.py
的 Contract5 連續 teacher / deployed binarized 同 train/eval split、同操作點（FPR≤1%）。

特徵：contract-5（protocol + pkt_len_mean + fwd_max_q + sym_ratio + pkt_cv_sq）。
桶化：每特徵以 BENIGN 訓練集的 i/N 分位數（i=1..N-1）為邊界 → 整數桶索引 [0, N-1]。
  N=2 等價部署的中位數二值化（1 條邊界）；N=4 用 25/50/75 百分位（3 條邊界，1024-entry）。

範圍：CIC-DDoS2019 only。執行：
  python -m service.model.experiments.run33_static_bucket
"""
from __future__ import annotations

import json

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from service.model.data.sample import (
    get_balance_sample_from_files,
    get_normal_sample_from_files,
)
from service.model.metrics import threshold_at_fpr
from service.model.experiments.results_benchmark import (
    CIC_TRAIN_PATHS,
    CIC_TEST_PATHS,
    CONTAMINATION,
    N_ESTIMATORS,
    N_EVAL_PER_LABEL,
    N_TRAIN_PER_SOURCE,
    SEED,
    TARGET_FPR,
    RATIO_RAW,
    metrics_at_fpr,
    x_contract5,
)

EVAL_COLS = sorted(set(RATIO_RAW) | {"Label"})


def _select(cols):
    return lambda lf: lf.select(cols)


def fit_quantile_edges(x_train: np.ndarray, n_buckets: int) -> list[np.ndarray]:
    """每欄回傳 N-1 條分位邊界（i/N 分位，i=1..N-1），只用 BENIGN 訓練集。"""
    qs = [i / n_buckets for i in range(1, n_buckets)]
    return [np.quantile(x_train[:, c], qs) for c in range(x_train.shape[1])]


def bucketize(x: np.ndarray, edges: list[np.ndarray]) -> np.ndarray:
    """以固定邊界把連續特徵轉成整數桶索引 [0, N-1]（static，不更新）。"""
    cols = [np.searchsorted(edges[c], x[:, c], side="right") for c in range(x.shape[1])]
    return np.column_stack(cols).astype(np.float64)


def fit_if(x: np.ndarray):
    mask = np.isfinite(x).all(axis=1)
    sc = StandardScaler()
    m = IsolationForest(n_estimators=N_ESTIMATORS, contamination=CONTAMINATION,
                        random_state=SEED, n_jobs=-1)
    m.fit(sc.fit_transform(x[mask]))
    return sc, m


def score_if(sc, m, x: np.ndarray) -> np.ndarray:
    out = np.full(len(x), -np.inf)
    mask = np.isfinite(x).all(axis=1)
    if mask.any():
        out[mask] = -m.score_samples(sc.transform(x[mask]))
    return out


def main() -> None:
    train = get_normal_sample_from_files(
        CIC_TRAIN_PATHS, n=N_TRAIN_PER_SOURCE, seed=SEED, transform=_select(RATIO_RAW))
    ev = get_balance_sample_from_files(
        CIC_TEST_PATHS, sample_count_per_label=N_EVAL_PER_LABEL, seed=SEED,
        transform=_select(EVAL_COLS))
    labels = ev["Label"].to_numpy()
    y = (labels != "BENIGN").astype(int)
    print(f"train BENIGN={len(train)}  eval={len(ev)}  (attack={int(y.sum())}, benign={int((y==0).sum())})")

    xtr = x_contract5(train)
    xev = x_contract5(ev)
    finite_tr = np.isfinite(xtr).all(axis=1)
    xtr = xtr[finite_tr]

    N_SWEEP = (2, 4, 8)
    FPRS = (0.01, 0.05, 0.10)
    print("\n===== IF + static quantile bucket (CIC-DDoS2019 in-scope) =====")
    hdr = (f"{'model':<22}{'table':>8}{'AUC':>8}{'PR-AUC':>8}{'F1@1%':>8}"
           + "".join(f"{'R@'+str(int(p*100))+'%':>8}" for p in FPRS))
    print(hdr)
    out = {"scope": "CIC-DDoS2019 only", "op_point": f"FPR<={TARGET_FPR}", "static_bucket": {}}
    per_attack = {}
    for n_buckets in N_SWEEP:
        edges = fit_quantile_edges(xtr, n_buckets)
        sc, m = fit_if(bucketize(xtr, edges))
        s = score_if(sc, m, bucketize(xev, edges))
        finite = np.isfinite(s)
        met = metrics_at_fpr(y, s, TARGET_FPR)
        table = n_buckets ** 5
        recs = {}
        for p in FPRS:
            thr = threshold_at_fpr(y[finite], s[finite], p)
            recs[p] = float((s >= thr)[y == 1].mean())
        print(f"{'IF static N='+str(n_buckets):<22}{table:>8}{met['roc_auc']:>8.3f}"
              f"{met['pr_auc']:>8.3f}{met['f1']:>8.3f}"
              + "".join(f"{recs[p]:>8.3f}" for p in FPRS))
        out["static_bucket"][f"N{n_buckets}"] = {
            **met, "table_entries": table,
            "recall_at_fpr": {f"{p}": recs[p] for p in FPRS}}
        thr1 = threshold_at_fpr(y[finite], s[finite], TARGET_FPR)
        per_attack[n_buckets] = (s >= thr1)

    print("\n--- per-attack recall @FPR≤1% ---")
    print(f"  {'attack':<22}" + "".join(f"{'N='+str(n):>8}" for n in N_SWEEP))
    for lab in sorted(set(labels.tolist())):
        if lab == "BENIGN":
            continue
        mk = labels == lab
        print(f"  {lab:<22}" + "".join(f"{per_attack[n][mk].mean():>8.3f}" for n in N_SWEEP))

    with open("service/model/experiments/run33_static_bucket.json", "w") as f:
        json.dump(out, f, indent=2, default=float)
    print("\nWrote -> service/model/experiments/run33_static_bucket.json")


if __name__ == "__main__":
    main()
