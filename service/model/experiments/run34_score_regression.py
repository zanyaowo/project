"""Run 34 — Student score regression vs bucket classification（E1/E2，CIC-DDoS2019 in-scope）。

回答 reviewer 必問：「為什麼不讓 student 直接回歸 IF 異常分數？」

設定（無 ground-truth label 參與蒸餾，純 teacher→student）：
  teacher  = Contract5 連續 IF（results_benchmark 的最終 teacher），train=03-11 BENIGN
  蒸餾切片 = 01-12 balanced，隨機對半切 distill-fit / eval（不洩漏 ground truth）
  student-reg     = DecisionTreeRegressor，MSE 回歸 teacher 分數（contract-5 連續特徵）
  student-bucket  = 部署 binarized 32-entry（model.json）

對照軸（E2）：
  - Ranking preservation：Spearman(student score, teacher score)
  - Detection @FPR≤1%：ROC-AUC / PR-AUC / F1（對 ground-truth label）
  - Top-k attack recall：前 k% 高分流量抓到多少真攻擊

假設：忠實回歸 teacher 分數 → 繼承 teacher 在嚴格操作點的不可用性（F1≈0.11）；
      分位桶把分數分布重塑為操作點穩健（F1≈0.90）。結論一律指向實測數字。

範圍：CIC-DDoS2019 only。執行：
  python -m service.model.experiments.run34_score_regression
"""
from __future__ import annotations

import json

import numpy as np
from sklearn.tree import DecisionTreeRegressor

from service.model.data.sample import (
    get_balance_sample_from_files,
    get_normal_sample_from_files,
)
from service.model.metrics import threshold_at_fpr
from service.model.pipeline.distill import DistilledClassifier
from service.model.experiments.results_benchmark import (
    CIC_TRAIN_PATHS,
    CIC_TEST_PATHS,
    CONTRACT_PATH,
    N_EVAL_PER_LABEL,
    N_TRAIN_PER_SOURCE,
    RATIO_RAW,
    SEED,
    TARGET_FPR,
    fit_if,
    metrics_at_fpr,
    score_if,
    x_contract5,
)

EVAL_COLS = sorted(set(RATIO_RAW) | {"Label"})


def _select(cols):
    return lambda lf: lf.select(cols)


def spearman(a: np.ndarray, b: np.ndarray) -> float:
    """Spearman rank correlation via Pearson of ranks（避免 scipy 依賴）。"""
    m = np.isfinite(a) & np.isfinite(b)
    ra = np.argsort(np.argsort(a[m])).astype(float)
    rb = np.argsort(np.argsort(b[m])).astype(float)
    return float(np.corrcoef(ra, rb)[0, 1])


def topk_recall(y: np.ndarray, score: np.ndarray, k_frac: float) -> float:
    """前 k% 高分流量中，真攻擊佔全部真攻擊的比例。"""
    n_top = max(1, int(len(score) * k_frac))
    top_idx = np.argsort(-score)[:n_top]
    return float(y[top_idx].sum() / y.sum())


def main() -> None:
    train = get_normal_sample_from_files(
        CIC_TRAIN_PATHS, n=N_TRAIN_PER_SOURCE, seed=SEED, transform=_select(RATIO_RAW))
    ev = get_balance_sample_from_files(
        CIC_TEST_PATHS, sample_count_per_label=N_EVAL_PER_LABEL, seed=SEED,
        transform=_select(EVAL_COLS))

    # teacher：Contract5 連續 IF（train=03-11 BENIGN）
    sc_t, m_t = fit_if(x_contract5(train))

    # 蒸餾切片對半切（無 ground-truth 參與 student 訓練）
    rng = np.random.default_rng(SEED)
    perm = rng.permutation(len(ev))
    half = len(ev) // 2
    fit_idx, eval_idx = perm[:half], perm[half:]
    ev_fit, ev_eval = ev[fit_idx], ev[eval_idx]

    Xfit = x_contract5(ev_fit)
    Xev = x_contract5(ev_eval)
    y = (ev_eval["Label"].to_numpy() != "BENIGN").astype(int)
    labels = ev_eval["Label"].to_numpy()

    t_fit = score_if(sc_t, m_t, Xfit)     # teacher 分數（蒸餾目標）
    t_eval = score_if(sc_t, m_t, Xev)     # teacher 分數（eval）

    # student-reg：回歸 teacher 分數（只用 finite 列）
    mfit = np.isfinite(Xfit).all(1) & np.isfinite(t_fit)
    reg = DecisionTreeRegressor(max_depth=8, random_state=SEED)
    reg.fit(Xfit[mfit], t_fit[mfit])
    s_reg = np.full(len(Xev), -np.inf)
    mev = np.isfinite(Xev).all(1)
    s_reg[mev] = reg.predict(Xev[mev])

    # student-bucket：部署 binarized 32-entry
    clf = DistilledClassifier.from_json(CONTRACT_PATH)
    s_bucket = clf.score(ev_eval.rename({"Total Backward Packets": "Total Bwd Packets"})).astype(float)

    rows = [
        ("teacher (Contract5 連續)", t_eval),
        ("student-reg (DT, MSE→teacher)", s_reg),
        ("student-bucket (32-entry)", s_bucket),
    ]
    print("\n===== Detection @FPR≤1% (CIC-DDoS2019 in-scope, eval half) =====")
    hdr = f"{'model':<32}{'AUC':>8}{'PR-AUC':>8}{'F1@1%':>8}{'R@1%':>8}{'Spear→T':>9}{'top5%R':>8}"
    print(hdr)
    out = {"scope": "CIC-DDoS2019 only", "op_point": f"FPR<={TARGET_FPR}", "models": {}}
    for name, s in rows:
        met = metrics_at_fpr(y, s, TARGET_FPR)
        sp = spearman(s, t_eval)
        tk = topk_recall(y, np.where(np.isfinite(s), s, -np.inf), 0.05)
        print(f"{name:<32}{met['roc_auc']:>8.3f}{met['pr_auc']:>8.3f}{met['f1']:>8.3f}"
              f"{met['recall']:>8.3f}{sp:>9.3f}{tk:>8.3f}")
        out["models"][name] = {**met, "spearman_to_teacher": sp, "top5pct_recall": tk}

    print("\n--- per-attack recall @FPR≤1% (student-reg vs student-bucket) ---")
    thr_r = threshold_at_fpr(y[np.isfinite(s_reg)], s_reg[np.isfinite(s_reg)], TARGET_FPR)
    thr_b = threshold_at_fpr(y, s_bucket, TARGET_FPR)
    pr_r, pr_b = (s_reg >= thr_r), (s_bucket >= thr_b)
    print(f"  {'attack':<22}{'reg':>8}{'bucket':>8}")
    for lab in sorted(set(labels.tolist())):
        if lab == "BENIGN":
            continue
        mk = labels == lab
        print(f"  {lab:<22}{pr_r[mk].mean():>8.3f}{pr_b[mk].mean():>8.3f}")

    with open("service/model/experiments/run34_score_regression.json", "w") as f:
        json.dump(out, f, indent=2, default=float)
    print("\nWrote -> service/model/experiments/run34_score_regression.json")


if __name__ == "__main__":
    main()
