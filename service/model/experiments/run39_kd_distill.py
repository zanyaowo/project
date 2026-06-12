"""run39 — 正式 teacher→student KD（per-bucket 聚合）對照組（CIC-DDoS2019 in-scope）。

目的：補強報告未來工作「正式 teacher-student distillation」。現行部署 32-entry 表
由「二值化特徵重訓 IF」產生（非正式 KD）；本實驗改以 **Contract5 連續 teacher 的
分數分布**蒸餾 score_table（per-bucket teacher-score aggregation），並與部署
binarized 版在**同一 32-桶切分、同一 eval split** 上對照。

對照組性質（不動部署 model.json）：
  - quantile_bounds 沿用部署 model.json（同一桶切分），只換 score_table / threshold
    ⇒ 唯一變因＝score_table 產生法（binarized-IF vs teacher 聚合）。
  - teacher = Contract5 連續 IF，train = CIC 03-11 BENIGN（CIC-only 硬邊界）。
  - 蒸餾池 = CIC 01-12 balanced 的一半（不用 ground-truth 訓 student），eval = 另一半。

預期（依「完整切分」洞察）：KD 表分數與 teacher 同序（Spearman→teacher 應遠高於
部署 binarized 的 0.549），但因此也**繼承 teacher 在嚴格操作點的低 recall**——
即正式 KD 不必然優於目前 binarized 表，反而印證報告 Table 2 的論點：binarized
表的價值在於重塑分數分布，而非忠實複製 teacher。結論一律掛實測數字。

執行：
  python -m service.model.experiments.run39_kd_distill
"""
from __future__ import annotations

import json

import numpy as np

from service.model.data.sample import (
    get_balance_sample_from_files,
    get_normal_sample_from_files,
)
from service.model.metrics import threshold_at_fpr
from service.model.pipeline.distill import DistilledClassifier
from service.model.pipeline.distill_kd import (
    SCORE_SCALE,
    build_kd_score_table,
    kd_rules_from_deployed,
)
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
from service.model.experiments.run34_score_regression import spearman

EVAL_COLS = sorted(set(RATIO_RAW) | {"Label"})
KD_CONTRACT_OUT = "service/model/experiments/run39_kd_distill_rules.json"
RESULTS_OUT = "service/model/experiments/run39_kd_distill.json"
CONTAMINATION = 0.01  # 與部署一致：threshold 取 teacher 分數 (1-contamination) 分位（nominal）


def _select(cols):
    return lambda lf: lf.select(cols)


def main() -> None:
    deployed = DistilledClassifier.from_json(CONTRACT_PATH)
    with open(CONTRACT_PATH) as f:
        deployed_rules = json.load(f)

    # ── teacher：Contract5 連續 IF（CIC 03-11 BENIGN，CIC-only 硬邊界）──────
    train = get_normal_sample_from_files(
        CIC_TRAIN_PATHS, n=N_TRAIN_PER_SOURCE, seed=SEED, transform=_select(RATIO_RAW))
    sc_t, m_t = fit_if(x_contract5(train))

    # ── 蒸餾池：CIC 01-12 balanced，對半切（fit 不用 ground-truth）──────────
    ev = get_balance_sample_from_files(
        CIC_TEST_PATHS, sample_count_per_label=N_EVAL_PER_LABEL, seed=SEED,
        transform=_select(EVAL_COLS))
    rng = np.random.default_rng(SEED)
    perm = rng.permutation(len(ev))
    half = len(ev) // 2
    ev_fit, ev_eval = ev[perm[:half]], ev[perm[half:]]

    ev_fit_r = ev_fit.rename({"Total Backward Packets": "Total Bwd Packets"})
    ev_eval_r = ev_eval.rename({"Total Backward Packets": "Total Bwd Packets"})

    # teacher 分數（fit 池）＋ 同一部署切分的桶索引 → KD score_table
    t_fit = score_if(sc_t, m_t, x_contract5(ev_fit))
    idx_fit = deployed._build_index(ev_fit_r)
    score_table_kd, empty_buckets = build_kd_score_table(t_fit, idx_fit, aggregate="mean")

    # nominal threshold：teacher fit 分數 (1-contamination) 分位（×SCORE_SCALE）。
    # 註：下方 eval 用 metrics_at_fpr 重校準至 FPR≤1%，此欄僅為 contract 自洽。
    finite_fit = np.isfinite(t_fit)
    thr_nominal = int(round(float(np.quantile(t_fit[finite_fit], 1 - CONTAMINATION)) * SCORE_SCALE))

    kd_rules = kd_rules_from_deployed(deployed_rules, score_table_kd, thr_nominal)
    kd_clf = DistilledClassifier(kd_rules)  # 通過 v1 contract 驗證即為合法部署格式
    with open(KD_CONTRACT_OUT, "w") as f:
        json.dump(kd_rules, f, indent=2)

    print(f"KD score_table 蒸餾完成：empty buckets={empty_buckets} "
          f"({len(empty_buckets)}/32 用全域 fallback)")
    print(f"  nominal threshold={thr_nominal}（eval 以 FPR≤1% 重校準）")
    print(f"  KD contract -> {KD_CONTRACT_OUT}")

    # ── eval（另一半，對 ground-truth）───────────────────────────────────
    y = (ev_eval["Label"].to_numpy() != "BENIGN").astype(int)
    labels = ev_eval["Label"].to_numpy()
    t_eval = score_if(sc_t, m_t, x_contract5(ev_eval))
    s_kd = kd_clf.score(ev_eval_r).astype(float)
    s_bin = deployed.score(ev_eval_r).astype(float)

    rows = [
        ("teacher (Contract5 連續)", t_eval),
        ("student-KD (per-bucket 聚合)", s_kd),
        ("student-binarized (部署 32-entry)", s_bin),
    ]
    print("\n===== Detection @FPR≤1% (CIC-DDoS2019 in-scope, eval half) =====")
    hdr = f"{'model':<34}{'AUC':>8}{'PR-AUC':>8}{'F1@1%':>8}{'R@1%':>8}{'Spear→T':>9}"
    print(hdr)
    out = {
        "scope": "CIC-DDoS2019 only",
        "op_point": f"FPR<={TARGET_FPR}",
        "method": "per-bucket teacher-score aggregation (deployed bounds, control group)",
        "empty_buckets": empty_buckets,
        "models": {},
    }
    for name, s in rows:
        met = metrics_at_fpr(y, s, TARGET_FPR)
        sp = spearman(s, t_eval)
        print(f"{name:<34}{met['roc_auc']:>8.3f}{met['pr_auc']:>8.3f}{met['f1']:>8.3f}"
              f"{met['recall']:>8.3f}{sp:>9.3f}")
        out["models"][name] = {**met, "spearman_to_teacher": sp}

    # per-attack：KD vs binarized（同 eval、各自 FPR≤1% 重校準）
    print("\n--- per-attack recall @FPR≤1% (student-KD vs student-binarized) ---")
    thr_kd = threshold_at_fpr(y[np.isfinite(s_kd)], s_kd[np.isfinite(s_kd)], TARGET_FPR)
    thr_b = threshold_at_fpr(y, s_bin, TARGET_FPR)
    pr_kd, pr_b = (s_kd >= thr_kd), (s_bin >= thr_b)
    print(f"  {'attack':<22}{'KD':>8}{'binarized':>11}")
    for lab in sorted(set(labels.tolist())):
        if lab == "BENIGN":
            continue
        mk = labels == lab
        print(f"  {lab:<22}{pr_kd[mk].mean():>8.3f}{pr_b[mk].mean():>11.3f}")

    with open(RESULTS_OUT, "w") as f:
        json.dump(out, f, indent=2, default=float)
    print(f"\nWrote -> {RESULTS_OUT}")


if __name__ == "__main__":
    main()
