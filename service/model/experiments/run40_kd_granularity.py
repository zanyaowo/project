"""run40 — KD 保真度 vs 桶粒度（檢驗「桶太少」假設，CIC-DDoS2019 in-scope）。

run39 發現：N=2（32 桶）下，KD（per-bucket teacher 聚合）與 binarized-IF 兩種
填法在偵測上等價（F1≈0.90），且兩者對 teacher 的 Spearman 都只有 ~0.55。
假設：這是「桶切分太粗」的產物——桶內 teacher 排序被整片抹掉，故填法不重要。

本實驗用**同一個連續 Contract5 teacher**，在 N=2/4/8（32 / 1024 / 32768 桶）三種
粒度下，各以兩種方式填桶並對照：
  - KD          : per-bucket 連續 teacher 分數聚合（distill_kd.build_kd_score_table）
  - binarized-IF: 在 bucket index 上重訓 IF 打分建表（run30.build_score_table）

預期（若假設成立）：桶變細 → KD 的 Spearman→teacher 上升（更保真）；兩法在偵測
操作點上的差距也可能隨粒度改變。但桶數爆炸時蒸餾池覆蓋率驟降（fallback 主導），
故同時報告「eval 流落入空桶（fallback）的比例」以界定 N=8 結論的可信度。

邊界與 teacher 訓練皆 CIC-only（硬邊界）。執行：
  python -m service.model.experiments.run40_kd_granularity
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
from service.model.pipeline.distill_kd import build_kd_score_table
from service.model.experiments.run27_boundary_overfit_check import (
    CONTAMINATION,
    N_ESTIMATORS,
    N_EVAL_PER_LABEL,
    N_TRAIN_PER_SOURCE,
    SEED,
    to_norm_cic,
)
from service.model.experiments.run30_n_sweep import (
    CIC_TRAIN_PATHS,
    CIC_TEST_PATHS,
    BoundsStore,
    FEATURE_EXTRACTORS,
    _ALL,
    add_bucket_features,
    build_score_table,
    col_name,
    encode_bucket_indices,
)
from service.model.experiments.results_benchmark import (
    TARGET_FPR,
    fit_if,
    metrics_at_fpr,
    score_if,
)
from service.model.experiments.run34_score_regression import spearman

RAW_COLS = [
    "Fwd Packet Length Max", "Fwd Packet Length Mean", "Total Fwd Packets",
    "Total Backward Packets", "Packet Length Std", "Packet Length Mean", "Protocol",
]
EVAL_COLS = sorted(set(RAW_COLS) | {"Label"})
N_VALUES = [2, 4, 8]
RESULTS_OUT = "service/model/experiments/run40_kd_granularity.json"


def _select(cols):
    return lambda lf: lf.select(cols)


def x_cont(df) -> np.ndarray:
    """連續 Contract5 teacher 輸入（5 連續特徵，與 run30 FEATURE_EXTRACTORS 一致）。"""
    return np.column_stack([FEATURE_EXTRACTORS[f](df) for f in _ALL])


def _bucket_idx(df, store, n_map, feat_cols, table_size) -> np.ndarray:
    bdf = add_bucket_features(df, store, n_map)
    x = bdf.select(feat_cols).to_numpy().astype(np.float32)
    return np.clip(encode_bucket_indices(x, n_map), 0, table_size - 1)


def main() -> None:
    # ── 連續 teacher（CIC 03-11 BENIGN）＋ 蒸餾池（CIC 01-12 balanced 對半切）──
    train = to_norm_cic(get_normal_sample_from_files(
        CIC_TRAIN_PATHS, n=N_TRAIN_PER_SOURCE, seed=SEED, transform=_select(RAW_COLS)))
    ev = to_norm_cic(get_balance_sample_from_files(
        CIC_TEST_PATHS, sample_count_per_label=N_EVAL_PER_LABEL, seed=SEED,
        transform=_select(EVAL_COLS)))

    sc_t, m_t = fit_if(x_cont(train))

    rng = np.random.default_rng(SEED)
    perm = rng.permutation(len(ev))
    half = len(ev) // 2
    ev_fit, ev_eval = ev[perm[:half]], ev[perm[half:]]

    y = (ev_eval["Label"].to_numpy() != "BENIGN").astype(int)
    t_fit = score_if(sc_t, m_t, x_cont(ev_fit))
    t_eval = score_if(sc_t, m_t, x_cont(ev_eval))

    # teacher 自身基準（同 eval）
    m_teacher = metrics_at_fpr(y, t_eval, TARGET_FPR)
    print(f"teacher (Contract5 連續)  F1@1%={m_teacher['f1']:.3f}  R@1%={m_teacher['recall']:.3f}  "
          f"Spear→T=1.000")

    store = BoundsStore()
    store.compute(train, N_VALUES)

    print(f"\n{'N':>3}{'buckets':>9}{'fallback%':>11}"
          f"{'KD F1@1%':>10}{'bin F1@1%':>11}{'KD Spear→T':>12}{'bin Spear→T':>13}")
    print("-" * 69)

    out = {"scope": "CIC-DDoS2019 only", "op_point": f"FPR<={TARGET_FPR}",
           "teacher": {k: m_teacher[k] for k in ("f1", "recall", "roc_auc")}, "by_N": []}

    for N in N_VALUES:
        n_map = {f: N for f in _ALL}
        feat_cols = [col_name(f, N) for f in _ALL]
        table_size = N ** len(_ALL)

        idx_fit = _bucket_idx(ev_fit, store, n_map, feat_cols, table_size)
        idx_eval = _bucket_idx(ev_eval, store, n_map, feat_cols, table_size)

        # KD 表：per-bucket 連續 teacher 聚合
        kd_table, empty = build_kd_score_table(t_fit, idx_fit, n_buckets=table_size, aggregate="mean")
        kd_arr = np.asarray(kd_table, dtype=np.float64)
        empty_set = set(empty)
        fallback_frac = float(np.mean([b in empty_set for b in idx_eval]))

        # binarized-IF 表：bucket index 上重訓 IF 打分（run30 法）
        train_b = add_bucket_features(train, store, n_map)
        xb = train_b.select(feat_cols).to_numpy().astype(np.float32)
        xb = xb[np.isfinite(xb).all(axis=1)]
        scaler = StandardScaler()
        m_if = IsolationForest(n_estimators=N_ESTIMATORS, contamination=float(CONTAMINATION),
                               random_state=SEED, n_jobs=-1)
        m_if.fit(scaler.fit_transform(xb))
        bin_arr = build_score_table(m_if, scaler, n_map)

        s_kd = kd_arr[idx_eval]
        s_bin = bin_arr[idx_eval]

        m_kd = metrics_at_fpr(y, s_kd, TARGET_FPR)
        m_bin = metrics_at_fpr(y, s_bin, TARGET_FPR)
        sp_kd = spearman(s_kd, t_eval)
        sp_bin = spearman(s_bin, t_eval)

        print(f"{N:>3}{table_size:>9}{fallback_frac*100:>10.1f}%"
              f"{m_kd['f1']:>10.3f}{m_bin['f1']:>11.3f}{sp_kd:>12.3f}{sp_bin:>13.3f}")

        out["by_N"].append({
            "N": N, "table_size": table_size,
            "eval_fallback_frac": fallback_frac, "empty_buckets": len(empty),
            "kd": {k: m_kd[k] for k in ("f1", "recall", "roc_auc")}, "kd_spearman_to_teacher": sp_kd,
            "binarized": {k: m_bin[k] for k in ("f1", "recall", "roc_auc")}, "bin_spearman_to_teacher": sp_bin,
        })

    with open(RESULTS_OUT, "w") as f:
        json.dump(out, f, indent=2, default=float)
    print(f"\nWrote -> {RESULTS_OUT}")
    print("\n讀法：若 KD Spear→T 隨 N 上升 → 證實『桶太少』導致低保真；"
          "fallback% 高（N=8）時該行結論不可信（蒸餾池覆蓋不足）。")


if __name__ == "__main__":
    main()
