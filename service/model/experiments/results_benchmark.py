"""results_benchmark — 為論文「成果與討論」產出實測數據（CIC-DDoS2019 in-scope）。

最終 teacher＝**five-contract 連續 IF**（protocol + pkt_len_mean + 3 比例，未二值化）。
本腳本做兩層對照（同 train/eval split、同 IF 超參，apples-to-apples）：

  [A] Teacher 對照（核心）：
      - Contract5 (FINAL teacher) ─ 5 連續 contract 特徵 IF
      - Abs20 (baseline)          ─ 20 維絕對特徵 IF（舊 if_model 系特徵集）
      回答：採用可重建的 5-contract 特徵，相對 20 維絕對特徵在 in-scope 付多少代價。

  [B] 蒸餾代價：部署 binarized 32-entry contract（model.json）同切片評估，
      量化「連續 teacher → 二值化 student」掉多少。

評估指標：ROC-AUC / PR-AUC / 固定 FPR=1% 操作點下 Precision/Recall/F1/FPR/FNR。
另含 per-flow 延遲（userspace）：IF 推論 vs contract 查表。

範圍：CIC-DDoS2019 only（CLAUDE.md 硬邊界）。不含 IDS2018 / BigFlow OOD。

執行：
  python -m service.model.experiments.results_benchmark
"""
from __future__ import annotations

import json
import time

import numpy as np
import polars as pl
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.preprocessing import StandardScaler

from service.model.data.sample import (
    get_balance_sample_from_files,
    get_normal_sample_from_files,
)
from service.model.metrics import threshold_at_fpr
from service.model.pipeline.distill import DistilledClassifier
from service.model.experiments.run27_boundary_overfit_check import (
    CIC_TRAIN_PATHS,
    CIC_TEST_PATHS,
    CONTAMINATION,
    N_ESTIMATORS,
    N_EVAL_PER_LABEL,
    N_TRAIN_PER_SOURCE,
    SEED,
)

CONTRACT_PATH = "service/firewall/firewall/src/data_format/model.json"
TARGET_FPR = 0.01

# 20 維絕對特徵集（舊 teacher if_model.joblib 所用，cleaned 欄名）。
ABS20_COLS = [
    "Source Port", "Destination Port", "Fwd Packet Length Max", "Max Packet Length",
    "min_seg_size_forward", "Init_Win_bytes_backward", "Init_Win_bytes_forward",
    "Total Fwd Packets", "Flow Bytes/s", "Fwd Header Length", "Flow Duration",
    "ACK Flag Count", "Flow Packets/s", "Active Std", "Bwd Avg Bulk Rate",
    "Bwd Avg Packets/Bulk", "Idle Std", "URG Flag Count", "CWE Flag Count",
    "ECE Flag Count",
]
# 重建 5-contract 連續特徵所需的原始欄位。
RATIO_RAW = [
    "Fwd Packet Length Max", "Fwd Packet Length Mean", "Total Fwd Packets",
    "Total Backward Packets", "Packet Length Std", "Packet Length Mean", "Protocol",
]
TRAIN_COLS = sorted(set(ABS20_COLS) | set(RATIO_RAW))
EVAL_COLS = sorted(set(TRAIN_COLS) | {"Label"})


def _select(cols):
    return lambda lf: lf.select(cols)


def _f64(df: pl.DataFrame, col: str) -> np.ndarray:
    return df[col].cast(pl.Float64, strict=False).to_numpy()


def x_abs20(df: pl.DataFrame) -> np.ndarray:
    return df.select([pl.col(c).cast(pl.Float64, strict=False) for c in ABS20_COLS]).to_numpy()


def x_contract5(df: pl.DataFrame) -> np.ndarray:
    max_pkt = _f64(df, "Fwd Packet Length Max")
    fwd_mean = _f64(df, "Fwd Packet Length Mean")
    fwd_p = _f64(df, "Total Fwd Packets")
    bwd_p = _f64(df, "Total Backward Packets")
    pkt_std = _f64(df, "Packet Length Std")
    pkt_mean = _f64(df, "Packet Length Mean")
    proto = _f64(df, "Protocol")
    return np.column_stack([
        proto, pkt_mean,
        max_pkt / (fwd_mean + 1.0),
        fwd_p / (bwd_p + 1.0),
        (pkt_std / (pkt_mean + 1.0)) ** 2,
    ])


def fit_if(x_train: np.ndarray):
    mask = np.isfinite(x_train).all(axis=1)
    sc = StandardScaler()
    m = IsolationForest(n_estimators=N_ESTIMATORS, contamination=CONTAMINATION,
                        random_state=SEED, n_jobs=-1)
    m.fit(sc.fit_transform(x_train[mask]))
    return sc, m


def score_if(sc, m, x: np.ndarray) -> np.ndarray:
    out = np.full(len(x), -np.inf)
    mask = np.isfinite(x).all(axis=1)
    if mask.any():
        out[mask] = -m.score_samples(sc.transform(x[mask]))
    return out


def metrics_at_fpr(y: np.ndarray, s: np.ndarray, target_fpr: float) -> dict:
    finite = np.isfinite(s)
    thr = threshold_at_fpr(y[finite], s[finite], target_fpr)
    pred = (s >= thr).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum()); fn = int(((pred == 0) & (y == 1)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    s_auc = s.copy(); s_auc[~finite] = s[finite].min() - 1.0
    return {
        "roc_auc": roc_auc_score(y, s_auc), "pr_auc": average_precision_score(y, s_auc),
        "precision": prec, "recall": rec, "f1": f1,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "fnr": fn / (fn + tp) if fn + tp else 0.0,
    }


def main() -> None:
    print(f"CIC-DDoS2019  train files={len(CIC_TRAIN_PATHS)}  test files={len(CIC_TEST_PATHS)}")
    train = get_normal_sample_from_files(
        CIC_TRAIN_PATHS, n=N_TRAIN_PER_SOURCE, seed=SEED, transform=_select(TRAIN_COLS))
    ev = get_balance_sample_from_files(
        CIC_TEST_PATHS, sample_count_per_label=N_EVAL_PER_LABEL, seed=SEED,
        transform=_select(EVAL_COLS))
    labels = ev["Label"].to_numpy()
    y = (labels != "BENIGN").astype(int)
    print(f"train BENIGN rows={len(train)}  eval rows={len(ev)}  "
          f"(attack={int(y.sum())}, benign={int((y==0).sum())})")

    # ── [A] Teacher 對照 ──────────────────────────────────────────────────
    sc5, m5 = fit_if(x_contract5(train))
    s5 = score_if(sc5, m5, x_contract5(ev))
    m_contract5 = metrics_at_fpr(y, s5, TARGET_FPR)

    sc20, m20 = fit_if(x_abs20(train))
    s20 = score_if(sc20, m20, x_abs20(ev))
    m_abs20 = metrics_at_fpr(y, s20, TARGET_FPR)

    # ── [B] 蒸餾代價：部署 binarized 32-entry contract ────────────────────
    ev_renamed = ev.rename({"Total Backward Packets": "Total Bwd Packets"})
    clf = DistilledClassifier.from_json(CONTRACT_PATH)
    s_bin = clf.score(ev_renamed).astype(np.float64)
    m_bin = metrics_at_fpr(y, s_bin, TARGET_FPR)

    print("\n===== Table 1 — Detection (CIC-DDoS2019 in-scope, op-point FPR≤1%) =====")
    hdr = f"{'model':<40}{'AUC':>8}{'PR-AUC':>8}{'P':>7}{'R':>7}{'F1':>7}{'FPR':>7}{'FNR':>7}"
    print(hdr)
    rows = [
        ("Teacher: Contract5 continuous (FINAL)", m_contract5),
        ("Baseline: Abs20 (20-dim absolute IF)", m_abs20),
        ("Student: deployed binarized 32-entry", m_bin),
    ]
    for name, m in rows:
        print(f"{name:<40}{m['roc_auc']:>8.3f}{m['pr_auc']:>8.3f}{m['precision']:>7.3f}"
              f"{m['recall']:>7.3f}{m['f1']:>7.3f}{m['fpr']:>7.3f}{m['fnr']:>7.3f}")

    # ── per-attack recall（最終 teacher Contract5 + 部署 binarized） ───────
    print("\n--- per-attack recall @FPR≤1% (in-scope subtypes) ---")
    thr5 = threshold_at_fpr(y[np.isfinite(s5)], s5[np.isfinite(s5)], TARGET_FPR)
    thrb = threshold_at_fpr(y, s_bin, TARGET_FPR)
    pred5, predb = (s5 >= thr5), (s_bin >= thrb)
    print(f"  {'attack':<22}{'n':>7}{'teacher5':>10}{'binarized':>11}")
    for lab in sorted(set(labels.tolist())):
        if lab == "BENIGN":
            continue
        mk = labels == lab
        print(f"  {lab:<22}{int(mk.sum()):>7}{pred5[mk].mean():>10.3f}{predb[mk].mean():>11.3f}")

    # ── 延遲（per-flow, userspace） ───────────────────────────────────────
    print("\n===== Table 2 (detection side) — per-flow latency (userspace) =====")
    x1 = x_contract5(ev.head(1))

    def t(fn, it=2000):
        fn()
        t0 = time.perf_counter()
        for _ in range(it):
            fn()
        return (time.perf_counter() - t0) / it * 1e6

    t_if = t(lambda: -m5.score_samples(sc5.transform(x1)))
    t_lookup = t(lambda: clf.score(ev_renamed.head(1)))
    print(f"  Contract5 IF per-flow inference : {t_if:10.2f} µs/flow")
    print(f"  contract table lookup (userspace proxy): {t_lookup:7.2f} µs/flow")
    print(f"  speedup (IF / lookup)           : {t_if / t_lookup:10.1f}x")
    print("  NOTE: kernel eBPF map-lookup ns 需 on-hardware + bpftool 另測；"
          "userspace lookup 含 polars/python overhead，為延遲上界。")

    out = {
        "scope": "CIC-DDoS2019 only",
        "eval_rows": int(len(ev)), "train_rows": int(len(train)),
        "op_point": f"FPR<={TARGET_FPR}",
        "detection": {
            "teacher_contract5_continuous_FINAL": m_contract5,
            "baseline_abs20": m_abs20,
            "student_binarized_32entry": m_bin,
        },
        "latency_us_per_flow": {
            "contract5_if_inference": t_if,
            "contract_lookup_userspace_proxy": t_lookup,
            "speedup": t_if / t_lookup,
        },
    }
    with open("service/model/experiments/results_benchmark.json", "w") as f:
        json.dump(out, f, indent=2, default=float)
    print("\nWrote -> service/model/experiments/results_benchmark.json")


if __name__ == "__main__":
    main()
