"""Run 31 — N=8 + Per-feature Additive Bucket Score（PAB-Score）驗證（CIC-only）

目的：量化 additive decomposition 對 N=8 全查表（32768-entry）的 AUC 損失，
     決定是否以 40-entry PAB-Score 取代 32768-entry 查表進行 eBPF 實作。

設計提案見 `docs/2_decision/quantile_bucket_strategy_log.md` Run 31 節。

方法（部署 contract 模式，與 eBPF 線上推論一致）：
  1. CIC BENIGN（03-11）訓練 IF，N=8（每特徵 8 桶）
  2. 列舉 8^5 = 32768 種 bucket 組合 → 對每組合算 IF anomaly score → full_table
  3. OLS（indicator 變數，5×8=40 欄 + intercept）擬合 additive model：
        IF_score(b₀..b₄) ≈ intercept + Σ sᵢ(bᵢ)
     得 40 個 per-bucket scores
  4. CIC 01-12 eval：對每攻擊類型分別用 full_table score 與 additive score 算 AUC
  5. Δ AUC = AUC(full) − AUC(additive) per attack；整數化後檢查 i32 range

決策門檻（quantile_bucket_strategy_log.md Run 31）：
  max Δ AUC < 0.02 且 FPR ≤ N=8 full 的 1.1×  →  採用 PAB-Score，進行 eBPF 實作

執行：
  uv run --project service/model python -m service.model.experiments.run31_additive_score
"""
from __future__ import annotations

from itertools import product

import numpy as np
import polars as pl
from sklearn.linear_model import LinearRegression
from sklearn.metrics import roc_auc_score

from service.model.experiments.run27_boundary_overfit_check import (
    N_EVAL_PER_LABEL,
    N_TRAIN_PER_SOURCE,
    SEED,
    to_norm_cic,
)
from service.model.experiments.run30_n_sweep import (
    CIC_TEST_PATHS,
    CIC_TRAIN_PATHS,
    BoundsStore,
    _ALL,
    _fit_variant,
    _load_cic_per_attack,
    _score_df,
    add_bucket_features,
    build_score_table,
    encode_bucket_indices,
)
from service.model.data.sample import get_normal_sample_from_files
from service.model.metrics import detection_metrics

# ── Config ──────────────────────────────────────────────────────────────────
N_BUCKETS = 8
N_FEATURES = len(_ALL)           # 5
N_MAP = {f: N_BUCKETS for f in _ALL}
N2_MAP = {f: 2 for f in _ALL}    # 部署 contract：5 特徵全用 N=2 分位桶（32-entry）
SCALE = 10_000                   # 與 distill_export score_scale 一致
DECISION_DELTA = 0.02            # max Δ AUC 採用門檻

# ── Additive decomposition ───────────────────────────────────────────────────

def build_indicator_matrix(n_features: int, n_buckets: int) -> tuple[np.ndarray, np.ndarray]:
    """列舉所有 bucket 組合並建 indicator 矩陣。

    Returns:
      combos : (n_buckets**n_features, n_features) 各特徵 bucket index（0..n_buckets-1）
      X      : (n_buckets**n_features, n_features*n_buckets) one-hot，
               欄佈局 [feat0_b0..feat0_b7, feat1_b0..feat1_b7, ...]，每列恰 n_features 個 1
    """
    combos = np.array(
        list(product(range(n_buckets), repeat=n_features)), dtype=np.int64
    )
    n_rows = combos.shape[0]
    X = np.zeros((n_rows, n_features * n_buckets), dtype=np.float64)
    rows = np.arange(n_rows)
    for i in range(n_features):
        X[rows, i * n_buckets + combos[:, i]] = 1.0
    return combos, X


def additive_scores_from_indices(idx: np.ndarray, per_bucket: np.ndarray,
                                 intercept: float) -> np.ndarray:
    """以 bucket index 陣列 (M, n_features) 取 additive score（與 eBPF compute_additive_score 同構）。"""
    score = np.full(idx.shape[0], intercept, dtype=np.float64)
    for i in range(idx.shape[1]):
        score += per_bucket[i * N_BUCKETS + idx[:, i].astype(np.int64)]
    return score


def _bucket_indices_matrix(df: pl.DataFrame, feat_cols: list[str]) -> tuple[np.ndarray, np.ndarray]:
    """從已 bucket 化的 df 取 (finite_mask, (M, n_features) int index 矩陣)。"""
    x = df.select(feat_cols).to_numpy().astype(np.float32)
    mask = np.asarray(np.isfinite(x).all(axis=1))
    return mask, x[mask].astype(np.int64)

# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    sep = "=" * 100
    print(sep)
    print("Run 31 — N=8 Per-feature Additive Bucket Score (PAB-Score) vs full 32768-entry table")
    print(sep)

    # ── Data ──────────────────────────────────────────────────────────────────
    print("\n[0] Loading data (CIC-only)")
    cic_train = to_norm_cic(
        get_normal_sample_from_files(CIC_TRAIN_PATHS, n=N_TRAIN_PER_SOURCE, seed=SEED)
    )
    print(f"  BENIGN train : {len(cic_train):>6} rows  ({len(CIC_TRAIN_PATHS)} files, 03-11)")

    per_attack_norm = {k: to_norm_cic(v)
                       for k, v in _load_cic_per_attack(CIC_TEST_PATHS, N_EVAL_PER_LABEL).items()}
    attack_names = sorted(per_attack_norm.keys())
    for name in attack_names:
        df = per_attack_norm[name]
        nb = int((df["Label"] == "BENIGN").sum())
        na = int((df["Label"] != "BENIGN").sum())
        print(f"  {name:<22}  BENIGN={nb:>4}  attack={na:>4}")

    # ── Bounds + bucketed features (N=8 全查表 與 N=2 部署 contract) ───────────
    store = BoundsStore()
    store.compute(cic_train, [2, N_BUCKETS])      # 兩者皆 BENIGN 分位桶邊界
    feat_cols = [f"{f}_{N_BUCKETS}b" for f in _ALL]
    n2_cols = [f"{f}_2b" for f in _ALL]

    train_feat = add_bucket_features(cic_train, store, N_MAP)
    eval_feat = {name: add_bucket_features(df, store, N_MAP)
                 for name, df in per_attack_norm.items()}
    # N=2 baseline 用「全特徵分位桶」同一份 BENIGN 邊界（與 D_n2_baseline / 部署 contract 一致）
    train_feat_n2 = add_bucket_features(cic_train, store, N2_MAP)
    eval_feat_n2 = {name: add_bucket_features(df, store, N2_MAP)
                    for name, df in per_attack_norm.items()}

    # ── Fit IF + full 32768-entry table（N=8）+ N=2 32-entry contract table ─────
    print("\n[1] Fit IF and build score tables (N=8 full 32768 + N=2 全分位桶 32-entry)")
    _, scaler, model = _fit_variant(train_feat, feat_cols, N_MAP)
    full_table = build_score_table(model, scaler, N_MAP)
    print(f"  N=8 full_table entries : {len(full_table)}  (8^5)")
    print(f"  N=8 score range        : [{full_table.min():.4f}, {full_table.max():.4f}]")

    # N=2 全分位桶 contract baseline（5 特徵皆 median split）
    _, scaler_n2, model_n2 = _fit_variant(train_feat_n2, n2_cols, N2_MAP)
    n2_table = build_score_table(model_n2, scaler_n2, N2_MAP)
    print(f"  N=2 contract entries   : {len(n2_table)}  (2^5; 全特徵分位桶, 非混合)")

    # ── OLS additive decomposition ────────────────────────────────────────────
    print("\n[2] OLS additive decomposition (5×8=40 indicator columns)")
    combos, X = build_indicator_matrix(N_FEATURES, N_BUCKETS)
    # encode_bucket_indices 使用 b0*8^4 + b1*8^3 + ... 編碼，須與 full_table 索引一致
    combo_idx = encode_bucket_indices(combos.astype(np.float32), N_MAP)
    y = full_table[combo_idx]

    reg = LinearRegression(fit_intercept=True).fit(X, y)
    per_bucket = reg.coef_.astype(np.float64)          # (40,)
    intercept = float(reg.intercept_)
    r2 = float(reg.score(X, y))

    additive_full = reg.predict(X)
    residual = y - additive_full
    print(f"  R² (additive vs full)      : {r2:.4f}")
    print(f"  intercept                  : {intercept:.4f}")
    print(f"  residual (cross-terms) RMSE: {np.sqrt(np.mean(residual ** 2)):.4f}")
    print(f"  residual max |abs|         : {np.abs(residual).max():.4f}")

    print("\n  per-bucket scores sᵢ(b)  (bucket 0..7):")
    print(f"  {'feature':<14}" + "".join(f"{b:>9}" for b in range(N_BUCKETS)))
    for i, f in enumerate(_ALL):
        row = per_bucket[i * N_BUCKETS:(i + 1) * N_BUCKETS]
        print(f"  {f:<14}" + "".join(f"{s:>9.4f}" for s in row))

    # ── Integer quantization range check ──────────────────────────────────────
    print("\n[3] Integer quantization (SCALE=%d) — i32 fit check" % SCALE)
    per_bucket_int = np.round(per_bucket * SCALE).astype(np.int64)
    intercept_int = int(round(intercept * SCALE))
    # 每特徵取該特徵 8 桶內的 max/min，加總得 additive score 的理論 range
    max_sum = intercept_int + sum(
        int(per_bucket_int[i * N_BUCKETS:(i + 1) * N_BUCKETS].max()) for i in range(N_FEATURES))
    min_sum = intercept_int + sum(
        int(per_bucket_int[i * N_BUCKETS:(i + 1) * N_BUCKETS].min()) for i in range(N_FEATURES))
    i32_max = 2 ** 31 - 1
    print(f"  per-bucket int range : [{per_bucket_int.min()}, {per_bucket_int.max()}]")
    print(f"  additive score range : [{min_sum}, {max_sum}]  (intercept_int={intercept_int})")
    fits = "OK (fits i32)" if -i32_max <= min_sum and max_sum <= i32_max else "OVERFLOW — 需擴 i64 或降 SCALE"
    print(f"  i32 (±{i32_max}) : {fits}")

    # ── AUC: N=8 full vs additive PAB vs N=2 contract per attack ──────────────
    print("\n[4] AUC-ROC — N=8 full(32768) vs additive PAB(40) vs N=2 全分位桶 contract(32)")
    hdr = (f"{'Attack':<22}{'AUC_full':>10}{'AUC_add':>9}{'AUC_n2':>9}"
           f"{'Δ(full-add)':>12}{'FPR_full':>9}{'FPR_add':>9}{'FPR_n2':>8}")
    print(hdr); print("-" * len(hdr))

    deltas: list[float] = []
    fpr_full_list: list[float] = []
    fpr_add_list: list[float] = []
    auc_full_list: list[float] = []
    auc_add_list: list[float] = []
    auc_n2_list: list[float] = []

    for attack in attack_names:
        eval_df = eval_feat[attack]
        y_raw = (eval_df["Label"] != "BENIGN").cast(pl.Int8).to_numpy()

        mask_f, full_scores = _score_df(eval_df, feat_cols, full_table, N_MAP)
        _, idx_mat = _bucket_indices_matrix(eval_df, feat_cols)
        add_scores = additive_scores_from_indices(idx_mat, per_bucket, intercept)
        # N=2 contract：同一 eval 列、同一 BENIGN 分位桶邊界
        mask_2, n2_scores = _score_df(eval_feat_n2[attack], n2_cols, n2_table, N2_MAP)

        yt = y_raw[mask_f]
        if yt.sum() == 0 or yt.sum() == len(yt):
            print(f"{attack:<22}{'(single class)':>50}")
            continue
        y2 = y_raw[mask_2]

        auc_full = float(roc_auc_score(yt, full_scores))
        auc_add = float(roc_auc_score(yt, add_scores))
        auc_n2 = float(roc_auc_score(y2, n2_scores))
        d = auc_full - auc_add

        m_full = detection_metrics(yt, full_scores)
        m_add = detection_metrics(yt, add_scores)
        m_n2 = detection_metrics(y2, n2_scores)

        deltas.append(d)
        auc_full_list.append(auc_full); auc_add_list.append(auc_add); auc_n2_list.append(auc_n2)
        fpr_full_list.append(m_full["fpr"]); fpr_add_list.append(m_add["fpr"])

        print(f"{attack:<22}{auc_full:>10.4f}{auc_add:>9.4f}{auc_n2:>9.4f}"
              f"{d:>+12.4f}{m_full['fpr']:>9.4f}{m_add['fpr']:>9.4f}{m_n2['fpr']:>8.4f}")

    if deltas:
        avg = lambda lst: sum(lst) / len(lst)
        print("-" * len(hdr))
        print(f"{'Avg':<22}{avg(auc_full_list):>10.4f}{avg(auc_add_list):>9.4f}"
              f"{avg(auc_n2_list):>9.4f}{avg(deltas):>+12.4f}"
              f"{avg(fpr_full_list):>9.4f}{avg(fpr_add_list):>9.4f}")

    # ── Decision ──────────────────────────────────────────────────────────────
    print("\n[5] Decision (門檻：max Δ AUC < %.2f 且 FPR_add ≤ 1.1× FPR_full)" % DECISION_DELTA)
    if not deltas:
        print("  無有效攻擊類型可評估")
        return
    avg = lambda lst: sum(lst) / len(lst)
    max_d = max(deltas)
    worst = attack_names[int(np.argmax(deltas))] if len(attack_names) == len(deltas) else "?"
    fpr_ok = all(fa <= 1.1 * ff + 1e-9 for fa, ff in zip(fpr_add_list, fpr_full_list))
    print(f"  max Δ AUC (full−add)  : {max_d:+.4f}  (worst: {worst})")
    print(f"  additive R²           : {r2:.4f}")
    print(f"  avg AUC: full={avg(auc_full_list):.4f}  additive={avg(auc_add_list):.4f}"
          f"  N=2 contract={avg(auc_n2_list):.4f}")
    print(f"  FPR_add ≤ 1.1×full    : {'PASS' if fpr_ok else 'FAIL'}")
    add_beats_n2 = avg(auc_add_list) > avg(auc_n2_list)
    print(f"  additive 勝過 N=2 contract : {'YES' if add_beats_n2 else 'NO（PAB 連現有 contract 都不如，無採用理由）'}")
    if max_d < DECISION_DELTA and fpr_ok and add_beats_n2:
        print("  → 採用 PAB-Score：40-entry 取代 32768-entry，進行 eBPF 實作")
    else:
        print("  → 不採用：保留 N=2 32-entry contract（distill_export.py 無需調整）")


if __name__ == "__main__":
    main()
