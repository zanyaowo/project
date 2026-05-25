"""Evaluation metrics for the eBPF anomaly detection pipeline.

Functions:
  detection_metrics   — AUC + at-threshold accuracy / FPR / FNR / F1
  overfit_check       — compare train vs test BENIGN score distributions
  threshold_at_fpr    — find threshold that achieves a target false-positive rate
"""
from __future__ import annotations

import numpy as np
from sklearn.metrics import confusion_matrix, roc_auc_score, roc_curve


def detection_metrics(
    y_true: np.ndarray,
    y_score: np.ndarray,
    threshold: float | None = None,
) -> dict[str, float]:
    """Compute AUC and at-threshold classification metrics.

    threshold=None → automatically selects the Youden-J optimal point on the ROC curve.

    Returns
    -------
    auc        : ROC AUC
    threshold  : decision boundary used
    accuracy   : (TP+TN) / total
    fpr        : 誤報率 — fraction of BENIGN flagged as attack  (FP / N_neg)
    fnr        : 漏報率 — fraction of attacks missed            (FN / N_pos)
    tpr        : 偵測率 — true positive rate                   (TP / N_pos)
    precision  : TP / (TP + FP)
    f1         : harmonic mean of precision and tpr
    """
    if len(np.unique(y_true)) < 2:
        raise ValueError("y_true must contain both classes")

    auc = float(roc_auc_score(y_true, y_score))
    fpr_arr, tpr_arr, thresholds = roc_curve(y_true, y_score)

    if threshold is None:
        best = int(np.argmax(tpr_arr - fpr_arr))
        threshold = float(thresholds[best])

    y_pred = (y_score >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    n_neg = tn + fp
    n_pos = fn + tp
    fpr   = fp / n_neg if n_neg > 0 else 0.0
    fnr   = fn / n_pos if n_pos > 0 else 0.0
    tpr   = tp / n_pos if n_pos > 0 else 0.0
    prec  = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    acc   = (tp + tn) / (tp + tn + fp + fn)
    f1    = 2 * prec * tpr / (prec + tpr) if (prec + tpr) > 0 else 0.0

    return {
        "auc":       auc,
        "threshold": threshold,
        "accuracy":  acc,
        "fpr":       fpr,
        "fnr":       fnr,
        "tpr":       tpr,
        "precision": prec,
        "f1":        f1,
    }


def overfit_check(
    train_benign_scores: np.ndarray,
    test_benign_scores: np.ndarray,
    *,
    warn_gap: float = 0.05,
) -> dict[str, float | bool | str]:
    """Check whether the model overfit to the BENIGN training distribution.

    Compares anomaly score distributions of training BENIGN vs test BENIGN.
    A large positive mean_gap means the model assigns lower anomaly scores to
    training data than to unseen test data → likely overfit / distribution shift.

    Distribution shift is measured with a percentile-band metric:
    pct_overlap = fraction of percentile-grid points where the two CDFs differ
    by less than 0.05. Higher overlap → more similar distributions.

    Returns
    -------
    mean_train   : mean anomaly score on BENIGN train samples
    mean_test    : mean anomaly score on BENIGN test samples
    mean_gap     : mean_test - mean_train  (positive = test looks more anomalous)
    std_ratio    : std(test) / std(train)  (> 1.5 → wider spread in test)
    pct_overlap  : CDF similarity in [0, 1]  (< 0.7 → meaningful distribution shift)
    is_overfit   : bool, True when mean_gap > warn_gap
    severity     : none / mild / moderate / severe
    """
    m_train = float(np.mean(train_benign_scores))
    m_test  = float(np.mean(test_benign_scores))
    gap     = m_test - m_train

    std_tr  = float(np.std(train_benign_scores)) + 1e-9
    std_te  = float(np.std(test_benign_scores))
    std_ratio = std_te / std_tr

    # Percentile-grid CDF comparison (cheap KS-like measure, no scipy needed)
    grid = np.linspace(
        min(train_benign_scores.min(), test_benign_scores.min()),
        max(train_benign_scores.max(), test_benign_scores.max()),
        200,
    )
    cdf_tr = np.mean(train_benign_scores[:, None] <= grid, axis=0)
    cdf_te = np.mean(test_benign_scores[:, None]  <= grid, axis=0)
    pct_overlap = float(np.mean(np.abs(cdf_tr - cdf_te) < 0.05))

    is_overfit = gap > warn_gap
    if gap > 0.20:
        severity = "severe"
    elif gap > 0.10:
        severity = "moderate"
    elif gap > warn_gap:
        severity = "mild"
    else:
        severity = "none"

    return {
        "mean_train":  m_train,
        "mean_test":   m_test,
        "mean_gap":    gap,
        "std_ratio":   std_ratio,
        "pct_overlap": pct_overlap,
        "is_overfit":  bool(is_overfit),
        "severity":    severity,
    }


def threshold_at_fpr(
    y_true: np.ndarray,
    y_score: np.ndarray,
    target_fpr: float = 0.01,
) -> float:
    """Return the lowest threshold that keeps FPR ≤ target_fpr.

    Useful for firewall tuning: target_fpr=0.01 caps misblocking of
    BENIGN traffic at 1%.  Apply as: y_pred = (y_score >= threshold).
    """
    fpr_arr, _tpr, thresholds = roc_curve(y_true, y_score)
    candidates = np.where(fpr_arr <= target_fpr)[0]
    if len(candidates) == 0:
        return float(thresholds[0])
    idx = int(candidates[-1])
    return float(thresholds[min(idx, len(thresholds) - 1)])
