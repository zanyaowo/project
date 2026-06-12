"""distill_kd — Contract5 連續 teacher → 32-entry bucket student 的知識蒸餾。

與現行 `distill_export.py`（在二值化特徵上重訓一個 IF 產 score_table）不同，
本模組把 score_table 直接蒸餾自**連續 teacher 的分數分布**：

  關鍵洞察：student 只看得到 5 個二值特徵 ⇒ 只有 32 種輸入 ⇒ bucket 是對輸入
  空間的「完整切分」。在任何 per-bucket loss（MSE/KL 對 teacher）下，每桶輸出
  單一值的 student 最佳解就是「該桶內 teacher 分數的聚合」。故正式 KD 在此塌縮為
  per-bucket teacher-score aggregation，不需梯度訓練 policy。

本模組為**對照組**用途（不動部署 model.json）：沿用部署的 quantile_bounds
（同一 32-桶切分），只把 score_table / threshold 換成 teacher 蒸餾版，藉此把
「score_table 產生法」這一個變因獨立出來比較。
"""
from __future__ import annotations

import copy

import numpy as np

SCORE_SCALE = 10000


def build_kd_score_table(
    teacher_scores: np.ndarray,
    bucket_indices: np.ndarray,
    *,
    n_buckets: int = 32,
    aggregate: str = "mean",
) -> tuple[list[int], list[int]]:
    """每桶聚合 teacher 分數 → 32-entry 整數 score_table。

    Args:
        teacher_scores: shape (N,) 連續 teacher 異常分數（越高越可疑）。
        bucket_indices: shape (N,) 每筆對應的 0..n_buckets-1 桶索引。
        aggregate: "mean" 或 "median"，桶內聚合方式。

    Returns:
        (score_table, empty_buckets)
        score_table  : 長度 n_buckets 的 int 清單（已 ×SCORE_SCALE 取整）。
        empty_buckets: 蒸餾池中無樣本、改用全域 fallback 的桶索引清單。

    Fallback：蒸餾池未覆蓋到的桶（多為純攻擊高分桶在 BENIGN-lean 池中缺席）
    填入全域聚合值，保守起見採全體中位數，避免空桶被當成 0（極度良性）。
    """
    finite = np.isfinite(teacher_scores)
    if not finite.any():
        raise ValueError("teacher_scores 全為非有限值，無法蒸餾")

    agg_fn = {"mean": np.mean, "median": np.median}.get(aggregate)
    if agg_fn is None:
        raise ValueError(f"未知 aggregate：{aggregate!r}")

    global_fallback = float(np.median(teacher_scores[finite]))

    table: list[int] = []
    empty: list[int] = []
    for b in range(n_buckets):
        mask = finite & (bucket_indices == b)
        if mask.any():
            val = float(agg_fn(teacher_scores[mask]))
        else:
            val = global_fallback
            empty.append(b)
        table.append(int(round(val * SCORE_SCALE)))
    return table, empty


def kd_rules_from_deployed(
    deployed_rules: dict,
    score_table: list[int],
    threshold: int,
) -> dict:
    """以部署 rules 為模板，換上 KD 蒸餾的 score_table 與 threshold。

    保留 quantile_bounds（同一 32-桶切分）、feature_order 與所有 contract
    metadata，使產出仍能通過 DistilledClassifier 的 v1 contract 驗證。
    """
    if len(score_table) != len(deployed_rules["score_table"]):
        raise ValueError(
            f"score_table 長度 {len(score_table)} 與部署模板 "
            f"{len(deployed_rules['score_table'])} 不符"
        )
    rules = copy.deepcopy(deployed_rules)
    rules["score_table"] = list(score_table)
    rules["threshold"] = int(threshold)
    return rules
