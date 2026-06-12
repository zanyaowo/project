"""Permutation Importance for IsolationForest（以 AUC-ROC 衡量）。

方法：
  1. 用 BENIGN 訓練 IF，在驗證集計算 baseline AUC。
  2. 對每個特徵依序做 permutation（打亂欄位值），重算 AUC。
  3. importance = baseline_AUC - permuted_AUC
     - 值越大：打亂後 AUC 下降越多 → 特徵越重要
     - 值 ≈ 0：打亂後 AUC 幾乎不變 → 特徵對模型無貢獻

記憶體策略：
  - 載入時只掃描 feature_cols + Label，不載入全部 80 個欄位
  - 逐檔處理（scan_parquet + filter + select），collect 後立即 del + gc
  - 訓練與驗證各只保留取樣後的小型 numpy array

用法：
  uv run --project service/model python -m service.model.view.permutation_importance \
      --train_dir service/model/dataset/parquet_clean/train \
      --val_dir   service/model/dataset/parquet_clean/test \
      --n_repeats 5
"""
import argparse
import gc
import glob

import numpy as np
import polars as pl
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import StandardScaler

from service.model.schema import FEATURE_COLS


# ── 記憶體安全的取樣 ─────────────────────────────────────────────

def _sample_benign(
    paths: list[str],
    feature_cols: list[str],
    n: int,
    seed: int,
) -> pl.DataFrame:
    """逐檔掃描，只 select feature_cols，filter BENIGN 後取樣，達到 n 筆即停。"""
    need_cols = feature_cols + ["Label"]
    result: list[pl.DataFrame] = []
    count = 0
    for path in paths:
        df = (
            pl.scan_parquet(path)
            .filter(pl.col("Label") == "BENIGN")
            .select(need_cols)
            .collect()
        )
        if len(df) == 0:
            del df
            continue
        take = min(len(df), n - count)
        result.append(df.sample(take, seed=seed))
        count += take
        del df
        gc.collect()
        if count >= n:
            break
    return pl.concat(result)


def _sample_balanced(
    paths: list[str],
    feature_cols: list[str],
    sample_count_per_label: int,
    seed: int,
) -> pl.DataFrame:
    """逐 label 逐檔掃描，只 select feature_cols + Label，記憶體峰值 ≈ 單一 label 單一檔案。"""
    need_cols = feature_cols + ["Label"]

    # 先只掃 Label 欄取得所有 labels（不載入特徵）
    all_labels: set[str] = set()
    for path in paths:
        chunk = (
            pl.scan_parquet(path)
            .select("Label")
            .unique()
            .collect()["Label"]
            .to_list()
        )
        all_labels.update(chunk)

    result: list[pl.DataFrame] = []
    for label in sorted(all_labels):
        chunks: list[pl.DataFrame] = []
        for path in paths:
            df = (
                pl.scan_parquet(path)
                .filter(pl.col("Label") == label)
                .select(need_cols)
                .collect()
            )
            if len(df) == 0:
                del df
                continue
            take = min(len(df), sample_count_per_label)
            chunks.append(df.sample(take, seed=seed))
            del df
            gc.collect()

        if not chunks:
            continue
        combined = pl.concat(chunks)
        if len(combined) > sample_count_per_label:
            combined = combined.sample(sample_count_per_label, seed=seed)
        result.append(combined)
        del chunks, combined
        gc.collect()

    return pl.concat(result)


# ── Permutation Importance ────────────────────────────────────────

def _score(model: IsolationForest, scaler: StandardScaler,
           X: np.ndarray, y: np.ndarray) -> float:
    return float(roc_auc_score(y, -model.score_samples(scaler.transform(X))))


def permutation_importance(
    benign_df: pl.DataFrame,
    val_df: pl.DataFrame,
    feature_cols: list[str],
    n_estimators: int = 200,
    contamination: float = 0.01,
    n_repeats: int = 5,
    seed: int = 42,
) -> tuple[list[dict], float]:
    rng = np.random.default_rng(seed)

    X_train = benign_df.select(feature_cols).to_numpy().astype(np.float32)
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    del X_train; gc.collect()

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,  # type: ignore[arg-type]
        random_state=seed,
        n_jobs=-1,
    )
    model.fit(X_train_s)
    del X_train_s; gc.collect()

    X_val = val_df.select(feature_cols).to_numpy().astype(np.float32)
    y_val = (val_df["Label"] != "BENIGN").cast(pl.Int8).to_numpy()
    baseline = _score(model, scaler, X_val, y_val)
    print(f"Baseline AUC: {baseline:.4f}")
    print(f"Permuting {len(feature_cols)} 個特徵（n_repeats={n_repeats}）...\n")

    results: list[dict] = []
    for i, feat in enumerate(feature_cols):
        col_idx = feature_cols.index(feat)
        aucs = []
        for _ in range(n_repeats):
            X_perm = X_val.copy()
            X_perm[:, col_idx] = rng.permutation(X_perm[:, col_idx])
            aucs.append(_score(model, scaler, X_perm, y_val))
            del X_perm

        mean_auc = float(np.mean(aucs))
        std_auc  = float(np.std(aucs))
        imp      = baseline - mean_auc
        results.append({
            "feature":        feat,
            "baseline_auc":   round(baseline, 4),
            "mean_auc":       round(mean_auc, 4),
            "std_auc":        round(std_auc, 4),
            "importance":     round(imp, 4),
        })
        bar = "█" * max(0, int(imp / 0.005))
        print(f"  [{i+1:02d}/{len(feature_cols)}] {feat:<35} "
              f"perm={mean_auc:.4f} ±{std_auc:.4f}  Δ={imp:+.4f}  {bar}")

    results.sort(key=lambda r: -r["importance"])
    return results, baseline


# ── CLI ──────────────────────────────────────────────────────────

def _run(args: argparse.Namespace) -> None:
    train_paths = glob.glob(f"{args.train_dir}/*.parquet")
    val_paths   = glob.glob(f"{args.val_dir}/*.parquet")
    if not train_paths:
        raise FileNotFoundError(f"找不到訓練 parquet：{args.train_dir}")
    if not val_paths:
        raise FileNotFoundError(f"找不到驗證 parquet：{args.val_dir}")

    feature_cols = list(FEATURE_COLS)
    print(f"特徵數：{len(feature_cols)}")
    print(f"訓練檔案：{len(train_paths)} 個，驗證檔案：{len(val_paths)} 個\n")

    print(f"[1/3] 載入 BENIGN 訓練樣本（最多 {args.sample_n} 筆，只載入 {len(feature_cols)+1} 個欄位）...")
    benign_df = _sample_benign(train_paths, feature_cols, n=args.sample_n, seed=args.seed)
    print(f"  BENIGN 筆數：{len(benign_df)}")

    print(f"\n[2/3] 載入驗證樣本（每 label 最多 {args.val_sample_n} 筆）...")
    val_df = _sample_balanced(val_paths, feature_cols, sample_count_per_label=args.val_sample_n, seed=args.seed)
    print(f"  驗證集總筆數：{len(val_df)}")

    print(f"\n[3/3] Permutation Importance")
    results, baseline = permutation_importance(
        benign_df, val_df, feature_cols,
        n_estimators=args.n_estimators,
        contamination=args.contamination,
        n_repeats=args.n_repeats,
        seed=args.seed,
    )

    print(f"\n{'排名':<4} {'特徵名稱':<35} {'Perm AUC':>9} {'±':>7} {'Δ (importance)':>15}")
    print("-" * 75)
    for rank, r in enumerate(results, 1):
        flag = "  ← 可考慮移除" if abs(r["importance"]) < 0.001 else ""
        print(f"  {rank:<3} {r['feature']:<35} {r['mean_auc']:>9.4f} "
              f"{r['std_auc']:>7.4f} {r['importance']:>+15.4f}{flag}")


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Permutation Importance for IsolationForest")
    p.add_argument("--train_dir",     default="service/model/dataset/parquet_clean/train")
    p.add_argument("--val_dir",       default="service/model/dataset/parquet_clean/test")
    p.add_argument("--sample_n",      type=int,   default=10000, help="BENIGN 訓練樣本數")
    p.add_argument("--val_sample_n",  type=int,   default=3000,  help="驗證集每 label 最多筆數")
    p.add_argument("--n_estimators",  type=int,   default=200)
    p.add_argument("--contamination", type=float, default=0.01)
    p.add_argument("--n_repeats",     type=int,   default=5,     help="每個特徵重複 permutation 次數")
    p.add_argument("--seed",          type=int,   default=42)
    return p.parse_args()


if __name__ == "__main__":
    _run(_parse_args())