"""每個特徵的分布統計（count / mean / std / min / p25 / median / p75 / max）。

依 Label 分組輸出，方便比較 BENIGN 與各攻擊類型的數值差距，
也可跨多個 parquet 資料夾比較（例如 DDoS2019 vs IDS2018）。

用法：
  # 單一資料夾
  uv run --project service/model python -m service.model.view.feature_stats \
      --data_dir service/model/dataset/parquet_clean/test \
      --sample_n 5000

  # 多資料夾對比（加 --dirs）
  uv run --project service/model python -m service.model.view.feature_stats \
      --dirs service/model/dataset/parquet_clean/train \
             service/model/dataset/parquet_clean/test \
      --sample_n 5000
"""
from __future__ import annotations

import argparse
import glob
from typing import Optional

import numpy as np
import polars as pl

from service.model.schema import FEATURE_COLS


# ── 核心統計 ──────────────────────────────────────────────────────

def compute_stats(
    df: pl.DataFrame,
    feature_cols: list[str],
    group_by_label: bool = True,
) -> pl.DataFrame:
    """回傳每個特徵（× 每個 label）的分布統計。"""
    rows = []
    labels = sorted(df["Label"].cast(pl.Utf8).unique().to_list()) if group_by_label else ["ALL"]

    for label in labels:
        sub = df.filter(pl.col("Label").cast(pl.Utf8) == label) if group_by_label else df
        for col in feature_cols:
            if col not in sub.columns:
                continue
            arr = sub[col].cast(pl.Float64).drop_nulls().to_numpy()
            if len(arr) == 0:
                continue
            rows.append({
                "label":   label,
                "feature": col,
                "count":   len(arr),
                "mean":    round(float(np.mean(arr)), 4),
                "std":     round(float(np.std(arr)), 4),
                "min":     round(float(np.min(arr)), 4),
                "p25":     round(float(np.percentile(arr, 25)), 4),
                "median":  round(float(np.median(arr)), 4),
                "p75":     round(float(np.percentile(arr, 75)), 4),
                "max":     round(float(np.max(arr)), 4),
            })

    return pl.DataFrame(rows)


# ── 載入 ─────────────────────────────────────────────────────────

def _load_sample(
    paths: list[str],
    feature_cols: list[str],
    sample_n: int,
    seed: int,
    rename_map: Optional[dict[str, str]] = None,
) -> pl.DataFrame:
    need = feature_cols + ["Label"]
    chunks: list[pl.DataFrame] = []
    per_file = max(1, sample_n // max(len(paths), 1))

    for path in paths:
        df = (
            pl.scan_parquet(path)
            .select([c for c in need if c in pl.scan_parquet(path).collect_schema().names()])
            .collect()
        )
        if rename_map:
            df = df.rename({k: v for k, v in rename_map.items() if k in df.columns})
        take = min(len(df), per_file)
        chunks.append(df.sample(take, seed=seed))

    return pl.concat(chunks)


# ── 出力 ─────────────────────────────────────────────────────────

def print_stats(stats: pl.DataFrame, title: str = "") -> None:
    if title:
        print(f"\n{'='*70}")
        print(f"  {title}")
        print(f"{'='*70}")

    features = stats["feature"].unique().sort().to_list()
    for feat in features:
        sub = stats.filter(pl.col("feature") == feat)
        print(f"\n  [{feat}]")
        print(f"  {'label':<30} {'count':>7} {'mean':>10} {'std':>10} "
              f"{'min':>8} {'p25':>8} {'median':>8} {'p75':>8} {'max':>10}")
        print("  " + "-" * 93)
        for row in sub.iter_rows(named=True):
            print(f"  {row['label']:<30} {row['count']:>7,} {row['mean']:>10.3f} "
                  f"{row['std']:>10.3f} {row['min']:>8.3f} {row['p25']:>8.3f} "
                  f"{row['median']:>8.3f} {row['p75']:>8.3f} {row['max']:>10.3f}")


# ── CLI ──────────────────────────────────────────────────────────

def _run(args: argparse.Namespace) -> None:
    feature_cols = list(FEATURE_COLS)

    # IDS2018 欄位對應表
    rename_map = {"Packet Length Min": "Min Packet Length"}

    if args.dirs:
        for d in args.dirs:
            paths = glob.glob(f"{d}/*.parquet")
            if not paths:
                print(f"[skip] 找不到 parquet：{d}")
                continue
            df = _load_sample(paths, feature_cols, args.sample_n, args.seed, rename_map)
            stats = compute_stats(df, feature_cols, group_by_label=args.by_label)
            print_stats(stats, title=d)
    else:
        paths = glob.glob(f"{args.data_dir}/*.parquet")
        if not paths:
            raise FileNotFoundError(f"找不到 parquet：{args.data_dir}")
        df = _load_sample(paths, feature_cols, args.sample_n, args.seed, rename_map)
        stats = compute_stats(df, feature_cols, group_by_label=args.by_label)
        print_stats(stats, title=args.data_dir)


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Feature distribution stats viewer")
    p.add_argument("--data_dir", default="service/model/dataset/parquet_clean/train",
                   help="單一資料夾路徑")
    p.add_argument("--dirs", nargs="+",
                   help="多個資料夾路徑（對比用），設定後忽略 --data_dir")
    p.add_argument("--sample_n",  type=int, default=5000, help="每個資料夾抽樣總筆數")
    p.add_argument("--seed",      type=int, default=42)
    p.add_argument("--by_label",  action="store_true", default=True,
                   help="依 Label 分組（預設開啟）")
    p.add_argument("--no_label",  dest="by_label", action="store_false",
                   help="不分組，整體統計")
    return p.parse_args()


if __name__ == "__main__":
    _run(_parse_args())