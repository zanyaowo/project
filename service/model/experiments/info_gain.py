"""計算所有數值欄位對 Label（binary: BENIGN vs attack）的資訊增益（Information Gain）。

方法：
  - 對每個連續數值欄位做等頻分箱（quantile binning），再以 Shannon entropy 計算 IG。
  - IG(X, Y) = H(Y) - H(Y|X)
    - H(Y)   = label 的 Shannon entropy（bits）
    - H(Y|X) = Σ P(bin_k) * H(Y | bin_k)，對各分箱做加權平均

輸出：
  - 標準輸出：各欄位 IG（由高至低排序）
  - --save_json：將結果寫入 JSON 供外部讀取

用法：
  uv run --project service/model python -m service.model.view.info_gain \\
      --data_dir service/model/dataset/parquet_clean/train \\
      --sample_n 5000 \\
      --bins 20
"""
import argparse
import glob
import json

import numpy as np
import polars as pl


# ── 熵計算 ────────────────────────────────────────────────────

def _binary_entropy(p: float) -> float:
    """H(p) for binary distribution."""
    if p <= 0.0 or p >= 1.0:
        return 0.0
    return -p * np.log2(p) - (1 - p) * np.log2(1 - p)


def _label_entropy(y: np.ndarray) -> float:
    """H(Y): Shannon entropy of a binary label array (0/1)."""
    n = len(y)
    if n == 0:
        return 0.0
    p = float(y.mean())
    return _binary_entropy(p)


def _conditional_entropy(x: np.ndarray, y: np.ndarray, n_bins: int) -> float:
    """H(Y|X): conditional entropy after quantile-binning X into n_bins.

    等頻分箱（quantile）讓每個 bin 的樣本數相近，
    比等寬分箱更穩定且不受極端值影響。
    """
    n = len(x)
    if n == 0:
        return 0.0

    # 用 quantile 切點做等頻分箱
    quantiles = np.linspace(0, 100, n_bins + 1)
    bin_edges = np.percentile(x, quantiles)
    bin_edges = np.unique(bin_edges)  # 去除重複切點（常數欄位會退化）

    if len(bin_edges) < 2:
        # 欄位值全相同 → 無法提供任何資訊
        return _label_entropy(y)

    bin_idx = np.digitize(x, bin_edges[1:-1])  # 0-indexed bin assignment

    cond_h = 0.0
    for b in np.unique(bin_idx):
        mask = bin_idx == b
        n_b = mask.sum()
        cond_h += (n_b / n) * _label_entropy(y[mask])

    return cond_h


def information_gain(x: np.ndarray, y: np.ndarray, n_bins: int = 20) -> float:
    """IG(X, Y) = H(Y) - H(Y|X)。"""
    h_y = _label_entropy(y)
    h_y_given_x = _conditional_entropy(x, y, n_bins=n_bins)
    return max(0.0, h_y - h_y_given_x)


# ── 資料載入 ──────────────────────────────────────────────────

_EXCLUDE = {"Unnamed: 0", "Flow ID", "Source IP", "Destination IP", "Timestamp", "Inbound"}
_NUMERIC_DTYPES = (
    pl.Float64, pl.Float32,
    pl.Int64, pl.Int32, pl.Int16, pl.Int8,
    pl.UInt64, pl.UInt32, pl.UInt16, pl.UInt8,
)


def _load_balanced(paths: list[str], sample_n: int, seed: int) -> pl.DataFrame:
    from service.model.data.sample import get_balance_sample_from_files
    return get_balance_sample_from_files(paths, sample_count_per_label=sample_n, seed=seed)


# ── 主計算 ────────────────────────────────────────────────────

def compute_all_ig(
    df: pl.DataFrame,
    label_col: str = "Label",
    n_bins: int = 20,
) -> list[tuple[str, float, float]]:
    """計算所有數值欄位的 IG。

    Returns
    -------
    list of (feature_name, ig, h_y)，已依 ig 由高至低排序。
    """
    if label_col not in df.columns:
        raise KeyError(f"找不到 label 欄位：{label_col!r}")

    y = (df[label_col] != "BENIGN").cast(pl.Int8).to_numpy().astype(np.int8)
    h_y = _label_entropy(y)

    numeric_cols = [
        c for c in df.columns
        if c not in _EXCLUDE and c != label_col and df[c].dtype in _NUMERIC_DTYPES
    ]

    results: list[tuple[str, float, float]] = []
    for col in numeric_cols:
        x = df[col].fill_nan(0.0).fill_null(0.0).to_numpy().astype(np.float64)
        ig = information_gain(x, y, n_bins=n_bins)
        results.append((col, ig, h_y))

    results.sort(key=lambda t: t[1], reverse=True)
    return results


# ── CLI ───────────────────────────────────────────────────────

def _run(args: argparse.Namespace) -> None:
    paths = glob.glob(f"{args.data_dir}/*.parquet")
    if not paths:
        raise FileNotFoundError(f"找不到 parquet：{args.data_dir}")

    print(f"[1/3] 載入資料（每 label 最多 {args.sample_n} 筆，seed={args.seed}）...")
    df = _load_balanced(paths, sample_n=args.sample_n, seed=args.seed)
    print(f"  總筆數：{len(df)}")
    print(f"  Label 分布：")
    print(df["Label"].value_counts().sort("Label"))

    y = (df["Label"] != "BENIGN").cast(pl.Int8).to_numpy()
    h_y = _label_entropy(y)
    print(f"\n[2/3] H(Y) = {h_y:.4f} bits  （攻擊比例 {y.mean():.1%}）")

    print(f"\n[3/3] 計算所有數值欄位的資訊增益（bins={args.bins}）...")
    results = compute_all_ig(df, n_bins=args.bins)

    # ── 輸出表格
    print(f"\n{'排名':<5} {'欄位名稱':<40} {'IG (bits)':>12} {'IG/H(Y)':>10}")
    print("-" * 72)
    for rank, (col, ig, hy) in enumerate(results, 1):
        ratio = ig / hy if hy > 0 else 0.0
        print(f"  {rank:<3} {col:<40} {ig:>12.4f} {ratio:>9.1%}")

    # ── 存 JSON
    if args.save_json:
        payload = {
            "h_y": h_y,
            "n_samples": len(df),
            "attack_ratio": float(y.mean()),
            "bins": args.bins,
            "seed": args.seed,
            "features": [
                {"rank": i + 1, "name": col, "ig": round(ig, 6), "ig_ratio": round(ig / h_y if h_y > 0 else 0.0, 6)}
                for i, (col, ig, _) in enumerate(results)
            ],
        }
        with open(args.save_json, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        print(f"\n結果已儲存 → {args.save_json}")


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="資訊增益計算（entropy-based IG for all numeric features）")
    p.add_argument("--data_dir", default="service/model/dataset/parquet_clean/train",
                   help="清洗後訓練集 parquet 目錄")
    p.add_argument("--sample_n", type=int, default=5000,
                   help="每個 label 最多取幾筆（平衡抽樣）")
    p.add_argument("--bins", type=int, default=20,
                   help="等頻分箱數（影響 H(Y|X) 精度；建議 10–50）")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--save_json", default=None,
                   help="將結果儲存為 JSON 路徑（供寫 log 用）")
    return p.parse_args()


if __name__ == "__main__":
    _run(_parse_args())