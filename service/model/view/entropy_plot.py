"""欄位熵值分佈視覺化。

計算任意數值欄位的 Shannon entropy，並按 Label 分組比較。
常用於分析 Source Port、Destination Port 等特徵在不同流量類型下的多樣性差異：
  - 高 entropy → 值分散（如正常流量的 Source Port 各異）
  - 低 entropy → 值集中（如 DDoS 大量相同來源端口）

用法：
  # 單一欄位
  python -m service.model.view.entropy_plot \\
      --input  service/model/dataset/parquet_clean/train \\
      --col   "Source Port" \\
      --output source_port_entropy.png

  # 多個欄位（依序產生各自圖片）
  python -m service.model.view.entropy_plot \\
      --input  service/model/dataset/parquet_clean/train \\
      --col   "Source Port" "Destination Port" "Flow Bytes/s"
"""
import argparse
import glob
import os

import matplotlib.pyplot as plt
import numpy as np
import polars as pl


# ── 核心計算 ──────────────────────────────────────────────────

def compute_entropy(values: np.ndarray, bins: int = 200) -> float:
    """計算一維數值陣列的 Shannon entropy（以 bits 為單位）。

    將連續值分 bins 個區間後，以各區間的相對頻率估計機率分佈。
    可獨立使用於任意 numpy array。

    Parameters
    ----------
    values : 一維數值陣列
    bins   : 直方圖分箱數，越大越精細（預設 200）

    Returns
    -------
    entropy : float，單位 bits（log base 2）
    """
    if len(values) == 0:
        return 0.0
    counts, _ = np.histogram(values, bins=bins)
    probs = counts / counts.sum()
    probs = probs[probs > 0]
    return float(-np.sum(probs * np.log2(probs)))


# ── 視覺化 ────────────────────────────────────────────────────

def plot_entropy_distribution(
    df: pl.DataFrame,
    col: str,
    label_col: str = "Label",
    output: str | None = None,
    bins: int = 200,
    sample_n: int = 3000,
    seed: int = 42,
    log_scale: bool = False,
) -> dict[str, float]:
    """按 Label 分組，繪製欄位值分佈直方圖與各 label 的 Shannon entropy 比較。

    Parameters
    ----------
    df        : 包含 col 與 label_col 的 DataFrame
    col       : 要分析的欄位名稱（數值型）
    label_col : 分組欄位（預設 "Label"）
    output    : 圖片輸出路徑（None 則只顯示不存檔）
    bins      : 直方圖與 entropy 計算的分箱數
    sample_n  : 每個 label 最多取幾筆（避免大 label 主導視覺）
    log_scale : 是否對值軸取 log（適合如 Flow Bytes/s 的長尾分佈）

    Returns
    -------
    dict[label, entropy_bits]
    """
    if col not in df.columns:
        raise KeyError(f"欄位 {col!r} 不存在")
    if label_col not in df.columns:
        raise KeyError(f"欄位 {label_col!r} 不存在")

    labels = sorted(df[label_col].unique().to_list())
    cmap = plt.get_cmap("tab10")
    colors = {lbl: cmap(i % 10) for i, lbl in enumerate(labels)}

    # ── 各 label 取樣 & 計算 entropy ─────────────────────────
    entropy_map: dict[str, float] = {}
    label_values: dict[str, np.ndarray] = {}

    for lbl in labels:
        subset = df.filter(pl.col(label_col) == lbl)
        if len(subset) > sample_n:
            subset = subset.sample(sample_n, seed=seed)
        vals = subset[col].drop_nulls().to_numpy().astype(np.float64)
        if log_scale:
            vals = vals[vals > 0]
            vals = np.log10(vals)
        label_values[lbl] = vals
        entropy_map[lbl] = compute_entropy(vals, bins=bins)

    # ── 繪圖（1 × 2）────────────────────────────────────────
    fig, axes = plt.subplots(1, 2, figsize=(15, 6))
    fig.suptitle(
        f"Entropy Distribution — {col}" + (" (log10 scale)" if log_scale else ""),
        fontsize=14,
    )

    # 左：各 label 的值分佈直方圖（半透明疊加）
    ax_hist = axes[0]
    all_vals = np.concatenate(list(label_values.values()))
    shared_range = (float(all_vals.min()), float(all_vals.max()))

    for lbl, vals in label_values.items():
        ax_hist.hist(
            vals,
            bins=bins,
            range=shared_range,
            color=colors[lbl],
            alpha=0.45,
            density=True,
            label=f"{lbl}  (H={entropy_map[lbl]:.2f} bits)",
        )

    ax_hist.set_title("Value Distribution per Label")
    xlabel = f"log10({col})" if log_scale else col
    ax_hist.set_xlabel(xlabel)
    ax_hist.set_ylabel("Density")
    ax_hist.legend(fontsize=8, loc="upper right")

    # 右：各 label 的 entropy 橫條圖（由高到低排序）
    ax_bar = axes[1]
    sorted_items = sorted(entropy_map.items(), key=lambda x: x[1], reverse=True)
    bar_labels = [item[0] for item in sorted_items]
    bar_values = [item[1] for item in sorted_items]
    bar_colors = [colors[lbl] for lbl in bar_labels]

    bars = ax_bar.barh(bar_labels, bar_values, color=bar_colors, edgecolor="white", height=0.6)
    ax_bar.bar_label(bars, fmt="%.2f bits", padding=4, fontsize=9)
    ax_bar.set_title("Shannon Entropy per Label")
    ax_bar.set_xlabel("Entropy (bits)")
    ax_bar.set_xlim(0, max(bar_values) * 1.2)
    ax_bar.invert_yaxis()

    fig.tight_layout()

    if output:
        os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
        plt.savefig(output, dpi=150)
        print(f"圖表已儲存 -> {output}")
    plt.show()
    plt.close(fig)

    return entropy_map


# ── 資料載入 ──────────────────────────────────────────────────

def _load_df(input_path: str, sample_n: int, seed: int) -> pl.DataFrame:
    """從單一 parquet 或目錄（取所有 parquet）載入，並依 label 平衡抽樣。"""
    if os.path.isdir(input_path):
        paths = glob.glob(os.path.join(input_path, "*.parquet"))
        if not paths:
            raise FileNotFoundError(f"目錄下找不到 parquet：{input_path}")
        from service.model.data.sample import get_balance_sample_from_files
        return get_balance_sample_from_files(paths, sample_count_per_label=sample_n, seed=seed)
    elif input_path.endswith(".parquet"):
        df = pl.read_parquet(input_path)
        return df
    elif input_path.endswith(".csv"):
        df = pl.read_csv(input_path, null_values=[""])
        return df
    else:
        raise ValueError(f"不支援的格式：{input_path}")


# ── CLI ───────────────────────────────────────────────────────

def _run(args: argparse.Namespace) -> None:
    print(f"[1/2] 載入資料：{args.input}（每 label 最多 {args.sample_n} 筆）")
    df = _load_df(args.input, sample_n=args.sample_n, seed=args.seed)
    print(f"  總筆數：{len(df)}")

    for col in args.col:
        print(f"\n[2/2] 分析欄位：{col}")
        safe_name = col.replace(" ", "_").replace("/", "_per_")
        output = args.output or f"{safe_name}_entropy.png"
        if len(args.col) > 1:
            base, ext = os.path.splitext(output)
            output = f"{base}_{safe_name}{ext}"

        entropy_map = plot_entropy_distribution(
            df, col,
            output=output,
            bins=args.bins,
            sample_n=args.sample_n,
            seed=args.seed,
            log_scale=args.log_scale,
        )

        print("  Entropy per label:")
        for lbl, h in sorted(entropy_map.items(), key=lambda x: -x[1]):
            print(f"    {lbl:<20} {h:.4f} bits")


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="欄位 Shannon entropy 分佈視覺化")
    p.add_argument("--input", required=True,
                   help="parquet 檔案、parquet 目錄、或 csv 檔案")
    p.add_argument("--col", nargs="+", default=["Source Port"],
                   help="要分析的欄位（可多個，空白分隔）")
    p.add_argument("--output", default=None,
                   help="圖片輸出路徑（多欄位時會自動加欄位名後綴；不指定則自動命名）")
    p.add_argument("--bins", type=int, default=200,
                   help="直方圖分箱數（也影響 entropy 計算精度）")
    p.add_argument("--sample_n", type=int, default=3000,
                   help="每個 label 最多取幾筆")
    p.add_argument("--log_scale", action="store_true",
                   help="對欄位值取 log10（適合長尾分佈如 Flow Bytes/s）")
    p.add_argument("--seed", type=int, default=42)
    return p.parse_args()


if __name__ == "__main__":
    _run(_parse_args())