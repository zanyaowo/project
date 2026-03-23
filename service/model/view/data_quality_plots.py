import polars as pl
import polars.selectors as cs
import matplotlib.pyplot as plt
import missingno

from service.model.data.cleaner import clean
from service.model.data.loader import _load_features_parquet


def plot_missing_counts(lf: pl.LazyFrame) -> None:
    """各欄位缺失數量長條圖，lazy 計算不載入原始資料。"""
    null_df = lf.null_count().collect()
    cols = null_df.columns
    counts = null_df.row(0)

    non_zero = [(c, v) for c, v in zip(cols, counts) if v > 0]
    if not non_zero:
        print("無缺失值")
        return

    names, values = zip(*non_zero)
    fig, ax = plt.subplots(figsize=(12, 5))
    ax.barh(names, values)
    ax.set_xlabel("Null count")
    ax.set_title("Missing values per column")
    fig.tight_layout()
    plt.show()


def plot_label_distribution(lf: pl.LazyFrame, label_col: str = "Label") -> None:
    """Label 類別分佈圓餅圖 + 數量，lazy 計算。"""
    dist = (
        lf.group_by(label_col)
        .len()
        .sort("len", descending=True)
        .collect()
    )
    labels = dist[label_col].to_list()
    counts = dist["len"].to_list()

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.pie(counts, labels=labels, autopct="%1.1f%%")
    ax.set_title("Label distribution")
    fig.tight_layout()
    plt.show()

    print(dist)


def plot_missing_matrix(
    lf: pl.LazyFrame, sample_per_label: int = 300, label_col: str = "Label"
) -> None:
    """每個 label 各取 sample 畫一張 missingno matrix，y 軸顯示 label name。"""
    label_counts = lf.group_by(label_col).len().collect()
    labels = label_counts[label_col].to_list()
    counts = dict(zip(labels, label_counts["len"].to_list()))

    fig, axes = plt.subplots(1, len(labels), figsize=(14, 6))
    if len(labels) == 1:
        axes = [axes]

    for ax, label in zip(axes, sorted(labels)):
        n = min(sample_per_label, counts[label])
        subset = (
            lf.filter(pl.col(label_col) == label)
            .collect(engine="streaming")
            .sample(n=n, seed=42)
            .to_pandas()
            .set_index(label_col)
        )
        missingno.matrix(subset, ax=ax, sparkline=False)
        ax.set_title(f"{label} (n={n})")

    plt.tight_layout()
    plt.show()


def plot_numeric_stats(lf: pl.LazyFrame) -> None:
    """數值欄位描述統計，lazy 計算後印出。"""
    stats = lf.select(cs.numeric()).collect(engine="streaming").describe()
    print(stats)

if __name__ == "__main__":
    lf = pl.scan_parquet('/home/zanya/code/ebpf_project/project/service/model/dataset/parquet/03*.parquet')
    lf = clean(lf)
    plot_missing_counts(lf)
    plot_label_distribution(lf)
    plot_missing_matrix(lf)
    plot_numeric_stats(lf)