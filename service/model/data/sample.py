import polars as pl
import glob
from collections.abc import Callable


def get_balance_sample_from_files(
        paths: list[str],
        sample_count_per_label: int = 5000,
        label_col: str = "Label",
        seed: int = 42,
        transform: Callable[[pl.LazyFrame], pl.LazyFrame] | None = None,
) -> pl.DataFrame:
    """
    逐檔讀入 → (選用) transform → 採樣 → del 釋放 → 最後合併小樣本
    記憶體峰值 ≈ 單一最大 parquet 檔，而非所有檔案總和

    transform: 在 collect 前套用的 lazy 轉換，例如 clean
        get_balance_sample_from_files(paths, transform=clean)
    """
    if not paths:
        raise ValueError("paths 不能為空")

    per_label: dict[str, list[pl.DataFrame]] = {}

    for path in paths:
        lf = pl.scan_parquet(path)
        if transform is not None:
            lf = transform(lf)
        df = lf.collect()
        for label in df[label_col].unique().to_list():  # unique() 避免重複迭代
            subset = df.filter(pl.col(label_col) == label)
            n = min(sample_count_per_label, len(subset))
            per_label.setdefault(label, []).append(
                subset.sample(n, seed=seed)
            )

        del df

    result = []
    for label, chunks in per_label.items():
        combined = pl.concat(chunks)
        if len(combined) > sample_count_per_label:
            combined = combined.sample(sample_count_per_label, seed=seed)
        result.append(combined)

    return pl.concat(result)


if __name__ == "__main__":
    paths = glob.glob(".../dataset/parquet/*.parquet")
    df = get_balance_sample_from_files(paths, sample_count_per_label=5000)