import polars as pl
import glob
from collections.abc import Callable


def _unique_labels(paths: list[str], label_col: str) -> list[str]:
    """只掃描 label 欄位取得所有唯一值，不載入完整資料。"""
    labels: set[str] = set()
    for path in paths:
        lf = pl.scan_parquet(path)
        schema_names = lf.collect_schema().names()
        rename_map = {c: c.strip() for c in schema_names if c != c.strip()}
        chunk = (
            lf
            .rename(rename_map)
            .select(label_col)
            .unique()
            .collect()[label_col]
            .to_list()
        )
        labels.update(chunk)
    return sorted(labels)


def get_balance_sample_from_files(
        paths: list[str],
        sample_count_per_label: int = 5000,
        label_col: str = "Label",
        seed: int = 42,
        min_samples: int = 0,
        transform: Callable[[pl.LazyFrame], pl.LazyFrame] | None = None,
) -> pl.DataFrame:
    """
    逐 label 逐檔過濾後再 collect，避免將整個 parquet 載入記憶體。
    記憶體峰值 ≈ 單一 label 在單一檔案的資料量，而非整個檔案。

    transform: 在 collect 前套用的 lazy 轉換，例如 clean
        get_balance_sample_from_files(paths, transform=clean)

    注意：transform 會在 label 過濾後套用，清洗統計值（如 quantile）
    是以各 label 的子集計算，而非全資料集。

    min_samples: 全資料集中該 label 筆數低於此值則跳過（0 表示不過濾）。
    """
    if not paths:
        raise ValueError("paths 不能為空")

    all_labels = _unique_labels(paths, label_col)

    result: list[pl.DataFrame] = []
    for label in all_labels:
        chunks: list[pl.DataFrame] = []
        for path in paths:
            lf = pl.scan_parquet(path).filter(pl.col(label_col) == label)
            if transform is not None:
                lf = transform(lf)
            df = lf.collect()
            if len(df) == 0:
                continue
            n = min(sample_count_per_label, len(df))
            chunks.append(df.sample(n, seed=seed))
            del df

        if not chunks:
            continue
        combined = pl.concat(chunks)
        if min_samples > 0 and len(combined) < min_samples:
            print(f"跳過 {label!r}：總筆數 {len(combined)} < min_samples {min_samples}")
            del combined
            continue
        if len(combined) > sample_count_per_label:
            combined = combined.sample(sample_count_per_label, seed=seed)
        result.append(combined)
        del chunks, combined

    return pl.concat(result)

def get_normal_sample_from_files(
        paths: list[str],
        n: int = 50000,
        label_col: str = "Label",
        normal_label = "BENIGN",
        seed: int = 42,
        transform: Callable[[pl.LazyFrame], pl.LazyFrame] | None = None,
) -> pl.DataFrame:

    if not paths:
        raise ValueError("paths 不能為空")

    result: list[pl.DataFrame] = []
    count = 0
    for path in paths:
        lf = pl.scan_parquet(path).filter(pl.col(label_col) == normal_label)
        if transform is not None:
            lf = transform(lf)
        df = lf.collect()
        if len(df) == 0:
            continue

        take = min(len(df), n - count)
        result.append(df.sample(take, seed=seed))
        count += take
        del df
        if count >= n:
            break

    return pl.concat(result)


def get_binary_sample_from_files(
        paths: list[str],
        n_per_class: int = 5000,
        label_col: str = "Label",
        benign_label: str = "BENIGN",
        seed: int = 42,
        transform: Callable[[pl.LazyFrame], pl.LazyFrame] | None = None,
) -> pl.DataFrame:
    """
    二分法抽樣：BENIGN n_per_class 筆 + 所有攻擊合計 n_per_class 筆。
    攻擊側逐檔抽樣後合併再裁剪，確保各攻擊類型都有代表性。
    適合 feature selection 的 RF 二分類訓練。
    """
    if not paths:
        raise ValueError("paths 不能為空")

    benign_chunks: list[pl.DataFrame] = []
    attack_chunks: list[pl.DataFrame] = []

    for path in paths:
        lf = pl.scan_parquet(path)

        for chunks, expr in [
            (benign_chunks, pl.col(label_col) == benign_label),
            (attack_chunks, pl.col(label_col) != benign_label),
        ]:
            filtered = lf.filter(expr)
            if transform is not None:
                filtered = transform(filtered)
            df = filtered.collect()
            if len(df) == 0:
                continue
            take = min(len(df), n_per_class)
            chunks.append(df.sample(take, seed=seed))
            del df

    def _cap(chunks: list[pl.DataFrame]) -> pl.DataFrame:
        combined = pl.concat(chunks)
        if len(combined) > n_per_class:
            combined = combined.sample(n_per_class, seed=seed)
        return combined

    return pl.concat([_cap(benign_chunks), _cap(attack_chunks)])


if __name__ == "__main__":
    import os
    _base = os.path.dirname(os.path.dirname(__file__))
    data_path = glob.glob(os.path.join(_base, "dataset/parquet_clean/*.parquet"))
    df = get_balance_sample_from_files(paths=data_path, sample_count_per_label=5000)
    print(df)