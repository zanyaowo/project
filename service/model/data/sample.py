import numpy as np
import polars as pl
import glob
from collections.abc import Callable


def random_sample_lazyframe(lf: pl.LazyFrame, n: int, seed: int = 42) -> pl.LazyFrame:
    """從 LazyFrame 隨機抽取 n 筆，不將全部資料載入記憶體。

    做法：先從 metadata 取得總行數，再用 row_index + is_in filter
    只 collect 抽到的行，記憶體峰值 ≈ 抽樣結果大小而非全量資料。
    """
    total = lf.select(pl.len()).collect().item()
    sample_size = min(n, int(total))
    rng = np.random.default_rng(seed)
    indices = set(int(i) for i in rng.choice(int(total), size=sample_size, replace=False))
    return (
        lf
        .with_row_index("__row__")
        .filter(pl.col("__row__").is_in(indices))
        .drop("__row__")
    )


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
        n: int = 10000,
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


def get_mixed_normal_sample(
        sources: list[dict],
        n_per_source: int = 10000,
        common_cols: list[str] | None = None,
        seed: int = 42,
) -> pl.DataFrame:
    """多來源 BENIGN 混合抽樣，用於跨資料集邊界計算。

    sources 每個元素為 dict，支援以下 key：
        paths        : list[str]  —— parquet 路徑列表（必填）
        label_col    : str        —— label 欄位名稱（預設 "Label"）
        normal_label : str        —— 正常樣本的 label 值（預設 "BENIGN"）
        post_transform: Callable[[pl.DataFrame], pl.DataFrame] | None
                                  —— collect 後套用的欄位轉換（如 BigFlow 欄位映射）

    common_cols: 最終輸出保留的欄位名稱列表（None = 自動取交集）

    範例：
        sources = [
            {"paths": cic_paths},
            {"paths": bigflow_paths,
             "label_col": "Attack",
             "normal_label": "Benign",
             "post_transform": add_bigflow_features},
        ]
        df = get_mixed_normal_sample(sources, n_per_source=10000,
                                     common_cols=RUN17_FEATURE_COLS)
    """
    if not sources:
        raise ValueError("sources 不能為空")

    chunks: list[pl.DataFrame] = []
    for src in sources:
        paths        = src["paths"]
        label_col    = src.get("label_col", "Label")
        normal_label = src.get("normal_label", "BENIGN")
        post_tf      = src.get("post_transform", None)

        read_cols = src.get("read_cols", None)
        result: list[pl.DataFrame] = []
        count = 0
        for path in paths:
            if read_cols is not None:
                # Column-pruned read avoids OOM and cross-file schema conflicts
                df = pl.read_parquet(path, columns=read_cols).filter(
                    pl.col(label_col) == normal_label
                )
            else:
                df = pl.scan_parquet(path).filter(pl.col(label_col) == normal_label).collect()
            if len(df) == 0:
                continue
            if post_tf is not None:
                df = post_tf(df)
            take = min(len(df), n_per_source - count)
            result.append(df.sample(take, seed=seed))
            count += take
            del df
            if count >= n_per_source:
                break

        if not result:
            continue
        chunks.append(pl.concat(result))

    if not chunks:
        raise ValueError("所有 sources 均無法取得 BENIGN 資料")

    if len(chunks) < len(sources):
        import warnings
        n_skipped = len(sources) - len(chunks)
        warnings.warn(
            f"get_mixed_normal_sample: {n_skipped}/{len(sources)} sources 無 BENIGN 資料，"
            "邊界以部分來源計算，可能 overfit",
            UserWarning,
            stacklevel=2,
        )

    # 欄位對齊：取交集或指定 common_cols
    if common_cols is not None:
        aligned = [df.select([c for c in common_cols if c in df.columns])
                   for df in chunks]
    else:
        shared = set(chunks[0].columns)
        for df in chunks[1:]:
            shared &= set(df.columns)
        aligned = [df.select(sorted(shared)) for df in chunks]

    return pl.concat(aligned)


if __name__ == "__main__":
    import os
    _base = os.path.dirname(os.path.dirname(__file__))
    data_path = glob.glob(os.path.join(_base, "dataset/parquet_clean/*.parquet"))
    df = get_balance_sample_from_files(paths=data_path, sample_count_per_label=5000)
    print(df)