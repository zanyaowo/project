import polars as pl
import polars.selectors as cs

from service.model.schema import STRING_TO_FLOAT_COLS, CLIP_UPPER_PERCENTILE


def clean(lf: pl.LazyFrame) -> pl.LazyFrame:
    lf = _strip_column_names(lf)
    lf = _cast_types(lf)
    lf = _cap_infinite(lf)
    lf = _fill_nulls(lf)
    return lf

def _strip_column_names(lf: pl.LazyFrame) -> pl.LazyFrame:
    return lf.rename({c: c.strip() for c in lf.collect_schema().names()})

def _cap_infinite(lf: pl.LazyFrame) -> pl.LazyFrame:
    # inf（Flow Duration=0 造成的 Bytes/s、Packets/s 極大值）以該欄位非 inf 的最大值替換
    # 保留極端值的語義（高流量特徵），避免直接刪除損失 DDoS 判斷依據
    num_cols = lf.select(cs.numeric()).collect_schema().names()
    inf_cols = [c for c in num_cols if lf.filter(pl.col(c).is_infinite()).limit(1).collect().height > 0]
    if not inf_cols:
        return lf

    caps = (
        lf.select([
            pl.col(c).filter(~pl.col(c).is_infinite())
            .quantile(CLIP_UPPER_PERCENTILE, interpolation="nearest")
            .alias(c)
            for c in inf_cols
        ])
        .collect()
        .row(0, named=True)
    )

    return lf.with_columns([
        pl.when(pl.col(c).is_infinite())
        .then(pl.lit(caps[c], dtype=pl.Float64))
        .otherwise(pl.col(c))
        .alias(c)
        for c in inf_cols
        if caps[c] is not None
    ])


def _fill_nulls(lf: pl.LazyFrame) -> pl.LazyFrame:
    # cast 後剩餘的 null（原始空值或 NaN 字串轉換失敗）填 0
    num_cols = lf.select(cs.numeric()).collect_schema().names()
    return lf.with_columns([
        pl.col(c).fill_nan(None).fill_null(0.0).alias(c)
        for c in num_cols
    ])


def _clip_outliers(lf: pl.LazyFrame) -> pl.LazyFrame:
    num_cols = lf.select(cs.numeric()).collect_schema().names()

    caps = (
        lf.select([
            pl.col(c).quantile(CLIP_UPPER_PERCENTILE, interpolation="nearest")
            for c in num_cols
        ])
        .collect()
        .row(0, named=True)
    )
    return lf.with_columns([
        pl.col(c).clip(upper_bound=caps[c])
        for c in num_cols
    ])


def _cast_types(lf: pl.LazyFrame) -> pl.LazyFrame:
    schema_names = lf.collect_schema().names()
    if "Unnamed: 0" in schema_names:
        lf = lf.drop("Unnamed: 0")
    cols_to_cast = [c for c in STRING_TO_FLOAT_COLS if c in schema_names]
    if not cols_to_cast:
        return lf
    return lf.with_columns([
        pl.col(c).cast(pl.Float64, strict=False)
        for c in cols_to_cast
    ])
