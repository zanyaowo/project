import polars as pl
import polars.selectors as cs

from service.model.schema import STRING_TO_FLOAT_COLS, ID_COLS, CLIP_UPPER_PERCENTILE


def clean(lf: pl.LazyFrame) -> pl.LazyFrame:
    lf = _strip_column_names(lf)
    lf = _cast_types(lf)
    lf = _fill_nulls(lf)
    lf = _clip_outliers(lf)
    return lf

def _strip_column_names(lf: pl.LazyFrame) -> pl.LazyFrame:
    return lf.rename({c: c.strip() for c in lf.collect_schema().names()})

def _fill_nulls(lf: pl.LazyFrame) -> pl.LazyFrame:
    nums_col = [c for c in lf.collect_schema().names() if c not in ID_COLS]
    return lf.with_columns([
        pl.when(pl.col(c).is_infinite() | pl.col(c).is_nan())
        .then(pl.lit(None, dtype=pl.Float64))
        .otherwise(pl.col(c))
        .fill_null(0.0)
        .alias(c)
        for c in nums_col
    ])


def _clip_outliers(lf: pl.LazyFrame) -> pl.LazyFrame:
    num_cols = lf.select(cs.numeric()).collect_schema().names()

    caps = (
        lf.select(num_cols)
        .collect()
        .select([
            pl.col(c).quantile(CLIP_UPPER_PERCENTILE, interpolation="nearest")
            for c in num_cols
        ])
        .row(0, named=True)
    )
    return lf.with_columns([
        pl.col(c).clip(upper_bound=caps[c])
        for c in num_cols
    ])


def _cast_types(lf: pl.LazyFrame) -> pl.LazyFrame:
    lf = lf.drop("Unnamed: 0")
    return lf.with_columns(
        [
        pl.col(c).cast(pl.Float64, strict=False)
        for c in STRING_TO_FLOAT_COLS
        ]
    )
