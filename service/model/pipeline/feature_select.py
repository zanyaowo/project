import argparse

import numpy as np
import polars as pl
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance

from service.model.data.cleaner import clean
from service.model.data.loader import _load_features_csv as load_features_csv


def _extract_label(lf: pl.LazyFrame) -> pl.LazyFrame:
    # set normal to 0, attack to 1
    return lf.with_columns(
        pl.col("Label") != "BENIGN"
    )

def feature_select(
    lf: pl.LazyFrame,
    top_n: int = 20,
    n_estimators: int = 100,
    sample_n: int = 200_000,
    output: str = "feature_importance.png",
) -> list[str]:
    lf = _extract_label(lf)
    tmp_path = "/tmp/_feature_select_tmp.parquet"
    clean(lf).sink_parquet(tmp_path)
    df = (
        pl.scan_parquet(tmp_path)
        .collect()
        .sample(n=sample_n, shuffle=True, seed=42)
    )

    label = df.select("Label").to_numpy().flatten()
    X_df = df.drop("Label")
    feature_names = X_df.columns
    X = X_df.to_numpy()

    forest = RandomForestClassifier(n_estimators=n_estimators, class_weight="balanced")
    forest.fit(X, label)

    result = permutation_importance(forest, X, label, n_repeats=10, random_state=42, n_jobs=2)

    sorted_idx = np.argsort(result.importances_mean)[::-1]
    top_features = [feature_names[i] for i in sorted_idx[:top_n]]
    top_importances = result.importances_mean[sorted_idx[:top_n]]
    top_std = result.importances_std[sorted_idx[:top_n]]

    _draw_feature_importance(top_features, top_importances, top_std, output)

    print("\nFEATURE_COLS = [")
    for f in top_features:
        print(f'    "{f}",')
    print("]")

    return top_features


def _draw_feature_importance(
    feature_names: list[str],
    importances: np.ndarray,
    std: np.ndarray,
    output: str,
) -> None:
    fig, ax = plt.subplots()
    ax.barh(feature_names, importances, xerr=std)
    ax.set_title("Feature importances using permutation on full model")
    ax.set_xlabel("Mean accuracy decrease")
    fig.tight_layout()
    plt.savefig(output)
    plt.show()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to CIC IDS 2019 CSV")
    parser.add_argument("--top", type=int, default=20, help="Number of top features")
    parser.add_argument("--trees", type=int, default=100, help="Number of RF estimators")
    parser.add_argument("--output", default="feature_importance.png", help="Output plot path")
    args = parser.parse_args()

    lf = load_features_csv(args.input)
    feature_select(lf, top_n=args.top, n_estimators=args.trees, output=args.output)