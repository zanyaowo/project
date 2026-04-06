"""
IF 異常點視覺化：使用 PCA 降至 2D，標記正常點（藍）與異常點（紅）。

用法：
  # 從已訓練的 IF bundle 直接繪製
  python -m service.model.view.if_anomaly_plot \\
      --input  service/model/dataset/parquet_clean/some.parquet \\
      --model  service/model/model_store/if_model.joblib \\
      --output if_anomaly.png

  # 程式內呼叫
  from service.model.view.if_anomaly_plot import plot_if_anomaly
  plot_if_anomaly(result_df, feature_cols, output="if_anomaly.png")
"""
import argparse

import matplotlib.pyplot as plt
import numpy as np
import polars as pl
from sklearn.decomposition import PCA


def plot_if_anomaly(
    df: pl.DataFrame,
    feature_cols: list[str],
    anomaly_score_col: str = "anomaly_score",
    is_alert_col: str = "is_alert",
    output: str = "if_anomaly.png",
    sample_n: int = 5000,
    seed: int = 42,
) -> None:
    """
    df 需含有 feature_cols、anomaly_score_col、is_alert_col 三組欄位
    （通常是 infer.py 的輸出結果）。

    Parameters
    ----------
    sample_n : 最多取幾筆繪圖（資料量大時加快速度）
    """
    if len(df) > sample_n:
        df = df.sample(sample_n, seed=seed)

    X = df.select(feature_cols).to_numpy().astype(np.float32)
    scores = df[anomaly_score_col].to_numpy()
    is_alert = df[is_alert_col].to_numpy().astype(bool)

    # ── PCA 降至 2D ───────────────────────────────────────────
    pca = PCA(n_components=2, random_state=seed)
    X2d = pca.fit_transform(X)
    var_explained = pca.explained_variance_ratio_

    normal_idx = ~is_alert
    alert_idx = is_alert

    # ── 繪圖 ─────────────────────────────────────────────────
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))

    # 左：正常 vs 異常散點圖
    ax = axes[0]
    ax.scatter(
        X2d[normal_idx, 0], X2d[normal_idx, 1],
        c="steelblue", alpha=0.3, s=8, label=f"Normal ({normal_idx.sum():,})",
    )
    ax.scatter(
        X2d[alert_idx, 0], X2d[alert_idx, 1],
        c="crimson", alpha=0.6, s=12, label=f"Anomaly ({alert_idx.sum():,})",
        zorder=3,
    )
    ax.set_title(
        f"IsolationForest Anomaly Detection (PCA)\n"
        f"PC1={var_explained[0]:.1%}  PC2={var_explained[1]:.1%}"
    )
    ax.set_xlabel("PC1")
    ax.set_ylabel("PC2")
    ax.legend(markerscale=2)

    # 右：anomaly score 分布直方圖（分組）
    ax2 = axes[1]
    ax2.hist(
        scores[normal_idx], bins=60, color="steelblue",
        alpha=0.6, label="Normal", density=True,
    )
    ax2.hist(
        scores[alert_idx], bins=60, color="crimson",
        alpha=0.6, label="Anomaly", density=True,
    )
    # 標出 threshold（以 alert 側最小值近似）
    if alert_idx.sum() > 0:
        thr_approx = float(scores[alert_idx].min())
        ax2.axvline(thr_approx, color="black", linestyle="--", linewidth=1.2,
                    label=f"threshold ≈ {thr_approx:.4f}")
    ax2.set_title("Anomaly Score Distribution")
    ax2.set_xlabel("Anomaly Score  (higher = more suspicious)")
    ax2.set_ylabel("Density")
    ax2.legend()

    fig.tight_layout()
    plt.savefig(output, dpi=150)
    print(f"圖表已儲存 -> {output}")
    plt.show()


# ── CLI 入口 ──────────────────────────────────────────────────

def _run(args: argparse.Namespace) -> None:
    from joblib import load
    from service.model.data.cleaner import clean

    bundle = load(args.model)
    if bundle.get("model_type") != "if":
        raise ValueError("此腳本只支援 IsolationForest bundle（model_type='if'）")

    meta: dict = bundle["meta"]
    from sklearn.preprocessing import StandardScaler
    from sklearn.ensemble import IsolationForest

    scaler: StandardScaler = bundle["scaler"]
    model: IsolationForest = bundle["model"]
    feature_cols: list[str] = meta["feature_cols"]
    threshold: float = meta["threshold"]

    lf = pl.scan_parquet(args.input) if args.input.endswith(".parquet") else pl.scan_csv(args.input)
    df = clean(lf).collect()

    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        raise KeyError(f"缺少特徵欄位：{missing}")

    X = df.select(feature_cols).to_numpy().astype(np.float32)
    X_scaled = scaler.transform(X)
    scores = -model.score_samples(X_scaled)
    is_alert = scores > threshold

    result = df.with_columns([
        pl.Series("anomaly_score", scores.astype(np.float32)),
        pl.Series("is_alert", is_alert),
    ])

    plot_if_anomaly(result, feature_cols, output=args.output, sample_n=args.sample_n)


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="繪製 IF 異常點 PCA 散點圖")
    p.add_argument("--input", required=True, help="輸入資料（.parquet 或 .csv）")
    p.add_argument("--model", required=True, help="IF joblib 路徑")
    p.add_argument("--output", default="if_anomaly.png", help="圖表輸出路徑")
    p.add_argument("--sample_n", type=int, default=5000, help="最多繪製筆數")
    return p.parse_args()


if __name__ == "__main__":
    _run(_parse_args())