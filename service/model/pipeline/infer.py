"""推論流程：load model → score → 輸出 alerts。

輸入須為 loader.clean_and_save() 產出的 parquet_clean/ 目錄下的檔案，資料已預先清洗。

用法範例：
  python -m service.model.pipeline.infer \\
      --input service/model/dataset/parquet_clean/some.parquet \\
      --model service/model/model_store/if_model.joblib

  # 大型檔案：隨機抽樣 N 筆避免記憶體溢出
  python -m service.model.pipeline.infer ... --sample_n 50000

  # 若輸入有 Label 欄位，加 --report 顯示 classification report
  python -m service.model.pipeline.infer ... --report
"""
import argparse
import os

import numpy as np
import polars as pl
from joblib import load

from service.model.data.sample import random_sample_lazyframe


# ── 各模型推論實作 ─────────────────────────────────────────────

def _infer_if(df: pl.DataFrame, bundle: dict) -> pl.DataFrame:
    """IsolationForest：輸出 anomaly_score 與 is_alert。"""
    from sklearn.preprocessing import StandardScaler
    from sklearn.ensemble import IsolationForest

    meta: dict = bundle["meta"]
    scaler: StandardScaler = bundle["scaler"]
    model: IsolationForest = bundle["model"]
    feature_cols: list[str] = meta["feature_cols"]
    threshold: float = meta["threshold"]

    _check_features(df, feature_cols)
    X = df.select(feature_cols).to_numpy().astype(np.float32)
    X = scaler.transform(X)

    scores = -model.score_samples(X)
    is_alert = scores > threshold

    return df.with_columns([
        pl.Series("anomaly_score", scores.astype(np.float32)),
        pl.Series("is_alert", is_alert),
    ])


def _infer_rf(df: pl.DataFrame, bundle: dict) -> pl.DataFrame:
    """RandomForest：輸出 pred_label 與 pred_confidence。"""
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.ensemble import RandomForestClassifier

    meta: dict = bundle["meta"]
    scaler: StandardScaler = bundle["scaler"]
    model: RandomForestClassifier = bundle["model"]
    le: LabelEncoder = meta["label_encoder"]
    feature_cols: list[str] = meta["feature_cols"]

    _check_features(df, feature_cols)
    X = df.select(feature_cols).to_numpy().astype(np.float32)
    X = scaler.transform(X)

    y_pred = model.predict(X)
    pred_labels: np.ndarray = le.inverse_transform(y_pred)  # type: ignore[assignment]
    proba: np.ndarray = np.array(model.predict_proba(X))  # type: ignore[arg-type]
    confidence = proba.max(axis=1).astype(np.float32)

    return df.with_columns([
        pl.Series("pred_label", pred_labels.astype(str)),
        pl.Series("pred_confidence", confidence),
        pl.Series("is_alert", pred_labels != "BENIGN"),
    ])


_INFER_FN = {
    "if": _infer_if,
    "rf": _infer_rf,
}

# ── 工具 ──────────────────────────────────────────────────────

def _check_features(df: pl.DataFrame, feature_cols: list[str]) -> None:
    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        print(f"警告：缺少特徵欄位（補 0）：{missing}")
        # 補 0 讓推論繼續，呼叫方需注意結果可信度
        raise KeyError(f"輸入資料缺少必要特徵欄位：{missing}")


def _load_input(path: str) -> pl.LazyFrame:
    if path.endswith(".parquet"):
        return pl.scan_parquet(path)
    if path.endswith(".csv"):
        return pl.scan_csv(path, null_values=[""])
    raise ValueError(f"不支援的格式：{path}，請提供 .parquet 或 .csv")


def _save_output(df: pl.DataFrame, path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    if path.endswith(".parquet"):
        df.write_parquet(path)
    else:
        df.write_csv(path)


def _print_report(result: pl.DataFrame, model_type: str) -> None:
    """若輸入有 Label 欄位，印出 classification report。"""
    if "Label" not in result.columns:
        return
    from sklearn.metrics import classification_report

    true_labels = result["Label"].to_list()

    if model_type == "if":
        # IF 為二分類：BENIGN=0, alert=1
        y_true = [0 if l == "BENIGN" else 1 for l in true_labels]
        y_pred = result["is_alert"].cast(pl.Int32).to_list()
        print("\nclassification report（二分類）:")
        print(classification_report(y_true, y_pred, target_names=["BENIGN", "ALERT"]))
    else:
        pred_labels = result["pred_label"].to_list()
        print("\nclassification report:")
        print(classification_report(true_labels, pred_labels))


# ── 主流程 ────────────────────────────────────────────────────

def run(args: argparse.Namespace) -> None:
    print(f"[1/4] 載入模型：{args.model}")
    bundle: dict = load(args.model)
    model_type: str = bundle.get("model_type", "if")
    print(f"      model_type={model_type}，特徵數={len(bundle['meta']['feature_cols'])}")

    if model_type not in _INFER_FN:
        raise ValueError(f"不支援的 model_type：{model_type!r}")

    print(f"\n[2/4] 載入並清洗資料：{args.input}")
    lf = _load_input(args.input)
    if args.sample_n:
        lf = random_sample_lazyframe(lf, args.sample_n, seed=args.seed)
    df = lf.collect()
    print(f"      筆數：{len(df)}" + (f"（隨機抽樣 {args.sample_n} 筆）" if args.sample_n else ""))

    print(f"\n[3/4] 推論...")
    result = _INFER_FN[model_type](df, bundle)
    alerts = result.filter(pl.col("is_alert"))
    if model_type == "rf" and "pred_confidence" in alerts.columns:
        alerts = alerts.sort("pred_confidence", descending=True)
    elif model_type == "if" and "anomaly_score" in alerts.columns:
        alerts = alerts.sort("anomaly_score", descending=True)

    print(f"      告警數：{len(alerts)} / {len(result)}")
    if len(alerts) > 0:
        col = "pred_label" if model_type == "rf" else "is_alert"
        if col in alerts.columns and model_type == "rf":
            print(alerts["pred_label"].value_counts().sort("pred_label"))

    if args.report:
        _print_report(result, model_type)

    print(f"\n[4/4] 儲存告警 -> {args.output}")
    _save_output(alerts, args.output)
    print("完成。")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="推論 IsolationForest / RandomForest 模型")
    p.add_argument("--input", required=True, help="輸入檔案（.parquet 或 .csv）")
    p.add_argument("--model", required=True, help="模型 joblib 路徑")
    p.add_argument("--output", default="alerts.csv", help="告警輸出路徑（.csv 或 .parquet）")
    p.add_argument("--report", action="store_true", help="若輸入有 Label 欄位，印出 classification report")
    p.add_argument("--sample_n", type=int, default=0,
                   help="隨機抽樣 N 筆推論（0=全部載入；大型 parquet 建議指定此值避免記憶體溢出）")
    p.add_argument("--seed", type=int, default=42, help="隨機抽樣 seed")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run(args)