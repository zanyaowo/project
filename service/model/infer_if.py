#核心異常偵測模型：Isolation Forest 推論腳本
import argparse
import numpy as np
import pandas as pd
from joblib import load
from utils import FEATURE_COLS

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", type=str, required=True, help="conn_features.csv")
    ap.add_argument("--model", type=str, required=True, help="if_model.joblib")
    ap.add_argument("--output", type=str, default="alerts_if.csv")
    ap.add_argument("--override_threshold", type=float, default=None, help="覆寫模型內建阈值（可選）")
    args = ap.parse_args()

    bundle = load(args.model)
    scaler = bundle["scaler"]
    model = bundle["model"]
    meta = bundle.get("meta", {})
    thr = args.override_threshold if args.override_threshold is not None else meta.get("threshold", None)

    df = pd.read_csv(args.input)
    X = df[FEATURE_COLS].replace([np.inf,-np.inf], np.nan).fillna(0.0).values
    Xn = scaler.transform(X)

    scores = -model.score_samples(Xn)  # 越大越可疑
    df["anomaly_score"] = scores

    if thr is None:
        # 保底：若沒有 threshold，就取 99.5 百分位
        thr = float(np.quantile(scores, 0.995))

    df["is_alert"] = df["anomaly_score"] > thr
    cols = ["ts","src","sport","dst","dport","anomaly_score","bytes_sum","pkts_sum","bps_approx","bytes_ratio"]
    alerts = df[df["is_alert"]][cols].sort_values("anomaly_score", ascending=False)

    alerts.to_csv(args.output, index=False)
    print(f"Alerts (IF) -> {args.output}, count={len(alerts)}, threshold={thr:.6f}")

if __name__ == "__main__":
    main()
