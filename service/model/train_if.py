import argparse
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from joblib import dump
from utils import FEATURE_COLS

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", type=str, required=True, help="conn_features.csv")
    ap.add_argument("--model", type=str, default="if_model.joblib")
    ap.add_argument("--alert_rate", type=float, default=0.005, help="預期異常比例 (0.005 = 0.5%)")
    ap.add_argument("--trees", type=int, default=300)
    args = ap.parse_args()

    df = pd.read_csv(args.input)
    X = df[FEATURE_COLS].replace([np.inf,-np.inf], np.nan).fillna(0.0).values

    scaler = StandardScaler()
    Xn = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=args.trees,
        contamination=args.alert_rate,  # 僅影響 score 門檻的內部估計
        random_state=42,
        n_jobs=-1,
    )
    model.fit(Xn)

    scores = -model.score_samples(Xn)  # 值越大越可疑
    thr = float(np.quantile(scores, 1.0 - args.alert_rate))

    meta = {
        "feature_cols": FEATURE_COLS,
        "threshold": thr,
        "alert_rate": args.alert_rate,
    }

    dump({"scaler": scaler, "model": model, "meta": meta}, args.model)
    print(f"Saved model -> {args.model}")
    print(f"Learned threshold (approx at alert_rate={args.alert_rate}): {thr:.6f}")

if __name__ == "__main__":
    main()
