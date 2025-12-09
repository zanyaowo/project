import argparse
import pandas as pd

def score_rule(row):
    s = 0
    # 例：單向小封包洪流
    if row["bytes_sum"] < 400 and row["pkts_sum"] > 20:
        s += 2
    # 例：非典型服務 + 高連線速度
    if (str(row.get("service","")) in {"-","unknown",""}) and row["bps_approx"] > 1e6:
        s += 1
    # 例：流量極度不對稱
    if row["bytes_ratio"]>20 or row["bytes_ratio"]<0.05:
        s += 1
    return s

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", type=str, required=True, help="conn_features.csv")
    ap.add_argument("--output", type=str, default="alerts_rule.csv")
    args = ap.parse_args()

    df = pd.read_csv(args.input)
    df["rule_score"] = df.apply(score_rule, axis=1)

    cols = ["ts","src","sport","dst","dport","rule_score","bytes_sum","pkts_sum","bps_approx","bytes_ratio"]
    alerts = df[df["rule_score"] >= 2][cols].sort_values("rule_score", ascending=False)

    alerts.to_csv(args.output, index=False)
    print(f"Alerts (rule) -> {args.output}, count={len(alerts)}")

if __name__ == "__main__":
    main()
