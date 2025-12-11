#將TSV格式的conn日誌轉換為帶有基本特徵的CSV文件
import argparse
import pandas as pd
from utils import build_basic_features

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", type=str, required=True, help="conn.tsv (zeek-cut 輸出)")
    ap.add_argument("--output", type=str, default="conn_features.csv")
    args = ap.parse_args()

    df = pd.read_csv(args.input, sep="\t", comment="#", header=None, names=[
        "ts","uid","src","sport","dst","dport","proto","service","duration",
        "orig_bytes","resp_bytes","orig_ip_bytes","resp_ip_bytes","orig_pkts","resp_pkts","history"
    ], na_values=["-","(empty)"])

    out = build_basic_features(df)
    out.to_csv(args.output, index=False)
    print(f"Saved features -> {args.output}, rows={len(out)}")

if __name__ == "__main__":
    main()
