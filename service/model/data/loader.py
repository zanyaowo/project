"""
負責 I/O：從磁碟讀取原始資料，回傳 LazyFrame。
以CIC IDS 2019資料
"""

import polars as pl

def load_features_csv(path: str) -> pl.LazyFrame:
    return pl.scan_csv(path, null_values=["", "Infinity", "NaN", "nan"])

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to CIC IDS 2019 CSV")
    args = parser.parse_args()

    lf = load_features_csv(args.input).collect()
    print(lf.head(5))