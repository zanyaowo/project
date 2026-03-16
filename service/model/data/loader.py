"""
負責 I/O：從磁碟讀取原始資料，回傳 LazyFrame。
以CIC IDS 2019資料
"""

import polars as pl
import glob
import os
import argparse

# CSV 原始欄位名含前置空格，需與 parquet 後 _strip_column_names 清洗前的名稱一致
_CSV_FLOAT_OVERRIDES = {
    'SimillarHTTP': pl.String,
    'Flow Bytes/s': pl.Float64,
    ' Flow Packets/s': pl.Float64,
}

def _load_features_csv(path: str) -> pl.LazyFrame:
    return pl.scan_csv(path, null_values=[""], schema_overrides=_CSV_FLOAT_OVERRIDES)

def csv_to_parquet():
    csv_files = glob.glob(
        '/home/zanya/code/ebpf_project/project/service/model/dataset/*/*.csv')
    out_dir = "/home/zanya/code/ebpf_project/project/service/model/dataset/parquet"
    for file in csv_files:
        print(f"csv path: {file}")
        base_name = os.path.basename(file)
        folder_name = os.path.basename(os.path.dirname(file))
        parquet_filename = f"{folder_name}_{base_name}".replace('.csv', '.parquet')
        save_path = os.path.join(out_dir, parquet_filename)
        pl.scan_csv(file, schema_overrides=_CSV_FLOAT_OVERRIDES).sink_parquet(save_path)
        print(f"已成功轉換: {base_name} -> {save_path}")

if __name__ == "__main__":
    csv_to_parquet()