import polars as pl
import glob
import os
import argparse
from service.model.data.cleaner import clean

_CSV_FLOAT_OVERRIDES = {
    'SimillarHTTP': pl.String,
    'Flow Bytes/s': pl.Float64,
    ' Flow Packets/s': pl.Float64,
}

def _load_features_parquet(path: str) -> pl.LazyFrame:
    return pl.scan_parquet(path)

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

def clean_and_save(
    src_dir: str = "/home/zanya/code/ebpf_project/project/service/model/dataset/parquet",
    out_dir: str = "/home/zanya/code/ebpf_project/project/service/model/dataset/parquet_clean",
) -> None:
    """將 parquet_dir 下所有 parquet 清洗後寫入 out_dir。"""

    os.makedirs(out_dir, exist_ok=True)
    files = glob.glob(os.path.join(src_dir, "*.parquet"))
    for path in files:
        name = os.path.basename(path)
        out_path = os.path.join(out_dir, name)
        clean(pl.scan_parquet(path)).sink_parquet(out_path)
        print(f"cleaned: {name} -> {out_path}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "clean":
        clean_and_save()
    else:
        csv_to_parquet()