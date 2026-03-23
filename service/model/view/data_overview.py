import glob
import polars as pl

def get_each_label_count(
        paths: list[str]
):
    frame = []
    for path in paths:
        df = pl.scan_parquet(path).select("Label").collect()
        frame.append(df)

    combined = pl.concat(frame)
    result = combined.group_by("Label").len().sort("len", descending=True)
    for row in result.iter_rows(named=True):
        print(f"{row['Label']:20s} {row['len']:>10,}")


if __name__ == "__main__":
    paths = glob.glob("/home/zanya/code/ebpf_project/project/service/model/dataset/parquet_clean/*.parquet")
    get_each_label_count(paths)