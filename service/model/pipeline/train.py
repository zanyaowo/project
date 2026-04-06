"""訓練流程：sample → fit → save model。

輸入須為 loader.clean_and_save() 產出的 parquet_clean/ 目錄，資料已預先清洗，
此處不再重複套用 clean()。

用法範例：
  # IsolationForest（預設，只用 BENIGN 資料）
  python -m service.model.pipeline.train --model_type if
"""
import argparse
import glob
import os

from service.model.data.sample import (
    get_balance_sample_from_files,
    get_normal_sample_from_files,
)
from service.model.pipeline.trainer import get_trainer


def _load_data_for_if(paths: list[str], args: argparse.Namespace):
    """IF：只取 BENIGN 資料建模正常行為。"""
    print(f"      抽樣策略：BENIGN only，最多 {args.sample_count} 筆")
    return get_normal_sample_from_files(
        paths,
        n=args.sample_count,
        seed=args.seed,
    )


def _load_data_for_rf(paths: list[str], args: argparse.Namespace):
    """RF：每 label 均衡抽樣。"""
    print(f"      抽樣策略：balanced，每 label 最多 {args.sample_count} 筆")
    return get_balance_sample_from_files(
        paths,
        sample_count_per_label=args.sample_count,
        seed=args.seed,
    )


_DATA_LOADER = {
    "if": _load_data_for_if,
    "rf": _load_data_for_rf,
}


def run(args: argparse.Namespace) -> None:
    paths = glob.glob(os.path.join(args.data_dir, "*.parquet"))
    if not paths:
        raise FileNotFoundError(f"找不到 parquet 檔案：{args.data_dir}")

    print(f"[1/4] 載入資料（{len(paths)} 個檔案）...")
    df = _DATA_LOADER[args.model_type](paths, args)
    print(f"      總筆數：{len(df)}")
    print(df["Label"].value_counts().sort("Label"))

    print(f"\n[2/4] 初始化 Trainer（model_type={args.model_type}）...")
    trainer = get_trainer(
        args.model_type,
        n_estimators=args.n_estimators,
        seed=args.seed,
        **_extra_kwargs(args),
    )

    print("\n[3/4] 訓練模型...")
    trainer.fit(df)

    print(f"\n[4/4] 儲存模型...")
    trainer.save(args.output)


def _extra_kwargs(args: argparse.Namespace) -> dict:
    """依模型類型傳入額外參數。"""
    if args.model_type == "if":
        return {"contamination": args.contamination}
    return {}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="訓練 IsolationForest / RandomForest 模型")
    p.add_argument(
        "--model_type",
        choices=["if", "rf"],
        default="if",
        help="模型類型（預設：if）",
    )
    p.add_argument(
        "--data_dir",
        default="service/model/dataset/parquet_clean/train",
        help="清洗後 parquet 目錄",
    )
    p.add_argument(
        "--output",
        default=None,
        help="模型輸出路徑（預設：model_store/{model_type}_model.joblib）",
    )
    p.add_argument("--n_estimators", type=int, default=200)
    p.add_argument("--sample_count", type=int, default=10000, help="抽樣筆數（IF: 總筆數；RF: 每 label）")
    p.add_argument("--contamination", type=float, default=0.01, help="IF 用：預期異常比例")
    p.add_argument("--seed", type=int, default=42)
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.output is None:
        args.output = f"service/model/model_store/{args.model_type}_model.joblib"
    run(args)