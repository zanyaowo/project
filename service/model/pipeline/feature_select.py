"""Feature selection for IsolationForest.

方案 B：BENIGN-only variance filter + correlation filter
方案 D：以 B 篩出的特徵訓練 IF，在含攻擊驗證集上計算 AUC-ROC

輸入須為 loader.clean_and_save() 產出的 parquet_clean/ 目錄，資料已預先清洗，
此處不再重複套用 clean()。

執行範例：
  python -m service.model.pipeline.feature_select \\
      --data_dir  service/model/dataset/parquet_clean/train \\
      --val_dir   service/model/dataset/parquet_clean/val
"""
import argparse
import glob

import numpy as np
import polars as pl
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import StandardScaler

from service.model.data.sample import get_balance_sample_from_files, get_normal_sample_from_files
from service.model.pipeline.correlation_filter import drop_correlated
from service.model.schema import ID_COLS


# ── 共用工具 ──────────────────────────────────────────────────

_EXCLUDE = set(ID_COLS) | {"Inbound"}
_NUMERIC_DTYPES = (pl.Float64, pl.Float32, pl.Int64, pl.Int32, pl.Int16, pl.Int8, pl.UInt32, pl.UInt16, pl.UInt8)


def _numeric_matrix(df: pl.DataFrame) -> tuple[np.ndarray, list[str]]:
    """取出非 ID 的數值欄位，回傳 (X: float32 ndarray, feature_names)。"""
    cols = [c for c in df.columns if c not in _EXCLUDE and df[c].dtype in _NUMERIC_DTYPES]
    return df.select(cols).to_numpy().astype(np.float32), cols


# ── 方案 B：Variance filter ───────────────────────────────────

def variance_select(
    benign_df: pl.DataFrame,
    var_threshold: float = 1e-4,
    corr_threshold: float = 0.9,
) -> list[str]:
    """
    只用 BENIGN 資料：
      1. 移除 variance ≤ var_threshold 的特徵（近乎常數，IF 無法用來隔離）
      2. 移除 Pearson |r| > corr_threshold 的冗餘特徵
    回傳存活特徵名稱清單。
    """
    X, feature_names = _numeric_matrix(benign_df)
    n_total = len(feature_names)

    # --- step 1: variance filter ---
    variances = X.var(axis=0)
    keep_idx = [i for i, v in enumerate(variances) if v > var_threshold]
    dropped = [feature_names[i] for i in range(n_total) if i not in set(keep_idx)]
    X = X[:, keep_idx]
    feature_names = [feature_names[i] for i in keep_idx]

    print(f"\n[方案 B] Variance filter (threshold={var_threshold})")
    print(f"  {n_total} → {len(feature_names)} 個特徵（移除 {len(dropped)} 個）")
    if dropped:
        print(f"  低 variance 移除：{dropped}")

    # --- step 2: correlation filter ---
    X, feature_names = drop_correlated(X, feature_names, threshold=corr_threshold)

    print(f"\n方案 B 最終：{len(feature_names)} 個特徵")
    # 印出各特徵的 variance 供參考
    final_var = {f: float(X[:, i].var()) for i, f in enumerate(feature_names)}
    print(f"\n{'特徵名稱':<40} {'Variance':>14}")
    print("-" * 56)
    for f, v in sorted(final_var.items(), key=lambda x: -x[1]):
        print(f"  {f:<38} {v:>14.4f}")

    return feature_names


# ── 方案 D：IF anomaly score AUC ─────────────────────────────

def if_auc_validate(
    benign_df: pl.DataFrame,
    val_df: pl.DataFrame,
    feature_names: list[str],
    n_estimators: int = 200,
    contamination: float = 0.01,
    seed: int = 42,
) -> float:
    """
    以 feature_names 訓練 IF（BENIGN-only），
    在含攻擊的驗證集上以 anomaly score 計算 AUC-ROC。
    AUC 越高 → 這組特徵讓攻擊流量在 IF 座標空間中越孤立。
    """
    missing = [f for f in feature_names if f not in benign_df.columns]
    if missing:
        raise KeyError(f"BENIGN 資料缺少特徵：{missing}")
    missing_val = [f for f in feature_names if f not in val_df.columns]
    if missing_val:
        raise KeyError(f"驗證資料缺少特徵：{missing_val}")

    # 訓練
    X_train = benign_df.select(feature_names).to_numpy().astype(np.float32)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    print(f"\n[方案 D] 訓練 IF（特徵數={len(feature_names)}, "
          f"n_estimators={n_estimators}, contamination={contamination}）...")
    iso = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,  # type: ignore[arg-type]
        random_state=seed,
        n_jobs=-1,
    )
    iso.fit(X_train_scaled)

    # 驗證
    X_val = val_df.select(feature_names).to_numpy().astype(np.float32)
    X_val_scaled = scaler.transform(X_val)

    y_true = (val_df["Label"] != "BENIGN").cast(pl.Int8).to_numpy()
    scores = -iso.score_samples(X_val_scaled)   # 值越大 = 越異常

    auc = float(roc_auc_score(y_true, scores))
    attack_ratio = float(y_true.mean())

    print(f"  驗證集：{len(val_df)} 筆，攻擊比例：{attack_ratio:.1%}")
    print(f"  AUC-ROC：{auc:.4f}")

    if auc >= 0.90:
        verdict = "優秀，這組特徵可直接使用"
    elif auc >= 0.75:
        verdict = "尚可，建議再用 --var_threshold 調高或手動排除幾個特徵"
    else:
        verdict = "偏低，建議搭配領域知識手動挑選特徵"
    print(f"  判讀：{verdict}")

    return auc


# ── 主流程 ────────────────────────────────────────────────────

def run(args: argparse.Namespace) -> None:
    train_paths = glob.glob(f"{args.data_dir}/*.parquet")
    if not train_paths:
        raise FileNotFoundError(f"找不到 parquet：{args.data_dir}")

    val_dir = args.val_dir or args.data_dir
    val_paths = glob.glob(f"{val_dir}/*.parquet")
    if not val_paths:
        raise FileNotFoundError(f"找不到驗證 parquet：{val_dir}")
    if val_dir == args.data_dir:
        print("警告：val_dir 與 data_dir 相同，驗證集與訓練集重疊，AUC 結果僅供參考（存在 data leakage）")

    # ── 載入 BENIGN 資料（方案 B 用）
    print(f"\n[1/4] 載入 BENIGN 訓練樣本（最多 {args.sample_n} 筆）...")
    benign_df = get_normal_sample_from_files(
        train_paths, n=args.sample_n, seed=args.seed
    )
    print(f"  BENIGN 筆數：{len(benign_df)}")

    # ── 方案 B
    print("\n[2/4] 方案 B：Variance + Correlation filter（只看 BENIGN 分布）")
    features = variance_select(
        benign_df,
        var_threshold=args.var_threshold,
        corr_threshold=args.corr_threshold,
    )

    # ── 載入驗證資料（方案 D 用）
    print(f"\n[3/4] 載入驗證樣本（每 label 最多 {args.val_sample_n} 筆）...")
    val_df = get_balance_sample_from_files(
        val_paths,
        sample_count_per_label=args.val_sample_n,
        seed=args.seed,
    )
    print(f"  驗證集總筆數：{len(val_df)}")
    print(val_df["Label"].value_counts().sort("Label"))

    # ── 方案 D
    print("\n[4/4] 方案 D：IF AUC-ROC 驗證")
    if_auc_validate(
        benign_df, val_df, features,
        n_estimators=args.n_estimators,
        contamination=args.contamination,
        seed=args.seed,
    )

    # ── 輸出可貼入 schema.py 的 FEATURE_COLS
    print("\n" + "=" * 60)
    print("可貼入 schema.py 的 FEATURE_COLS：")
    print("FEATURE_COLS = [")
    for f in features:
        print(f'    "{f}",')
    print("]")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="IF 特徵選擇（方案 B + D）")
    p.add_argument("--data_dir", default="service/model/dataset/parquet_clean/train",
                   help="清洗後訓練集 parquet 目錄")
    p.add_argument("--val_dir", default=None,
                   help="驗證集 parquet 目錄（建議與 data_dir 分開；不指定則用 data_dir，會有 leakage 警告）")
    p.add_argument("--var_threshold", type=float, default=1e-4,
                   help="Variance 下限（低於此值的特徵視為常數，直接移除）")
    p.add_argument("--corr_threshold", type=float, default=0.9,
                   help="Pearson 相關係數上限（高於此值的冗餘特徵移除）")
    p.add_argument("--sample_n", type=int, default=10000,
                   help="BENIGN 訓練樣本數")
    p.add_argument("--val_sample_n", type=int, default=3000,
                   help="驗證集每 label 最多筆數")
    p.add_argument("--n_estimators", type=int, default=200)
    p.add_argument("--contamination", type=float, default=0.01)
    p.add_argument("--seed", type=int, default=42)
    return p.parse_args()


if __name__ == "__main__":
    run(parse_args())