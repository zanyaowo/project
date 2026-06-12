"""Run 17：分位數整數化比率特徵 AUC 驗證

測試以分位數離散化（quantile discretization）取代 log1p 浮點比率特徵，
驗證 AUC 損失是否可接受，以利 eBPF kernel 純整數實作。

執行：
  uv run --project service/model python -m service.model.view.run17_quantile_ratio
"""
import glob

import numpy as np
import polars as pl
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import StandardScaler

from service.model.data.sample import get_normal_sample_from_files

# ── 資料路徑 ──────────────────────────────────────────────────
TRAIN_DIR  = "service/model/dataset/parquet_clean"
IDS2018_D1 = f"{TRAIN_DIR}/test/DDoS1-Tuesday-20-02-2018_TrafficForML_CICFlowMeter.parquet"
IDS2018_D2 = f"{TRAIN_DIR}/test/DDoS2-Wednesday-21-02-2018_TrafficForML_CICFlowMeter.parquet"
DDOS2019_TEST  = sorted(glob.glob(f"{TRAIN_DIR}/03-11_*.parquet"))
DDOS2019_TRAIN = sorted(glob.glob(f"{TRAIN_DIR}/01-12_*.parquet"))

# ── 欄位定義 ──────────────────────────────────────────────────
SHAPE_NUM = "Min Packet Length"
SHAPE_DEN = "Fwd Packet Length Mean"
SYM_NUM   = "Total Fwd Packets"
SYM_DEN   = "Total Backward Packets"
BYTES_NUM = "Total Length of Bwd Packets"
BYTES_DEN = "Total Length of Fwd Packets"

IDS_RENAME = {
    "Packet Length Min":        "Min Packet Length",
    "Bwd Packets Length Total": "Total Length of Bwd Packets",
    "Fwd Packets Length Total": "Total Length of Fwd Packets",
}

BASE_FEATURES = ["Protocol", "Packet Length Mean"]
SCALE = 1 << 20

# ── 抽樣設定（避免 OOM）──────────────────────────────────────
TRAIN_N      = 30_000   # BENIGN 訓練樣本
VAL_N_EACH   = 5_000    # 每個驗證集最多取樣筆數
SEED         = 42


# ── 輔助函式 ──────────────────────────────────────────────────

def load_and_sample(path: str, n: int, seed: int = SEED) -> pl.DataFrame:
    """讀取 parquet，normalize Label，隨機抽樣至最多 n 筆。"""
    df = pl.read_parquet(path)
    # rename IDS2018 columns
    df = df.rename({k: v for k, v in IDS_RENAME.items() if k in df.columns})
    # normalize Label
    df = df.with_columns(
        pl.when(pl.col("Label").cast(pl.Utf8).str.to_uppercase().str.contains("BENIGN"))
        .then(pl.lit("BENIGN"))
        .otherwise(pl.col("Label").cast(pl.Utf8).str.to_uppercase())
        .alias("Label")
    )
    if len(df) > n:
        df = df.sample(n, seed=seed)
    return df


def load_ddos2019_test(n_per_file: int = 5000) -> pl.DataFrame:
    """逐檔抽樣 DDoS2019 test（03-11），concat 後回傳。"""
    frames = []
    for p in DDOS2019_TEST:
        df = pl.read_parquet(p)
        if len(df) > n_per_file:
            df = df.sample(n_per_file, seed=SEED)
        frames.append(df)
    return pl.concat(frames)


def compute_quantile_boundaries(
    arr_num: np.ndarray,
    arr_den: np.ndarray,
    n_buckets: int,
) -> list[tuple[int, int]]:
    """從 BENIGN 資料計算 n_buckets-1 個分位數邊界，回傳整數對 (numer, SCALE)。"""
    ratio = arr_num / (arr_den + 1e-6)
    ratio = ratio[np.isfinite(ratio)]
    percentiles = np.linspace(0, 100, n_buckets + 1)[1:-1]
    thresholds = np.percentile(ratio, percentiles)
    return [(int(t * SCALE), SCALE) for t in thresholds]


def get_ratio_arrays(df: pl.DataFrame, col_num: str, col_den: str) -> tuple[np.ndarray, np.ndarray]:
    num = df[col_num].cast(pl.Float64).fill_null(0).fill_nan(0).to_numpy()
    den = df[col_den].cast(pl.Float64).fill_null(0).fill_nan(0).to_numpy()
    return num, den


def apply_quantile_bucket(
    arr_num: np.ndarray,
    arr_den: np.ndarray,
    bounds: list[tuple[int, int]],
) -> np.ndarray:
    """以交叉乘法判斷分位桶，模擬 kernel 整數邏輯。"""
    result = np.full(len(arr_num), len(bounds), dtype=np.int32)
    num_i64 = arr_num.astype(np.int64)
    den_i64 = arr_den.astype(np.int64) + 1
    for k, (numer_k, denom_k) in enumerate(bounds):
        cond = (num_i64 * np.int64(denom_k)) < (den_i64 * np.int64(numer_k))
        result = np.where(cond & (result == len(bounds)), np.int32(k), result)
    return result


def add_log1p_features(df: pl.DataFrame) -> pl.DataFrame:
    """Run 16 浮點 log1p 比率特徵（純 numpy → Series，避免 polars expr 計算錯誤）。"""
    sn, sd = get_ratio_arrays(df, SHAPE_NUM, SHAPE_DEN)
    yn, yd = get_ratio_arrays(df, SYM_NUM, SYM_DEN)
    bn, bd = get_ratio_arrays(df, BYTES_NUM, BYTES_DEN)
    return df.with_columns([
        pl.Series("log1p_Shape", np.log1p(sn / (sd + 1e-6)).astype(np.float32)),
        pl.Series("log1p_Sym",   np.log1p(yn / (yd + 1.0)).astype(np.float32)),
        pl.Series("log1p_Bytes", np.log1p(bn / (bd + 1e-6)).astype(np.float32)),
    ])


def add_quantile_features(
    df: pl.DataFrame,
    shape_b: list[tuple[int, int]],
    sym_b:   list[tuple[int, int]],
    bytes_b: list[tuple[int, int]],
) -> pl.DataFrame:
    sn, sd = get_ratio_arrays(df, SHAPE_NUM, SHAPE_DEN)
    yn, yd = get_ratio_arrays(df, SYM_NUM, SYM_DEN)
    bn, bd = get_ratio_arrays(df, BYTES_NUM, BYTES_DEN)
    return df.with_columns([
        pl.Series("Shape_q", apply_quantile_bucket(sn, sd, shape_b).astype(np.float32)),
        pl.Series("Sym_q",   apply_quantile_bucket(yn, yd, sym_b).astype(np.float32)),
        pl.Series("Bytes_q", apply_quantile_bucket(bn, bd, bytes_b).astype(np.float32)),
    ])


def run_auc(
    train_df: pl.DataFrame,
    val_df: pl.DataFrame,
    features: list[str],
) -> float:
    X_tr = train_df.select(features).to_numpy().astype(np.float32)
    scaler = StandardScaler()
    X_tr = scaler.fit_transform(X_tr)

    iso = IsolationForest(n_estimators=200, contamination=0.01, random_state=SEED, n_jobs=-1)
    iso.fit(X_tr)

    X_val = val_df.select(features).to_numpy().astype(np.float32)
    X_val = scaler.transform(X_val)
    y_true = (val_df["Label"] != "BENIGN").cast(pl.Int8).to_numpy()

    if y_true.sum() == 0 or y_true.sum() == len(y_true):
        return float("nan")
    scores = -iso.score_samples(X_val)
    return float(roc_auc_score(y_true, scores))


def eval_per_attack(
    train_df: pl.DataFrame,
    val_df: pl.DataFrame,
    features: list[str],
    label_substr: str,
) -> float:
    sub = val_df.filter(
        (pl.col("Label") == "BENIGN") | pl.col("Label").str.contains(label_substr)
    )
    return run_auc(train_df, sub, features)


# ── 主程序 ────────────────────────────────────────────────────

def main() -> None:
    print("=" * 65)
    print("Run 17：分位數整數化比率特徵 AUC 驗證")
    print("=" * 65)

    # 1. 載入訓練 BENIGN
    print(f"\n[1/5] 載入訓練 BENIGN（最多 {TRAIN_N} 筆）...")
    benign_raw = get_normal_sample_from_files(DDOS2019_TRAIN, n=TRAIN_N, seed=SEED)
    print(f"      筆數：{len(benign_raw)}")

    # 2. 載入驗證集（抽樣）
    print(f"\n[2/5] 載入驗證集（每集最多 {VAL_N_EACH} 筆）...")
    dds_test_raw = load_ddos2019_test(n_per_file=VAL_N_EACH)
    print(f"      DDoS2019 test：{len(dds_test_raw)} 筆")

    d1_raw = load_and_sample(IDS2018_D1, VAL_N_EACH * 4)   # 兩個 label：BENIGN + LOIC-HTTP
    d2_raw = load_and_sample(IDS2018_D2, VAL_N_EACH * 4)   # 三個 label
    print(f"      IDS2018 DDoS1 labels：{sorted(d1_raw['Label'].unique().to_list())}")
    print(f"      IDS2018 DDoS2 labels：{sorted(d2_raw['Label'].unique().to_list())}")

    # 3. Run 16 基準（log1p）
    print("\n[3/5] 計算 Run 16 log1p 基準...")
    FEAT_LOG1P = BASE_FEATURES + ["log1p_Shape", "log1p_Sym", "log1p_Bytes"]

    benign_l  = add_log1p_features(benign_raw)
    dds_l     = add_log1p_features(dds_test_raw)
    d1_l      = add_log1p_features(d1_raw)
    d2_l      = add_log1p_features(d2_raw)

    baseline = {
        "DDoS2019":  run_auc(benign_l, dds_l, FEAT_LOG1P),
        "LOIC-HTTP": eval_per_attack(benign_l, d1_l, FEAT_LOG1P, "LOIC-HTTP"),
        "HOIC":      eval_per_attack(benign_l, d2_l, FEAT_LOG1P, "HOIC"),
        "LOIC-UDP":  eval_per_attack(benign_l, d2_l, FEAT_LOG1P, "LOIC-UDP"),
    }
    # 釋放 log1p 版本
    del benign_l, dds_l, d1_l, d2_l

    print(f"  DDoS2019={baseline['DDoS2019']:.4f}  HOIC={baseline['HOIC']:.4f}  "
          f"LOIC-HTTP={baseline['LOIC-HTTP']:.4f}  LOIC-UDP={baseline['LOIC-UDP']:.4f}")

    # 預先取出 ratio arrays（避免重複 cast）
    sn_tr, sd_tr = get_ratio_arrays(benign_raw,   SHAPE_NUM, SHAPE_DEN)
    yn_tr, yd_tr = get_ratio_arrays(benign_raw,   SYM_NUM,   SYM_DEN)
    bn_tr, bd_tr = get_ratio_arrays(benign_raw,   BYTES_NUM, BYTES_DEN)

    # 4. 分位桶實驗
    print("\n[4/5] 分位桶實驗（N = 16 / 64 / 256）...")
    FEAT_Q = BASE_FEATURES + ["Shape_q", "Sym_q", "Bytes_q"]
    results: dict[str, dict[str, float]] = {}

    for N in [16, 64, 256]:
        print(f"\n  --- N={N} ---")
        shape_b = compute_quantile_boundaries(sn_tr, sd_tr, N)
        sym_b   = compute_quantile_boundaries(yn_tr, yd_tr, N)
        bytes_b = compute_quantile_boundaries(bn_tr, bd_tr, N)

        benign_q   = add_quantile_features(benign_raw,  shape_b, sym_b, bytes_b)
        dds_test_q = add_quantile_features(dds_test_raw, shape_b, sym_b, bytes_b)
        d1_q       = add_quantile_features(d1_raw,       shape_b, sym_b, bytes_b)
        d2_q       = add_quantile_features(d2_raw,       shape_b, sym_b, bytes_b)

        r = {
            "DDoS2019":  run_auc(benign_q, dds_test_q, FEAT_Q),
            "LOIC-HTTP": eval_per_attack(benign_q, d1_q, FEAT_Q, "LOIC-HTTP"),
            "HOIC":      eval_per_attack(benign_q, d2_q, FEAT_Q, "HOIC"),
            "LOIC-UDP":  eval_per_attack(benign_q, d2_q, FEAT_Q, "LOIC-UDP"),
        }
        results[f"N={N}"] = r
        print(f"    DDoS2019={r['DDoS2019']:.4f}  HOIC={r['HOIC']:.4f}  "
              f"LOIC-HTTP={r['LOIC-HTTP']:.4f}  LOIC-UDP={r['LOIC-UDP']:.4f}")

        del benign_q, dds_test_q, d1_q, d2_q

    # 5. 彙整報告
    print("\n[5/5] 彙整結果")
    print("=" * 75)
    print(f"{'特徵組合':<22} {'DDoS2019':>10} {'HOIC':>8} {'LOIC-HTTP':>10} {'LOIC-UDP':>10}")
    print("-" * 75)
    print(f"{'Run16 基準(log1p)':<22} "
          f"{baseline['DDoS2019']:>10.4f} {baseline['HOIC']:>8.4f} "
          f"{baseline['LOIC-HTTP']:>10.4f} {baseline['LOIC-UDP']:>10.4f}")

    for name, r in results.items():
        dd = r['DDoS2019']  - baseline['DDoS2019']
        dh = r['HOIC']      - baseline['HOIC']
        dl = r['LOIC-HTTP'] - baseline['LOIC-HTTP']
        du = r['LOIC-UDP']  - baseline['LOIC-UDP']
        print(f"{'分位桶 ' + name:<22} "
              f"{r['DDoS2019']:>10.4f} {r['HOIC']:>8.4f} "
              f"{r['LOIC-HTTP']:>10.4f} {r['LOIC-UDP']:>10.4f}  "
              f"Δ({dd:+.4f}/{dh:+.4f}/{dl:+.4f}/{du:+.4f})")

    print("=" * 75)

    # 最終判斷
    print("\n判斷：")
    for name, r in results.items():
        max_loss = max(
            baseline[k] - r[k]
            for k in ["DDoS2019", "HOIC", "LOIC-UDP"]  # 排除 LOIC-HTTP（本身就不可偵測）
            if not (np.isnan(baseline[k]) or np.isnan(r[k]))
        )
        if max_loss <= 0.01:
            verdict = "✓ 可採用（損失≤0.01）"
        elif max_loss <= 0.03:
            verdict = "△ 勉強可接受（損失0.01–0.03）"
        else:
            verdict = "✗ 損失過大（>0.03）"
        print(f"  {name}: 最大損失={max_loss:+.4f}  → {verdict}")


if __name__ == "__main__":
    main()