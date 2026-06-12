"""時序驗證：比較原始時序（01-12 訓練 → 03-11 測試）vs 正確時序（03-11 訓練 → 01-12 測試）

原始實驗的時序問題：
  Train: 01-12（2018-12-01）← 較新
  Test:  03-11（2018-11-03）← 較舊
→ 模型以「未來資料」訓練，用「過去資料」評估，可能高估 AUC

正確時序：
  Train: 03-11（2018-11-03）← 較舊
  Test:  01-12（2018-12-01）← 較新

重跑的實驗：
  - Run 07：9 個特徵（Fwd Packet Length Min / Flow Bytes/s 等）
  - Run 16：log1p 比率特徵（Protocol + Packet Length Mean + log1p Shape/Sym/Bytes）
  - Run 17：N=256 分位桶特徵

執行：
  uv run --project service/model python -m service.model.view.temporal_order_check
"""
import glob
import numpy as np
import polars as pl
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import StandardScaler

from service.model.data.sample import get_normal_sample_from_files

# ── 路徑 ──────────────────────────────────────────────────────
BASE = "service/model/dataset/parquet_clean"
PATHS_0112 = sorted(glob.glob(f"{BASE}/01-12_*.parquet"))
PATHS_0311 = sorted(glob.glob(f"{BASE}/03-11_*.parquet"))
IDS_D1 = f"{BASE}/test/DDoS1-Tuesday-20-02-2018_TrafficForML_CICFlowMeter.parquet"
IDS_D2 = f"{BASE}/test/DDoS2-Wednesday-21-02-2018_TrafficForML_CICFlowMeter.parquet"

TRAIN_N    = 30_000
VAL_N_FILE = 5_000
SEED       = 42

# ── 特徵集定義 ────────────────────────────────────────────────
FEAT_RUN07 = [
    "Fwd Packet Length Min", "Flow Bytes/s", "Flow Packets/s",
    "Destination Port", "Min Packet Length",
    "Fwd Packet Length Mean", "Protocol", "Bwd Packets/s", "Packet Length Mean",
]

# log1p 比率特徵名稱（計算後加入 df）
FEAT_RUN16 = ["Protocol", "Packet Length Mean", "log1p_Shape", "log1p_Sym", "log1p_Bytes"]
FEAT_RUN17 = ["Protocol", "Packet Length Mean", "Shape_q", "Sym_q", "Bytes_q"]

# 比率欄位（DDoS2019 命名）
SHAPE_NUM = "Min Packet Length";      SHAPE_DEN = "Fwd Packet Length Mean"
SYM_NUM   = "Total Fwd Packets";      SYM_DEN   = "Total Backward Packets"
BYTES_NUM = "Total Length of Bwd Packets"; BYTES_DEN = "Total Length of Fwd Packets"

IDS_RENAME = {
    "Packet Length Min":        "Min Packet Length",
    "Bwd Packets Length Total": "Total Length of Bwd Packets",
    "Fwd Packets Length Total": "Total Length of Fwd Packets",
}
SCALE = 1 << 20

# ── 輔助 ──────────────────────────────────────────────────────

def sample_df(paths: list[str], n_per_file: int) -> pl.DataFrame:
    frames = []
    for p in paths:
        df = pl.read_parquet(p)
        if len(df) > n_per_file:
            df = df.sample(n_per_file, seed=SEED)
        frames.append(df)
    return pl.concat(frames)


def load_ids(path: str, n: int) -> pl.DataFrame:
    df = pl.read_parquet(path)
    df = df.rename({k: v for k, v in IDS_RENAME.items() if k in df.columns})
    df = df.with_columns(
        pl.when(pl.col("Label").cast(pl.Utf8).str.to_uppercase().str.contains("BENIGN"))
        .then(pl.lit("BENIGN"))
        .otherwise(pl.col("Label").cast(pl.Utf8).str.to_uppercase())
        .alias("Label")
    )
    if len(df) > n:
        df = df.sample(n, seed=SEED)
    return df


def get_arrays(df: pl.DataFrame, num: str, den: str):
    n = df[num].cast(pl.Float64).fill_null(0).fill_nan(0).to_numpy()
    d = df[den].cast(pl.Float64).fill_null(0).fill_nan(0).to_numpy()
    return n, d


def add_log1p(df: pl.DataFrame) -> pl.DataFrame:
    sn, sd = get_arrays(df, SHAPE_NUM, SHAPE_DEN)
    yn, yd = get_arrays(df, SYM_NUM,   SYM_DEN)
    bn, bd = get_arrays(df, BYTES_NUM, BYTES_DEN)
    return df.with_columns([
        pl.Series("log1p_Shape", np.log1p(sn / (sd + 1e-6)).astype(np.float32)),
        pl.Series("log1p_Sym",   np.log1p(yn / (yd + 1.0 )).astype(np.float32)),
        pl.Series("log1p_Bytes", np.log1p(bn / (bd + 1e-6)).astype(np.float32)),
    ])


def compute_bounds(arr_n: np.ndarray, arr_d: np.ndarray, N: int) -> list[tuple[int, int]]:
    ratio = arr_n / (arr_d + 1e-6)
    ratio = ratio[np.isfinite(ratio)]
    thresholds = np.percentile(ratio, np.linspace(0, 100, N + 1)[1:-1])
    return [(int(t * SCALE), SCALE) for t in thresholds]


def apply_buckets(arr_n: np.ndarray, arr_d: np.ndarray, bounds: list) -> np.ndarray:
    result = np.full(len(arr_n), len(bounds), dtype=np.int32)
    ni = arr_n.astype(np.int64)
    di = arr_d.astype(np.int64) + 1
    for k, (nk, dk) in enumerate(bounds):
        cond = (ni * np.int64(dk)) < (di * np.int64(nk))
        result = np.where(cond & (result == len(bounds)), np.int32(k), result)
    return result


def add_quantile(df: pl.DataFrame, sb, yb, bb) -> pl.DataFrame:
    sn, sd = get_arrays(df, SHAPE_NUM, SHAPE_DEN)
    yn, yd = get_arrays(df, SYM_NUM,   SYM_DEN)
    bn, bd = get_arrays(df, BYTES_NUM, BYTES_DEN)
    return df.with_columns([
        pl.Series("Shape_q", apply_buckets(sn, sd, sb).astype(np.float32)),
        pl.Series("Sym_q",   apply_buckets(yn, yd, yb).astype(np.float32)),
        pl.Series("Bytes_q", apply_buckets(bn, bd, bb).astype(np.float32)),
    ])


def run_auc(train: pl.DataFrame, val: pl.DataFrame, feats: list[str]) -> float:
    # 確認欄位都存在
    miss_tr = [f for f in feats if f not in train.columns]
    miss_val = [f for f in feats if f not in val.columns]
    if miss_tr or miss_val:
        return float("nan")
    X_tr = train.select(feats).to_numpy().astype(np.float32)
    sc = StandardScaler().fit(X_tr)
    iso = IsolationForest(n_estimators=200, contamination=0.01,
                          random_state=SEED, n_jobs=-1).fit(sc.transform(X_tr))
    X_v  = sc.transform(val.select(feats).to_numpy().astype(np.float32))
    y    = (val["Label"] != "BENIGN").cast(pl.Int8).to_numpy()
    if y.sum() == 0 or y.sum() == len(y):
        return float("nan")
    return float(roc_auc_score(y, -iso.score_samples(X_v)))


def eval_attack(train, val, feats, substr):
    sub = val.filter(
        (pl.col("Label") == "BENIGN") | pl.col("Label").str.contains(substr)
    )
    return run_auc(train, sub, feats)


# ── 主程序 ────────────────────────────────────────────────────

def run_scenario(label: str, train_paths: list[str], test_paths: list[str]) -> dict:
    print(f"\n{'='*60}")
    print(f"  情境：{label}")
    print(f"  Train: {[p.split('/')[-1] for p in train_paths[:2]]} ...")
    print(f"  Test : {[p.split('/')[-1] for p in test_paths[:2]]} ...")
    print(f"{'='*60}")

    # 載入資料
    benign_raw = get_normal_sample_from_files(train_paths, n=TRAIN_N, seed=SEED)
    test_raw   = sample_df(test_paths, VAL_N_FILE)
    d1 = load_ids(IDS_D1, VAL_N_FILE * 4)
    d2 = load_ids(IDS_D2, VAL_N_FILE * 4)
    print(f"  BENIGN 訓練：{len(benign_raw)} 筆｜Test：{len(test_raw)} 筆")

    results: dict[str, dict] = {}

    # Run 07：9 個特徵（檢查 Destination Port 是否存在）
    print("\n--- Run 07（9 特徵）---")
    feats07 = [f for f in FEAT_RUN07 if f in benign_raw.columns and f in test_raw.columns]
    r07 = {
        "DDoS2019": run_auc(benign_raw, test_raw, feats07),
        "LOIC-HTTP": eval_attack(benign_raw, d1, [f for f in feats07 if f in d1.columns], "LOIC-HTTP"),
        "HOIC":     eval_attack(benign_raw, d2, [f for f in feats07 if f in d2.columns], "HOIC"),
        "LOIC-UDP": eval_attack(benign_raw, d2, [f for f in feats07 if f in d2.columns], "LOIC-UDP"),
    }
    print(f"  DDoS2019={r07['DDoS2019']:.4f}  HOIC={r07['HOIC']:.4f}  "
          f"LOIC-HTTP={r07['LOIC-HTTP']:.4f}  LOIC-UDP={r07['LOIC-UDP']:.4f}")
    results["Run07"] = r07

    # Run 16：log1p 比率特徵
    print("\n--- Run 16（log1p 比率）---")
    benign_l = add_log1p(benign_raw)
    test_l   = add_log1p(test_raw)
    d1_l     = add_log1p(d1)
    d2_l     = add_log1p(d2)
    r16 = {
        "DDoS2019": run_auc(benign_l, test_l, FEAT_RUN16),
        "LOIC-HTTP": eval_attack(benign_l, d1_l, FEAT_RUN16, "LOIC-HTTP"),
        "HOIC":     eval_attack(benign_l, d2_l, FEAT_RUN16, "HOIC"),
        "LOIC-UDP": eval_attack(benign_l, d2_l, FEAT_RUN16, "LOIC-UDP"),
    }
    print(f"  DDoS2019={r16['DDoS2019']:.4f}  HOIC={r16['HOIC']:.4f}  "
          f"LOIC-HTTP={r16['LOIC-HTTP']:.4f}  LOIC-UDP={r16['LOIC-UDP']:.4f}")
    results["Run16"] = r16
    del benign_l, test_l, d1_l, d2_l

    # Run 17：N=256 分位桶
    print("\n--- Run 17（N=256 分位桶）---")
    sn, sd = get_arrays(benign_raw, SHAPE_NUM, SHAPE_DEN)
    yn, yd = get_arrays(benign_raw, SYM_NUM,   SYM_DEN)
    bn, bd = get_arrays(benign_raw, BYTES_NUM, BYTES_DEN)
    sb = compute_bounds(sn, sd, 256)
    yb = compute_bounds(yn, yd, 256)
    bb = compute_bounds(bn, bd, 256)

    benign_q = add_quantile(benign_raw, sb, yb, bb)
    test_q   = add_quantile(test_raw,   sb, yb, bb)
    d1_q     = add_quantile(d1,         sb, yb, bb)
    d2_q     = add_quantile(d2,         sb, yb, bb)
    r17 = {
        "DDoS2019": run_auc(benign_q, test_q, FEAT_RUN17),
        "LOIC-HTTP": eval_attack(benign_q, d1_q, FEAT_RUN17, "LOIC-HTTP"),
        "HOIC":     eval_attack(benign_q, d2_q, FEAT_RUN17, "HOIC"),
        "LOIC-UDP": eval_attack(benign_q, d2_q, FEAT_RUN17, "LOIC-UDP"),
    }
    print(f"  DDoS2019={r17['DDoS2019']:.4f}  HOIC={r17['HOIC']:.4f}  "
          f"LOIC-HTTP={r17['LOIC-HTTP']:.4f}  LOIC-UDP={r17['LOIC-UDP']:.4f}")
    results["Run17_N256"] = r17

    return results


def print_comparison(orig: dict, rev: dict) -> None:
    print("\n" + "=" * 72)
    print("  比較彙整：原始時序（01-12 Train）vs 正確時序（03-11 Train）")
    print("=" * 72)
    fmt = "{:<18} {:<12} {:>10} {:>8} {:>10} {:>10}  {}"
    print(fmt.format("實驗", "時序", "DDoS2019", "HOIC", "LOIC-HTTP", "LOIC-UDP", ""))
    print("-" * 72)
    for run in ["Run07", "Run16", "Run17_N256"]:
        o = orig[run]
        r = rev[run]
        print(fmt.format(run, "原始(01-12 Train)",
              f"{o['DDoS2019']:.4f}", f"{o['HOIC']:.4f}",
              f"{o['LOIC-HTTP']:.4f}", f"{o['LOIC-UDP']:.4f}", ""))
        dd = r['DDoS2019'] - o['DDoS2019']
        dh = r['HOIC']     - o['HOIC']
        dl = r['LOIC-HTTP']- o['LOIC-HTTP']
        du = r['LOIC-UDP'] - o['LOIC-UDP']
        print(fmt.format("", "正確(03-11 Train)",
              f"{r['DDoS2019']:.4f}", f"{r['HOIC']:.4f}",
              f"{r['LOIC-HTTP']:.4f}", f"{r['LOIC-UDP']:.4f}",
              f"Δ({dd:+.4f}/{dh:+.4f}/{dl:+.4f}/{du:+.4f})"))
        print()
    print("=" * 72)
    print("判斷：若 |Δ| ≤ 0.02 → 時序對結論影響不大；> 0.05 → 原始結論需修正")


def main() -> None:
    print("時序驗證實驗：DDoS2019 train/test 對調")

    orig_results = run_scenario(
        "原始時序（01-12 Train → 03-11 Test）",
        PATHS_0112, PATHS_0311,
    )
    rev_results = run_scenario(
        "正確時序（03-11 Train → 01-12 Test）",
        PATHS_0311, PATHS_0112,
    )

    print_comparison(orig_results, rev_results)


if __name__ == "__main__":
    main()
