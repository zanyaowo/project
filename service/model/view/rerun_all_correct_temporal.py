"""全部實驗重跑（正確時序：03-11 Train → 01-12 Test）

Run 01 / 02 / 04 / 07 / 08 / 09 / 11 / 12 / 13 / 14 / 15 / 16 / 17

執行：
  uv run --project service/model python -m service.model.view.rerun_all_correct_temporal
"""
import glob
import numpy as np
import polars as pl
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import StandardScaler

from service.model.data.sample import get_normal_sample_from_files

# ── 路徑（正確時序）────────────────────────────────────────────
BASE        = "service/model/dataset/parquet_clean"
TRAIN_PATHS = sorted(glob.glob(f"{BASE}/03-11_*.parquet"))   # Nov（較早）→ 訓練
TEST_PATHS  = sorted(glob.glob(f"{BASE}/01-12_*.parquet"))   # Dec（較晚）→ 測試
IDS_D1      = f"{BASE}/test/IDS-2018-DDOS/DDoS1-Tuesday-20-02-2018_TrafficForML_CICFlowMeter.parquet"
IDS_D2      = f"{BASE}/test/IDS-2018-DDOS/DDoS2-Wednesday-21-02-2018_TrafficForML_CICFlowMeter.parquet"

TRAIN_N    = 30_000
VAL_N_FILE = 5_000
SEED       = 42

# IDS2018 欄位對應
IDS_RENAME = {
    "Packet Length Min":        "Min Packet Length",
    "Bwd Packets Length Total": "Total Length of Bwd Packets",
    "Fwd Packets Length Total": "Total Length of Fwd Packets",
}

# ── 特徵集 ────────────────────────────────────────────────────
FEAT_41 = [
    "Flow Bytes/s", "Bwd Header Length", "Fwd Header Length", "Flow Duration",
    "Flow IAT Max", "Bwd IAT Std", "Flow IAT Std", "Idle Std", "Bwd IAT Mean",
    "Fwd IAT Mean", "Flow IAT Mean", "Active Max", "Active Mean", "Flow Packets/s",
    "Flow IAT Min", "Active Std", "Bwd Packets/s", "Source Port", "Destination Port",
    "Total Length of Bwd Packets", "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "Total Length of Fwd Packets", "Bwd Packet Length Max", "Fwd Packet Length Max",
    "Bwd Packet Length Mean", "Packet Length Mean", "Fwd Packet Length Mean",
    "Bwd Packet Length Min", "Fwd Packet Length Min", "Min Packet Length",
    "Total Fwd Packets", "act_data_pkt_fwd", "Protocol", "Bwd IAT Min",
    "Down/Up Ratio", "URG Flag Count", "CWE Flag Count", "ACK Flag Count",
    "Fwd PSH Flags", "SYN Flag Count",
]
FEAT_40 = [f for f in FEAT_41 if f != "SYN Flag Count"]  # Run 02：移除 SYN Flag Count

FEAT_26 = [  # Run 04
    "Destination Port", "Fwd Packet Length Mean", "Bwd Header Length",
    "Packet Length Mean", "Bwd IAT Min", "Min Packet Length",
    "Fwd Packet Length Min", "Down/Up Ratio", "Fwd Packet Length Max",
    "Bwd IAT Mean", "Total Length of Fwd Packets", "Flow IAT Mean",
    "Flow Packets/s", "Flow IAT Max", "Flow IAT Std", "Flow Duration",
    "Flow Bytes/s", "Fwd Header Length", "Init_Win_bytes_forward",
    "Init_Win_bytes_backward", "Bwd Packets/s", "Fwd IAT Mean",
    "Total Fwd Packets", "Flow IAT Min", "act_data_pkt_fwd", "Protocol",
]
FEAT_9 = [  # Run 07
    "Fwd Packet Length Min", "Flow Bytes/s", "Flow Packets/s",
    "Destination Port", "Min Packet Length", "Fwd Packet Length Mean",
    "Protocol", "Bwd Packets/s", "Packet Length Mean",
]
FEAT_8 = [f for f in FEAT_9 if f != "Destination Port"]  # Run 08：IDS2018 無 Destination Port
FEAT_5_STRUCT = [  # Run 09：純封包結構
    "Fwd Packet Length Min", "Min Packet Length",
    "Fwd Packet Length Mean", "Protocol", "Packet Length Mean",
]

# 比率相關常數
SHAPE_NUM = "Min Packet Length";            SHAPE_DEN = "Fwd Packet Length Mean"
SYM_NUM   = "Total Fwd Packets";            SYM_DEN   = "Total Backward Packets"
BYTES_NUM = "Total Length of Bwd Packets";  BYTES_DEN = "Total Length of Fwd Packets"
SCALE     = 1 << 20

# ── 工具函式 ──────────────────────────────────────────────────

def sample_val(paths: list[str], n_per: int) -> pl.DataFrame:
    frames = []
    for p in paths:
        df = pl.read_parquet(p)
        if len(df) > n_per:
            df = df.sample(n_per, seed=SEED)
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


def fit_predict(train: pl.DataFrame, val: pl.DataFrame, feats: list[str]) -> float:
    avail_tr  = [f for f in feats if f in train.columns]
    avail_val = [f for f in feats if f in val.columns]
    use = [f for f in avail_tr if f in avail_val]
    if not use:
        return float("nan")
    X_tr = train.select(use).to_numpy().astype(np.float32)
    sc   = StandardScaler().fit(X_tr)
    iso  = IsolationForest(n_estimators=200, contamination=0.01,
                           random_state=SEED, n_jobs=-1).fit(sc.transform(X_tr))
    X_v  = sc.transform(val.select(use).to_numpy().astype(np.float32))
    y    = (val["Label"] != "BENIGN").cast(pl.Int8).to_numpy()
    if y.sum() == 0 or y.sum() == len(y):
        return float("nan")
    return float(roc_auc_score(y, -iso.score_samples(X_v)))


def per_attack(train, val, feats, substr):
    sub = val.filter(
        (pl.col("Label") == "BENIGN") | pl.col("Label").str.contains(substr)
    )
    return fit_predict(train, sub, feats)


def get_arr(df, col):
    return df[col].cast(pl.Float64).fill_null(0).fill_nan(0).to_numpy()


def add_log1p(df: pl.DataFrame) -> pl.DataFrame:
    sn, sd = get_arr(df, SHAPE_NUM), get_arr(df, SHAPE_DEN)
    yn, yd = get_arr(df, SYM_NUM),   get_arr(df, SYM_DEN)
    bn, bd = get_arr(df, BYTES_NUM),  get_arr(df, BYTES_DEN)
    return df.with_columns([
        pl.Series("log1p_Shape", np.log1p(sn / (sd + 1e-6)).astype(np.float32)),
        pl.Series("log1p_Sym",   np.log1p(yn / (yd + 1.0 )).astype(np.float32)),
        pl.Series("log1p_Bytes", np.log1p(bn / (bd + 1e-6)).astype(np.float32)),
    ])


def mk_bounds(n_arr, d_arr, N):
    r = n_arr / (d_arr + 1e-6)
    r = r[np.isfinite(r)]
    ts = np.percentile(r, np.linspace(0, 100, N + 1)[1:-1])
    return [(int(t * SCALE), SCALE) for t in ts]


def apply_q(n_arr, d_arr, bounds):
    res = np.full(len(n_arr), len(bounds), dtype=np.int32)
    ni  = n_arr.astype(np.int64)
    di  = d_arr.astype(np.int64) + 1
    for k, (nk, dk) in enumerate(bounds):
        c = (ni * np.int64(dk)) < (di * np.int64(nk))
        res = np.where(c & (res == len(bounds)), np.int32(k), res)
    return res


def add_q(df, sb, yb, bb):
    return df.with_columns([
        pl.Series("Shape_q", apply_q(get_arr(df, SHAPE_NUM), get_arr(df, SHAPE_DEN), sb).astype(np.float32)),
        pl.Series("Sym_q",   apply_q(get_arr(df, SYM_NUM),   get_arr(df, SYM_DEN),   yb).astype(np.float32)),
        pl.Series("Bytes_q", apply_q(get_arr(df, BYTES_NUM),  get_arr(df, BYTES_DEN), bb).astype(np.float32)),
    ])


def add_ratio_raw(df: pl.DataFrame) -> pl.DataFrame:
    sn, sd = get_arr(df, SHAPE_NUM), get_arr(df, SHAPE_DEN)
    yn, yd = get_arr(df, SYM_NUM),   get_arr(df, SYM_DEN)
    bn, bd = get_arr(df, BYTES_NUM),  get_arr(df, BYTES_DEN)
    pkt_mean = get_arr(df, "Packet Length Mean")
    pkt_std  = df["Packet Length Std"].cast(pl.Float64).fill_null(0).fill_nan(0).to_numpy() \
               if "Packet Length Std" in df.columns else np.zeros(len(df))
    return df.with_columns([
        pl.Series("Shape_Ratio", (sn / (sd + 1e-6)).astype(np.float32)),
        pl.Series("Sym_Ratio",   (yn / (yd + 1.0 )).astype(np.float32)),
        pl.Series("Bytes_Asym",  (bn / (bd + 1e-6)).astype(np.float32)),
        pl.Series("Pkt_CV",      (pkt_std / (pkt_mean + 1e-6)).astype(np.float32)),
    ])


def hdr_asym(df):
    fh = df["Fwd Header Length"].cast(pl.Float64).fill_null(0).fill_nan(0).to_numpy() if "Fwd Header Length" in df.columns else np.zeros(len(df))
    bh = df["Bwd Header Length"].cast(pl.Float64).fill_null(0).fill_nan(0).to_numpy() if "Bwd Header Length" in df.columns else np.zeros(len(df))
    bpl = df["Bwd Packet Length Mean"].cast(pl.Float64).fill_null(0).fill_nan(0).to_numpy() if "Bwd Packet Length Mean" in df.columns else np.zeros(len(df))
    fpl = df["Fwd Packet Length Mean"].cast(pl.Float64).fill_null(0).fill_nan(0).to_numpy()
    mxp = df["Fwd Packet Length Max"].cast(pl.Float64).fill_null(0).fill_nan(0).to_numpy() if "Fwd Packet Length Max" in df.columns else np.zeros(len(df))
    mnp = get_arr(df, SHAPE_NUM)
    return df.with_columns([
        pl.Series("Hdr_Asym",      (bh / (fh + 1e-6)).astype(np.float32)),
        pl.Series("Len_Asym",      (bpl / (fpl + 1e-6)).astype(np.float32)),
        pl.Series("Max_Min_Ratio", (mxp / (mnp + 1e-6)).astype(np.float32)),
    ])


# ── 主程序 ────────────────────────────────────────────────────
def main():
    print("=" * 65)
    print("全部實驗重跑（正確時序：03-11 Train → 01-12 Test）")
    print("=" * 65)

    # 1. 載入資料
    print("\n[1/2] 載入資料...")
    benign = get_normal_sample_from_files(TRAIN_PATHS, n=TRAIN_N, seed=SEED)
    dds_test = sample_val(TEST_PATHS, VAL_N_FILE)
    d1 = load_ids(IDS_D1, VAL_N_FILE * 4)
    d2 = load_ids(IDS_D2, VAL_N_FILE * 4)
    print(f"  Train BENIGN: {len(benign)}  |  DDoS2019 test: {len(dds_test)}")
    print(f"  IDS2018 DDoS1 labels: {sorted(d1['Label'].unique().to_list())}")
    print(f"  IDS2018 DDoS2 labels: {sorted(d2['Label'].unique().to_list())}")

    print("\n[2/2] 各 Run 重跑...")
    R = {}   # 收集結果

    # ── Run 01（41 特徵）
    print("\n--- Run 01（41 特徵）---")
    R["01"] = {"DDoS2019": fit_predict(benign, dds_test, FEAT_41)}
    print(f"  DDoS2019={R['01']['DDoS2019']:.4f}")

    # ── Run 02（40 特徵）
    print("\n--- Run 02（40 特徵，移除 SYN Flag Count）---")
    R["02"] = {"DDoS2019": fit_predict(benign, dds_test, FEAT_40)}
    print(f"  DDoS2019={R['02']['DDoS2019']:.4f}")

    # ── Run 04（26 特徵）
    print("\n--- Run 04（26 特徵）---")
    R["04"] = {"DDoS2019": fit_predict(benign, dds_test, FEAT_26)}
    print(f"  DDoS2019={R['04']['DDoS2019']:.4f}")

    # ── Run 07（9 特徵）
    print("\n--- Run 07（9 特徵）---")
    R["07"] = {"DDoS2019": fit_predict(benign, dds_test, FEAT_9)}
    print(f"  DDoS2019={R['07']['DDoS2019']:.4f}")

    # ── Run 08（跨資料集，8 特徵）
    print("\n--- Run 08（8 特徵，跨資料集）---")
    R["08"] = {
        "DDoS2019":  fit_predict(benign, dds_test, FEAT_8),
        "LOIC-HTTP": per_attack(benign, d1, FEAT_8, "LOIC-HTTP"),
        "Web1":      fit_predict(benign, d1.filter(pl.col("Label") != "BENIGN").head(500)
                                 .vstack(d1.filter(pl.col("Label") == "BENIGN").head(5000)), FEAT_8),
    }
    print(f"  DDoS2019={R['08']['DDoS2019']:.4f}  LOIC-HTTP={R['08']['LOIC-HTTP']:.4f}")

    # ── Run 09（5 特徵，純結構）
    print("\n--- Run 09（5 特徵，純結構）---")
    R["09"] = {
        "DDoS2019":  fit_predict(benign, dds_test, FEAT_5_STRUCT),
        "LOIC-HTTP": per_attack(benign, d1, FEAT_5_STRUCT, "LOIC-HTTP"),
    }
    print(f"  DDoS2019={R['09']['DDoS2019']:.4f}  LOIC-HTTP={R['09']['LOIC-HTTP']:.4f}")

    # ── Run 10（單特徵）
    print("\n--- Run 10（單特徵逐一）---")
    single_feats = ["Fwd Packet Length Min", "Flow Bytes/s", "Flow Packets/s",
                    "Min Packet Length", "Fwd Packet Length Mean",
                    "Protocol", "Bwd Packets/s", "Packet Length Mean"]
    R["10"] = {}
    for f in single_feats:
        a_dds  = fit_predict(benign, dds_test, [f])
        a_http = per_attack(benign, d1, [f], "LOIC-HTTP")
        R["10"][f] = {"DDoS2019": a_dds, "LOIC-HTTP": a_http}
        print(f"  {f:<32} DDoS={a_dds:.4f}  LOIC-HTTP={a_http:.4f}")

    # ── Run 11（3 比例特徵）
    print("\n--- Run 11（3 比例特徵）---")
    benign_r   = add_ratio_raw(benign)
    dds_r      = add_ratio_raw(dds_test)
    d1_r       = add_ratio_raw(d1)
    d2_r       = add_ratio_raw(d2)
    FEAT_R3    = ["Shape_Ratio", "Sym_Ratio", "Pkt_CV"]
    R["11"] = {
        "DDoS2019":  fit_predict(benign_r, dds_r,  FEAT_R3),
        "LOIC-HTTP": per_attack(benign_r, d1_r,   FEAT_R3, "LOIC-HTTP"),
    }
    print(f"  DDoS2019={R['11']['DDoS2019']:.4f}  LOIC-HTTP={R['11']['LOIC-HTTP']:.4f}")

    # ── Run 12（7 比例特徵）
    print("\n--- Run 12（7 比例特徵）---")
    benign_h = hdr_asym(benign_r)
    dds_h    = hdr_asym(dds_r)
    d1_h     = hdr_asym(d1_r)
    d2_h     = hdr_asym(d2_r)
    FEAT_R7 = FEAT_R3 + ["Hdr_Asym", "Len_Asym", "Max_Min_Ratio", "Bytes_Asym"]
    R["12"] = {
        "DDoS2019":  fit_predict(benign_h, dds_h, FEAT_R7),
        "LOIC-HTTP": per_attack(benign_h, d1_h,  FEAT_R7, "LOIC-HTTP"),
    }
    print(f"  DDoS2019={R['12']['DDoS2019']:.4f}  LOIC-HTTP={R['12']['LOIC-HTTP']:.4f}")

    # ── Run 13（精簡組合）
    print("\n--- Run 13（精簡比例組合）---")
    combos = {
        "Shape+Bytes(2)":       ["Shape_Ratio", "Bytes_Asym"],
        "Shape+Sym+Bytes(3)":   ["Shape_Ratio", "Sym_Ratio", "Bytes_Asym"],
        "Shape+Sym+CV+Bytes(4)":["Shape_Ratio", "Sym_Ratio", "Pkt_CV", "Bytes_Asym"],
    }
    R["13"] = {}
    for name, feats in combos.items():
        a_dds  = fit_predict(benign_h, dds_h,  feats)
        a_http = per_attack(benign_h, d1_h,   feats, "LOIC-HTTP")
        R["13"][name] = {"DDoS2019": a_dds, "LOIC-HTTP": a_http}
        print(f"  {name:<28} DDoS={a_dds:.4f}  LOIC-HTTP={a_http:.4f}")

    # ── Run 14（DDoS2 驗證，3 比例特徵）
    print("\n--- Run 14（DDoS2 驗證）---")
    R["14"] = {
        "HOIC":     per_attack(benign_h, d2_h, ["Shape_Ratio", "Sym_Ratio", "Bytes_Asym"], "HOIC"),
        "LOIC-UDP": per_attack(benign_h, d2_h, ["Shape_Ratio", "Sym_Ratio", "Bytes_Asym"], "LOIC-UDP"),
    }
    print(f"  HOIC={R['14']['HOIC']:.4f}  LOIC-UDP={R['14']['LOIC-UDP']:.4f}")
    del benign_r, dds_r, d1_r, d2_r, benign_h, dds_h, d1_h, d2_h

    # ── Run 15（log1p 3 比例特徵）
    print("\n--- Run 15（log1p 3 比例特徵）---")
    benign_l = add_log1p(benign)
    dds_l    = add_log1p(dds_test)
    d1_l     = add_log1p(d1)
    d2_l     = add_log1p(d2)
    FEAT_L3  = ["log1p_Shape", "log1p_Sym", "log1p_Bytes"]
    R["15"] = {
        "DDoS2019":  fit_predict(benign_l, dds_l,  FEAT_L3),
        "HOIC":      per_attack(benign_l, d2_l,   FEAT_L3, "HOIC"),
        "LOIC-HTTP": per_attack(benign_l, d1_l,   FEAT_L3, "LOIC-HTTP"),
        "LOIC-UDP":  per_attack(benign_l, d2_l,   FEAT_L3, "LOIC-UDP"),
    }
    print(f"  DDoS2019={R['15']['DDoS2019']:.4f}  HOIC={R['15']['HOIC']:.4f}  "
          f"LOIC-HTTP={R['15']['LOIC-HTTP']:.4f}  LOIC-UDP={R['15']['LOIC-UDP']:.4f}")

    # ── Run 16（整合特徵，log1p）
    print("\n--- Run 16（log1p 整合特徵）---")
    FEAT_L5 = ["Protocol", "Packet Length Mean"] + FEAT_L3
    R["16"] = {
        "DDoS2019":  fit_predict(benign_l, dds_l,  FEAT_L5),
        "HOIC":      per_attack(benign_l, d2_l,   FEAT_L5, "HOIC"),
        "LOIC-HTTP": per_attack(benign_l, d1_l,   FEAT_L5, "LOIC-HTTP"),
        "LOIC-UDP":  per_attack(benign_l, d2_l,   FEAT_L5, "LOIC-UDP"),
    }
    print(f"  DDoS2019={R['16']['DDoS2019']:.4f}  HOIC={R['16']['HOIC']:.4f}  "
          f"LOIC-HTTP={R['16']['LOIC-HTTP']:.4f}  LOIC-UDP={R['16']['LOIC-UDP']:.4f}")
    del benign_l, dds_l, d1_l, d2_l

    # ── Run 17（分位桶 N=16/64/256）
    print("\n--- Run 17（分位桶）---")
    sn, sd = get_arr(benign, SHAPE_NUM), get_arr(benign, SHAPE_DEN)
    yn, yd = get_arr(benign, SYM_NUM),   get_arr(benign, SYM_DEN)
    bn, bd = get_arr(benign, BYTES_NUM),  get_arr(benign, BYTES_DEN)
    FEAT_Q = ["Protocol", "Packet Length Mean", "Shape_q", "Sym_q", "Bytes_q"]
    R["17"] = {}
    for N in [16, 64, 256]:
        sb = mk_bounds(sn, sd, N)
        yb = mk_bounds(yn, yd, N)
        bb = mk_bounds(bn, bd, N)
        bq = add_q(benign,   sb, yb, bb)
        tq = add_q(dds_test, sb, yb, bb)
        q1 = add_q(d1,       sb, yb, bb)
        q2 = add_q(d2,       sb, yb, bb)
        R["17"][f"N={N}"] = {
            "DDoS2019":  fit_predict(bq, tq, FEAT_Q),
            "HOIC":      per_attack(bq, q2, FEAT_Q, "HOIC"),
            "LOIC-HTTP": per_attack(bq, q1, FEAT_Q, "LOIC-HTTP"),
            "LOIC-UDP":  per_attack(bq, q2, FEAT_Q, "LOIC-UDP"),
        }
        r = R["17"][f"N={N}"]
        print(f"  N={N}: DDoS2019={r['DDoS2019']:.4f}  HOIC={r['HOIC']:.4f}  "
              f"LOIC-HTTP={r['LOIC-HTTP']:.4f}  LOIC-UDP={r['LOIC-UDP']:.4f}")
        del bq, tq, q1, q2

    # ── 彙整輸出 ─────────────────────────────────────────────
    print("\n" + "=" * 65)
    print("  彙整（正確時序：03-11 Train → 01-12 Test）")
    print("=" * 65)
    print(f"{'Run':<8} {'DDoS2019':>10} {'HOIC':>8} {'LOIC-HTTP':>10} {'LOIC-UDP':>10}")
    print("-" * 55)
    for run in ["01", "02", "04", "07"]:
        r = R[run]
        print(f"Run {run:<5} {r.get('DDoS2019', float('nan')):>10.4f}  {'—':>7}  {'—':>9}  {'—':>9}")
    for run in ["08", "09", "11", "12", "15", "16"]:
        r = R[run]
        print(f"Run {run:<5} {r.get('DDoS2019', float('nan')):>10.4f} "
              f"{r.get('HOIC', float('nan')):>8.4f} "
              f"{r.get('LOIC-HTTP', float('nan')):>10.4f} "
              f"{r.get('LOIC-UDP', float('nan')):>10.4f}")
    print()
    print("Run 17 (分位桶):")
    for n, r in R["17"].items():
        print(f"  {n:<8} {r['DDoS2019']:>10.4f} {r['HOIC']:>8.4f} "
              f"{r['LOIC-HTTP']:>10.4f} {r['LOIC-UDP']:>10.4f}")
    print("=" * 65)
    return R


if __name__ == "__main__":
    main()
