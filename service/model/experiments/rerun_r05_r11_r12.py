"""重跑 Run 05 / Run 11 / Run 12 — 正確時序版本

Run 05：用正確的訓練集 (parquet_clean/train/ = 03-11) 重跑 Per-label Entropy 分析
Run 11：Shape_Ratio / Sym_Ratio / Pkt_CV 單特徵 AUC（正確時序）
Run 12：Hdr_Asym / Len_Asym / Max_Min_Ratio / Bytes_Asym 單特徵 AUC（正確時序）

執行：
  uv run --project service/model python -m service.model.view.rerun_r05_r11_r12
"""
import glob
import numpy as np
import polars as pl
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import StandardScaler

from service.model.data.sample import (
    get_balance_sample_from_files,
    get_normal_sample_from_files,
)
from service.model.view.entropy_plot import compute_entropy

# ── 資料路徑 ──────────────────────────────────────────────────
TRAIN_PATHS = sorted(glob.glob("service/model/dataset/parquet_clean/train/*.parquet"))  # 03-11 訓練集
VAL_PATHS   = sorted(glob.glob("service/model/dataset/parquet_clean/test/*.parquet"))   # 01-12 測試集
IDS2018_D1  = "service/model/dataset/parquet_clean/test/IDS-2018-DDOS/DDoS1-Tuesday-20-02-2018_TrafficForML_CICFlowMeter.parquet"
IDS2018_D2  = "service/model/dataset/parquet_clean/test/IDS-2018-DDOS/DDoS2-Wednesday-21-02-2018_TrafficForML_CICFlowMeter.parquet"

SEED = 42
N_ESTIMATORS = 200
CONTAMINATION = 0.01

# Run 03 的 29 個特徵
FEATURES_29 = [
    "Min Packet Length", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Destination Port", "Fwd Packet Length Max", "Total Length of Fwd Packets",
    "Bwd Packets/s", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Max",
    "Flow IAT Mean", "Flow Duration", "Flow IAT Std", "Bwd Header Length",
    "Packet Length Variance", "Bwd Packet Length Max", "Bwd Packet Length Mean",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Min", "act_data_pkt_fwd",
    "Init_Win_bytes_backward", "Down/Up Ratio", "Total Fwd Packets",
    "Bwd Packet Length Min", "Init_Win_bytes_forward", "Fwd Header Length",
    "Flow IAT Min", "Protocol",
]


# ── 特徵計算（比例特徵） ───────────────────────────────────────

def add_ratio_features(df: pl.DataFrame) -> pl.DataFrame:
    """為 CIC-DDoS2019 欄位命名格式的 DataFrame 加入比例特徵。"""
    return df.with_columns([
        (pl.col("Min Packet Length") / (pl.col("Fwd Packet Length Mean") + 1e-6)).alias("Shape_Ratio"),
        (pl.col("Total Fwd Packets") / (pl.col("Total Backward Packets") + 1.0)).alias("Sym_Ratio"),
        (pl.col("Packet Length Std") / (pl.col("Packet Length Mean") + 1e-6)).alias("Pkt_CV"),
        (pl.col("Bwd Header Length") / (pl.col("Fwd Header Length") + 1e-6)).alias("Hdr_Asym"),
        (pl.col("Bwd Packet Length Mean") / (pl.col("Fwd Packet Length Mean") + 1e-6)).alias("Len_Asym"),
        (pl.col("Max Packet Length") / (pl.col("Min Packet Length") + 1e-6)).alias("Max_Min_Ratio"),
        (pl.col("Total Length of Bwd Packets") / (pl.col("Total Length of Fwd Packets") + 1e-6)).alias("Bytes_Asym"),
    ])


def add_ratio_features_ids2018(df: pl.DataFrame) -> pl.DataFrame:
    """為 CIC-IDS2018 欄位命名格式的 DataFrame 加入比例特徵。

    欄位差異對應：
      Min Packet Length        → Packet Length Min
      Max Packet Length        → Packet Length Max
      Total Fwd Packets        → Subflow Fwd Packets（相關係數 1.0）
      Total Length of Fwd Packets → Fwd Packets Length Total
      Total Length of Bwd Packets → Bwd Packets Length Total
    """
    return df.with_columns([
        (pl.col("Packet Length Min") / (pl.col("Fwd Packet Length Mean") + 1e-6)).alias("Shape_Ratio"),
        (pl.col("Subflow Fwd Packets") / (pl.col("Total Backward Packets") + 1.0)).alias("Sym_Ratio"),
        (pl.col("Packet Length Std") / (pl.col("Packet Length Mean") + 1e-6)).alias("Pkt_CV"),
        (pl.col("Bwd Header Length") / (pl.col("Fwd Header Length") + 1e-6)).alias("Hdr_Asym"),
        (pl.col("Bwd Packet Length Mean") / (pl.col("Fwd Packet Length Mean") + 1e-6)).alias("Len_Asym"),
        (pl.col("Packet Length Max") / (pl.col("Packet Length Min") + 1e-6)).alias("Max_Min_Ratio"),
        (pl.col("Bwd Packets Length Total") / (pl.col("Fwd Packets Length Total") + 1e-6)).alias("Bytes_Asym"),
    ])


# ── IF 單特徵 AUC 工具 ────────────────────────────────────────

def single_feature_auc(
    benign_df: pl.DataFrame,
    val_df: pl.DataFrame,
    feature: str,
) -> float | None:
    if feature not in benign_df.columns or feature not in val_df.columns:
        return None
    X_train = benign_df.select(feature).to_numpy().astype(np.float32)
    X_val = val_df.select(feature).to_numpy().astype(np.float32)
    # 移除 NaN / Inf
    mask_train = np.isfinite(X_train[:, 0])
    mask_val = np.isfinite(X_val[:, 0])
    if mask_train.sum() < 10 or mask_val.sum() < 10:
        return None
    X_train = X_train[mask_train]
    X_val = X_val[mask_val]
    y_val = (val_df["Label"] != "BENIGN").cast(pl.Int8).to_numpy()[mask_val]
    if y_val.sum() == 0 or y_val.sum() == len(y_val):
        return None

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_val_s = scaler.transform(X_val)

    iso = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination=CONTAMINATION,
        random_state=SEED,
        n_jobs=-1,
    )
    iso.fit(X_train_s)
    scores = -iso.score_samples(X_val_s)
    return float(roc_auc_score(y_val, scores))


# ═══════════════════════════════════════════════════════════════
# Run 05：Per-label Entropy 分析（正確時序：parquet_clean/train/ = 03-11）
# ═══════════════════════════════════════════════════════════════

def run_05():
    print("\n" + "=" * 60)
    print("Run 05 重跑 — Per-label Entropy（正確時序 03-11 訓練集）")
    print("=" * 60)

    df = get_balance_sample_from_files(TRAIN_PATHS, sample_count_per_label=3000, seed=SEED)
    labels = sorted(df["Label"].unique().to_list())
    attack_labels = [l for l in labels if l != "BENIGN"]
    print(f"Labels: {labels}")
    print(f"總筆數: {len(df)}")

    results = []
    for col in FEATURES_29:
        if col not in df.columns:
            continue
        vals_benign = df.filter(pl.col("Label") == "BENIGN")[col].drop_nulls().cast(pl.Float64).to_numpy()
        h_benign = compute_entropy(vals_benign, bins=100)

        atk_hs = []
        for lbl in attack_labels:
            vals = df.filter(pl.col("Label") == lbl)[col].drop_nulls().cast(pl.Float64).to_numpy()
            atk_hs.append(compute_entropy(vals, bins=100))

        h_atk_avg = float(np.mean(atk_hs))
        h_atk_min = float(np.min(atk_hs))
        delta = h_benign - h_atk_avg
        results.append((col, h_benign, h_atk_avg, h_atk_min, delta))

    results.sort(key=lambda x: -x[4])

    print(f"\n{'特徵名稱':<35} {'H(BENIGN)':>9} {'H(atk avg)':>10} {'H(atk min)':>10} {'Δ':>7} 判斷")
    print("-" * 85)
    for col, hb, ha, hm, d in results:
        if d > 0.5:
            mark = "★ 攻擊明顯規律"
        elif d > 0:
            mark = "○ 攻擊略有規律"
        elif d > -0.5:
            mark = "~ 無顯著差異"
        else:
            mark = "▼ BENIGN 更規律"
        print(f"  {col:<33} {hb:>9.3f} {ha:>10.3f} {hm:>10.3f} {d:>7.3f}  {mark}")

    return results


# ═══════════════════════════════════════════════════════════════
# Run 11 / 12：比例特徵單特徵 AUC（正確時序）
# ═══════════════════════════════════════════════════════════════

def run_11_12():
    print("\n" + "=" * 60)
    print("Run 11 / 12 重跑 — 比例特徵單特徵 AUC（正確時序）")
    print("=" * 60)

    # ── 載入訓練集 BENIGN（03-11）
    print("\n[1/3] 載入 03-11 BENIGN 訓練集...")
    benign_raw = get_normal_sample_from_files(TRAIN_PATHS, n=10000, seed=SEED)
    benign = add_ratio_features(benign_raw)
    print(f"  BENIGN 筆數: {len(benign)}")

    # ── 載入 DDoS2019 驗證集（01-12）
    print("\n[2/3] 載入 01-12 驗證集（DDoS2019）...")
    val_raw = get_balance_sample_from_files(VAL_PATHS, sample_count_per_label=3000, seed=SEED)
    val_ddos2019 = add_ratio_features(val_raw)
    print(f"  DDoS2019 驗證筆數: {len(val_ddos2019)}")

    # ── 載入 IDS2018 DDoS1（LOIC-HTTP）
    print("\n[3/3] 載入 IDS2018 DDoS1（LOIC-HTTP）...")
    ids18_d1_raw = pl.read_parquet(IDS2018_D1)
    ids18_d1_raw = ids18_d1_raw.with_columns(
        pl.col("Label").cast(pl.String).str.to_uppercase().alias("Label")
    )
    ids18_d1 = add_ratio_features_ids2018(ids18_d1_raw)
    labels_d1 = ids18_d1["Label"].unique().to_list()
    print(f"  DDoS1 labels: {labels_d1}, 總筆數: {len(ids18_d1)}")
    # 只保留 BENIGN + LOIC-HTTP
    ids18_d1_sub = ids18_d1.filter(pl.col("Label").is_in(["BENIGN", "DDOS ATTACKS-LOIC-HTTP"]))
    ids18_d1_sub = ids18_d1_sub.sample(min(10000, len(ids18_d1_sub)), seed=SEED)
    print(f"  DDoS1 抽樣後: {len(ids18_d1_sub)}")

    # ── 特徵清單
    run11_features = ["Shape_Ratio", "Sym_Ratio", "Pkt_CV"]
    run12_features = ["Hdr_Asym", "Len_Asym", "Max_Min_Ratio", "Bytes_Asym"]

    all_ratio_features = run11_features + run12_features

    print("\n單特徵 AUC 結果（正確時序，03-11 BENIGN 訓練）：")
    print(f"\n{'特徵':<18} {'DDoS2019':>10} {'IDS2018 DDoS1':>14}  判斷")
    print("-" * 55)

    feature_results = {}
    for feat in all_ratio_features:
        auc_ddos2019 = single_feature_auc(benign, val_ddos2019, feat)
        auc_loic_http = single_feature_auc(benign, ids18_d1_sub, feat)

        d2019_str = f"{auc_ddos2019:.4f}" if auc_ddos2019 is not None else "nan"
        loic_str = f"{auc_loic_http:.4f}" if auc_loic_http is not None else "nan"

        # 簡單判斷
        if auc_loic_http is not None and auc_loic_http > 0.55:
            note = "★ IDS2018 有效"
        elif auc_ddos2019 is not None and auc_ddos2019 > 0.6:
            note = "DDoS2019 有效"
        else:
            note = "兩者均差"

        print(f"  {feat:<16} {d2019_str:>10} {loic_str:>14}  {note}")
        feature_results[feat] = (auc_ddos2019, auc_loic_http)

    return feature_results


if __name__ == "__main__":
    r05_results = run_05()
    r11_r12_results = run_11_12()
    print("\n\n✅ 全部重跑完成")