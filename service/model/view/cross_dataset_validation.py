import polars as pl
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import glob
import os
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import StandardScaler
from joblib import load

# ── 設定 ──────────────────────────────────────────────────────
CIC_DIR = "dataset/parquet_clean/train"
BIGFLOW_DIR = "dataset/parquet_clean/test/BigFlow-NIDS-V2-Merged-Parquet"
OUTPUT_PLOT = "view/feature_distribution_comparison.png"

FEATURES_6 = [
    "Destination Port",
    "Protocol",
    "Packet Length Mean",
    "Shape_Ratio",
    "Sym_Ratio",
    "Bytes_Asym"
]

def map_cic_2019(df: pl.DataFrame) -> pl.DataFrame:
    """將 CIC-IDS-2019 欄位對應至 6 核心特徵"""
    return df.with_columns([
        pl.col("Destination Port").cast(pl.Float32),
        pl.col("Protocol").cast(pl.Float32),
        pl.col("Packet Length Mean").cast(pl.Float32),
        (pl.col("Min Packet Length") / (pl.col("Fwd Packet Length Mean") + 1e-6)).cast(pl.Float32).alias("Shape_Ratio"),
        (pl.col("Total Fwd Packets") / (pl.col("Total Backward Packets") + 1e-6)).cast(pl.Float32).alias("Sym_Ratio"),
        ((pl.col("Total Length of Fwd Packets") - pl.col("Total Length of Bwd Packets")) / 
         (pl.col("Total Length of Fwd Packets") + pl.col("Total Length of Bwd Packets") + 1e-6)).cast(pl.Float32).alias("Bytes_Asym")
    ]).select(FEATURES_6 + ["Label"])

def map_bigflow(df: pl.DataFrame) -> pl.DataFrame:
    """將 BigFlow (NetFlow) 欄位對應至 6 核心特徵"""
    return df.with_columns([
        pl.col("L4_DST_PORT").cast(pl.Float32).alias("Destination Port"),
        pl.col("PROTOCOL").cast(pl.Float32).alias("Protocol"),
        ((pl.col("IN_BYTES") + pl.col("OUT_BYTES")) / (pl.col("IN_PKTS") + pl.col("OUT_PKTS") + 1e-6)).cast(pl.Float32).alias("Packet Length Mean"),
        (pl.col("MIN_IP_PKT_LEN") / (pl.col("IN_BYTES") / (pl.col("IN_PKTS") + 1e-6) + 1e-6)).cast(pl.Float32).alias("Shape_Ratio"),
        (pl.col("IN_PKTS") / (pl.col("OUT_PKTS") + 1e-6)).cast(pl.Float32).alias("Sym_Ratio"),
        ((pl.col("IN_BYTES") - pl.col("OUT_BYTES")) / (pl.col("IN_BYTES") + pl.col("OUT_BYTES") + 1e-6)).cast(pl.Float32).alias("Bytes_Asym")
    ]).with_columns([
        pl.col("Attack").alias("Label")
    ]).select(FEATURES_6 + ["Label"])

# ── 執行分析 ──────────────────────────────────────────────────

def run_analysis():
    print("[1/4] 載入資料...")
    # 抽樣 CIC
    cic_paths = glob.glob(f"{CIC_DIR}/*.parquet")
    cic_df = pl.read_parquet(cic_paths[0]).sample(n=10000, seed=42)
    cic_mapped = map_cic_2019(cic_df)
    cic_mapped = cic_mapped.with_columns(pl.lit("CIC-IDS-2019").alias("Dataset"))

    # 抽樣 BigFlow
    bf_paths = glob.glob(f"{BIGFLOW_DIR}/*.parquet")
    bf_df = pl.read_parquet(bf_paths[0]).sample(n=10000, seed=42)
    bf_mapped = map_bigflow(bf_df)
    bf_mapped = bf_mapped.with_columns(pl.lit("BigFlow").alias("Dataset"))

    # 合併繪圖資料
    plot_df = pl.concat([cic_mapped, bf_mapped]).to_pandas()
    plot_df["is_attack"] = plot_df["Label"].apply(lambda x: "Attack" if str(x).upper() != "BENIGN" and str(x) != "0" else "Benign")
    plot_df["Group"] = plot_df["Dataset"] + "_" + plot_df["is_attack"]

    print("[2/4] 繪製分佈圖...")
    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    axes = axes.flatten()

    for i, feat in enumerate(FEATURES_6):
        sns.kdeplot(data=plot_df, x=feat, hue="Group", ax=axes[i], common_norm=False, fill=True, alpha=0.2)
        axes[i].set_title(f"Distribution of {feat}")
        if "Ratio" in feat or "Asym" in feat:
            axes[i].set_xlim(-1.5, 5.0) if "Sym" in feat else axes[i].set_xlim(-1.1, 1.1)

    plt.tight_layout()
    plt.savefig(OUTPUT_PLOT)
    print(f"      分佈圖已儲存至: {OUTPUT_PLOT}")

    print("\n[3/4] 跨資料集推論驗證 (Run 17 邏輯)...")
    # 模擬 Run 17: 使用 6 特徵在 CIC 訓練，在 BigFlow 測試
    X_train = cic_mapped.filter(pl.col("Label") == "BENIGN").select(FEATURES_6).to_numpy()
    y_test_true = (bf_mapped["Label"].apply(lambda x: 1 if str(x).upper() != "BENIGN" and str(x) != "0" else 0)).to_numpy()
    X_test = bf_mapped.select(FEATURES_6).to_numpy()

    # 處理 NaN/Inf
    X_train = np.nan_to_num(X_train, nan=0.0, posinf=1e6, neginf=-1e6)
    X_test = np.nan_to_num(X_test, nan=0.0, posinf=1e6, neginf=-1e6)

    from sklearn.ensemble import IsolationForest
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    model.fit(X_train_scaled)
    
    scores = -model.score_samples(X_test_scaled)
    auc = roc_auc_score(y_test_true, scores)

    print(f"\n[4/4] 驗證結果:")
    print(f"      訓練資料集: CIC-IDS-2019 (BENIGN only)")
    print(f"      測試資料集: BigFlow")
    print(f"      使用特徵數: 6 (Port, Proto, PktLen, Shape_R, Sym_R, Bytes_Asym)")
    print(f"      跨資料集 AUC-ROC: {auc:.4f}")

if __name__ == "__main__":
    run_analysis()
