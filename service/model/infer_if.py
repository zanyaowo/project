#核心異常偵測模型：Isolation Forest 推論腳本
import argparse
import numpy as np
import pandas as pd
from joblib import load
from utils import FEATURE_COLS
import json
import os

#輸出 Web 報告的函式
def generate_web_report(df_alerts, df_features, output_json_path):
    # 總連線數 (來自完整的特徵數據)
    total_connections = len(df_features)
    # 異常連線數 (來自報警數據)
    total_alerts = len(df_alerts)

    # 異常率
    alert_rate = (total_alerts / total_connections) * 100 if total_connections > 0 else 0

    # 統計 Top 5 異常連線的目的端口 (dport) 分佈
    # 確保 'dport' 欄位存在於報警數據中
    if 'dport' in df_alerts.columns:
        dport_distribution = df_alerts['dport'].value_counts().nlargest(5).to_dict()
    else:
        # 如果報警數據中沒有 dport，則使用空字典
        dport_distribution = {"Note": "Dport data not available in alerts."}

    # 建立 JSON 報告結構
    report_data = {
        "status": "success",
        "last_updated": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
        "metrics": {
            "total_connections": int(total_connections),
            "total_alerts": int(total_alerts),
            "alert_rate_percent": round(alert_rate, 2),
            "model_type": "Isolation Forest"
        },
        "top_dports": dport_distribution,
        "raw_alerts_path": "./alerts_if.csv" # 指向原始 CSV 報警清單
    }

    # 寫入 JSON 檔案
    # 確保目標目錄存在
    os.makedirs(os.path.dirname(output_json_path), exist_ok=True)
    with open(output_json_path, 'w') as f:
        json.dump(report_data, f, indent=4)
    
    print(f"Web report JSON successfully saved to {output_json_path}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", type=str, required=True, help="conn_features.csv")
    ap.add_argument("--model", type=str, required=True, help="if_model.joblib")
    ap.add_argument("--output", type=str, default="alerts_if.csv")
    ap.add_argument("--override_threshold", type=float, default=None, help="覆寫模型內建阈值（可選）")
    ap.add_argument("--json_output", type=str, default="web/static/web_report.json", help="Web 報告 JSON 輸出路徑")
    args = ap.parse_args()

    bundle = load(args.model)
    scaler = bundle["scaler"]
    model = bundle["model"]
    meta = bundle.get("meta", {})
    thr = args.override_threshold if args.override_threshold is not None else meta.get("threshold", None)

    # 讀取特徵資料並進行標準化
    df = pd.read_csv(args.input)
    
    #數據標準化與推論
    X = df[FEATURE_COLS].replace([np.inf,-np.inf], np.nan).fillna(0.0).values
    Xn = scaler.transform(X)

    scores = -model.score_samples(Xn)  # 越大越可疑
    df["anomaly_score"] = scores

    if thr is None:
        # 保底：若沒有 threshold，就取 99.5 百分位
        thr = float(np.quantile(scores, 0.995))

    df["is_alert"] = df["anomaly_score"] > thr
    cols = ["ts","src","sport","dst","dport","anomaly_score","bytes_sum","pkts_sum","bps_approx","bytes_ratio"]
    alerts = df[df["is_alert"]][cols].sort_values("anomaly_score", ascending=False)

    # 儲存CSV報警清單
    alerts.to_csv(args.output, index=False)
    print(f"Alerts (IF) -> {args.output}, count={len(alerts)}, threshold={thr:.6f}")
    
    # 產生 Web 報告 JSON
    generate_web_report(alerts, df, args.json_output)

if __name__ == "__main__":
    main()
