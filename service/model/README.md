# Net Anomaly MVP

最小可行的異常封包/連線偵測模型：
- Zeek `conn.log` 轉表格特徵
- 規則基線（rule baseline）
- Isolation Forest 無監督模型（含 scaler 與自動閾值）

## 1) 安裝
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## 2) 準備資料
使用 Zeek 將 pcap 轉成 `conn.log`，再用 `zeek-cut` 轉成 `conn.tsv`。
（若沒有 Zeek，也可以直接用已提供的 `conn_features.csv` 自行測試。）

```bash
# 例：把 conn.log 轉成 conn.tsv (欄位與腳本一致)
zeek-cut ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration   orig_bytes resp_bytes orig_ip_bytes resp_ip_bytes orig_pkts resp_pkts history   < conn.log > conn.tsv
```

## 3) 產生特徵
```bash
python src/build_features.py --input conn.tsv --output conn_features.csv
```

## 4) 規則基線
```bash
python src/rule_baseline.py --input conn_features.csv --output alerts_rule.csv
```

## 5) 訓練 Isolation Forest
```bash
python src/train_if.py --input conn_features.csv --model if_model.joblib --alert_rate 0.005
```
- `--alert_rate` 代表你可接受的異常比例（預設 0.5%）。

## 6) 推理（產生模型告警）
```bash
python src/infer_if.py --input conn_features.csv --model if_model.joblib --output alerts_if.csv
```

## 7) 欄位說明
- `conn.tsv`：由 Zeek `conn.log` 對應欄位轉出。
- `conn_features.csv`：特徵化後的 per-flow 表格。
- `alerts_rule.csv` / `alerts_if.csv`：告警清單（包含基本指標與分數）。

## 備註
- 你可以將 `--alert_rate` 調小（更嚴格）或調大（更寬鬆）。
- 若要即時化，請以 30s/60s 窗口批次處理新增的 `conn.log` 行，重複「特徵 → 推理 → 輸出告警」。
