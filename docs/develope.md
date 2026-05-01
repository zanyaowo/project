# 開發日誌

## 掛載點選擇
+ XDP處理RX以及阻擋黑名單IP
+ TC負責抓取TC資料給模型辨識及訓練使用

## 模型缺陷
在處理proto_h欄位時，Feature hashing的值(16)過小，協定設定的大小為u8(256)，容易發生碰撞
需要檢視原先模型的訓練參數

## 待開發功能
支援IPv6
掛載訓練好的模型進行識別
syn_cookie ack的部份還沒進行判斷

# 2/13
進行TC egress流量紀錄的開發

# 2/20
新增icmp協議解析

# 4/28 蒸餾架構轉向：N=2 分位桶 + 查表法
原先設計為 N=16 分位桶 + 線性加權，但根據離線實驗結果：
+ N=16 與 N=256 AUC 差距不大，N 越大反而下降
+ N=2 已足夠表達 IF 的 per-feature 邊際貢獻
+ 線性加權在 N=2 時退化為加權投票，失去意義

改為 N=2 + 32 entry score table：5 特徵共 2^5 = 32 種桶組合，userspace 預先計算每種組合的 IF 分數，kernel 端只做 5 次邊界比較 + 1 次查表。

特徵調整：將 Shape_Ratio (Min/Fwd Mean) 替換為 FwdMax_q (Max/Fwd Mean)，因為 Shape 與 Protocol 語義重疊，FwdMax 更獨立且具區辨力。

## 改動範圍
+ firewall-common: model.rs 移除 ModelWeight、CROSS_MULT_MASK，新增 SCORE_TABLE_SIZE 與 ScoreResult；session.rs 改為追蹤 max_pkt_len
+ firewall-ebpf: scorer.rs 重寫為查表邏輯，回傳 ScoreResult (score + action)；main.rs XDP 路徑整合 scorer，依 action 決定 DROP；collector.rs 事件帶上 score
+ firewall (userspace): 新增 model_loader.rs（讀 JSON 並依 disable → 寫 maps → enable 流程注入 eBPF）；config.rs 對齊 toml section 命名並新增 ModelSetting；main.rs 啟動時呼叫 loader
+ docs/kernel_inference_design.md: 補上分位桶切割方法討論章節（等頻、等寬、最佳閾值、IF score-driven、決策樹分裂、KDE valley），目前採用等頻 (p50)

## 待後續處理
+ Python 端輸出 model.json（目前只有 schema 範例）
+ IAT 熵值特徵（先跳過）
+ Rate limiting 執行層
+ logger.rs 內舊的 ModelFeature 建構邏輯可清理