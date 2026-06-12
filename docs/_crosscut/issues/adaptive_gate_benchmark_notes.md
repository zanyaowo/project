# 自適應閘控 × 效能量測踩坑（map update latency / benign 觸發）

> 紀錄量測 Boundary Adaptive Update 路徑（Table 2 / 8.A-5 map update latency）時，
> 對「為何 loopback 合成流量無法自然觸發 map write」的調查與結論。
> 結論以實測數字 + 來源佐證，量測環境：Linux 6.12.91 / lo / xdpgeneric / hping3。

---

## A1. 合成 flood 流量無法自然觸發 boundary publish（2026-06-12，已驗證）

**現象：** 在 loopback 對 firewall 灌各種合成流量（SYN flood、distinct-port UDP flood、
單一重用流、ICMP ping flood），`boundary_updater` 從不發布邊界更新，
`write_boundary_version` 從不被呼叫 → map update latency 無從量測。

**逐層排查（重要：先前有兩條誤判，一併記錄）：**

1. **SYN flood 早退**：TCP SYN 走 `syn_cookie::send_syn_cookie` 在 `update_session` 前
   就 `XDP_TX` return，**到不了 scorer**，不產生 StatsEvent。SYN flood 不適合測 scorer 路徑。

2. **❌ 誤判（已更正）「SESSIONS 表灌爆 → 新流不評分」**：`SESSIONS` 是
   `LruPerCpuHashMap`（`firewall-ebpf/src/table.rs:12`），滿表會 LRU 淘汰最舊 entry、
   `insert` 永遠成功，**不存在插入失敗**。先前 distinct-port flood 那輪沒觸發，真正原因是
   firewall 從 project root 啟動、config 的 `model_file` 相對路徑沒對到檔案 →
   model 未載入（`MODEL_CONFIG.enabled==0`）→ `score_session` 直接 return、不取樣。
   修正＝用絕對路徑 model_file 或從 `service/firewall/firewall/` 啟動。

3. **✅ 真正的設計性攔阻：benign 參考批餓死（AttackFreeze by starvation）**。
   model 正確載入後（`MODEL_CONFIG` = enabled 1 / fcount 5 / threshold 7073），
   distinct-port UDP flood（`hping3 --udp -i u300`，~3000pps，20s）下：

   | 觀測 | 數值 | 來源 |
   |------|------|------|
   | EVENTS_POOL 事件（logger ring） | 75022 | firewall metrics log |
   | 建立的 session（LRU） | 37512 | `bpftool map dump name SESSIONS \| grep -c '^key'` |
   | StatsEvent 流入 updater（live_batch，臨時 debug log） | 持續增長 1000→7000 | `boundary_updater DEBUG` |
   | **benign-gated 樣本（ref_batch）** | **全程 = 0** | 同上 |
   | boundary publish / map write | **0 次** | log 無 `published boundaries` |

   **根因：** `batch_ready()` 需 `live_batch >= batch_size` **且** `ref_batch >= batch_size`
   （`boundary_updater.rs`）。`ref_batch` 只收 benign-gated 樣本
   （eBPF scorer：`score*2 < threshold`）。合成 UDP flood 被 model **正確判為 attack**
   （score 全 ≥ threshold/2 = 3536），故 `ref_batch` 永遠停在 0 → batch 永不 ready →
   gate 從不重新校準。這正是 **dual-sketch gated 設計的防污染本意**：純攻擊流量下凍結
   reference，不讓攻擊樣本污染邊界。

**結論：** 要自然觸發 boundary publish，需要 model 判為 benign 的流量
（CIC-BENIGN-like：封包大小多樣、雙向真實 session），這正是 loopback hping3/ping
測試床無法合成的。`StatsEvent` 流入路徑本身正常（live_batch 有長），問題純在
benign 分類，**非 bug**。

---

## A2. Map update latency 改用直接微基準量測（2026-06-12）

**決策：** 因 A1，不靠自然觸發，改用 env-gated 微基準直接量 syscall 成本。

**方法：** `main.rs::bench_map_update`，`FIREWALL_BENCH_MAP_UPDATE=<n>` 啟用。
對已載入 kernel 的 `QUANTILE_BOUNDS` / `BOUNDARY_META` 連續呼叫 `write_boundary_version`
（5 筆 bounds `set` + 1 筆 meta 版本切換），取 min/p50/p99/max。與穩態下每批發布的
動作完全相同，不依賴流量分類。

**結果（3 runs × 1000 iters，kernel maps）：**

| run | p50 (µs) | p99 (µs) |
|-----|:---:|:---:|
| 1 | 3.05 | 3.19 |
| 2 | 1.69 | 2.58 |
| 3 | 2.45 | 2.89 |

→ 報告填 **p50 ≈ 2–3 µs、p99 ≈ 3 µs**（`report/main.tex` tab:hardware-perf-plan）。
原始紀錄：`bench_results/table2.md`。

**caveat：** 微基準為背靠背呼叫，cache 較熱；production 每批發布間隔較長，
單次成本可能略高，但同為個位數 µs 量級，syscall-bound，差異可忽略。
