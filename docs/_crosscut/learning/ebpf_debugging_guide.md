# eBPF 除錯指南：如何從 verifier error 推斷程式問題

> 目標：建立一個「看到錯誤訊息 → 在腦中對應到原始碼問題 → 找到修法」的反射流程。
> 配合 `docs/_crosscut/issues/ebpf_verifier_pitfalls.md` 的真實案例對照使用。

---

## 0. 心智模型：BPF verifier 在做什麼

BPF verifier 是 kernel 對 eBPF 程式做的**靜態分析器**，在 `BPF_PROG_LOAD` syscall 內執行。它做兩件事：

1. **結構檢查（pre-walk）**：程式長度、最後一條指令必須是 `BPF_EXIT`、call target 是否合法、所有 helper id 有效。
2. **抽象解釋（symbolic execution）**：模擬每一條指令對 register state 的影響，逐個探索所有可能路徑。對每個 program point 維護「register 是否已初始化、值的可能範圍、是不是 packet pointer、bounds check 過了沒」。

只要任何一條路徑做了「verifier 不允許的事」，整個 program load 失敗。

**重要：verifier 不執行你的 packet payload；它執行你的程式碼結構。**

---

## 1. 解讀 verifier output 的 anatomy

典型錯誤訊息（kernel 6.12）：

```
0: R1=ctx() R10=fp0
0: (b7) r0 = 0                        ; R0_w=0
1: (61) r9 = *(u32 *)(r1 +80)         ; R1=ctx() R9_w=pkt_end()
2: (61) r5 = *(u32 *)(r1 +76)         ; R1=ctx() R5_w=pkt(r=0)
...
175: (bf) r8 = r9
    R9 !read_ok
verification time 1054 usec
stack depth 200+0
processed 549 insns (limit 1000000) max_states_per_insn 3 total_states 36 peak_states 36 mark_read 17
```

逐行拆解：

| 欄位 | 意思 | 怎麼用 |
|------|------|--------|
| `0: R1=ctx() R10=fp0` | 進入點的 register state，`R1=ctx()` 表示第一個參數是 context，`R10=fp0` 是 frame pointer。 | 確認你的 program type；offset 76/80 = TC skb context，offset 0/4 = XDP context。 |
| `1: (61) r9 = *(u32 *)(r1 +80)` | 第 1 條指令：`r9 = u32 load from ctx+80`。 | 對應 `data_end` 讀取。`;` 後是該指令執行後 register state 更新。 |
| `R9_w=pkt_end()` | R9 變成 packet end pointer，verifier 之後可以用它做 bounds check。 | `_w` 表示 write，`R9_w` = 這條指令寫了 R9。 |
| `R5_w=pkt(r=0)` | R5 是 packet pointer，`r=0` 表示「目前已被驗證可讀的 byte 數為 0」（還沒做 bounds check）。 | 看到 `r=N` 就是「最多可讀到 packet+N」。 |
| `175: (bf) r8 = r9` + `R9 !read_ok` | 失敗點：第 175 條讀 R9，但這條路徑上 R9 從未被寫入。 | **行號 + register 名 = 你要在原始碼找的位置與變數**。 |
| `processed 549 insns` | 失敗前驗證了 549 條指令。 | 接近 limit（1000000）= state explosion，看 §3。 |
| `stack depth 200+0` | 主程式用 200 bytes stack，BPF-to-BPF callee 用 0。 | 上限 512；超過會以另一種錯誤拒絕。 |

---

## 2. 錯誤訊息對照表（最常見的幾類）

### 2.1 `R? !read_ok`：讀取未初始化 register

> 「在這條路徑上，這個 register 從來沒被寫過。」

- **找尋方式**：往回看 verifier output，找出該 register 在哪些路徑被寫、哪些路徑沒被寫。
- **常見來源**：multi-arm `match`，某個 arm 沒寫到某 register；LLVM optimizer 在 join point 假設某些值會在 register 裡。
- **快速 reproduce 方式**：用 `llvm-objdump -d --section=<sec_name> <bin>` 看真實 BPF assembly，找出該指令周圍的 control flow。
- **修法主軸**：把 body 移到回傳 scalar 的 helper function（隔離 register allocation）。詳見 [Pitfall I2](../issues/ebpf_verifier_pitfalls.md#i2)。

### 2.2 `last insn is not an exit or jmp`

> 「程式最後一條指令不是 `exit` 或 `jmp`。」

- **常見來源**：aggregate return（sret convention）讓 LLVM 沒在 section 尾端放 `exit`；或編譯出的 program 真的是空的。
- **驗證方式**：`llvm-objdump --section-headers <bin>` 看 section size，size = 0 或 size 很小通常意味著有問題。
- **修法**：詳見 [Pitfall I1 / I5](../issues/ebpf_verifier_pitfalls.md#i1)。

### 2.3 `BPF program is too large. Processed 1000001 insn`

> 「verifier 處理的 instruction 數超過 1M，state space 爆炸。」

- **常見來源**：
  - `while` 迴圈 verifier 無法靜態 bound
  - 大量分支 + 共用 join point 導致 state cross-product
- **判斷方式**：看 `processed` 數值；接近 1M = state explosion；同時看 `total_states` / `peak_states` 是否異常大。
- **修法**：unrolled fixed-iteration、或拆函式以縮小 state 範圍。詳見 [Pitfall I3](../issues/ebpf_verifier_pitfalls.md#i3)。

### 2.4 `invalid access to packet, off=X size=Y, R5(id=N,off=O,r=R)`

> 「想讀 packet+off 的 Y bytes，但目前 verifier 只允許讀到 packet+R。」

- **常見來源**：忘了在讀取前做 `if data + off + sizeof(T) > data_end { return ERROR; }`。
- **修法**：永遠先做 bounds check，然後 verifier 會把該 register 的 `r=` 提升到至少 off + sizeof(T)。

### 2.5 `R0 has value (or unbounded value) which is not allowed for program type`

> 「return value 不符合該 program type 規定的合法值。」

- **常見來源**：忘了 `return XDP_PASS` 之類；或回傳值由動態值決定但 verifier 認為它可能是非法。
- **修法**：明確讓回傳值落在 `{ TC_ACT_OK, TC_ACT_SHOT, ... }`，必要時用 `if` 把 fallback 寫死。

### 2.6 `unreleased reference id=N alloc_insn=...`

> 「某資源（如 ringbuf reserve 的 slot）沒釋放。」

- **常見來源**：`RingBuf::reserve` 後在某條路徑沒 `submit` 也沒 `discard`。
- **修法**：所有 path 都必須走完釋放流程；用 RAII 包裝。

### 2.7 `__multi3` / `__divti3` / `__udivti3` undefined symbol

> Link 階段失敗（不算 verifier 但常被歸在 BPF 載入錯誤）。

- **常見來源**：`u64 * u64` 在 debug mode、`u64.saturating_mul`、`u128` 運算。
- **修法**：`wrapping_mul` 取代；release build；避免 128-bit 算術。詳見 [Pitfall I4](../issues/ebpf_verifier_pitfalls.md#i4)。

---

## 3. State explosion 的偵測與處置

state explosion 不一定爆 1M insn 上限；常見前兆：

- `verification time` 從幾百 usec 跳到幾百萬 usec
- `total_states` / `peak_states` 從幾十跳到幾千
- `max_states_per_insn` > 4

**處置流程：**
1. 找出 verifier 在哪附近 stuck（看最後一段 instruction 是不是反覆同一段，例如 instruction 498-503 重複出現多次 → 那段就是有問題的迴圈）。
2. 用 `llvm-objdump -d` 把該 instruction 範圍對應回原始碼（透過 line annotation 或結構推測）。
3. 替換成 unrolled / bounded 版本。

---

## 4. 工具書：常用 inspect 指令

```bash
# Section size & type
llvm-objdump --section-headers <bpf.o>

# 反組譯特定 section
llvm-objdump -d --section=classifier <bpf.o>
llvm-objdump -d --section=xdp <bpf.o>
llvm-objdump -d --section=.text <bpf.o>

# Relocation 條目
llvm-readelf -r <bpf.o>

# 看 BTF / DWARF（程式越大越有用）
llvm-readelf --sections <bpf.o>
bpftool btf dump file <bpf.o>

# Runtime：看 kernel 載入的 BPF programs 與 maps
sudo bpftool prog show
sudo bpftool map show

# 拿到 verifier log（更詳細的 dump，需要 libbpf 或 aya 的 verbose flag）
# Rust aya 在 load 時可以透過 EbpfLoader::verifier_log_level 取得完整 log
```

**判讀技巧：**
- Section size = 0 → 程式可能被 strip 掉；確認對應的 `#[xdp]` / `#[classifier]` 函式是否被編譯到。
- Section size 很小（< 100 bytes）+ 有 `call -0x1` → 不是真的小，是用 BPF-to-BPF call 跳到 `.text`；要把該函式 inline 或檢查 sret 問題。
- `.rel<section>` 的 entry 數 = BPF-to-BPF call 數 + map relocation 數。

---

## 5. 從 Rust 原始碼預測 verifier 反應的 checklist

寫 eBPF Rust 程式時，每段邏輯先腦中 review：

- [ ] 每個 packet bounds check 之後是否確保 `data + need <= data_end`？
- [ ] 所有 `while` 是否能靜態 bound？不能就要改 unrolled。
- [ ] 任何 `u64 * u64` / `u64.saturating_mul`？替換成 `wrapping_mul`。
- [ ] entry function 內有沒有 multi-arm `match`，且各 arm 行為差異大？考慮把 body 移到 helper。
- [ ] 函式回傳 aggregate（Result, tuple, struct）？避免 `#[inline(never)]`，或改回 scalar。
- [ ] BPF maps、ringbuf reserve 是否所有路徑都釋放？
- [ ] Return value 是不是該 program type 認可的合法值？

---

## 6. 對照表：本專案踩過的坑 → 訊息 → 修補位置

| 訊息片段 | Issue | 修補檔 |
|----------|-------|--------|
| `aggregate returns are not supported` | [I1](../issues/ebpf_verifier_pitfalls.md#i1) | `firewall-ebpf/src/main.rs` |
| `R9 !read_ok` / `R7 !read_ok` | [I2](../issues/ebpf_verifier_pitfalls.md#i2) | `firewall-ebpf/src/main.rs::tc_egress` 改用 helper |
| `BPF program is too large. Processed 1000001 insn` | [I3](../issues/ebpf_verifier_pitfalls.md#i3) | `syn_cookie.rs::update_checksum` 拆 unrolled fold |
| `__multi3` undefined | [I4](../issues/ebpf_verifier_pitfalls.md#i4) | `scorer.rs`、`table.rs` 改 `wrapping_mul` |
| `last insn is not an exit or jmp` + `processed 0 insns` | [I5](../issues/ebpf_verifier_pitfalls.md#i5) | 同 I1 |
| Userspace 編譯 `expected &u32, found integer` | [I6](../issues/ebpf_verifier_pitfalls.md#i6) | `model_loader.rs`、`boundary_updater.rs` |

---

## 7. 延伸閱讀

- Cilium eBPF book - verifier chapter（外部，理論說明）
- Linux kernel: `Documentation/bpf/verifier.rst`、`kernel/bpf/verifier.c`（最終真相）
- aya book: <https://aya-rs.dev>（Rust 端 API 與 troubleshooting）
- 本專案歷史踩坑：`docs/_crosscut/issues/ebpf_verifier_pitfalls.md`
