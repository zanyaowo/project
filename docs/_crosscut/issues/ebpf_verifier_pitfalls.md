# eBPF Verifier × LLVM Code Generation Pitfalls

> 紀錄與 Linux eBPF verifier + LLVM eBPF backend 互動時踩到的坑與規避方法。
> 每個 issue 記載：症狀、發生時機、Rust 原始碼模式、verifier 訊息、修復方式、根因。

---

## I1. `aggregate returns are not supported`（2026-05-22）

**症狀：** BPF_PROG_LOAD 失敗，verifier 輸出 `aggregate returns are not supported`。

**觸發條件：**
- 函式被標 `#[inline(never)]`
- 回傳型別為 aggregate（如 `Result<i32, ()>`、`(u16, u16, u8)` tuple、struct）

**Rust 原始碼模式：**
```rust
#[inline(never)]
unsafe fn try_tc_egress(ctx: TcContext) -> Result<i32, ()> { ... }
```

**根因：** eBPF ABI 只支援單一 scalar（r0）做為函式回傳值。Aggregate type 需要透過 sret（pointer 寫回 stack）convention 回傳，目前 verifier 不允許 BPF-to-BPF call 走 sret。

**規避方式：**
- 把 `#[inline(never)]` 改成 `#[inline(always)]`（強制 inline，消除 BPF-to-BPF call）— 但若函式太複雜會引發 I2
- 或：改變函式回傳型別為 scalar（如 `i32`），用 sentinel value 代替 `Err`

**相關修補：** `service/firewall/firewall-ebpf/src/main.rs` `tc_egress`／`tc_egress_impl`

---

## I2. Multi-arm `match` + LLVM register allocation → `R? !read_ok`（2026-05-23）

**症狀：** BPF_PROG_LOAD 失敗，verifier 輸出形如 `R9 !read_ok` 或 `R7 !read_ok`。

**觸發條件：**
- entry function 直接包含 multi-arm enum match
- 各 arm 取出不同欄位放進共用後續邏輯（join point）
- 至少有一個 arm（如 `_ => ()` 或 `_ => (0, 0, 0)`）沒有對某個 register 做寫入

**Rust 原始碼模式：**
```rust
let (src_port, dst_port, flag) = match pkt.l4_info {
    L4Info::Tcp(tcp) => (tcp.src_port, tcp.dst_port, tcp.flags),
    L4Info::Udp(udp) => (udp.src_port, udp.dst_port, 0),
    L4Info::Icmp(icmp) => (icmp.icmp_id, icmp.icmp_seq, 0),
    L4Info::Unknown => (0, 0, 0),  // ← 沒實際解析 L4 header，register 未被寫
};
// 後續 join 程式碼讀 R9，但 Unknown 分支從未寫過 R9
```

**根因：** LLVM eBPF backend 在 entry function 內展開 match 時，會用 register 暫存某些 arm 才會解析出的中介值（如 L4 packet pointer）；join point 之後若用到該 register，verifier 在「沒寫過的 arm」路徑會抓到讀取未初始化值。

**規避方式（依優先序）：**
1. **把 body 包進獨立 helper function**（仿 `try_xdp_firewall` 模式）— LLVM 會把該函式當成 BPF-to-BPF call，register 分配與 entry function 隔離。注意 helper 必須回傳 scalar 才不會踩到 I1。
2. **針對 fallback arm 直接 `return`**，跳過 join point —— 但 LLVM 有時仍會合併 return 路徑（已驗證在我們的場景下不足以解決）。
3. **預先初始化所有共用變數為 0**：`let mut x = 0; match { … x = …; … }` —— 也常被 LLVM optimizer 看穿後優化掉。

**相關修補：** `tc_egress` 改成 thin wrapper 呼叫 `tc_egress_impl(&ctx) -> i32`，內部處理 match。

---

## I3. `while` 迴圈導致 verifier insn limit 爆炸（2026-05-23）

**症狀：** BPF_PROG_LOAD 失敗，verifier 訊息 `BPF program is too large. Processed 1000001 insn / verification time XXX usec`，state explosion。

**觸發條件：**
- 程式有 `while` 迴圈，迴圈條件依賴於 input-derived 的值
- verifier 無法靜態決定迴圈上界

**Rust 原始碼模式：**
```rust
// Internet checksum carry fold
while (sum >> 16) > 0 {
    sum = (sum & 0xFFFF) + (sum >> 16);
}
```

**根因：** eBPF verifier 對所有可能的執行路徑做 state space exploration；當迴圈次數不可靜態 bound，可能要展開到 65536 次以上，total states 暴增至 100 萬上限。

**規避方式：**
- 把迴圈轉成固定次數的 unrolled fold：對 32-bit checksum，數學上最多 2 次折疊就一定收斂
  ```rust
  sum = (sum & 0xFFFF) + (sum >> 16);
  sum = (sum & 0xFFFF) + (sum >> 16);
  ```
- 若真的需要動態次數，使用 kernel 5.17+ 的 `bpf_loop()` helper

**相關修補：** `service/firewall/firewall-ebpf/src/syn_cookie.rs::update_checksum`

---

## I4. `u64.saturating_mul(u64)` / debug-mode `u64 * u64` 產生 `__multi3`（2026-05-22）

**症狀：** eBPF ELF link 階段失敗 / verifier 拒絕，提到 `__multi3` undefined symbol。

**觸發條件：**
- 程式碼有 `u64.saturating_mul(u64)`
- 或 debug build（未開 release optimization）下做 `u64 * u64`

**根因：** `saturating_mul` 內部會做 `self as u128 * rhs as u128` 來偵測 overflow；debug mode 的 overflow check 也走 u128 路徑。eBPF 沒有 128-bit native multiplication，需要 compiler-rt 提供 `__multi3` intrinsic，而 BPF target 沒有 link 進來。

**規避方式：**
- 改用 `wrapping_mul`（不做 overflow detection）
- 對 product 已知不會 overflow 的場景，這是正確且更便宜的選擇

**相關修補：** `firewall-ebpf/src/scorer.rs`、`firewall-ebpf/src/table.rs`

---

## I5. ELF section "last insn is not an exit or jmp"（2026-05-22）

**症狀：** BPF_PROG_LOAD 失敗，`processed 0 insns`、`last insn is not an exit or jmp`。

**觸發條件：**
- 函式以 sret convention 透過 BPF-to-BPF call 回傳 aggregate
- 結果是 entry section 末尾不是 `exit`（而是被 LLVM 結構化成奇怪的尾部）

**根因：** 與 I1 同源，但表現形式不同。Section 結構在 sret call 收尾後 LLVM 沒有放上適當的 `exit`，kernel verifier 在進入 verification 前的 sanity check 就拒絕。

**規避方式：** 同 I1—— 不要對 aggregate-returning function 用 `#[inline(never)]`；或改用 scalar return。

---

## I7. aya 0.13.1 `qdisc_detach_program` 不清 clsact qdisc（2026-05-23）

**症狀：** Firewall graceful shutdown 後，介面上 `tc qdisc show dev <iface>` 仍顯示 `qdisc clsact ffff: parent ffff:fff1`。下次啟動雖然不影響功能，但是殘留會累積。

**伴隨 log：**
```
[WARN  firewall] TC cleanup failed (qdisc may already be gone): failed to detach tc_egress program
```

**根因：**
- aya 0.13.1 的 `tc::qdisc_detach_program` 只 detach 「program」自身，**不**移除底下的 `clsact` qdisc。
- 而且 program 通常隨 `Ebpf::drop()` 自動清除，所以 detach call 本身大多會 fail。
- aya 0.13.1 **沒提供** `qdisc_del_clsact` API。

**規避方式：** 用 `std::process::Command` 呼叫 iproute2 的 `tc qdisc del dev <iface> clsact`。雖然要 fork 一個 process，但這是 cleanup path 不在 hot path 上，可接受。

```rust
let _ = std::process::Command::new("tc")
    .args(["qdisc", "del", "dev", iface, "clsact"])
    .status();
```

**相關修補：** `service/firewall/firewall/src/lib/controller.rs::detach_tc`

---

## I6. `aya::Array::get` API 變更（2026-05-22）

**症狀：** Rust 編譯錯誤 `expected &u32, found integer`。

**觸發條件：** 升級到 aya 0.13.1 之後，userspace 端呼叫 `Array::get(0, 0)`。

**根因：** aya 0.13.1 把 `Array::get` 的 key 參數從 `K` 改成 `&K`。

**規避方式：** 把所有 `get(N, 0)` 改成 `get(&N, 0)`。

**相關修補：** `service/firewall/firewall/src/lib/model_loader.rs`、`boundary_updater.rs`

---

## I8. `combined stack size of 2 calls is 640. Too large`（2026-06-11）

**症狀：** BPF_PROG_LOAD 失敗，`combined stack size of N calls is XXX. Too large`，並列出 per-subprogram `stack depth 288+0+344+...`。

**觸發條件：** 512-byte stack 上限是**沿 call path 累加**的（每個 frame round up 到 32 bytes）。IPv6 位址改 16-byte 後 `parse_packet` frame 漲到 344，`xdp_firewall(288) + parse_packet(352) = 640 > 512`。

**根因：** `parse_packet` 內 `L3Fields` struct 存了兩個 `[u8; 16]` 位址（32 B），之後又複製進 `PacketInfo { … }` literal（~64 B stack 暫存）才 `*out =` 寫出——兩個位址在 frame 上活了兩份。

**規避方式：** 子函式改收 `&mut PacketInfo`，把大欄位（位址、len）**直接寫進 `*out`**，metadata struct 只留小 scalar；尾端逐欄寫入取代整個 struct literal。`parse_packet` frame 344 → 80。注意**不可**用「再拆一層 call」來修——巢狀 call 加進同一條 path 的總和。

**量測工具：** `llvm-objdump -d` 後統計每個函式最大 `r10 - 0xNN` offset（per-function frame size）。

**相關修補：** `service/firewall/firewall-ebpf/src/parser.rs`（`L3Meta` 重構）

---

## I9. bpf-linker 的 memset/memcpy 不寫 R0 → `R0 !read_ok`（2026-06-11）

**症狀：** BPF_PROG_LOAD 失敗，verifier 在某個 sub-8-byte store 處報 `R0 !read_ok`。

**觸發條件：**
- Rust 端有「大半為常數 0 的陣列賦值」（如 `out.src_ip = ipv4_mapped(addr)` 的 10-byte 零前綴）或大 struct 複製，LLVM 把它降成 `memset()` / `memcpy()` **libcall**（bpf-linker 以真正的 BPF-to-BPF 函式提供這些 symbol）
- 同時 LLVM 的 regalloc 把一個活值留在 R0 **跨越**該 call

**根因：** bpf-linker 的 memset/memcpy 在 `exit` 前從不寫 R0。verifier 視 call 之後的 R0 為 callee 回傳值＝未定義；caller 若讀取舊值即拒絕。是否觸發取決於 regalloc，**換個版本/改點程式碼就可能爆**。

**規避方式：** 熱路徑避免會變 libcall 的 pattern——零前綴陣列用「一個 u64 store + 個別 byte store」明確寫（`set_ipv4_mapped`）；16-byte 複製用兩組 `read_unaligned`/`write_unaligned` u64（`copy_ip16`）。
**診斷：** `llvm-objdump -dr` 找 `R_BPF_64_32 memset/memcpy` 的 call site，看 call 之後 R0 是否在被讀取前重新定義。

**相關修補：** `service/firewall/firewall-ebpf/src/parser.rs`

---

## I10. Enum payload poison 複製 → `invalid size of register spill`（2026-06-11）

**症狀：** BPF_PROG_LOAD 失敗，`invalid size of register spill`，trace 中可見一個**指標值**（如 `R1=fp[0]-216`）被以 u8 store 寫進 stack。

**觸發條件：** `let l4_info = match … _ => L4Info::Unknown;` 之後 `out.l4_info = l4_info`。`Unknown` variant 的 payload bytes 是未初始化（poison）；整個 enum 複製時 LLVM 可用**任何活暫存器**填這些 bytes——本例選了還活著的 `out` 指標，指標以 sub-8-byte 寫進 stack 即被拒。

**根因：** Rust/LLVM 對 poison bytes 的 store 內容無任何保證；verifier 卻對 stack store 做 pointer/scalar 型別追蹤。舊寫法（`*out = PacketInfo{…}` 整塊 stack 暫存 memcpy）讀的是 STACK_MISC，合法，所以以前沒爆。

**規避方式：** 不要 materialise 帶 payload 的 enum 再複製。各 match arm **直接寫** `out.l4_info = L4Info::Tcp(tcp)`；無 payload 的 variant（Unknown）**完全不寫**，依賴 caller 的 `PacketInfo::default()`（`L4Info` 的 `#[default]` 即 Unknown）。

**相關修補：** `service/firewall/firewall-ebpf/src/parser.rs`（`parse_packet` L4 段）

---

## 通用學到的原則

1. **eBPF entry function 越大越脆弱**：LLVM 的 register allocator 在大量 inline 時更容易產生「某 register 跨分支半初始化」的程式碼。把實作放到 helper function（回傳 scalar）通常最穩。
2. **`#[inline(always)]` 不保證會真的 inline**：LLVM 可能仍判斷成本太高而保留 BPF-to-BPF call。觀察 `llvm-objdump -d --section=<name>` 確認。
3. **任何 `while` / loop 都要能靜態 bound**：對 BPF 來說最安全的是 unrolled fixed-iteration。
4. **debug vs release 不只是優化差距**：debug 會插入 overflow check，可能引入 BPF 不支援的 intrinsic。常規路徑：用 release 編 eBPF。
5. **遇到 verifier 錯誤先看 ELF section dump**：classifier / xdp section 的 size 與末尾指令往往直接揭示問題（empty section、未終止於 exit、有不該存在的 BPF-to-BPF call）。
6. **大型陣列/struct 的隱式複製是三重地雷**：stack frame 膨脹（I8）、memset/memcpy libcall 的 R0 hazard（I9）、enum poison bytes 的指標 spill（I10）。熱路徑上對 16-byte 以上的資料移動一律用明確 scalar store／逐欄寫入，並以 `llvm-objdump -dr` 驗證沒有 `R_BPF_64_32 mem*` relocation 出現在意料之外的位置。
