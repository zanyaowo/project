# PacketInfo 結構重構設計提案

**提案日期：** 2026-02-21
**狀態：** 待審核
**影響範圍：** firewall-ebpf 模組
**提案人：** 基於程式碼審查建議

---

## 目錄

- [背景與動機](#背景與動機)
- [當前設計分析](#當前設計分析)
- [問題描述](#問題描述)
- [建議的新設計](#建議的新設計)
- [實作計畫](#實作計畫)
- [風險評估](#風險評估)
- [替代方案](#替代方案)
- [決策建議](#決策建議)

---

## 背景與動機

### 觸發問題

在實作 SYN Cookie ACK 驗證功能時，發現需要在 `PacketInfo` 中添加 TCP 特定欄位（`seq` 和 `ack_seq`）。這引發了對當前資料結構設計的重新思考。

### 當前面臨的需求

1. **SYN Cookie 驗證** - 需要 TCP `seq` 和 `ack_seq` 欄位
2. **支援多種協議** - 已有 TCP、UDP、ICMP，未來可能支援更多
3. **記憶體效率** - eBPF 程式對記憶體使用敏感
4. **型別安全** - 避免在錯誤的協議下存取不相關欄位

---

## 當前設計分析

### 現有結構

```rust
// firewall-ebpf/src/parser.rs
pub struct PacketInfo {
    // 通用欄位（所有協議）
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,      // UDP/TCP 有效，ICMP 存 ID
    pub dst_port: u16,      // UDP/TCP 有效，ICMP 存 Seq
    pub proto: u8,
    pub len: u64,
    pub payload_len: u64,

    // TCP 特定
    pub flags: u8,

    // ICMP 特定
    pub icmp_type: u8,
    pub icmp_code: u8,
}
```

### 當前使用方式

```rust
// main.rs
let pkt: PacketInfo = parse_packet(&ctx)?;

if pkt.flags == 0x0002 {  // SYN
    return syn_cookie::send_syn_cookie(&ctx);
}

// table.rs
let params = SessionUpdateParams::from(&pkt);
update_session(&params);
```

---

## 問題描述

### 問題 1：欄位語義混亂

**問題：** `src_port`/`dst_port` 在不同協議下有不同含義

```rust
// TCP/UDP: 真正的埠號
pkt.src_port = 443;

// ICMP:
// src_port 實際存的是 icmp_id
// dst_port 實際存的是 icmp_seq
pkt.src_port = icmp_id;  // 語義不清晰！
pkt.dst_port = icmp_seq;
```

**影響：**
- ❌ 程式碼可讀性差
- ❌ 容易誤用
- ❌ 維護困難

---

### 問題 2：記憶體浪費

**問題：** 每個封包都攜帶所有協議的欄位

```rust
// UDP 封包
PacketInfo {
    src_port: 53,      // ✅ 使用
    dst_port: 12345,   // ✅ 使用
    flags: 0,          // ❌ 未使用（TCP 專用）
    icmp_type: 0,      // ❌ 未使用（ICMP 專用）
    icmp_code: 0,      // ❌ 未使用（ICMP 專用）
}

// ICMP 封包
PacketInfo {
    src_port: 1234,    // ⚠️  存的是 icmp_id（語義錯誤）
    dst_port: 5678,    // ⚠️  存的是 icmp_seq（語義錯誤）
    flags: 0,          // ❌ 未使用
    icmp_type: 8,      // ✅ 使用
    icmp_code: 0,      // ✅ 使用
}
```

**記憶體分析：**

| 協議 | 實際需要 | 當前大小 | 浪費 |
|------|----------|----------|------|
| TCP | ~32 bytes | 36 bytes | 4 bytes |
| UDP | ~24 bytes | 36 bytes | 12 bytes |
| ICMP | ~28 bytes | 36 bytes | 8 bytes |

---

### 問題 3：擴展性差

**問題：** 每次支援新協議或新需求都需要修改結構

```rust
// 當前需要添加 SYN Cookie 支援
pub struct PacketInfo {
    // ... 現有欄位
    pub flags: u8,
    pub icmp_type: u8,
    pub icmp_code: u8,

    // 新增：SYN Cookie 需要
    pub seq: u32,      // ⚠️ 只有 TCP 使用
    pub ack_seq: u32,  // ⚠️ 只有 TCP 使用
}
```

**未來需求示例：**
- 支援 IPv6 → 需要擴充 IP 地址欄位
- 支援 SCTP → 需要新的協議特定欄位
- 支援 GRE 隧道 → 需要隧道資訊欄位

**影響：**
- ❌ 結構持續膨脹
- ❌ 編譯時間增加
- ❌ 記憶體浪費加劇

---

### 問題 4：缺乏型別安全

**問題：** 可以在錯誤的協議下存取不相關欄位

```rust
let pkt = parse_packet(&ctx)?;

// 如果是 UDP 封包，但錯誤地檢查 TCP flags
if pkt.flags == 0x02 {  // ⚠️ UDP 沒有 flags，但編譯通過！
    // 錯誤的邏輯
}

// 如果是 TCP 封包，但錯誤地檢查 ICMP type
if pkt.icmp_type == 8 {  // ⚠️ TCP 沒有 icmp_type，但編譯通過！
    // 錯誤的邏輯
}
```

**Rust 無法在編譯期捕獲這類錯誤！**

---

## 建議的新設計

### 方案：使用 Enum + 協議特定結構

```rust
// firewall-ebpf/src/parser.rs

/// 通用封包資訊（所有協議共享）
pub struct PacketInfo {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub proto: u8,
    pub len: u64,
    pub payload_len: u64,
    pub l4_info: L4Info,  // 協議特定資訊
}

/// Layer 4 協議資訊（使用 enum 區分）
pub enum L4Info {
    Tcp(TcpInfo),
    Udp(UdpInfo),
    Icmp(IcmpInfo),
    Unknown,
}

/// TCP 協議資訊
pub struct TcpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: u8,
    pub seq: u32,
    pub ack_seq: u32,
    pub window: u16,       // 未來可能需要
    pub _padding: [u8; 1], // 8 位元組對齊
}

/// UDP 協議資訊
pub struct UdpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub _padding: [u8; 4], // 8 位元組對齊
}

/// ICMP 協議資訊
pub struct IcmpInfo {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub icmp_id: u16,
    pub icmp_seq: u16,
    pub _padding: [u8; 2], // 8 位元組對齊
}
```

### 記憶體佈局分析

```
PacketInfo:
├─ src_ip: u32        (4 bytes)
├─ dst_ip: u32        (4 bytes)
├─ proto: u8          (1 byte)
├─ [padding]          (7 bytes) - 對齊
├─ len: u64           (8 bytes)
├─ payload_len: u64   (8 bytes)
└─ l4_info: L4Info    (16 bytes) - enum 大小 = 1 (tag) + 15 (最大變體)
                      = 24 + 16 = 40 bytes

對比當前設計：36 bytes
增加：4 bytes (11% 增加)

但獲得：
✅ 型別安全
✅ 清晰語義
✅ 更好的擴展性
```

---

## 優勢分析

### ✅ 優勢 1：型別安全

**編譯期保證正確性：**

```rust
match pkt.l4_info {
    L4Info::Tcp(tcp) => {
        // 只能存取 TCP 欄位
        if tcp.flags == TCP_FLAG_SYN {
            // SYN Cookie 處理
            verify_cookie(tcp.seq, tcp.ack_seq)?;
        }
    }
    L4Info::Udp(udp) => {
        // 只能存取 UDP 欄位
        // 無法錯誤地存取 flags!
    }
    L4Info::Icmp(icmp) => {
        // 只能存取 ICMP 欄位
        if icmp.icmp_type == 8 {  // Echo Request
            // ICMP 處理
        }
    }
    L4Info::Unknown => {
        // 未知協議處理
    }
}
```

**錯誤的程式碼無法編譯：**

```rust
// ❌ 編譯錯誤！
if let L4Info::Udp(udp) = pkt.l4_info {
    if udp.flags == TCP_FLAG_SYN {  // ❌ UDP 沒有 flags 欄位
        // ...
    }
}
```

---

### ✅ 優勢 2：語義清晰

**之前（混亂）：**
```rust
// ICMP 封包
pkt.src_port = icmp_id;   // ⚠️ 用 port 存 ID？
pkt.dst_port = icmp_seq;  // ⚠️ 用 port 存 Seq？
```

**之後（清晰）：**
```rust
// ICMP 封包
if let L4Info::Icmp(icmp) = pkt.l4_info {
    let id = icmp.icmp_id;    // ✅ 語義明確
    let seq = icmp.icmp_seq;  // ✅ 語義明確
}
```

---

### ✅ 優勢 3：易於擴展

**添加新協議很簡單：**

```rust
// 未來支援 SCTP
pub enum L4Info {
    Tcp(TcpInfo),
    Udp(UdpInfo),
    Icmp(IcmpInfo),
    Sctp(SctpInfo),  // ✅ 新增協議
    Unknown,
}

pub struct SctpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub verification_tag: u32,
    // SCTP 特定欄位
}
```

**不影響現有程式碼的其他分支！**

---

### ✅ 優勢 4：符合 Rust 慣例

**利用 Rust 型別系統表達業務邏輯：**

```rust
// Rust 標準庫使用類似設計
enum IpAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

enum Option<T> {
    Some(T),
    None,
}

// 我們的設計
enum L4Info {
    Tcp(TcpInfo),
    Udp(UdpInfo),
    Icmp(IcmpInfo),
    Unknown,
}
```

---

## 實作計畫

### Phase 1：準備工作（0.5 天）

#### 1.1 創建新分支
```bash
git checkout -b refactor/packetinfo-enum
```

#### 1.2 定義新結構
在 `parser.rs` 中定義新的資料結構：
- `PacketInfo`（新版）
- `L4Info` enum
- `TcpInfo`, `UdpInfo`, `IcmpInfo` struct

#### 1.3 保留舊結構
暫時保留舊的 `PacketInfo` 為 `PacketInfoOld`，方便對比和回滾。

---

### Phase 2：修改 Parser（1 天）

#### 2.1 修改 `parse_packet` 函數

**之前：**
```rust
pub unsafe fn parse_packet<C: PacketContext>(ctx: &C) -> Result<PacketInfo, ()> {
    // ...
    let packet = PacketInfo {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto,
        len: total_len,
        payload_len,
        flags,
        icmp_type,
        icmp_code,
    };
    Ok(packet)
}
```

**之後：**
```rust
pub unsafe fn parse_packet<C: PacketContext>(ctx: &C) -> Result<PacketInfo, ()> {
    let (eth_type, l3_offset) = parse_eth(ctx)?;
    let (src_ip, dst_ip, proto, l4_offset) = parse_ip(ctx, eth_type, l3_offset)?;

    let l4_info = match proto {
        IPPROTO_TCP => {
            let tcp = parse_tcp(ctx, l4_offset)?;
            L4Info::Tcp(tcp)
        }
        IPPROTO_UDP => {
            let udp = parse_udp(ctx, l4_offset)?;
            L4Info::Udp(udp)
        }
        IPPROTO_ICMP => {
            let icmp = parse_icmp(ctx, l4_offset)?;
            L4Info::Icmp(icmp)
        }
        _ => L4Info::Unknown,
    };

    Ok(PacketInfo {
        src_ip,
        dst_ip,
        proto,
        len: ctx.len() as u64,
        payload_len,
        l4_info,
    })
}
```

#### 2.2 實作協議特定解析函數

```rust
unsafe fn parse_tcp<C: PacketContext>(ctx: &C, offset: usize) -> Result<TcpInfo, ()> {
    let tcp_hdr: *const TcpHdr = ptr_at(ctx.data_start(), ctx.data_end(), offset)?;

    Ok(TcpInfo {
        src_port: u16::from_be_bytes((*tcp_hdr).source),
        dst_port: u16::from_be_bytes((*tcp_hdr).dest),
        flags: *ptr_at::<u8>(ctx.data_start(), ctx.data_end(), offset + 13)?,
        seq: u32::from_be_bytes((*tcp_hdr).seq),
        ack_seq: u32::from_be_bytes((*tcp_hdr).ack_seq),
        window: u16::from_be_bytes((*tcp_hdr).window),
        _padding: [0; 1],
    })
}

unsafe fn parse_udp<C: PacketContext>(ctx: &C, offset: usize) -> Result<UdpInfo, ()> {
    let udp_hdr: *const UdpHdr = ptr_at(ctx.data_start(), ctx.data_end(), offset)?;

    Ok(UdpInfo {
        src_port: u16::from_be_bytes((*udp_hdr).src),
        dst_port: u16::from_be_bytes((*udp_hdr).dst),
        _padding: [0; 4],
    })
}

unsafe fn parse_icmp<C: PacketContext>(ctx: &C, offset: usize) -> Result<IcmpInfo, ()> {
    let icmp_hdr: *const IcmpHdr = ptr_at(ctx.data_start(), ctx.data_end(), offset)?;

    let (icmp_id, icmp_seq) = if (*icmp_hdr).type_ == 8 || (*icmp_hdr).type_ == 0 {
        let id = ptr_at::<u16>(ctx.data_start(), ctx.data_end(), offset + 4)
            .map(|p| u16::from_be(*p))
            .unwrap_or(0);
        let seq = ptr_at::<u16>(ctx.data_start(), ctx.data_end(), offset + 6)
            .map(|p| u16::from_be(*p))
            .unwrap_or(0);
        (id, seq)
    } else {
        (0, 0)
    };

    Ok(IcmpInfo {
        icmp_type: (*icmp_hdr).type_,
        icmp_code: (*icmp_hdr).code,
        icmp_id,
        icmp_seq,
        _padding: [0; 2],
    })
}
```

---

### Phase 3：修改使用方（1.5 天）

#### 3.1 修改 `main.rs` - XDP/TC 主邏輯

**之前：**
```rust
unsafe fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let pkt: PacketInfo = parse_packet(&ctx)?;

    if pkt.flags == 0x0002 {
        return syn_cookie::send_syn_cookie(&ctx);
    } else if pkt.flags == 16 {
        let cookie = calculate_cookie(...);
    }

    if blocker::is_blocked(pkt.src_ip) {
        return Ok(xdp_action::XDP_DROP);
    }

    let params = SessionUpdateParams::from(&pkt);
    update_session(&params);
    collector::submit_event(&params);

    Ok(xdp_action::XDP_PASS)
}
```

**之後：**
```rust
unsafe fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let pkt: PacketInfo = parse_packet(&ctx)?;

    // TCP 特定處理
    if let L4Info::Tcp(tcp) = &pkt.l4_info {
        if tcp.flags == TCP_FLAG_SYN {
            return syn_cookie::send_syn_cookie(&ctx);
        } else if tcp.flags == TCP_FLAG_ACK {
            // 驗證 SYN Cookie
            let cookie = calculate_cookie(
                pkt.src_ip, pkt.dst_ip,
                tcp.src_port, tcp.dst_port,
                pkt.proto, tcp.seq - 1
            );

            if tcp.ack_seq != cookie + 1 {
                return Ok(xdp_action::XDP_DROP);  // Cookie 驗證失敗
            }
        }
    }

    // 通用處理
    if blocker::is_blocked(pkt.src_ip) {
        return Ok(xdp_action::XDP_DROP);
    }

    let params = SessionUpdateParams::from(&pkt);
    update_session(&params);
    collector::submit_event(&params);

    Ok(xdp_action::XDP_PASS)
}
```

#### 3.2 修改 `table.rs` - SessionUpdateParams

**之前：**
```rust
impl From<&PacketInfo> for SessionUpdateParams {
    fn from(packet: &PacketInfo) -> Self {
        SessionUpdateParams {
            src_ip: packet.src_ip,
            dst_ip: packet.dst_ip,
            src_port: packet.src_port,
            dst_port: packet.dst_port,
            proto: packet.proto,
            len: packet.len,
            payload_len: packet.payload_len,
            flag: packet.flags,
        }
    }
}
```

**之後：**
```rust
impl From<&PacketInfo> for SessionUpdateParams {
    fn from(packet: &PacketInfo) -> Self {
        let (src_port, dst_port, flag) = match &packet.l4_info {
            L4Info::Tcp(tcp) => (tcp.src_port, tcp.dst_port, tcp.flags),
            L4Info::Udp(udp) => (udp.src_port, udp.dst_port, 0),
            L4Info::Icmp(icmp) => (icmp.icmp_id, icmp.icmp_seq, 0),
            L4Info::Unknown => (0, 0, 0),
        };

        SessionUpdateParams {
            src_ip: packet.src_ip,
            dst_ip: packet.dst_ip,
            src_port,
            dst_port,
            proto: packet.proto,
            len: packet.len,
            payload_len: packet.payload_len,
            flag,
        }
    }
}
```

#### 3.3 修改 `collector.rs`

`collector.rs` 使用 `SessionUpdateParams`，不需要修改。

---

### Phase 4：測試與驗證（1 天）

#### 4.1 編譯測試
```bash
cd service/firewall
cargo xtask build-ebpf
cargo build
```

#### 4.2 功能測試

**測試案例：**
1. TCP 連線追蹤
2. UDP 流量記錄
3. ICMP ping 追蹤
4. SYN Cookie 驗證（新功能）
5. IP 阻擋

**測試指令：**
```bash
# 啟動防火牆
sudo IFACE=eth0 ./target/debug/firewall

# 測試 TCP
curl http://example.com

# 測試 UDP
dig @8.8.8.8 google.com

# 測試 ICMP
ping -c 3 8.8.8.8

# 測試 SYN Flood（需要專門工具）
hping3 -S --flood -p 80 target_ip
```

#### 4.3 效能測試

**測試指標：**
- 封包處理延遲
- CPU 使用率
- 記憶體使用

**基準測試工具：**
- `perf`
- `bpftool`

---

### Phase 5：文檔與合併（0.5 天）

#### 5.1 更新文檔
- [ ] 更新 README.md
- [ ] 更新程式碼註解
- [ ] 記錄 API 變更

#### 5.2 提交 PR
```bash
git add -A
git commit -m "refactor: redesign PacketInfo with enum-based L4Info

- Replace flat PacketInfo structure with enum-based design
- Add TcpInfo, UdpInfo, IcmpInfo structs for protocol-specific fields
- Implement SYN Cookie ACK validation
- Improve type safety and code readability

Breaking changes:
- PacketInfo structure changed
- parse_packet return type changed
- SessionUpdateParams::from implementation changed"

git push origin refactor/packetinfo-enum
```

#### 5.3 Code Review
- [ ] 自我審查
- [ ] 請求 review
- [ ] 處理 feedback

#### 5.4 合併到主分支
```bash
git checkout feat/ebpf-core-mvp
git merge refactor/packetinfo-enum
git push
```

---

## 風險評估

### 高風險項目

#### 風險 1：記憶體佈局變更

**風險描述：** Enum 的記憶體佈局可能與預期不同

**緩解措施：**
```rust
// 使用 repr(C) 和 repr(u8) 確保佈局可預測
#[repr(C)]
pub struct PacketInfo {
    // ...
    pub l4_info: L4Info,
}

#[repr(u8)]  // 使用 u8 作為 tag
pub enum L4Info {
    Tcp(TcpInfo) = 0,
    Udp(UdpInfo) = 1,
    Icmp(IcmpInfo) = 2,
    Unknown = 255,
}
```

**驗證方法：**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn test_memory_layout() {
        assert_eq!(mem::size_of::<PacketInfo>(), 40);
        assert_eq!(mem::align_of::<PacketInfo>(), 8);
        assert_eq!(mem::size_of::<L4Info>(), 16);
    }
}
```

---

#### 風險 2：效能影響

**風險描述：** Pattern matching 可能比直接欄位存取慢

**分析：**

```rust
// 當前（直接存取）
if pkt.flags == 0x02 {  // 1 次記憶體讀取
    // ...
}

// 新設計（pattern matching）
if let L4Info::Tcp(tcp) = &pkt.l4_info {  // 1 次 tag 檢查 + 1 次記憶體讀取
    if tcp.flags == TCP_FLAG_SYN {
        // ...
    }
}
```

**緩解措施：**
- 使用 `#[inline(always)]` 強制內聯
- Rust 編譯器會優化 pattern matching
- eBPF 驗證器會優化不必要的分支

**基準測試：**
```bash
# 測試前後的封包處理速率
perf stat -e cycles,instructions,cache-misses ./firewall
```

---

#### 風險 3：與現有資料結構不相容

**風險描述：** `firewall-common` 中已有 `L4Packet` enum，可能衝突

**當前狀況：**
```rust
// firewall-common/src/lib.rs
pub enum L4Packet {
    Tcp(TcpInfo),
    Udp(UdpInfo),
    Icmp(IcmpInfo),
    Unknown,
}
```

**解決方案：**

**選項 A：重用 firewall-common 的定義**
```rust
// firewall-ebpf/src/parser.rs
use firewall_common::L4Packet;

pub struct PacketInfo {
    // ...
    pub l4_info: L4Packet,  // 重用現有定義
}
```

優點：
- ✅ 減少重複
- ✅ 保持一致性

缺點：
- ❌ firewall-common 的 `TcpInfo` 缺少 `seq`、`ack_seq`
- ❌ 需要修改共享結構，影響用戶空間

**選項 B：使用不同的名稱**
```rust
// firewall-ebpf/src/parser.rs
pub enum L4Info {  // 不同名稱
    Tcp(TcpDetails),
    Udp(UdpDetails),
    Icmp(IcmpDetails),
    Unknown,
}
```

**建議：** 修改 firewall-common 的 `TcpInfo`，添加新欄位。

```rust
// firewall-common/src/lib.rs
pub struct TcpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: u8,
    pub header_len: u64,
    pub seq: u32,       // 新增
    pub ack_seq: u32,   // 新增
    pub window: u16,    // 新增
    pub padding: [u8; 1],
}
```

---

### 中風險項目

#### 風險 4：測試覆蓋不足

**緩解措施：**
- 編寫單元測試
- 手動功能測試
- 使用 fuzzing 測試邊界情況

---

## 替代方案

### 方案 A：繼續擴充當前結構（不推薦）

```rust
pub struct PacketInfo {
    // ... 現有欄位
    pub flags: u8,
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub seq: u32,      // 新增
    pub ack_seq: u32,  // 新增
}
```

**優點：**
- ✅ 修改量最小
- ✅ 無需重構

**缺點：**
- ❌ 記憶體浪費持續增加
- ❌ 語義混亂持續存在
- ❌ 缺乏型別安全
- ❌ 技術債累積

**結論：** 短期方便，長期痛苦。**不推薦。**

---

### 方案 B：使用 Union（不推薦）

```rust
pub struct PacketInfo {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub proto: u8,
    pub len: u64,
    pub payload_len: u64,
    pub l4_info: L4InfoUnion,
}

pub union L4InfoUnion {
    pub tcp: TcpInfo,
    pub udp: UdpInfo,
    pub icmp: IcmpInfo,
}
```

**優點：**
- ✅ 記憶體效率最高（與最大變體相同）

**缺點：**
- ❌ 所有操作都是 unsafe
- ❌ 沒有型別標記，無法知道當前是哪個協議
- ❌ 容易誤用

**結論：** 記憶體效率高但缺乏安全性。**不推薦。**

---

### 方案 C：Tagged Union（手動實作，不推薦）

```rust
pub struct PacketInfo {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub proto: u8,  // 當作 tag
    pub len: u64,
    pub payload_len: u64,
    pub l4_info: L4InfoUnion,  // union
}
```

**優點：**
- ✅ 記憶體效率較高

**缺點：**
- ❌ 需要手動維護 tag 和 union 的一致性
- ❌ 容易出錯
- ❌ Rust 的 enum 已經是優化過的 tagged union

**結論：** 重新發明輪子。**不推薦。**

---

## 決策建議

### ✅ 推薦方案：Enum-based 設計

**理由：**

1. **型別安全是首要考量** - eBPF 程式的錯誤很難 debug
2. **記憶體增加可接受** - 4 bytes (11%) 換取清晰性和安全性
3. **符合 Rust 慣例** - 充分利用型別系統
4. **易於維護和擴展** - 長期收益大於短期成本

### 實施建議

**時機選擇：**
- ✅ **建議：現在就做** - 專案還在早期，重構成本低
- ❌ 推遲會讓技術債累積，未來重構成本更高

**實施策略：**
1. 創建新分支進行重構
2. 保留舊結構作為備份
3. 分階段測試和驗證
4. 確保功能完全對等後再合併

**預期時間：**
- 總計：3.5 天
- 如果遇到問題，最多 5 天

**風險評估：**
- 整體風險：中等
- 可控性：高（可回滾）
- 長期收益：高

---

## 總結

### 核心觀點

> **"Pay the complexity cost once in the type system, rather than repeatedly in runtime checks and debugging."**
>
> 在型別系統中支付一次複雜性成本，而不是在運行時檢查和除錯中反覆支付。

### 最終建議

**強烈建議採用 Enum-based 設計重構 PacketInfo。**

這是一個經過深思熟慮的技術決策，不僅解決了當前的 SYN Cookie 需求，更為專案的長期健康發展奠定基礎。

---

**提案結束**

**下一步：**
- [ ] 團隊討論此提案
- [ ] 確認實施時間
- [ ] 分配開發資源
- [ ] 開始實施

如有任何問題或建議，歡迎討論！
