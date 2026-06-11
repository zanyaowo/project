use core::mem::size_of;
use firewall_common::constants::{
    ETH_IPV4, ETH_IPV6, IPPROTO_ICMP, IPPROTO_ICMP_V6, IPPROTO_TCP, IPPROTO_UDP,
};
use firewall_common::protocol::{IcmpInfo, L4Info, TcpInfo, UdpInfo};
use network_types::eth::EthHdr;
use network_types::icmp::IcmpHdr;
use network_types::ip::{IpProto, Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

// Small L3 metadata returned by parse_ipv4 / parse_ipv6. The 16-byte src/dst
// addresses, `is_ipv6` and `len` are *not* carried here: they are written
// straight into the caller-provided `&mut PacketInfo` by parse_ipv4/parse_ipv6.
// Keeping the two [u8; 16] addresses out of this struct (and out of a separate
// PacketInfo literal) removes ~120 B from parse_packet's BPF stack frame — the
// xdp_firewall(288) → parse_packet path otherwise sums to 640 > the 512-byte
// combined-stack limit ("combined stack size of 2 calls is 640. Too large").
struct L3Meta {
    proto: u8,
    ip_header_len: usize,
    l4_offset: usize,
}

#[derive(Default)]
pub struct PacketInfo {
    // 16-byte IPv6 form; IPv4 packets are stored IPv4-mapped (::ffff:a.b.c.d).
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub proto: u8,
    /// True for native IPv6 packets. Used to gate IPv4-only fast paths
    /// (e.g. the SYN-cookie XDP_TX, which rewrites an IPv4 header).
    pub is_ipv6: bool,
    pub len: u16,
    pub payload_len: u64,
    pub l4_info: L4Info,
    pub padding: [u8; 5],
}

// Packet bounds (`start` / `end`) are passed as plain `usize` rather than
// behind a `PacketContext` trait + `&C` argument. Going through a trait method
// that returns `usize` (e.g. aya's `XdpContext::data_end()` = `(*ctx).data_end
// as usize`) inside a non-inlined subprogram makes LLVM re-truncate the
// arg-promoted 64-bit packet pointer (`pkt_end as u32 as usize` → `pkt_end <<
// 32`), which the verifier rejects ("pointer arithmetic on pkt_end
// prohibited"). The caller reads `data()` / `data_end()` once in the inlined
// entry frame; here we only *compare* against `end`, never reconstruct it.

/// Returns a raw pointer to `T` at `start + offset` after bounds-checking against `end`.
///
/// # Safety
/// The caller must only dereference the returned pointer while the underlying packet buffer
/// is still live. The caller is also responsible for ensuring that the memory at the
/// computed address is a valid, initialized `T`.
#[inline(always)]
unsafe fn ptr_at<T>(start: usize, end: usize, offset: usize) -> Result<*const T, ()> {
    let len = size_of::<T>();

    if start.wrapping_add(offset).wrapping_add(len) > end {
        return Err(());
    }

    Ok(start.wrapping_add(offset) as *const T)
}

/// Write the IPv4-mapped form (`::ffff:a.b.c.d`) of `addr` into `dst` using
/// explicit scalar stores instead of `*dst = ipv4_mapped(addr)`.
///
/// The array assignment materialises a [u8; 16] whose 10-byte zero prefix LLVM
/// lowers to a memset() *call* (bpf-linker emits memset as a real BPF-to-BPF
/// function). That callee never writes R0 before `exit`, so when LLVM keeps a
/// live value in R0 across the call the verifier rejects the program with
/// "R0 !read_ok" (hit on load, 2026-06-11). A u64 store plus individual byte
/// stores cannot be turned into a libcall.
#[inline(always)]
fn set_ipv4_mapped(dst: &mut [u8; 16], addr: [u8; 4]) {
    // SAFETY: `dst` is a valid `&mut [u8; 16]`; the 8-byte store lies within it.
    // BPF allows unaligned access, and byte order is irrelevant for zeroes.
    unsafe {
        core::ptr::write_unaligned(dst.as_mut_ptr().cast::<u64>(), 0u64);
    }
    dst[8] = 0;
    dst[9] = 0;
    dst[10] = 0xff;
    dst[11] = 0xff;
    dst[12] = addr[0];
    dst[13] = addr[1];
    dst[14] = addr[2];
    dst[15] = addr[3];
}

/// 16-byte copy as two u64 load/store pairs. Same rationale as
/// `set_ipv4_mapped`: a plain `[u8; 16]` assignment is at LLVM's mercy to
/// become a memcpy() libcall, and bpf-linker's memcpy has the same
/// R0-never-written hazard as its memset.
#[inline(always)]
fn copy_ip16(dst: &mut [u8; 16], src: &[u8; 16]) {
    // SAFETY: both are valid 16-byte buffers; BPF allows unaligned access.
    // Native-endian read + native-endian write preserves byte order.
    unsafe {
        let s = src.as_ptr();
        let d = dst.as_mut_ptr();
        let lo = core::ptr::read_unaligned(s.cast::<u64>());
        let hi = core::ptr::read_unaligned(s.add(8).cast::<u64>());
        core::ptr::write_unaligned(d.cast::<u64>(), lo);
        core::ptr::write_unaligned(d.add(8).cast::<u64>(), hi);
    }
}

pub fn parse_eth(start: usize, end: usize) -> Result<(u16, usize), ()> {
    // SAFETY: `ptr_at` verifies that [0, size_of::<EthHdr>()) lies within
    // [start, end). `EthHdr` is `#[repr(C, packed)]`, so unaligned reads
    // are valid and all field accesses are safe once bounds are confirmed.
    unsafe {
        let eth_hdr: *const EthHdr = ptr_at(start, end, 0)?;
        let eth_type = u16::from_be((*eth_hdr).ether_type);
        Ok((eth_type, size_of::<EthHdr>()))
    }
}

fn parse_ipv4(start: usize, end: usize, offset: usize, out: &mut PacketInfo) -> Result<L3Meta, ()> {
    // SAFETY: `ptr_at` verifies that [offset, offset + size_of::<Ipv4Hdr>()) lies within
    // [start, end). `Ipv4Hdr` is `#[repr(C, packed)]`, allowing unaligned reads.
    // The header is copied out by value (`*ptr`) so all field reads — and the
    // ipv4_mapped() address construction — operate on stack scalars. Reading
    // fields through the live packet pointer instead keeps that pointer alive
    // into the PacketInfo build, where the verifier rejects spilling a packet
    // pointer into a sub-8-byte field ("invalid size of register spill").
    //
    // The 16-byte addresses, `is_ipv6` and `len` are written straight into `*out`
    // rather than returned: the by-value copy above already kills the packet
    // pointer's liveness, so these stores are plain stack writes, and keeping the
    // two [u8; 16] arrays out of a returned struct keeps parse_packet's frame small.
    unsafe {
        let ipv4_hdr: Ipv4Hdr = *ptr_at::<Ipv4Hdr>(start, end, offset)?;
        let proto = match ipv4_hdr.proto {
            IpProto::Tcp => IPPROTO_TCP,
            IpProto::Udp => IPPROTO_UDP,
            IpProto::Icmp => IPPROTO_ICMP,
            _ => 0,
        };
        set_ipv4_mapped(&mut out.src_ip, ipv4_hdr.src_addr);
        set_ipv4_mapped(&mut out.dst_ip, ipv4_hdr.dst_addr);
        out.is_ipv6 = false;
        out.len = u16::from_be_bytes(ipv4_hdr.tot_len);
        Ok(L3Meta {
            proto,
            ip_header_len: ((ipv4_hdr.vihl & 0x0F) as usize) * 4,
            l4_offset: offset + size_of::<Ipv4Hdr>(),
        })
    }
}

fn parse_ipv6(start: usize, end: usize, offset: usize, out: &mut PacketInfo) -> Result<L3Meta, ()> {
    // SAFETY: `ptr_at` verifies that [offset, offset + size_of::<Ipv6Hdr>()) lies within
    // [start, end). `Ipv6Hdr` is `#[repr(C, packed)]`, allowing unaligned reads.
    // The header is copied out by value (`*ptr`) before any field is read, for the same
    // reason as parse_ipv4: reading the 16-byte src/dst addresses through the live packet
    // pointer keeps it alive into the PacketInfo build, where spilling a packet pointer
    // into a sub-8-byte field is rejected ("invalid size of register spill"). Copying
    // first materialises the addresses as stack scalars; they (and `is_ipv6` / `len`)
    // are then written straight into `*out` to keep parse_packet's frame small.
    unsafe {
        let hdr: Ipv6Hdr = *ptr_at::<Ipv6Hdr>(start, end, offset)?;
        // next_hdr is the protocol number (IpProto is repr(u8)). Extension headers
        // are not followed; unknown next_hdr falls through to L4Info::Unknown.
        let proto = match hdr.next_hdr as u8 {
            IPPROTO_TCP => IPPROTO_TCP,
            IPPROTO_UDP => IPPROTO_UDP,
            IPPROTO_ICMP_V6 => IPPROTO_ICMP_V6,
            _ => 0,
        };
        // IPv6 payload_len excludes the 40-byte header; add it back so `len`
        // stays comparable to IPv4 tot_len downstream.
        copy_ip16(&mut out.src_ip, &hdr.src_addr);
        copy_ip16(&mut out.dst_ip, &hdr.dst_addr);
        out.is_ipv6 = true;
        out.len = u16::from_be_bytes(hdr.payload_len).saturating_add(size_of::<Ipv6Hdr>() as u16);
        Ok(L3Meta {
            proto,
            ip_header_len: size_of::<Ipv6Hdr>(),
            l4_offset: offset + size_of::<Ipv6Hdr>(),
        })
    }
}

pub fn parse_tcp(start: usize, end: usize, offset: usize) -> Result<TcpInfo, ()> {
    // SAFETY:
    // - `ptr_at` for `tcp_hdr` verifies [offset, offset + size_of::<TcpHdr>()) is in bounds.
    //   All field accesses (source, dest, seq, ack_seq, window) are within TcpHdr (20 bytes).
    // - `ptr_at` at offset+12 (data-offset byte) and offset+13 (flags byte) are re-checked
    //   individually because the eBPF verifier does not reason about struct sizes and requires
    //   an explicit bounds check before every pointer dereference.
    // - `TcpHdr` is `#[repr(C, packed)]`, so all field reads are unaligned-safe.
    unsafe {
        let tcp_hdr: *const TcpHdr = ptr_at(start, end, offset)?;
        let src_port = u16::from_be_bytes((*tcp_hdr).source);
        let dst_port = u16::from_be_bytes((*tcp_hdr).dest);
        let seq = u32::from_be_bytes((*tcp_hdr).seq);
        let ack_seq = u32::from_be_bytes((*tcp_hdr).ack_seq);
        let windows = u16::from_be_bytes((*tcp_hdr).window);

        let flag_ptr: *const u8 = ptr_at(start, end, offset + 13)?;
        let flags: u8 = *flag_ptr;

        let offset_byte: u8 = *ptr_at(start, end, offset + 12)?;
        let data_offset = (offset_byte & 0xF0) >> 4;
        let header_len = (data_offset * 4) as u8;

        Ok(TcpInfo {
            src_port,
            dst_port,
            flags,
            seq,
            ack_seq,
            windows,
            header_len,
        })
    }
}

pub fn parse_udp(start: usize, end: usize, offset: usize) -> Result<UdpInfo, ()> {
    // SAFETY: `ptr_at` verifies that [offset, offset + size_of::<UdpHdr>()) lies within
    // [start, end). `UdpHdr` is `#[repr(C, packed)]`, allowing unaligned reads.
    unsafe {
        let udp_hdr: *const UdpHdr = ptr_at(start, end, offset)?;
        let src_port = u16::from_be_bytes((*udp_hdr).src);
        let dst_port = u16::from_be_bytes((*udp_hdr).dst);
        let header_len = size_of::<UdpHdr>() as u8;

        Ok(UdpInfo {
            src_port,
            dst_port,
            header_len,
            padding: [0; 3],
        })
    }
}

pub fn parse_icmp(start: usize, end: usize, offset: usize) -> Result<IcmpInfo, ()> {
    // SAFETY: `ptr_at` verifies that [offset, offset + size_of::<IcmpHdr>()) is in bounds.
    // For echo request (type 8) and echo reply (type 0), additional `ptr_at` calls verify
    // offset+4 (identifier) and offset+6 (sequence number) individually, as required by the
    // eBPF verifier. Failures on those optional fields are silently ignored; the packet is
    // still considered valid with id/seq defaulting to 0.
    // `IcmpHdr` is `#[repr(C, packed)]`, so all field reads are unaligned-safe.
    unsafe {
        let icmp_hdr: *const IcmpHdr = ptr_at(start, end, offset)?;
        let icmp_type = (*icmp_hdr).type_;
        let icmp_code = (*icmp_hdr).code;
        let mut icmp_id = 0u16;
        let mut icmp_seq = 0u16;

        if icmp_type == 8 || icmp_type == 0 {
            if let Ok(id_ptr) = ptr_at::<u16>(start, end, offset + 4) {
                icmp_id = u16::from_be(*id_ptr);
            }
            if let Ok(seq_ptr) = ptr_at::<u16>(start, end, offset + 6) {
                icmp_seq = u16::from_be(*seq_ptr);
            }
        }

        Ok(IcmpInfo {
            icmp_type,
            icmp_code,
            icmp_id,
            icmp_seq,
            header_len: 8,
            padding: [0; 1],
        })
    }
}

// `#[inline(never)]` keeps the header-copy temporaries (a full Ipv4Hdr/Ipv6Hdr
// copied by value, plus PacketInfo construction) inside this function's own
// BPF stack frame instead of folding them into the xdp_firewall entry frame,
// which would overflow the 512-byte per-subprogram stack limit at opt-level=3.
// The out-param + bool return (rather than Result<PacketInfo, ()>) avoids
// bpf-linker's "aggregate returns are not supported" rejection for non-inlined
// fns — the same pattern used by update_session / score_session.
//
// `start` / `end` (packet bounds) and `total_len` are all passed in rather than
// derived from a context here: deriving them via trait/aya accessors inside this
// non-inlined subprogram makes LLVM re-truncate the arg-promoted packet pointers
// (`pkt_end << 32`), which the verifier rejects. The caller reads them once in
// the inlined entry frame. `total_len` differs from `end - start` for TC (skb
// length), so it is computed by the caller, not here.
#[inline(never)]
pub fn parse_packet(start: usize, end: usize, total_len: u64, out: &mut PacketInfo) -> bool {
    let (eth_type, l3_offset) = match parse_eth(start, end) {
        Ok(v) => v,
        Err(_) => return false,
    };

    // parse_ipv4 / parse_ipv6 write src_ip, dst_ip, is_ipv6 and len directly into
    // `*out`; only the small scalars needed for the L4 offset come back here.
    let l3 = match eth_type {
        ETH_IPV4 => parse_ipv4(start, end, l3_offset, out),
        ETH_IPV6 => parse_ipv6(start, end, l3_offset, out),
        _ => return false,
    };
    let L3Meta {
        proto,
        ip_header_len,
        l4_offset,
    } = match l3 {
        Ok(v) => v,
        Err(_) => return false,
    };

    // Each arm writes `out.l4_info` directly instead of materialising an
    // `L4Info` local and copying it into `*out` afterwards. The whole-enum
    // copy includes the variant payload bytes, which are *uninitialized*
    // (poison) for `Unknown` — LLVM is free to "fill" them from any live
    // register, and it picked the `out` pointer itself, which the verifier
    // rejects when stored sub-8-byte into stack memory ("invalid size of
    // register spill", IPv6 unknown-next_hdr path, 2026-06-11). The Unknown
    // arm therefore writes nothing at all: callers pass a fresh
    // `PacketInfo::default()`, whose `l4_info` already is `L4Info::Unknown`.
    let l4_header_len = match proto {
        IPPROTO_TCP => match parse_tcp(start, end, l4_offset) {
            Ok(tcp) => {
                let hl = tcp.header_len as usize;
                out.l4_info = L4Info::Tcp(tcp);
                hl
            }
            Err(_) => return false,
        },
        IPPROTO_UDP => match parse_udp(start, end, l4_offset) {
            Ok(udp) => {
                let hl = udp.header_len as usize;
                out.l4_info = L4Info::Udp(udp);
                hl
            }
            Err(_) => return false,
        },
        IPPROTO_ICMP | IPPROTO_ICMP_V6 => match parse_icmp(start, end, l4_offset) {
            Ok(icmp) => {
                let hl = icmp.header_len as usize;
                out.l4_info = L4Info::Icmp(icmp);
                hl
            }
            Err(_) => return false,
        },
        _ => 0,
    };

    let header_len = (l3_offset + ip_header_len + l4_header_len) as u64;

    let payload_len = if total_len > header_len {
        total_len - header_len
    } else {
        0
    };

    // src_ip / dst_ip / is_ipv6 / len were written by parse_ipv4/parse_ipv6 and
    // l4_info by the match above. Write the rest directly into `*out` rather than
    // building a full PacketInfo literal on the stack (the literal was a ~64 B
    // temporary that, on top of the L3 addresses, pushed parse_packet's frame over
    // the 512-byte combined limit). `padding` is not touched: the caller's
    // PacketInfo::default() already zeroed it, and writing `[0; 5]` here emitted
    // one more memset() libcall (R0-hazard-prone, see set_ipv4_mapped).
    out.proto = proto;
    out.payload_len = payload_len;

    true
}
