#!/usr/bin/env bash
#
# validate_runtime.sh — on-hardware runtime validation for the eBPF firewall.
#
# Prerequisite: the firewall must already be running in another terminal
#   (e.g. `make run-firewall IFACE=<iface>`), so the BPF maps are loaded and
#   the XDP/TC programs are attached. This script inspects those live maps and
#   drives traffic against them; it does NOT start the firewall itself.
#
# Requires: root (sudo), bpftool, and for traffic generation `hping3`/`ping`.
# Maps (names from firewall-ebpf): SCORE_TABLE, QUANTILE_BOUNDS, BOUNDARY_META,
#   BLOCK_LIST, SESSIONS, PKT_DROPS.
#
# Usage:
#   sudo ./scripts/validate_runtime.sh load                    # P0: attach + maps loaded
#   sudo ./scripts/validate_runtime.sh packets [IFACE]         # P1: traffic -> SCORE_TABLE/SESSIONS
#   sudo ./scripts/validate_runtime.sh boundary [IFACE]        # P1: flood -> AttackFreeze/version
#   sudo ./scripts/validate_runtime.sh blocklist IFACE IP      # BLOCK_LIST -> DROP
#
# Env overrides: IFACE (default wlp3s0).
set -euo pipefail

IFACE="${IFACE:-wlp3s0}"

c_red()   { printf '\033[31m%s\033[0m\n' "$*"; }
c_grn()   { printf '\033[32m%s\033[0m\n' "$*"; }
c_ylw()   { printf '\033[33m%s\033[0m\n' "$*"; }
hr()      { printf '%s\n' "------------------------------------------------------------"; }
section() { hr; c_ylw "## $*"; hr; }

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        c_red "ERROR: must run as root (sudo). bpftool + traffic generation need it."
        exit 1
    fi
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        c_red "ERROR: '$1' not found. ${2:-Install it and retry.}"
        exit 1
    fi
}

map_loaded() {
    # Direct name lookup; grepping the full `map show` listing proved flaky
    # (BLOCK_LIST/SESSIONS reported missing while demonstrably loaded).
    bpftool map show name "$1" >/dev/null 2>&1
}

require_maps_loaded() {
    if ! map_loaded SCORE_TABLE; then
        c_red "ERROR: SCORE_TABLE map not loaded."
        c_red "       Start the firewall first:  make run-firewall IFACE=${IFACE}"
        exit 1
    fi
}

dump_map() {
    local name="$1"
    printf 'map %s:\n' "${name}"
    if map_loaded "${name}"; then
        sudo bpftool map dump name "${name}" 2>/dev/null || echo "  (dump failed)"
    else
        echo "  (not loaded)"
    fi
}

# BoundaryMeta = { version:u32, active:u32, expiry_ns:u64 } little-endian.
# Array map value bytes come from `bpftool -j map dump`. The first 4 value
# bytes are `version` in LE order; recombine them big-endian for $((...)).
boundary_version() {
    local b0 b1 b2 b3
    read -r b0 b1 b2 b3 _ < <(sudo bpftool -j map dump name BOUNDARY_META 2>/dev/null \
        | grep -oE '"value":\[[^]]*\]' | head -1 \
        | grep -oE '0x[0-9a-fA-F]+' | sed 's/0x//' | tr '\n' ' ')
    if [[ -z "${b0:-}" ]]; then echo "?"; return; fi
    printf '%d\n' "$(( 0x${b3:-00}${b2:-00}${b1:-00}${b0:-00} ))" 2>/dev/null || echo "?"
}

# ---------------------------------------------------------------------------
cmd_load() {
    section "P0 — attach + maps loaded (IFACE=${IFACE})"

    echo "[XDP] ip link show ${IFACE}:"
    if ip link show "${IFACE}" 2>/dev/null | grep -q xdp; then
        c_grn "  PASS: XDP program attached to ${IFACE}"
    else
        c_red  "  FAIL: no xdp marker on ${IFACE} (is the firewall running?)"
    fi

    # aya 0.13 attaches the classifier as a TCX link on kernels >= 6.6, which
    # is invisible to legacy `tc filter show`; check `bpftool net show` first
    # and keep the legacy filter check as fallback for older kernels.
    echo "[TC]  egress program on ${IFACE} (tcx via bpftool net / legacy tc filter):"
    if bpftool net show dev "${IFACE}" 2>/dev/null | grep -q 'tcx/egress'; then
        c_grn "  PASS: TCX egress program attached"
        bpftool net show dev "${IFACE}" 2>/dev/null | grep 'tcx/egress' | sed 's/^/    /'
    elif tc filter show dev "${IFACE}" egress 2>/dev/null | grep -q .; then
        c_grn "  PASS: TC egress filter present (legacy netlink)"
        tc filter show dev "${IFACE}" egress 2>/dev/null | sed 's/^/    /'
    else
        c_red  "  FAIL: no TC egress program on ${IFACE}"
    fi

    echo "[MAPS] expected maps:"
    local m ok=1
    for m in SCORE_TABLE QUANTILE_BOUNDS BOUNDARY_META BLOCK_LIST SESSIONS; do
        if map_loaded "${m}"; then
            c_grn "  PASS: ${m} loaded"
        else
            c_red "  FAIL: ${m} not loaded"; ok=0
        fi
    done

    echo "[SCORE_TABLE] expect 32 i32 entries:"
    local n
    n="$(sudo bpftool map dump name SCORE_TABLE 2>/dev/null | grep -c 'value' || true)"
    echo "  entries dumped: ${n:-0} (expected 32)"

    echo "[QUANTILE_BOUNDS] expect 10 entries (5 features x 2 banks):"
    n="$(sudo bpftool map dump name QUANTILE_BOUNDS 2>/dev/null | grep -c 'value' || true)"
    echo "  entries dumped: ${n:-0} (expected 10)"

    [[ "${ok}" -eq 1 ]] && c_grn "load: all expected maps present" || c_red "load: some maps missing"
}

# ---------------------------------------------------------------------------
cmd_packets() {
    IFACE="${1:-$IFACE}"
    section "P1 — packet flow -> SCORE_TABLE / SESSIONS (IFACE=${IFACE})"
    require_maps_loaded

    echo "BEFORE:"
    local before
    before="$(sudo bpftool map dump name SESSIONS 2>/dev/null | grep -c 'key' || true)"
    echo "  SESSIONS entries: ${before:-0}"

    local target
    target="$(ip -4 addr show "${IFACE}" 2>/dev/null | grep -oE 'inet [0-9.]+' | awk '{print $2}' | head -1)"
    if [[ -z "${target}" ]]; then
        c_ylw "  no IPv4 on ${IFACE}; using loopback 127.0.0.1 for traffic"
        target="127.0.0.1"
    fi
    echo "Generating traffic toward ${target} ..."
    if command -v hping3 >/dev/null 2>&1; then
        hping3 -c 20 -S -p 80 "${target}" >/dev/null 2>&1 || true
    fi
    ping -c 5 -W 1 "${target}" >/dev/null 2>&1 || true
    sleep 1

    echo "AFTER:"
    local after
    after="$(sudo bpftool map dump name SESSIONS 2>/dev/null | grep -c 'key' || true)"
    echo "  SESSIONS entries: ${after:-0}"
    if [[ "${after:-0}" -gt "${before:-0}" ]]; then
        c_grn "  PASS: SESSIONS grew (${before:-0} -> ${after:-0})"
    else
        c_ylw "  NOTE: SESSIONS did not grow; may need traffic on a non-loopback iface"
    fi

    echo
    dump_map SCORE_TABLE
    echo
    echo "PKT_DROPS (per-CPU packet-drop counter):"
    dump_map PKT_DROPS
}

# ---------------------------------------------------------------------------
cmd_boundary() {
    IFACE="${1:-$IFACE}"
    section "P1 — adaptive boundary: Normal -> AttackFreeze (IFACE=${IFACE})"
    require_maps_loaded

    echo "BOUNDARY_META before:"
    dump_map BOUNDARY_META
    local v0
    v0="$(boundary_version)"
    echo "  decoded version: ${v0}"

    local target
    target="$(ip -4 addr show "${IFACE}" 2>/dev/null | grep -oE 'inet [0-9.]+' | awk '{print $2}' | head -1)"
    target="${target:-127.0.0.1}"

    if command -v hping3 >/dev/null 2>&1; then
        echo "Sending SYN flood toward ${target} (3s) to drive high-risk traffic ..."
        timeout 3 hping3 --flood -S -p 80 "${target}" >/dev/null 2>&1 || true
    else
        c_ylw "  hping3 not installed; cannot generate flood. Install hping3 to exercise AttackFreeze."
    fi
    sleep 2

    echo "BOUNDARY_META after:"
    dump_map BOUNDARY_META
    local v1
    v1="$(boundary_version)"
    echo "  decoded version: ${v1}"

    c_ylw "Expected behaviour:"
    echo "  - Under flood, the firewall log should print 'boundary_updater: AttackFreeze'"
    echo "    and BOUNDARY_META.version should STOP advancing (frozen reference)."
    echo "  - Under benign traffic, version increments as calibration runs."
    echo "  Watch the firewall terminal for the GateState transition log line."
}

# ---------------------------------------------------------------------------
cmd_blocklist() {
    IFACE="${1:?usage: blocklist IFACE IP}"
    local ip="${2:?usage: blocklist IFACE IP}"
    section "BLOCK_LIST -> DROP (IFACE=${IFACE}, IP=${ip})"
    require_maps_loaded
    require_cmd hping3 "Needed to send probe packets from the blocked IP path."

    # Build IPv4-mapped key: 00 x10? no — 10 zero bytes, ff ff, then 4 IPv4 octets.
    IFS='.' read -r o1 o2 o3 o4 <<< "${ip}"
    if [[ -z "${o4:-}" ]]; then
        c_red "ERROR: IP must be dotted IPv4 (e.g. 1.2.3.4)"; exit 1
    fi
    local key
    key=$(printf '00 00 00 00 00 00 00 00 00 00 ff ff %02x %02x %02x %02x' \
        "${o1}" "${o2}" "${o3}" "${o4}")
    echo "IPv4-mapped 16-byte key: ${key}"

    echo "Writing BLOCK_LIST[${ip}] = 1 via bpftool ..."
    sudo bpftool map update name BLOCK_LIST key hex ${key} value hex 01 00 00 00
    c_grn "  written. dump:"
    sudo bpftool map dump name BLOCK_LIST 2>/dev/null | sed 's/^/    /'

    local dst
    dst="$(ip -4 addr show "${IFACE}" 2>/dev/null | grep -oE 'inet [0-9.]+' | awk '{print $2}' | head -1)"
    dst="${dst:-127.0.0.1}"

    local drops_before drops_after
    drops_before="$(sudo bpftool map dump name PKT_DROPS 2>/dev/null | grep -oE '0x[0-9a-fA-F]+' | head -1 || echo 0x0)"
    echo "Sending probe packets spoofed-from ${ip} toward ${dst} (should be XDP_DROP) ..."
    timeout 3 hping3 -c 10 -a "${ip}" -S -p 80 "${dst}" >/dev/null 2>&1 || true
    sleep 1
    drops_after="$(sudo bpftool map dump name PKT_DROPS 2>/dev/null | grep -oE '0x[0-9a-fA-F]+' | head -1 || echo 0x0)"
    echo "  PKT_DROPS[0]: ${drops_before} -> ${drops_after}"

    c_ylw "Cleanup: removing BLOCK_LIST entry ..."
    sudo bpftool map delete name BLOCK_LIST key hex ${key} 2>/dev/null \
        && c_grn "  entry removed" || c_ylw "  (entry already gone)"

    c_ylw "Expected: packets from ${ip} get XDP_DROP; PKT_DROPS increments."
    echo "  Note: hping3 spoofed-source probes are best run from a second host;"
    echo "  on a single box, confirm DROP via 'bpftool prog tracelog' or metrics."
}

# ---------------------------------------------------------------------------
main() {
    require_root
    require_cmd bpftool "Install with: apt install bpftool / pacman -S bpf"
    local sub="${1:-}"
    shift || true
    case "${sub}" in
        load)      cmd_load "$@" ;;
        packets)   cmd_packets "$@" ;;
        boundary)  cmd_boundary "$@" ;;
        blocklist) cmd_blocklist "$@" ;;
        *)
            c_red "Unknown subcommand: '${sub}'"
            echo "Usage: $0 {load|packets|boundary|blocklist} [args]"
            echo "  load                    P0: XDP/TC attached + maps loaded"
            echo "  packets [IFACE]         P1: drive traffic -> SCORE_TABLE/SESSIONS"
            echo "  boundary [IFACE]        P1: flood -> AttackFreeze / version freeze"
            echo "  blocklist IFACE IP      write BLOCK_LIST key -> confirm DROP"
            exit 1
            ;;
    esac
}

main "$@"
