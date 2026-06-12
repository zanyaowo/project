#!/usr/bin/env bash
#
# lib.sh — shared helpers for the eBPF firewall benchmark harness (Table 2 / E4).
#
# Sourced by setup_testbed.sh / throughput.sh / map_latency.sh /
# mitigation_latency.sh. Mirrors the conventions of scripts/validate_runtime.sh
# (colored output, root + cmd checks, BPF map helpers, IFACE env override).
#
# All measurement scripts append a row to ${RESULTS_DIR}/table2.md so the paper
# Table 2 (System Overhead) can be filled by copy-paste.
#
# Env overrides: IFACE (default wlp3s0), RESULTS_DIR (default ./bench_results),
#   DURATION (seconds per measurement, default 10).

set -euo pipefail

IFACE="${IFACE:-wlp3s0}"
RESULTS_DIR="${RESULTS_DIR:-bench_results}"
DURATION="${DURATION:-10}"

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
        return 1
    fi
}

map_loaded() { bpftool map show 2>/dev/null | grep -q "name $1"; }

require_maps_loaded() {
    if ! map_loaded SCORE_TABLE; then
        c_red "ERROR: SCORE_TABLE map not loaded."
        c_red "       Start the firewall first:  make run-firewall IFACE=${IFACE}"
        exit 1
    fi
}

results_init() {
    mkdir -p "${RESULTS_DIR}"
    local f="${RESULTS_DIR}/table2.md"
    if [[ ! -f "${f}" ]]; then
        {
            echo "# Table 2 — System Overhead (on-hardware, CIC-DDoS2019 scope)"
            echo ""
            echo "> 機器：$(uname -srm)  | IFACE=${IFACE}  | $(date -Iseconds)"
            echo "> 每列由 scripts/bench/*.sh 產生；kernel ns 為 eBPF 路徑，µs/ms 為 userspace 對照。"
            echo ""
            echo "| 指標 | 方法 / 對照組 | 數值 | 單位 | 備註 |"
            echo "|------|---------------|------|------|------|"
        } > "${f}"
    fi
}

# results_row "<metric>" "<group>" "<value>" "<unit>" "<note>"
results_row() {
    results_init
    printf '| %s | %s | %s | %s | %s |\n' "$1" "$2" "$3" "$4" "${5:-}" \
        >> "${RESULTS_DIR}/table2.md"
    c_grn "  recorded -> ${RESULTS_DIR}/table2.md : $1 / $2 = $3 $4"
}

# Sum RX+TX packets on IFACE from /sys (portable, no extra deps).
iface_packets() {
    local rx tx
    rx="$(cat "/sys/class/net/${IFACE}/statistics/rx_packets" 2>/dev/null || echo 0)"
    tx="$(cat "/sys/class/net/${IFACE}/statistics/tx_packets" 2>/dev/null || echo 0)"
    echo $(( rx + tx ))
}

# Sum of the per-CPU PKT_DROPS counter. PKT_DROPS counts actual XDP_DROP /
# TC_ACT_SHOT decisions; DROP_EVENTS counts ring-buffer event loss and must NOT
# be used as a packet-drop signal.
#
# bpftool prints each CPU's u64 as 8 space-separated little-endian hex bytes:
#   value (CPU 00): 87 5c 0c 00 00 00 00 00
# so we reassemble byte0 + byte1<<8 + ... per line and sum across CPUs.
drop_events_total() {
    if ! map_loaded PKT_DROPS; then echo 0; return; fi
    sudo bpftool map dump name PKT_DROPS 2>/dev/null | awk '
        /value.*CPU/ {
            v = 0
            for (i = 0; i < 8; i++) v += strtonum("0x" $(NF-7+i)) * (2 ^ (8 * i))
            sum += v
        }
        END { printf "%d\n", sum }'
}

# IPv4-mapped 16-byte BLOCK_LIST key (same layout as validate_runtime.sh).
blocklist_key() {
    local o1 o2 o3 o4
    IFS='.' read -r o1 o2 o3 o4 <<< "$1"
    printf '00 00 00 00 00 00 00 00 00 00 ff ff %02x %02x %02x %02x' \
        "${o1}" "${o2}" "${o3}" "${o4}"
}

seed_blocklist() {
    bpftool map update name BLOCK_LIST key hex $(blocklist_key "$1") value hex 01 00 00 00
}

unseed_blocklist() {
    bpftool map delete name BLOCK_LIST key hex $(blocklist_key "$1") 2>/dev/null || true
}

# Pick a traffic target IP on IFACE, fall back to loopback.
target_ip() {
    local t
    t="$(ip -4 addr show "${IFACE}" 2>/dev/null \
            | grep -oE 'inet [0-9.]+' | awk '{print $2}' | head -1)"
    echo "${t:-127.0.0.1}"
}
