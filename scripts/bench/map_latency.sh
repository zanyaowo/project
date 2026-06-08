#!/usr/bin/env bash
#
# map_latency.sh — eBPF program / map-lookup latency (ns) (TASKS §8.A-4, Table 2).
#
# Uses `bpftool prog profile` to measure per-run cycles of the XDP firewall
# program (which contains the SCORE_TABLE / QUANTILE_BOUNDS lookups) while
# traffic flows, then converts cycles -> ns using the CPU base frequency.
#
# This is the headline systems number: the bucket policy decision cost in the
# kernel datapath, to contrast against userspace IF inference (ms, results_benchmark).
#
# Requires: root, bpftool with `prog profile` support (kernel >= 5.7, perf).
#           Firewall running so XDP prog is attached and traffic is flowing.
#
# Usage:
#   sudo ./scripts/bench/map_latency.sh [IFACE]
# Env: IFACE, DURATION, RESULTS_DIR.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${HERE}/lib.sh"

IFACE="${1:-$IFACE}"
require_root
require_cmd bpftool || exit 1
require_maps_loaded

# Resolve the XDP firewall prog id (name from firewall-ebpf: xdp_firewall).
PROG_ID="$(bpftool prog show 2>/dev/null | grep -iE 'xdp_firewall|xdp' | head -1 | grep -oE '^[0-9]+' || true)"
if [[ -z "${PROG_ID}" ]]; then
    c_red "ERROR: no XDP prog found. Is the firewall running (make run-firewall IFACE=${IFACE})?"
    exit 1
fi
section "map/prog latency: XDP prog id=${PROG_ID} (IFACE=${IFACE}, ${DURATION}s)"

# CPU base frequency (kHz) for cycles->ns. Fallback to /proc/cpuinfo MHz.
KHZ="$(cat /sys/devices/system/cpu/cpu0/cpufreq/base_frequency 2>/dev/null || true)"
if [[ -z "${KHZ}" ]]; then
    MHZ="$(awk '/cpu MHz/{print $4; exit}' /proc/cpuinfo 2>/dev/null || echo 0)"
    KHZ="$(awk -v m="${MHZ}" 'BEGIN{printf "%d", m*1000}')"
fi
GHZ="$(awk -v k="${KHZ}" 'BEGIN{printf "%.3f", k/1000000.0}')"
echo "  CPU base ≈ ${GHZ} GHz (cycles->ns conversion)"

# Drive traffic while profiling.
tgt="$(target_ip)"
if command -v hping3 >/dev/null 2>&1; then
    timeout "${DURATION}" hping3 --flood -S -p 80 "${tgt}" >/dev/null 2>&1 &
fi

# bpftool prog profile prints cycles + run_cnt over the profiling window.
PROF="$(timeout "$((DURATION+2))" bpftool prog profile id "${PROG_ID}" \
            duration "${DURATION}" cycles instructions 2>/dev/null || true)"
echo "${PROF}" | sed 's/^/    /'
wait 2>/dev/null || true

# Parse "<cycles> cycles" and "<runs> run_cnt" if present; else guide user.
CYC="$(echo "${PROF}" | grep -iE 'cycles' | grep -oE '[0-9,]+' | head -1 | tr -d ',')"
RUNS="$(bpftool prog show id "${PROG_ID}" 2>/dev/null | grep -oE 'run_cnt [0-9]+' | grep -oE '[0-9]+' || echo '')"
if [[ -n "${CYC}" && -n "${RUNS}" && "${RUNS}" -gt 0 ]]; then
    NS="$(awk -v c="${CYC}" -v r="${RUNS}" -v g="${GHZ}" 'BEGIN{printf "%.1f", (c/r)/g}')"
    echo "  per-invocation: ${CYC} cycles / ${RUNS} runs ÷ ${GHZ} GHz ≈ ${NS} ns"
    results_row "Map/prog lookup latency" "ebpf-bucket (XDP)" "${NS}" "ns" "bpftool prog profile, ${GHZ}GHz"
else
    c_ylw "  Could not auto-parse cycles/runs. Manual fallback:"
    echo  "    1) note 'run_cnt' before & after a fixed traffic burst:"
    echo  "         bpftool prog show id ${PROG_ID} | grep run_cnt"
    echo  "    2) 'run_time_ns' field (if BPF stats on) gives total ns:"
    echo  "         sysctl kernel.bpf_stats_enabled=1 ; then run_time_ns/run_cnt = ns/pkt"
    results_row "Map/prog lookup latency" "ebpf-bucket (XDP)" "see-log" "ns" "manual: run_time_ns/run_cnt"
fi

c_ylw "Tip: enable BPF runtime stats for a clean ns/pkt number:"
echo  "  sudo sysctl kernel.bpf_stats_enabled=1"
echo  "  # run traffic, then:"
echo  "  bpftool prog show id ${PROG_ID}   # divide run_time_ns / run_cnt"
