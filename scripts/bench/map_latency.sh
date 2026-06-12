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
# Keep stderr: when profile is unsupported (no fentry/perf) we want to see why.
PROF="$(timeout "$((DURATION+2))" bpftool prog profile id "${PROG_ID}" \
            duration "${DURATION}" cycles instructions 2>&1 || true)"
echo "${PROF}" | sed 's/^/    /'
wait 2>/dev/null || true

# "run_time_ns <t> run_cnt <c>" from prog show (fields only exist while
# kernel.bpf_stats_enabled=1); echoes "0 0" when absent.
prog_stats() {
    local out
    out="$(bpftool prog show id "$1" 2>/dev/null \
            | grep -oE 'run_time_ns [0-9]+ run_cnt [0-9]+' \
            | awk '{print $2, $4}')"
    echo "${out:-0 0}"
}

# Parse "<cycles> cycles" and "<runs> run_cnt" if present.
CYC="$(echo "${PROF}" | grep -iE '[0-9,]+[[:space:]]+cycles' | grep -oE '[0-9,]+' | head -1 | tr -d ',' || true)"
RUNS="$(echo "${PROF}" | grep -oE 'run_cnt[[:space:]]+[0-9,]+' | grep -oE '[0-9,]+' | tr -d ',' || true)"
if [[ -n "${CYC}" && -n "${RUNS}" && "${RUNS}" -gt 0 ]]; then
    NS="$(awk -v c="${CYC}" -v r="${RUNS}" -v g="${GHZ}" 'BEGIN{printf "%.1f", (c/r)/g}')"
    echo "  per-invocation: ${CYC} cycles / ${RUNS} runs ÷ ${GHZ} GHz ≈ ${NS} ns"
    results_row "Map/prog lookup latency" "ebpf-bucket (XDP)" "${NS}" "ns" "bpftool prog profile, ${GHZ}GHz"
else
    # Fallback: kernel.bpf_stats_enabled gives exact run_time_ns / run_cnt
    # deltas over a flood window — no perf/fentry support needed.
    c_ylw "  'bpftool prog profile' gave no parseable output; falling back to kernel.bpf_stats_enabled."
    OLD_STATS="$(sysctl -n kernel.bpf_stats_enabled 2>/dev/null || echo 0)"
    sysctl -qw kernel.bpf_stats_enabled=1
    read -r T0 C0 <<< "$(prog_stats "${PROG_ID}")"
    tgt="$(target_ip)"
    if command -v hping3 >/dev/null 2>&1; then
        timeout "${DURATION}" hping3 --flood -S -p 80 "${tgt}" >/dev/null 2>&1 || true
    else
        sleep "${DURATION}"
    fi
    read -r T1 C1 <<< "$(prog_stats "${PROG_ID}")"
    sysctl -qw kernel.bpf_stats_enabled="${OLD_STATS}"
    if (( C1 > C0 )); then
        NS="$(awk -v t="$((T1 - T0))" -v c="$((C1 - C0))" 'BEGIN{printf "%.1f", t/c}')"
        echo "  run_time_ns Δ=$((T1 - T0)) / run_cnt Δ=$((C1 - C0)) ≈ ${NS} ns per invocation"
        results_row "Map/prog lookup latency" "ebpf-bucket (XDP)" "${NS}" "ns" "bpf_stats run_time_ns/run_cnt, ${DURATION}s flood"
    else
        c_red "  run_cnt did not increase — is the XDP prog attached to ${IFACE} and traffic flowing?"
        exit 1
    fi
fi
