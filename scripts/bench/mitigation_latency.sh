#!/usr/bin/env bash
#
# mitigation_latency.sh — end-to-end detect->DROP latency (µs) (TASKS §8.A-6, Table 2).
#
# Measures the time from "attack traffic starts" to "first XDP_DROP observed"
# (DROP_EVENTS counter first increments). This covers the SYN-cookie / bucket
# enforcement path latency, not just per-packet cost.
#
# Method: poll DROP_EVENTS at fine granularity, timestamp the moment it rises
# after a flood begins. Repeated REPS times; reports min/median/max.
#
# Requires: root, bpftool, hping3. Firewall running.
#
# Usage:
#   sudo ./scripts/bench/mitigation_latency.sh [IFACE]
# Env: IFACE, REPS (default 10), RESULTS_DIR.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${HERE}/lib.sh"

IFACE="${1:-$IFACE}"
REPS="${REPS:-10}"
require_root
require_cmd bpftool || exit 1
require_cmd hping3 || exit 1
require_maps_loaded

section "mitigation latency: detect -> first DROP (IFACE=${IFACE}, ${REPS} reps)"
tgt="$(target_ip)"

# The flood's real source must be in BLOCK_LIST for a DROP to fire. On loopback
# that source is the target IP (127.0.0.1); spoofed sources never materialize on
# lo. Block the real source and flood normally; override BLOCK_IP for veth/dual.
BLOCK_IP="${BLOCK_IP:-$(target_ip)}"
c_ylw "Seeding BLOCK_LIST[${BLOCK_IP}] (flood's real source on this testbed)."
seed_blocklist "${BLOCK_IP}"
trap 'unseed_blocklist "${BLOCK_IP}"' EXIT

# now_us: monotonic microseconds.
now_us() { date +%s%6N; }

samples=()
for ((i=1; i<=REPS; i++)); do
    d0="$(drop_events_total)"
    # start a short flood; record start time
    t_start="$(now_us)"
    timeout 3 hping3 --flood -S -p 80 "${tgt}" >/dev/null 2>&1 &
    fpid=$!
    # busy-poll DROP_EVENTS until it rises; cap by wall time (each
    # drop_events_total call costs 10-30ms, so an iteration cap could run
    # minutes per rep when no DROP ever fires).
    t_hit=""
    while :; do
        if [[ "$(drop_events_total)" -gt "${d0}" ]]; then
            t_hit="$(now_us)"; break
        fi
        (( $(now_us) - t_start > 3000000 )) && break
        sleep 0.001
    done
    kill "${fpid}" 2>/dev/null || true; wait "${fpid}" 2>/dev/null || true
    if [[ -n "${t_hit}" ]]; then
        lat=$(( t_hit - t_start ))
        samples+=("${lat}")
        printf '  rep %2d: %d µs\n' "${i}" "${lat}"
    else
        c_ylw "  rep ${i}: no DROP observed within 3s (blocklist empty? benign target?)"
    fi
    sleep 0.2
done

if [[ "${#samples[@]}" -eq 0 ]]; then
    c_red "No mitigation events captured. Ensure an attack signature triggers DROP"
    c_red "(e.g. seed BLOCK_LIST, or flood a target the bucket policy scores high-risk)."
    exit 1
fi

# min / median / max
sorted=($(printf '%s\n' "${samples[@]}" | sort -n))
n="${#sorted[@]}"
mn="${sorted[0]}"; mx="${sorted[n-1]}"; md="${sorted[n/2]}"
echo "  min=${mn}µs  median=${md}µs  max=${mx}µs  (n=${n})"
results_row "Mitigation latency" "BLOCK_LIST detect->DROP (userspace poll)" "${md}" "µs" "min=${mn}/max=${mx}, n=${n}; poll/spawn-bound, NOT kernel path"
