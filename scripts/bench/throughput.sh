#!/usr/bin/env bash
#
# throughput.sh — packet throughput (pps) + CPU% across 4 mitigation modes
#                 (TASKS §8.A-2/8.A-3, Table 2).
#
# Comparison groups (the firewall must already be running for the eBPF group):
#   no-mitigation    : XDP detached (raw NIC datapath baseline)
#   static-blocklist : single BLOCK_LIST entry, IP-lookup-only enforcement
#   userspace-IF     : per-flow sklearn IF inference rate (from results_benchmark.json)
#   ebpf-bucket      : full XDP+TC bucket policy datapath (your method)
#
# For each group it floods ${DURATION}s, samples interface pps and CPU% (mpstat),
# and records DROP_EVENTS delta. Run one group per invocation to control which
# enforcement is attached, OR pass `all` to run the measurable subset.
#
# Usage:
#   sudo ./scripts/bench/throughput.sh ebpf-bucket      # firewall running
#   sudo ./scripts/bench/throughput.sh no-mitigation    # firewall stopped
#   sudo ./scripts/bench/throughput.sh static-blocklist
#   sudo ./scripts/bench/throughput.sh userspace-IF     # reads results_benchmark.json
#
# Env: IFACE, DURATION, RESULTS_DIR, FLOOD (syn|udp, default syn).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${HERE}/lib.sh"
FLOOD="${FLOOD:-syn}"

flood_bg() {
    local tgt="$1" spoof="${2:-}"
    local args=(--flood -p 80)
    [[ "${FLOOD}" == "udp" ]] && args=(--flood --udp -p 80) || args+=(-S)
    [[ -n "${spoof}" ]] && args+=(-a "${spoof}")
    timeout "${DURATION}" hping3 "${args[@]}" "${tgt}" >/dev/null 2>&1 &
    echo $!
}

sample_cpu() {
    # mean %%busy over DURATION via mpstat (LC_ALL=C: localized output has no
    # "Average" line); fallback n/a.
    local v
    if command -v mpstat >/dev/null 2>&1; then
        v="$(LC_ALL=C mpstat 1 "${DURATION}" 2>/dev/null \
                | awk '/Average/ && $NF ~ /[0-9.]+/ {print 100 - $NF; exit}')"
    fi
    echo "${v:-n/a}"
}

measure_group() {
    local group="$1" spoof="${2:-}"
    section "throughput: ${group} (IFACE=${IFACE}, ${DURATION}s, FLOOD=${FLOOD}${spoof:+, spoof-src=${spoof}})"
    require_cmd hping3 || { c_red "hping3 required"; return 1; }
    local tgt; tgt="$(target_ip)"

    local p0 p1 d0 d1 pid cpu pps drops
    p0="$(iface_packets)"; d0="$(drop_events_total)"
    pid="$(flood_bg "${tgt}" "${spoof}")"
    cpu="$(sample_cpu)"            # blocks ~DURATION while flood runs
    wait "${pid}" 2>/dev/null || true
    p1="$(iface_packets)"; d1="$(drop_events_total)"

    # XDP_DROP'd packets never accumulate in /sys rx/tx, so a pass-through-only
    # delta undercounts the drop path (blocklist drops everything -> /sys Δ≈0).
    # Total handled rate = passed packets + dropped packets.
    drops=$(( d1 - d0 ))
    if (( drops < 0 )); then
        # PKT_DROPS went backwards => the firewall restarted mid-measurement
        # (per-CPU counter reset). The sample is corrupt; don't record it.
        c_red "  PKT_DROPS Δ=${drops} < 0: firewall restarted during measurement; sample discarded."
        c_red "  Re-run with a stable firewall (check it stays up for >${DURATION}s)."
        return 1
    fi
    pps=$(( (p1 - p0 + drops) / DURATION ))
    echo "  packets Δ=$(( p1 - p0 ))  PKT_DROPS Δ=${drops}  ->  ${pps} pps handled"
    echo "  CPU busy≈${cpu}%"
    results_row "Throughput" "${group}" "${pps}" "pps" "passed Δ=$(( p1 - p0 )), dropped Δ=${drops}"
    if [[ "${cpu}" != "n/a" ]]; then
        results_row "CPU usage" "${group}" "${cpu}" "%" "flood ${DURATION}s"
    fi
}

measure_userspace_if() {
    section "throughput: userspace-IF (from results_benchmark.json)"
    local json="service/model/experiments/results_benchmark.json"
    if [[ ! -f "${json}" ]]; then
        c_ylw "  ${json} not found; run: python -m service.model.experiments.results_benchmark"
        return 0
    fi
    # latency µs/flow -> achievable flows(pps) = 1e6 / latency
    local lat pps
    lat="$(grep -oE '"contract5_if_inference"[^,}]*' "${json}" \
            | grep -oE ':[[:space:]]*[0-9.]+' | grep -oE '[0-9.]+' | head -1)"
    if [[ -z "${lat}" ]]; then c_ylw "  could not parse latency"; return 0; fi
    pps="$(awk -v l="${lat}" 'BEGIN{printf "%d", 1000000.0/l}')"
    echo "  per-flow IF latency=${lat} µs -> ~${pps} flows/s (single core, sklearn)"
    results_row "Throughput" "userspace-IF" "${pps}" "flow/s" "1e6/${lat}µs (results_benchmark.json)"
}

case "${1:-ebpf-bucket}" in
    no-mitigation)    require_root; measure_group "no-mitigation" ;;
    static-blocklist)
        # Exercise the IP-lookup-only DROP path: block the flood's real source
        # (on loopback that is the target IP itself; override BLOCK_IP for veth/
        # dual). Spoofed sources never materialize on lo, so we block the real
        # one and flood normally. Clean up the entry on exit.
        require_root; require_maps_loaded
        BLOCK_IP="${BLOCK_IP:-$(target_ip)}"
        seed_blocklist "${BLOCK_IP}"
        trap 'unseed_blocklist "${BLOCK_IP}"' EXIT
        measure_group "static-blocklist"
        ;;
    ebpf-bucket)      require_root; require_maps_loaded; measure_group "ebpf-bucket" ;;
    userspace-IF)     measure_userspace_if ;;
    all)
        require_root
        measure_userspace_if
        if map_loaded SCORE_TABLE; then measure_group "ebpf-bucket"; else
            c_ylw "firewall not running; only userspace-IF measured. Start firewall for ebpf-bucket."
        fi ;;
    *) c_red "usage: throughput.sh [no-mitigation|static-blocklist|ebpf-bucket|userspace-IF|all]"; exit 1 ;;
esac
