#!/usr/bin/env bash
#
# setup_testbed.sh — benchmark testbed setup + capability probe (TASKS §8.A-1).
#
# Documents the test topology and verifies the box can generate enough load to
# stress the eBPF datapath. Three supported topologies (pick per `MODE`):
#   loopback : single box, traffic to 127.0.0.1 (simplest; XDP on lo via xdpgeneric)
#   veth     : single box, veth pair ns0<->ns1 (isolated, recommended for repeatable)
#   dual     : two machines (this box = target, generator = $GEN_HOST) — manual
#
# Requires: root. Recommends: hping3 and/or pktgen (kernel module), mpstat, bpftool.
#
# Usage:
#   sudo MODE=veth   ./scripts/bench/setup_testbed.sh     # create veth pair
#   sudo MODE=loopback ./scripts/bench/setup_testbed.sh
#   sudo ./scripts/bench/setup_testbed.sh teardown        # remove veth pair
#
# Env: IFACE, MODE (loopback|veth|dual), GEN_HOST (for dual), RESULTS_DIR.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "${HERE}/lib.sh"

MODE="${MODE:-loopback}"
VETH_A="vethbenchA"
VETH_B="vethbenchB"
NS="benchns"

probe_caps() {
    section "capability probe"
    local ok=1
    require_cmd bpftool "Install bpftool (pacman: bpf / apt: linux-tools)." || ok=0
    require_cmd hping3  "Install hping3 for SYN/UDP flood generation."        || ok=0
    require_cmd mpstat  "Install sysstat for CPU%% (mpstat/pidstat)."         || true
    if command -v pktgen >/dev/null 2>&1 || [[ -d /proc/net/pktgen ]]; then
        c_grn "  pktgen available (high-rate kernel traffic gen)"
    else
        c_ylw "  pktgen not loaded (optional): 'sudo modprobe pktgen' for >1 Mpps"
    fi
    # rough max-rate probe with hping3 flood for 2s toward target
    if command -v hping3 >/dev/null 2>&1; then
        local tgt before after dt pps
        tgt="$(target_ip)"
        before="$(iface_packets)"
        timeout 2 hping3 --flood -S -p 80 "${tgt}" >/dev/null 2>&1 || true
        after="$(iface_packets)"
        pps=$(( (after - before) / 2 ))
        echo "  rough generation rate: ~${pps} pps (hping3 --flood, 2s, single core)"
        [[ "${pps}" -ge 100000 ]] && c_grn "  PASS: can push >=100 kpps" \
            || c_ylw "  NOTE: <100 kpps single-core; use pktgen or a 2nd host for >1 Mpps"
    fi
    [[ "${ok}" -eq 1 ]] && c_grn "core tools present" || c_red "missing core tools (see above)"
}

setup_veth() {
    section "veth topology: ${VETH_A} <-> ${VETH_B} (ns ${NS})"
    ip netns add "${NS}" 2>/dev/null || true
    ip link add "${VETH_A}" type veth peer name "${VETH_B}" 2>/dev/null || true
    ip link set "${VETH_B}" netns "${NS}" 2>/dev/null || true
    ip addr add 10.123.0.1/24 dev "${VETH_A}" 2>/dev/null || true
    ip link set "${VETH_A}" up
    ip netns exec "${NS}" ip addr add 10.123.0.2/24 dev "${VETH_B}" 2>/dev/null || true
    ip netns exec "${NS}" ip link set "${VETH_B}" up
    ip netns exec "${NS}" ip link set lo up
    c_grn "  veth pair up. Target IFACE for firewall: ${VETH_A} (10.123.0.1)"
    echo "  generate load from peer: sudo ip netns exec ${NS} hping3 --flood -S 10.123.0.1"
    echo "  -> run firewall with: make run-firewall IFACE=${VETH_A}"
}

teardown_veth() {
    section "teardown veth"
    ip link del "${VETH_A}" 2>/dev/null && c_grn "  ${VETH_A} removed" || c_ylw "  ${VETH_A} already gone"
    ip netns del "${NS}" 2>/dev/null && c_grn "  ns ${NS} removed" || c_ylw "  ns ${NS} already gone"
}

record_topology() {
    results_init
    {
        echo ""
        echo "## Testbed (MODE=${MODE})"
        echo "- host: $(uname -srm)"
        echo "- IFACE: ${IFACE}"
        echo "- CPUs: $(nproc)  | kernel: $(uname -r)"
        [[ "${MODE}" == "veth" ]] && echo "- topology: veth ${VETH_A}(10.123.0.1) <-> ${VETH_B}@${NS}(10.123.0.2)"
        [[ "${MODE}" == "loopback" ]] && echo "- topology: loopback 127.0.0.1 (XDP via xdpgeneric on lo)"
        [[ "${MODE}" == "dual" ]] && echo "- topology: dual-host, generator=${GEN_HOST:-<set GEN_HOST>}"
        echo "- date: $(date -Iseconds)"
    } >> "${RESULTS_DIR}/table2.md"
    c_grn "  topology recorded -> ${RESULTS_DIR}/table2.md"
}

main() {
    require_root
    case "${1:-setup}" in
        teardown) teardown_veth ;;
        setup)
            probe_caps
            case "${MODE}" in
                veth) setup_veth ;;
                loopback) c_grn "loopback mode: target 127.0.0.1; run firewall on 'lo' (SKB/xdpgeneric)";;
                dual) c_ylw "dual-host: configure GEN_HOST=${GEN_HOST:-?} manually; this box is the target";;
                *) c_red "unknown MODE='${MODE}' (loopback|veth|dual)"; exit 1 ;;
            esac
            record_topology
            hr; c_grn "testbed ready. Next: make bench-throughput / bench-maplat / bench-mitigation"
            ;;
        *) c_red "usage: setup_testbed.sh [setup|teardown]"; exit 1 ;;
    esac
}
main "$@"
