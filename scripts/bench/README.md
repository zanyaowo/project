# Benchmark Harness — Table 2 / E4 (System Overhead)

On-hardware measurement of the eBPF firewall datapath cost, to fill the paper's
**Table 2 — System Overhead**. Offline detection numbers (Table 1, Figure 2) come
from `service/model/experiments/`; this harness produces the *system* side.

All scripts share `lib.sh`, take `IFACE` (env), and **append rows to
`bench_results/table2.md`** (copy-paste into the paper). Run as root.

## Prerequisites

- `bpftool` (pacman: `bpf` / apt: `linux-tools-$(uname -r)`) — **currently missing on this box**
- `hping3` (SYN/UDP flood), `sysstat` (`mpstat` for CPU%), optional `pktgen` for >1 Mpps
- The firewall **running in another terminal** for eBPF-path measurements:
  `make run-firewall IFACE=<iface>`

## Run order

```bash
# 0. install missing tools (one-time)
sudo pacman -S bpf hping3 sysstat        # adjust to your distro

# 1. probe capabilities + record topology (loopback | veth | dual)
make bench-setup IFACE=lo MODE=loopback
#   or isolated veth pair:
make bench-setup MODE=veth               # creates vethbenchA <-> vethbenchB@benchns

# 2. start the firewall (separate terminal), target the bench IFACE
make run-firewall IFACE=lo               # or IFACE=vethbenchA

# 3. measurements (each appends to bench_results/table2.md)
make bench-throughput GROUP=ebpf-bucket IFACE=lo   # pps + CPU% (your method)
make bench-throughput GROUP=userspace-IF           # IF inference ceiling (no firewall needed)
make bench-throughput GROUP=no-mitigation IFACE=lo # baseline (firewall detached)
make bench-maplat IFACE=lo                          # kernel prog/map lookup ns  ← headline
make bench-mitigation IFACE=lo                      # detect->DROP latency µs

# or the full eBPF suite at once (firewall must be running):
make bench IFACE=lo

# 4. teardown veth (if used)
sudo MODE=veth scripts/bench/setup_testbed.sh teardown
```

## What each script measures (TASKS §8.A)

| script | metric | Table 2 row |
|--------|--------|-------------|
| `setup_testbed.sh` | topology + max generation rate | testbed header |
| `throughput.sh` | packet throughput (pps) + CPU% | 8.A-2 / 8.A-3 |
| `map_latency.sh` | XDP prog/map lookup latency (ns) | 8.A-4 (headline) |
| `mitigation_latency.sh` | detect→DROP end-to-end (µs) | 8.A-6 |

## Notes / honest caveats

- **map_latency.sh** uses `bpftool prog profile` (needs kernel ≥5.7 + perf). If it
  can't auto-parse, enable BPF stats: `sudo sysctl kernel.bpf_stats_enabled=1`, run
  traffic, then `run_time_ns / run_cnt` from `bpftool prog show id <id>` = ns/pkt.
- **userspace-IF** is computed from `results_benchmark.json` (per-flow IF latency →
  flows/s ceiling, ≈168 flow/s single-core); it needs no hardware.
- Single-box loopback caps generation at single-core hping3 rate; for >1 Mpps use
  `pktgen` or a second host (`MODE=dual`, set `GEN_HOST`).
- `static-blocklist` group approximates IP-blacklist-only enforcement; seed one
  `BLOCK_LIST` entry first (see `scripts/validate_runtime.sh blocklist`).
