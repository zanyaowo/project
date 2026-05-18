# Kernel Distilled Model Contract

> Status: P0 engineering contract for aligning Python distillation, Rust userspace loader, and eBPF scorer.
> Version: 1
> Scope: 5-feature N=2 distilled model with 32-entry score table.

---

## 1. Purpose

This document is the single source of truth for the kernel-side distilled model.

All of the following must implement this contract exactly:

- `service/model/pipeline/distill_export.py`
- `service/model/pipeline/distill.py`
- `service/firewall/firewall/src/lib/model_loader.rs`
- `service/firewall/firewall-ebpf/src/scorer.rs`
- `service/firewall/firewall-ebpf/src/table.rs`
- `service/firewall/firewall-common/src/session.rs`

If this document and code disagree, treat the code as a bug unless this document is intentionally updated first.

---

## 2. Model Format

The distilled model JSON must include explicit metadata. Hidden feature order is forbidden.

```json
{
  "version": 1,
  "feature_order": [
    "protocol",
    "pkt_len_mean",
    "fwd_max_q",
    "sym_ratio",
    "pkt_cv_sq"
  ],
  "threshold_cmp": ">=",
  "score_scale": 10000,
  "length_unit": "packet_len",
  "threshold": 1234,
  "quantile_bounds": [...],
  "score_table": [...]
}
```

Required validation:

- `version == 1`
- `feature_order` exactly equals the order in section 3
- `threshold_cmp == ">="`
- `score_scale == 10000`
- `length_unit == "packet_len"`
- `len(quantile_bounds) == 5`
- `len(score_table) == 32`

Rust userspace must reject unsupported or malformed JSON instead of silently loading it.

---

## 3. Canonical Feature / Bit Order

The index is built least-significant bit first.

| Bit | Feature | Meaning |
|---:|---------|---------|
| 0 | `protocol` | L4 protocol bucket |
| 1 | `pkt_len_mean` | mean packet length bucket |
| 2 | `fwd_max_q` | forward packet length dispersion bucket |
| 3 | `sym_ratio` | direction symmetry bucket |
| 4 | `pkt_cv_sq` | squared packet length coefficient-of-variation bucket |

Canonical index formula:

```text
index = (protocol_bit     << 0)
      | (pkt_len_mean_bit << 1)
      | (fwd_max_q_bit    << 2)
      | (sym_ratio_bit    << 3)
      | (pkt_cv_sq_bit    << 4)
```

This order intentionally follows the existing Python `idx |= bit << i` convention.

Any older documentation using this order is obsolete and must be updated:

```text
(fwdmax_q << 4) | (sym_q << 3) | (pkt_cv_q << 2) | (proto << 1) | mean
```

---

## 4. Length Unit

All kernel model features must use packet length, not payload length.

Definition:

```text
packet_len = full packet/frame length as observed by the parser for model statistics
```

Forbidden mixing:

```text
mean from payload_len, but max/std from packet_len
```

The session state may separately track payload bytes for non-model telemetry, but model fields must be named so the unit is unambiguous.

Recommended model statistics in `SessionValue`:

```rust
orig_pkt_len_sum: u64,
orig_pkts: u64,
resp_pkt_len_sum: u64,
resp_pkts: u64,
pkt_len_sum_sq: u64,
fwd_pkt_len_max: u32,
```

---

## 5. Feature Definitions

### 5.1 `protocol`

Source:

```text
SessionKey.proto
```

Boundary type:

```json
{"name": "protocol", "type": "absolute", "value": <integer>}
```

Bucket rule:

```text
protocol_bit = 1 if proto > value else 0
```

---

### 5.2 `pkt_len_mean`

Source:

```text
total_pkt_len_sum = orig_pkt_len_sum + resp_pkt_len_sum
total_pkts = orig_pkts + resp_pkts
pkt_len_mean = total_pkt_len_sum / total_pkts
```

Boundary type:

```json
{"name": "pkt_len_mean", "type": "absolute", "value": <integer>}
```

Bucket rule at the model semantics layer:

```text
pkt_len_mean_bit = 1 if pkt_len_mean > value else 0
```

Kernel implementation must preserve the absolute-feature semantics while avoiding division:

```text
total_pkt_len_sum / total_pkts > value
<=> total_pkt_len_sum > total_pkts * value
```

Denominator guard:

```text
if total_pkts == 0, treat the bit as 0 or skip scoring
```

---

### 5.3 `fwd_max_q`

Definition:

```text
fwd_max_q = Fwd Packet Length Max / Fwd Packet Length Mean
          = fwd_pkt_len_max / (orig_pkt_len_sum / orig_pkts)
          = fwd_pkt_len_max * orig_pkts / orig_pkt_len_sum
```

Boundary type:

```json
{"name": "fwd_max_q", "type": "ratio", "numer": <integer>, "denom": <integer>}
```

Bucket rule:

```text
fwd_pkt_len_max * orig_pkts / orig_pkt_len_sum > numer / denom
<=> fwd_pkt_len_max * orig_pkts * denom > orig_pkt_len_sum * numer
```

Important:

- `fwd_pkt_len_max` must be forward-only.
- Bidirectional `max_pkt_len` is not equivalent and must not be used.
- `orig_pkt_len_sum` must use packet length, not payload length.

---

### 5.4 `sym_ratio`

Definition:

```text
sym_ratio = Total Fwd Packets / Total Bwd Packets
```

Boundary type:

```json
{"name": "sym_ratio", "type": "ratio", "numer": <integer>, "denom": <integer>}
```

Bucket rule:

```text
orig_pkts / (resp_pkts + 1) > numer / denom
<=> orig_pkts * denom > (resp_pkts + 1) * numer
```

The `+ 1` denominator guard must match Python export and parity tests.

---

### 5.5 `pkt_cv_sq`

Use squared CV in the kernel contract to avoid square root in eBPF.

Definition:

```text
mean = total_pkt_len_sum / total_pkts
variance = (pkt_len_sum_sq / total_pkts) - mean^2
CV^2 = variance / mean^2
```

Integer form:

```text
pkt_cv_sq = (pkt_len_sum_sq * total_pkts - total_pkt_len_sum^2)
            / total_pkt_len_sum^2
```

Boundary type:

```json
{"name": "pkt_cv_sq", "type": "ratio", "numer": <integer>, "denom": <integer>}
```

Bucket rule:

```text
(pkt_len_sum_sq * total_pkts - total_pkt_len_sum^2) / total_pkt_len_sum^2 > numer / denom
<=> (pkt_len_sum_sq * total_pkts - total_pkt_len_sum^2) * denom
    > total_pkt_len_sum^2 * numer
```

Important:

- Python export must export `pkt_cv_sq` boundaries, not raw `pkt_cv` boundaries.
- If Python starts from CICFlowMeter `Packet Length Std / Packet Length Mean`, it must square that value before producing the boundary.

---

## 6. Score Lookup and Alert Rule

Score lookup:

```text
score = score_table[index]
```

Alert comparison:

```text
is_alert = score >= threshold
```

Rust/eBPF must not use `score > threshold` unless `threshold_cmp` is changed and all parity tests are updated.

---

## 7. Required Parity Tests

Minimum parity tests before trusting kernel-side inference:

1. all 32 feature-bit combinations map to the expected score table index
2. `score == threshold` alerts under `>=`
3. `resp_pkts == 0` uses the same denominator guard as Python
4. `pkt_cv_sq` uses squared boundary, not raw CV
5. forward max differs from bidirectional max and still uses forward-only max
6. packet length and payload length differ and model uses packet length

---

## 8. Non-goals

This contract does not define:

- Full 25-feature Python IsolationForest inference
- L7 / HTTP features for LOIC-HTTP
- entropy features
- rate-limiter policy
- blocklist behavior

Those may consume the model score, but they are outside this contract.
