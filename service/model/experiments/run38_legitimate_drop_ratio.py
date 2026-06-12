"""run38 — Legitimate drop ratio（FPR-in-the-wild，CIC-DDoS2019 in-scope）。

回答 Table 2 唯一仍標「待測」的格：部署到 eBPF fast-path 後，正常流量被誤
DROP 的比例。與 Table 1 的 FPR=0.007 不同——後者是用 `threshold_at_fpr`
**重新校準**到 FPR≤1% 操作點的理想值；本實驗用實際 ship 的 `model.json`
**固定 threshold**（kernel `score >= threshold → DROP` 的同一條件），在
benign+attack 混流上量正常封包真正被丟的比例，才是「in-the-wild」誤丟率。

評分路徑與 results_benchmark.py 完全相同（同 CIC test split、同 Contract5
特徵重建、同 DistilledClassifier），確保數字可與 Table 1 對齊。

per-flow 評分下，legitimate drop ratio 只取決於 benign 流自身（與攻擊混入比例
無關），故主數字為「benign 流命中 drop 桶的比例」；另以幾個代表性混流比例
回放，報告整條串流視角的 benign-dropped / attack-caught，佐證 ground-truth 對照。

執行：
  python -m service.model.experiments.run38_legitimate_drop_ratio
"""
from __future__ import annotations

import json

import numpy as np

from service.model.data.sample import get_balance_sample_from_files
from service.model.pipeline.distill import DistilledClassifier
from service.model.experiments.results_benchmark import EVAL_COLS, _select
from service.model.experiments.run27_boundary_overfit_check import (
    CIC_TEST_PATHS,
    N_EVAL_PER_LABEL,
    SEED,
)

CONTRACT_PATH = "service/firewall/firewall/src/data_format/model.json"
OUT_PATH = "service/model/experiments/run38_legitimate_drop_ratio.json"

# 代表性混流比例（attack 佔整條串流的比例）。legitimate drop ratio 本身
# 與此無關（per-flow 獨立評分），列出是為了呈現整條串流的 ground-truth 對照。
MIX_ATTACK_FRACTIONS = [0.1, 0.3, 0.5, 0.8]


def main() -> None:
    clf = DistilledClassifier.from_json(CONTRACT_PATH)
    print(f"deployed model.json: threshold={clf.threshold} (fixed, kernel score>=threshold → DROP)")
    drop_buckets = [i for i, s in enumerate(clf.score_table) if s >= clf.threshold]
    print(f"drop buckets (score>=threshold): {drop_buckets}  ({len(drop_buckets)}/32)")

    # CIC test 混流：每 label 抽 N_EVAL_PER_LABEL，與 results_benchmark 同 split。
    ev = get_balance_sample_from_files(
        CIC_TEST_PATHS, sample_count_per_label=N_EVAL_PER_LABEL, seed=SEED,
        transform=_select(EVAL_COLS))
    ev = ev.rename({"Total Backward Packets": "Total Bwd Packets"})

    labels = ev["Label"].to_numpy()
    is_attack = labels != "BENIGN"
    scores = clf.score(ev).astype(np.int64)
    dropped = scores >= clf.threshold  # kernel DROP 條件

    n_benign = int((~is_attack).sum())
    n_attack = int(is_attack.sum())
    benign_dropped = int((dropped & ~is_attack).sum())
    attack_dropped = int((dropped & is_attack).sum())

    legit_drop_ratio = benign_dropped / n_benign if n_benign else 0.0
    attack_catch_ratio = attack_dropped / n_attack if n_attack else 0.0

    print(f"\neval rows={len(ev)}  benign={n_benign}  attack={n_attack}")
    print(f"\n=== Legitimate drop ratio (deployed fixed threshold) ===")
    print(f"  benign flows dropped : {benign_dropped}/{n_benign}")
    print(f"  LEGITIMATE DROP RATIO: {legit_drop_ratio*100:.2f}%  (FPR-in-the-wild)")
    print(f"  attack caught (context): {attack_dropped}/{n_attack} = {attack_catch_ratio*100:.2f}%")

    # 對照 Table 1 的理想操作點 FPR（重校準到 FPR≤1%）：說明兩者差異來源。
    print(f"\n  cf. Table 1 reports FPR=0.007 at a *re-calibrated* FPR≤1% op-point;")
    print(f"      this {legit_drop_ratio*100:.2f}% uses the *fixed shipped* threshold={clf.threshold}.")

    # per-attack：哪些攻擊型態混入時不會抬高 benign 誤丟（benign 評分與攻擊無關，
    # 此處列各攻擊自身的 caught rate 供對照，與 Table 3 per-attack recall 呼應）。
    print(f"\n--- per-attack caught @ deployed fixed threshold ---")
    print(f"  {'attack':<22}{'n':>7}{'caught':>9}")
    for lab in sorted(set(labels.tolist())):
        if lab == "BENIGN":
            continue
        mk = labels == lab
        print(f"  {lab:<22}{int(mk.sum()):>7}{dropped[mk].mean():>9.3f}")

    # 整條串流視角：legitimate drop ratio 本身與混流比例無關（per-flow 獨立），
    # 但「被丟的流裡有多少其實是正常流量」（false-drop share）會隨攻擊稀少而上升，
    # 是運維上更貼切的附帶成本指標。以各類率解析計算，不需重抽。
    print(f"\n--- mixed-stream ground-truth view ---")
    print(f"  {'attack%':>8}{'benign-drop%':>14}{'false-drop share%':>20}")
    mix_rows = []
    for frac in MIX_ATTACK_FRACTIONS:
        benign_drops = legit_drop_ratio * (1.0 - frac)
        attack_drops = attack_catch_ratio * frac
        total_drops = benign_drops + attack_drops
        false_drop_share = benign_drops / total_drops if total_drops else 0.0
        print(f"  {frac*100:>7.0f}%{legit_drop_ratio*100:>13.2f}%{false_drop_share*100:>19.3f}%")
        mix_rows.append({
            "attack_fraction": frac,
            "benign_drop_ratio": legit_drop_ratio,
            "false_drop_share": false_drop_share,
        })

    out = {
        "scope": "CIC-DDoS2019 only",
        "method": "deployed model.json fixed threshold (kernel DROP condition)",
        "threshold": clf.threshold,
        "drop_buckets": drop_buckets,
        "eval_rows": int(len(ev)),
        "n_benign": n_benign,
        "n_attack": n_attack,
        "benign_dropped": benign_dropped,
        "legitimate_drop_ratio": legit_drop_ratio,
        "attack_catch_ratio": attack_catch_ratio,
        "note": (
            "legitimate_drop_ratio uses the fixed shipped threshold; differs from "
            "Table 1 FPR=0.007 which re-calibrates to the FPR<=1% op-point."
        ),
        "mixed_stream": mix_rows,
    }
    with open(OUT_PATH, "w") as f:
        json.dump(out, f, indent=2, default=float)
    print(f"\nWrote -> {OUT_PATH}")


if __name__ == "__main__":
    main()
