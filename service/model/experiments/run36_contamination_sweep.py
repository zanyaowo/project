"""Run 36 — Attack contamination sweep：Naive vs Gated streaming（E5，CIC-DDoS2019 in-scope）。

論點：streaming 重算分位桶邊界時，若把攻擊流量當常態校準（naive），攻擊比例 ρ 升高
→ 邊界往攻擊分布漂移 → 攻擊落回「正常」桶 → FNR 上升；gated update 偵測到污染
（divergence > 門檻 且 high-risk 桶命中率跳升）→ 凍結 reference boundary → FNR 維持。

本模擬忠於部署 `boundary_updater.rs` 的 gate 邏輯：
  divergence(q_ref,q_live)=各特徵 |live-ref|/(|ref|+ε) 平均；
  decide_gate: divergence>div_thr 且 high_risk_jump → AttackFreeze（凍結 ref）；
  否則 high_risk 無跳升→Normal（EMA 更新）、divergence 不足→Uncertain（不動 ref）。
  門檻採部署預設 divergence_threshold=0.30、high_risk_rate_jump=2.0。

ref boundary＝部署 model.json（CIC BENIGN 中位數）。naive 邊界＝污染視窗逐特徵中位數。
FNR＝以結果邊界（+ model.json 固定 score_table/threshold）對攻擊 eval 評分後漏報比例。

範圍：CIC-DDoS2019 only。執行：
  python -m service.model.experiments.run36_contamination_sweep
"""
from __future__ import annotations

import copy
import json

import numpy as np
import polars as pl

from service.model.data.sample import get_balance_sample_from_files
from service.model.pipeline.distill import DistilledClassifier
from service.model.experiments.results_benchmark import (
    CIC_TEST_PATHS,
    CONTRACT_PATH,
    N_EVAL_PER_LABEL,
    RATIO_RAW,
    SEED,
    x_contract5,
)

EVAL_COLS = sorted(set(RATIO_RAW) | {"Label"})
DIV_THRESHOLD = 0.30      # boundary_updater config default
HIGH_RISK_JUMP = 2.0      # boundary_updater config default
RHOS = (0.10, 0.30, 0.50, 0.80)
RENAME = {"Total Backward Packets": "Total Bwd Packets"}


def _select(cols):
    return lambda lf: lf.select(cols)


def clf_with_bounds(base: dict, medians: np.ndarray) -> DistilledClassifier:
    """以逐特徵中位數覆寫 quantile_bounds（保留 score_table/threshold），回傳 scorer。"""
    spec = copy.deepcopy(base)
    for i, b in enumerate(spec["quantile_bounds"]):
        v = float(medians[i])
        if b["type"] == "absolute":
            b["value"] = int(round(max(v, 0.0)))
        else:
            b["numer"] = int(round(max(v, 0.0) * b["denom"]))
    return DistilledClassifier.from_dict(spec) if hasattr(DistilledClassifier, "from_dict") \
        else _from_spec(spec)


def _from_spec(spec: dict) -> DistilledClassifier:
    clf = DistilledClassifier.__new__(DistilledClassifier)
    clf.bounds = spec["quantile_bounds"]
    clf.score_table = np.asarray(spec["score_table"])
    clf.threshold = spec["threshold"]
    return clf


def fnr(clf: DistilledClassifier, df_attack: pl.DataFrame) -> float:
    s = clf.score(df_attack.rename(RENAME))
    return float((s < clf.threshold).mean())   # 漏報＝未達 threshold 的攻擊比例


def alert_rate(clf: DistilledClassifier, df: pl.DataFrame) -> float:
    s = clf.score(df.rename(RENAME))
    return float((s >= clf.threshold).mean())


def main() -> None:
    import json as _json
    base = _json.load(open(CONTRACT_PATH))
    ref_clf = _from_spec(copy.deepcopy(base))
    ref_vals = np.array([
        b["value"] if b["type"] == "absolute" else b["numer"] / b["denom"]
        for b in base["quantile_bounds"]])

    ev = get_balance_sample_from_files(
        CIC_TEST_PATHS, sample_count_per_label=N_EVAL_PER_LABEL, seed=SEED,
        transform=_select(EVAL_COLS))
    is_benign = ev["Label"].to_numpy() == "BENIGN"
    benign = ev.filter(pl.Series(is_benign))
    attack = ev.filter(pl.Series(~is_benign))
    # window / eval 切半，避免重用
    rng = np.random.default_rng(SEED)
    b_perm = rng.permutation(len(benign)); a_perm = rng.permutation(len(attack))
    benign_win, benign_ev = benign[b_perm[:len(benign)//2]], benign[b_perm[len(benign)//2:]]
    attack_win, attack_ev = attack[a_perm[:len(attack)//2]], attack[a_perm[len(attack)//2:]]

    base_fnr = fnr(ref_clf, attack_ev)
    benign_alert_base = alert_rate(ref_clf, benign_ev)  # high-risk baseline（≈FPR）
    print(f"ref(部署 BENIGN 中位數) baseline：attack FNR={base_fnr:.3f}  "
          f"benign high-risk rate={benign_alert_base:.3f}")

    print("\n===== Contamination sweep（Naive vs Gated streaming，CIC-DDoS2019 in-scope）=====")
    hdr = (f"{'ρ(攻擊%)':>8}{'divergence':>12}{'highRisk×':>11}{'gate':>14}"
           f"{'naive FNR':>11}{'gated FNR':>11}")
    print(hdr)
    out = {"scope": "CIC-DDoS2019 only", "baseline_fnr": base_fnr,
           "div_threshold": DIV_THRESHOLD, "high_risk_jump": HIGH_RISK_JUMP, "sweep": {}}

    W = 6000
    for rho in RHOS:
        n_atk = int(W * rho); n_ben = W - n_atk
        win = pl.concat([
            benign_win.sample(min(n_ben, len(benign_win)), with_replacement=n_ben > len(benign_win), seed=SEED),
            attack_win.sample(min(n_atk, len(attack_win)), with_replacement=n_atk > len(attack_win), seed=SEED),
        ])
        med = np.nanmedian(x_contract5(win), axis=0)
        divg = float(np.mean(np.abs(med - ref_vals) / (np.abs(ref_vals) + 1e-9)))
        hr_rate = alert_rate(ref_clf, win)               # 視窗 high-risk 命中率（用 ref 邊界）
        hr_ratio = hr_rate / (benign_alert_base + 1e-9)
        jump = hr_ratio > HIGH_RISK_JUMP

        # gate 決策（boundary_updater.decide_gate）
        if divg > DIV_THRESHOLD:
            gate = "AttackFreeze" if jump else "Normal"
        else:
            gate = "Uncertain"

        naive_clf = clf_with_bounds(base, med)
        naive_fnr = fnr(naive_clf, attack_ev)
        # gated：AttackFreeze/Uncertain 不動 ref；Normal 才更新（此處 ρ 攻擊→凍結）
        gated_clf = naive_clf if gate == "Normal" else ref_clf
        gated_fnr = fnr(gated_clf, attack_ev)

        print(f"{int(rho*100):>8}{divg:>12.3f}{hr_ratio:>11.2f}{gate:>14}"
              f"{naive_fnr:>11.3f}{gated_fnr:>11.3f}")
        out["sweep"][f"rho_{int(rho*100)}"] = {
            "divergence": divg, "high_risk_ratio": hr_ratio, "gate": gate,
            "naive_fnr": naive_fnr, "gated_fnr": gated_fnr}

    with open("service/model/experiments/run36_contamination_sweep.json", "w") as f:
        json.dump(out, f, indent=2, default=float)
    print("\nWrote -> service/model/experiments/run36_contamination_sweep.json")


if __name__ == "__main__":
    main()
