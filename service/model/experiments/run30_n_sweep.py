"""Run 30 — N-sweep: 多點分位桶 score-table 模式跨攻擊類型 AUC 矩陣（CIC-only）

目的：在「部署 contract 模式」下評估 N=2/4/8 均勻分位桶對全部 5 個特徵的影響，
     觀察多桶是否改善各攻擊類型偵測率，量化 table size 代價，
     並透過 metrics 模組報告誤報率（FPR）、準確率、overfit 狀況。

部署 contract 模式（與 eBPF 線上推論一致）：
  1. CIC BENIGN 訓練 IF（特徵為 bucket index 0..N-1）
  2. 預先列舉所有 ∏N_i 種 bucket 組合 → 對每組合算 IF anomaly score → 建表
  3. eval 樣本：bucket 後查表取 score → 算 AUC / FPR / 準確率

資料（CIC-only，不使用 BigFlow / IDS2018）：
  Train BENIGN : parquet_clean/03-11_*.parquet  BENIGN 列
  Eval         : parquet_clean/01-12_*.parquet  每檔取 BENIGN + 主攻擊類型

比較項（table_size = ∏ N_i）：
  D_n2_baseline:     N=2 all  →  2^5 = 32-entry     ← 部署 contract 對照
  E_n4_all:          N=4 all  →  4^5 = 1024-entry
  E_n8_all:          N=8 all  →  8^5 = 32768-entry
  F_n4ratio_n2abs:   ratio×3 N=4 + abs×2 N=2  →  256-entry
  G_proto3_n4rest:   protocol 3-cat + mean N=2 + ratio×3 N=4  →  384-entry

執行：
  uv run --project service/model python -m service.model.experiments.run30_n_sweep
"""
from __future__ import annotations

import glob
from dataclasses import dataclass, field
from itertools import product
from typing import Callable

import numpy as np
import polars as pl
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import StandardScaler

from service.model.experiments.run27_boundary_overfit_check import (
    CONTAMINATION,
    N_ESTIMATORS,
    N_EVAL_PER_LABEL,
    N_TRAIN_PER_SOURCE,
    SEED,
    to_norm_cic,
)
from service.model.data.sample import get_normal_sample_from_files
from service.model.metrics import detection_metrics, overfit_check, threshold_at_fpr

# ── Data paths ────────────────────────────────────────────────────────────────
BASE = "service/model/dataset/parquet_clean"
CIC_TRAIN_PATHS = sorted(glob.glob(f"{BASE}/03-11*.parquet"))
CIC_TEST_PATHS  = sorted(glob.glob(f"{BASE}/01-12*.parquet"))

NORM_COLS = ["max_pkt", "fwd_mean", "fwd_pkts", "bwd_pkts", "pkt_std", "pkt_len_mean", "protocol"]

# 只讀 to_norm_cic 需要的欄位（原始 CIC 檔有 87 欄，全讀 OOM）
_CIC_COLS = [
    "Label",
    "Fwd Packet Length Max",
    "Fwd Packet Length Mean",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Packet Length Std",
    "Packet Length Mean",
    "Protocol",
]

# ── Raw feature extractors ────────────────────────────────────────────────────

FEATURE_EXTRACTORS: dict[str, Callable[[pl.DataFrame], np.ndarray]] = {
    "protocol":     lambda df: df["protocol"].to_numpy().astype(np.float64),
    "pkt_len_mean": lambda df: df["pkt_len_mean"].to_numpy().astype(np.float64),
    "fwd_max_q":    lambda df: df["max_pkt"].to_numpy() / (df["fwd_mean"].to_numpy() + 1.0),
    "sym_ratio":    lambda df: df["fwd_pkts"].to_numpy() / (df["bwd_pkts"].to_numpy() + 1.0),
    "pkt_cv_sq":    lambda df: (df["pkt_std"].to_numpy() / (df["pkt_len_mean"].to_numpy() + 1.0)) ** 2,
}

# ── Bucketing helpers ─────────────────────────────────────────────────────────

def _finite(v: np.ndarray) -> np.ndarray:
    return v.astype(np.float64)[np.isfinite(v.astype(np.float64))]


def _quantile_bounds(values: np.ndarray, n: int) -> np.ndarray:
    v = _finite(values)
    if len(v) == 0:
        raise ValueError("empty finite values")
    return np.percentile(v, np.linspace(0, 100, n + 1)[1:-1])


def _bucket(values: np.ndarray, bounds: np.ndarray) -> np.ndarray:
    return np.searchsorted(bounds, values.astype(np.float64), side="right").astype(np.float32)


def _protocol_cat3(values: np.ndarray) -> np.ndarray:
    v = values.astype(np.int64)
    return np.where(v == 6, 0, np.where(v == 17, 1, 2)).astype(np.float32)

# ── Bounds store ──────────────────────────────────────────────────────────────

@dataclass
class BoundsStore:
    data: dict[str, dict[int, np.ndarray]] = field(default_factory=dict)

    def compute(self, train_df: pl.DataFrame, ns: list[int]) -> None:
        for feat, extractor in FEATURE_EXTRACTORS.items():
            raw = extractor(train_df)
            self.data[feat] = {n: _quantile_bounds(raw, n) for n in ns}

    def get(self, feat: str, n: int) -> np.ndarray:
        return self.data[feat][n]

# ── Feature builder ───────────────────────────────────────────────────────────

def add_bucket_features(df: pl.DataFrame, store: BoundsStore, n_map: dict[str, int]) -> pl.DataFrame:
    new_cols: list[pl.Series] = []
    for feat, n in n_map.items():
        raw = FEATURE_EXTRACTORS[feat](df)
        if feat == "protocol" and n == -1:
            new_cols.append(pl.Series("protocol_cat3", _protocol_cat3(raw)))
        else:
            new_cols.append(pl.Series(f"{feat}_{n}b", _bucket(raw, store.get(feat, n))))
    return df.with_columns(new_cols)


def col_name(feat: str, n: int) -> str:
    return "protocol_cat3" if (feat == "protocol" and n == -1) else f"{feat}_{n}b"

# ── Variant definitions ───────────────────────────────────────────────────────

_ALL = ["protocol", "pkt_len_mean", "fwd_max_q", "sym_ratio", "pkt_cv_sq"]


@dataclass(frozen=True)
class Variant:
    name: str
    description: str
    n_map: dict[str, int]

    @property
    def table_size(self) -> int:
        s = 1
        for n in self.n_map.values():
            s *= 3 if n == -1 else n
        return s

    @property
    def feature_cols(self) -> list[str]:
        return [col_name(feat, n) for feat, n in self.n_map.items()]


VARIANTS: list[Variant] = [
    Variant("D_n2_baseline",   "N=2 all; 32-entry（部署 contract）",     {f: 2 for f in _ALL}),
    Variant("E_n4_all",        "N=4 all; 1024-entry",                    {f: 4 for f in _ALL}),
    Variant("E_n8_all",        "N=8 all; 32768-entry",                   {f: 8 for f in _ALL}),
    Variant("F_n4ratio_n2abs", "ratio×3 N=4 + abs×2 N=2; 256-entry",
            {"protocol": 2, "pkt_len_mean": 2, "fwd_max_q": 4, "sym_ratio": 4, "pkt_cv_sq": 4}),
    Variant("G_proto3_n4rest", "protocol 3-cat + mean N=2 + ratio×3 N=4; 384-entry",
            {"protocol": -1, "pkt_len_mean": 2, "fwd_max_q": 4, "sym_ratio": 4, "pkt_cv_sq": 4}),
]

# ── Score-table mode ──────────────────────────────────────────────────────────

def _bucket_counts(n_map: dict[str, int]) -> list[int]:
    return [3 if n == -1 else n for n in n_map.values()]


def build_score_table(model: IsolationForest, scaler: StandardScaler,
                      n_map: dict[str, int]) -> np.ndarray:
    counts = _bucket_counts(n_map)
    combos = np.array(list(product(*[range(c) for c in counts])), dtype=np.float32)
    scores = -model.score_samples(scaler.transform(combos))
    return scores.astype(np.float64)


def encode_bucket_indices(x: np.ndarray, n_map: dict[str, int]) -> np.ndarray:
    counts = _bucket_counts(n_map)
    idx = np.zeros(len(x), dtype=np.int64)
    for i, c in enumerate(counts):
        idx = idx * c + x[:, i].astype(np.int64)
    return idx


def _score_df(df: pl.DataFrame, feat_cols: list[str], score_table: np.ndarray,
              n_map: dict[str, int]) -> tuple[np.ndarray, np.ndarray]:
    """Return (finite_mask, scores) for rows in df."""
    x = df.select(feat_cols).to_numpy().astype(np.float32)
    mask = np.isfinite(x).all(axis=1)
    x_f = x[mask]
    idx = np.clip(encode_bucket_indices(x_f, n_map), 0, len(score_table) - 1)
    return mask, score_table[idx]


def _fit_variant(train_df: pl.DataFrame, feat_cols: list[str],
                 n_map: dict[str, int]) -> tuple[np.ndarray, StandardScaler, IsolationForest]:
    """Fit scaler+IF on train_df; return (train_scores, scaler, model)."""
    x = train_df.select(feat_cols).to_numpy().astype(np.float32)
    x = x[np.isfinite(x).all(axis=1)]
    scaler = StandardScaler()
    model  = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination=float(CONTAMINATION),
        random_state=SEED,
        n_jobs=-1,
    )
    model.fit(scaler.fit_transform(x))
    table = build_score_table(model, scaler, n_map)
    _, train_scores = _score_df(train_df, feat_cols, table, n_map)
    return train_scores, scaler, model

# ── CIC per-attack eval loader ────────────────────────────────────────────────

def _load_cic_per_attack(paths: list[str], n_per_label: int) -> dict[str, pl.DataFrame]:
    """For each 01-12 file, load BENIGN + main attack (column-pruned to avoid OOM).

    Returns dict: attack_label → DataFrame with 'Label' column.
    """
    available: set[str] | None = None
    result: dict[str, pl.DataFrame] = {}
    for path in paths:
        if available is None:
            available = set(pl.scan_parquet(path).collect_schema().names())
        cols = [c for c in _CIC_COLS if c in available]
        df = (
            pl.scan_parquet(path)
            .select(cols)
            .with_columns(pl.col("Label").cast(pl.String).str.to_uppercase())
            .collect()
        )
        attacks = [l for l in df["Label"].unique().to_list() if l != "BENIGN"]
        if not attacks:
            continue
        # pick the label with the most rows as the "main" attack
        attack = max(attacks, key=lambda l: int((df["Label"] == l).sum()))
        sub = df.filter(pl.col("Label").is_in(["BENIGN", attack]))
        chunks = []
        for label in ["BENIGN", attack]:
            rows = sub.filter(pl.col("Label") == label)
            if len(rows):
                chunks.append(rows.sample(min(n_per_label, len(rows)), seed=SEED))
        if chunks:
            result[attack] = pl.concat(chunks)
    return result

# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    sep = "=" * 100
    print(sep)
    print("Run 30 — N-sweep (CIC-only): AUC × FPR × overfit check")
    print(sep)

    # ── Data loading ─────────────────────────────────────────────────────────
    print("\n[0] Loading data")
    cic_train = to_norm_cic(
        get_normal_sample_from_files(CIC_TRAIN_PATHS, n=N_TRAIN_PER_SOURCE, seed=SEED)
    )
    print(f"  BENIGN train : {len(cic_train):>6} rows  ({len(CIC_TRAIN_PATHS)} files, 03-11)")

    per_attack_raw  = _load_cic_per_attack(CIC_TEST_PATHS, N_EVAL_PER_LABEL)
    per_attack_norm = {k: to_norm_cic(v) for k, v in per_attack_raw.items()}
    attack_names    = sorted(per_attack_norm.keys())
    for name in attack_names:
        df = per_attack_norm[name]
        nb = int((df["Label"] == "BENIGN").sum())
        na = int((df["Label"] != "BENIGN").sum())
        print(f"  {name:<22}  BENIGN={nb:>4}  attack={na:>4}")

    # ── Compute quantile boundaries on BENIGN train ──────────────────────────
    store = BoundsStore()
    store.compute(cic_train, [2, 4, 8])

    print("\n[1] Variant definitions")
    for v in VARIANTS:
        print(f"  {v.name:<25}  table={v.table_size:<6}  {v.description}")

    # ── Pre-compute bucketed features ────────────────────────────────────────
    train_feat: dict[frozenset, pl.DataFrame] = {}
    eval_feat:  dict[frozenset, dict[str, pl.DataFrame]] = {}
    for v in VARIANTS:
        key = frozenset(v.n_map.items())
        if key not in train_feat:
            train_feat[key] = add_bucket_features(cic_train, store, v.n_map)
            eval_feat[key]  = {
                name: add_bucket_features(df, store, v.n_map)
                for name, df in per_attack_norm.items()
            }

    # ── Section 2: AUC-ROC matrix ────────────────────────────────────────────
    COL_W = 13
    print("\n[2] AUC-ROC matrix")
    hdr = f"{'Variant':<25}{'Table':>7}" + "".join(f"{n[:11]:>{COL_W}}" for n in attack_names) + f"{'Avg':>9}"
    print(hdr); print("-" * len(hdr))

    # Caches for later sections
    # all_auc[variant][attack] = float
    # stored[variant][attack]  = (y_true, eval_scores, train_benign_scores, eval_benign_scores)
    all_auc:    dict[str, dict[str, float]] = {}
    stored:     dict[str, dict[str, tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]]] = {}

    for v in VARIANTS:
        key = frozenset(v.n_map.items())
        row_auc: dict[str, float] = {}
        row_sto: dict[str, tuple] = {}

        train_scores, scaler, model = _fit_variant(train_feat[key], v.feature_cols, v.n_map)
        score_table = build_score_table(model, scaler, v.n_map)

        row = f"{v.name:<25}{v.table_size:>7}"
        for attack in attack_names:
            eval_df = eval_feat[key][attack]
            y_raw   = (eval_df["Label"] != "BENIGN").cast(pl.Int8).to_numpy()
            try:
                mask, eval_scores = _score_df(eval_df, v.feature_cols, score_table, v.n_map)
                y = y_raw[mask]
                if y.sum() == 0 or y.sum() == len(y):
                    raise ValueError("single class after nan mask")
                auc = float(roc_auc_score(y, eval_scores))
                row_auc[attack] = auc
                train_benign_scores = train_scores                    # all train rows are BENIGN
                eval_benign_scores  = eval_scores[y == 0]
                row_sto[attack] = (y, eval_scores, train_benign_scores, eval_benign_scores)
                row += f"{auc:>{COL_W}.4f}"
            except Exception as exc:
                row += f"{'ERR':>{COL_W}}"
                print(f"\n  [WARN] {v.name} / {attack}: {exc}")

        valid = list(row_auc.values())
        avg   = sum(valid) / len(valid) if valid else float("nan")
        row_auc["Avg"] = avg
        row += f"{avg:>9.4f}"
        all_auc[v.name] = row_auc
        stored[v.name]  = row_sto
        print(row)

    # ── Section 3: Delta vs baseline ─────────────────────────────────────────
    print("\n[3] Delta vs D_n2_baseline")
    baseline = all_auc.get("D_n2_baseline", {})
    dhdr = f"{'Variant':<25}" + "".join(f"{n[:11]:>{COL_W}}" for n in attack_names) + f"{'Avg':>9}"
    print(dhdr); print("-" * len(dhdr))
    for v in VARIANTS[1:]:
        row = f"{v.name:<25}"
        for attack in attack_names:
            d = all_auc[v.name].get(attack, float("nan")) - baseline.get(attack, float("nan"))
            row += f"{d:>+{COL_W}.4f}"
        d_avg = all_auc[v.name].get("Avg", float("nan")) - baseline.get("Avg", float("nan"))
        row += f"{d_avg:>+9.4f}"
        print(row)

    # ── Section 4: Detection metrics at Youden-J threshold ───────────────────
    print("\n[4] Detection metrics — Youden-J optimal threshold（averaged across attack types）")
    m4h = (f"{'Variant':<25}{'AUC':>8}{'Accuracy':>10}"
           f"{'FPR誤報':>10}{'FNR漏報':>10}{'Precision':>11}{'F1':>8}")
    print(m4h); print("-" * len(m4h))
    for v in VARIANTS:
        vals: dict[str, list[float]] = {k: [] for k in
                                        ["auc", "accuracy", "fpr", "fnr", "precision", "f1"]}
        for attack, (y, ev_sc, *_) in stored[v.name].items():
            try:
                m = detection_metrics(y, ev_sc)
                for k in vals:
                    vals[k].append(m[k])
            except Exception:
                pass
        if not vals["auc"]:
            continue
        a = {k: sum(lst) / len(lst) for k, lst in vals.items() if lst}
        print(f"{v.name:<25}{a['auc']:>8.4f}{a['accuracy']:>10.4f}"
              f"{a['fpr']:>10.4f}{a['fnr']:>10.4f}{a['precision']:>11.4f}{a['f1']:>8.4f}")

    # ── Section 5: Threshold at FPR ≤ 1% ─────────────────────────────────────
    print("\n[5] Threshold at FPR ≤ 1%（D_n2_baseline）")
    print(f"  {'Attack':<22}  {'Threshold':>10}  {'FPR':>7}  {'TPR':>7}  {'Accuracy':>9}")
    print("  " + "-" * 60)
    for attack, (y, ev_sc, *_) in stored["D_n2_baseline"].items():
        try:
            t  = threshold_at_fpr(y, ev_sc, target_fpr=0.01)
            m  = detection_metrics(y, ev_sc, threshold=t)
            print(f"  {attack:<22}  {t:>10.4f}  {m['fpr']:>7.4f}  {m['tpr']:>7.4f}  {m['accuracy']:>9.4f}")
        except Exception:
            pass

    # ── Section 6: Overfit check ──────────────────────────────────────────────
    print("\n[6] Overfit check（train BENIGN vs test BENIGN anomaly score distribution）")
    print("  mean_gap > 0  →  test BENIGN 被評估為比訓練資料更異常（可能 overfit 或 distribution shift）")
    print("  pct_overlap  ：CDF 相似度，< 0.70 表示明顯分布差異")
    of_h = (f"  {'Variant':<25}{'mean_tr':>9}{'mean_te':>9}"
            f"{'gap':>8}{'std_ratio':>11}{'pct_ovlp':>10}{'severity':<10}")
    print(of_h); print("  " + "-" * (len(of_h) - 2))
    for v in VARIANTS:
        gaps, stds, ovlps, m_trs, m_tes = [], [], [], [], []
        sevs: list[str] = []
        for attack, (_, _, tr_ben, ev_ben) in stored[v.name].items():
            if len(tr_ben) < 10 or len(ev_ben) < 10:
                continue
            r = overfit_check(tr_ben, ev_ben)
            gaps.append(r["mean_gap"])
            stds.append(r["std_ratio"])
            ovlps.append(r["pct_overlap"])
            m_trs.append(r["mean_train"])
            m_tes.append(r["mean_test"])
            sevs.append(str(r["severity"]))
        if not gaps:
            continue
        avg = lambda lst: sum(lst) / len(lst)
        worst = max(sevs, key=lambda s: ["none", "mild", "moderate", "severe"].index(s))
        print(f"  {v.name:<25}{avg(m_trs):>9.4f}{avg(m_tes):>9.4f}"
              f"{avg(gaps):>8.4f}{avg(stds):>11.4f}{avg(ovlps):>10.4f}  {worst}")

    # ── Section 7: Summary ───────────────────────────────────────────────────
    print("\n[7] Summary")
    print("  eBPF 可行 table 上限：256-entry（F_n4ratio_n2abs）")
    print("  FPR 誤報率是防火牆最關鍵指標：目標 < 1%")
    print("  Overfit 指標：mean_gap > 0.05 或 pct_overlap < 0.70 需重新評估訓練資料")
    print("  Protocol 在 Mixed BENIGN 以 TCP 主導（N=4 邊界退化），HOIC 無法靠 protocol 分離")


if __name__ == "__main__":
    main()