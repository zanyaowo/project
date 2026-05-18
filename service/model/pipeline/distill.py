"""蒸餾規則推論：JSON 規則檔 → 向量化推論（Python 驗證 + 可移植到 eBPF）。

規則格式：
  threshold       : int          告警分數門檻
  quantile_bounds : list[dict]   5 個特徵的二值化規則
  score_table     : list[int]    2^5 = 32 個整數分數

推論邏輯（bit i 對應 bounds[i]）：
  feature_value > 門檻  →  bit = 1，否則 0
  5 個 bit 拼成 0–31 索引  →  score_table[idx]  →  >= threshold 即告警

bounds 型別：
  absolute : 直接比較 feature_value > value
  ratio    : 比較 feature_value > numer / denom

蒸餾特徵與原始欄位對應：
  fwd_max_q  = Fwd Packet Length Max  / Fwd Packet Length Mean
  sym_ratio  = Total Fwd Packets      / Total Bwd Packets
  pkt_cv_sq  = (Packet Length Std / Packet Length Mean)^2；kernel 以 aggregate 統計等價近似，避免 sqrt
  protocol   = Protocol               (直接使用)
  pkt_len_mean = Packet Length Mean   (直接使用)
"""
import json
from pathlib import Path

import numpy as np
import polars as pl

CANONICAL_FEATURE_ORDER = [
    "protocol",
    "pkt_len_mean",
    "fwd_max_q",
    "sym_ratio",
    "pkt_cv_sq",
]

_FEATURE_COLUMN: dict[str, tuple[str, str | None]] = {
    "protocol": ("Protocol", None),
    "pkt_len_mean": ("Packet Length Mean", None),
    "fwd_max_q": ("Fwd Packet Length Max", "Fwd Packet Length Mean"),
    "sym_ratio":  ("Total Fwd Packets",     "Total Bwd Packets"),
    # Contract v1 uses CV^2 to avoid sqrt in eBPF. It is computed specially in
    # _feature_ratio_components() from packet length aggregate statistics.
    "pkt_cv_sq":  ("Packet Length Sum Sq",  "Packet Length Sum"),
}

class DistilledClassifier:
    """
    5-feature binary lookup-table classifier。

    每個特徵與門檻比較得 1 bit，5 bits 組成 score_table 索引。

    Args:
        rules: 從蒸餾 JSON 解析出的 dict。
    """

    def __init__(self, rules: dict) -> None:
        self._validate_contract(rules)
        self.version: int = rules["version"]
        self.feature_order: list[str] = list(rules["feature_order"])
        self.threshold_cmp: str = rules["threshold_cmp"]
        self.score_scale: int = rules["score_scale"]
        self.length_unit: str = rules["length_unit"]
        self.threshold: int = rules["threshold"]
        self.bounds: list[dict] = rules["quantile_bounds"]
        self.score_table: np.ndarray = np.array(rules["score_table"], dtype=np.int32)
        expected = 2 ** len(self.bounds)
        if len(self.score_table) != expected:
            raise ValueError(
                f"score_table 長度 {len(self.score_table)} 與 2^{len(self.bounds)}={expected} 不符"
            )

    @staticmethod
    def _validate_contract(rules: dict) -> None:
        """Validate distilled JSON contract v1 before any scoring happens."""
        checks = {
            "version": 1,
            "feature_order": CANONICAL_FEATURE_ORDER,
            "threshold_cmp": ">=",
            "score_scale": 10000,
            "length_unit": "packet_len",
        }
        for key, expected in checks.items():
            if rules.get(key) != expected:
                raise ValueError(f"distilled rules {key} must be {expected!r}, got {rules.get(key)!r}")

        bounds = rules.get("quantile_bounds")
        if not isinstance(bounds, list) or len(bounds) != len(CANONICAL_FEATURE_ORDER):
            raise ValueError("quantile_bounds must contain exactly 5 entries")
        bound_names = [bound.get("name") for bound in bounds]
        if bound_names != CANONICAL_FEATURE_ORDER:
            raise ValueError(f"quantile_bounds order must be {CANONICAL_FEATURE_ORDER!r}, got {bound_names!r}")

        score_table = rules.get("score_table")
        if not isinstance(score_table, list) or len(score_table) != 2 ** len(CANONICAL_FEATURE_ORDER):
            raise ValueError("score_table must contain exactly 32 entries")

    @classmethod
    def from_json(cls, path: str | Path) -> "DistilledClassifier":
        with open(path) as f:
            return cls(json.load(f))


    # ── 核心推論 ──────────────────────────────────────────────────

    def _feature_ratio_components(self, df: pl.DataFrame, name: str) -> tuple[np.ndarray, np.ndarray | None]:
        """Return integer numerator/denominator components for contract features."""
        if name == "pkt_cv_sq":
            if {"Packet Length Sum Sq", "Packet Length Sum", "Total Packets"}.issubset(set(df.columns)):
                sum_sq = df["Packet Length Sum Sq"].to_numpy(allow_copy=True).astype(np.int64)
                total_pkts = df["Total Packets"].to_numpy(allow_copy=True).astype(np.int64)
                total_len = df["Packet Length Sum"].to_numpy(allow_copy=True).astype(np.int64)
                total_len_sq = total_len * total_len
                numer = (sum_sq * total_pkts) - total_len_sq
                numer = np.maximum(numer, 0)
                return numer, total_len_sq

            std = df["Packet Length Std"].to_numpy(allow_copy=True).astype(np.int64)
            mean = df["Packet Length Mean"].to_numpy(allow_copy=True).astype(np.int64) + 1
            return std * std, mean * mean

        num_col, den_col = _FEATURE_COLUMN[name]
        num = df[num_col].to_numpy(allow_copy=True).astype(np.int64)
        if den_col is None:
            return num, None
        den = df[den_col].to_numpy(allow_copy=True).astype(np.int64) + 1
        return num, den

    def _build_index(self, df: pl.DataFrame) -> np.ndarray:
        """回傳 shape (N,) 的 0–31 整數索引陣列。"""
        idx = np.zeros(len(df), dtype=np.int64)

        for i, bound in enumerate(self.bounds):
            num, den = self._feature_ratio_components(df, bound["name"])

            if bound["type"] == "absolute":
                bit = num > np.int64(bound["value"])
            elif bound["type"] == "ratio":
                if den is None:
                    bit = (num * bound["denom"]) > bound["numer"]
                else:
                    bit = (num * bound["denom"]) > (den * bound["numer"])
            else:
                raise ValueError(f"未知 bound type：{bound['type']!r}")

            idx |= bit.astype(np.int64) << i
        return idx

    def score(self, df: pl.DataFrame) -> np.ndarray:
        """回傳每筆的整數分數，越高越可疑。"""
        return self.score_table[self._build_index(df)]

    def predict(self, df: pl.DataFrame) -> pl.DataFrame:
        """附加 distill_score 與 is_alert 欄到 DataFrame。"""
        scores = self.score(df)
        return df.with_columns([
            pl.Series("distill_score", scores),
            pl.Series("is_alert", scores >= self.threshold),
        ])

    # ── 驗證工具 ──────────────────────────────────────────────────

    def explain_index(self, idx: int) -> dict[str, int]:
        """給定 0–31 索引，回傳各特徵的 bit 值（除錯用）。"""
        return {
            self.bounds[i]["name"]: (idx >> i) & 1
            for i in range(len(self.bounds))
        }

    def summary(self) -> None:
        """印出所有 32 個索引的分數與判定結果。"""
        n = len(self.bounds)
        print(f"threshold={self.threshold}, features={n}")
        print(f"{'idx':>4}  {'bits':>{n}}  {'score':>6}  alert")
        for idx in range(2 ** n):
            bits = format(idx, f"0{n}b")
            score = self.score_table[idx]
            flag = "★" if score >= self.threshold else " "
            print(f"{idx:>4}  {bits}  {score:>6}  {flag}")


# ── CLI / 快速驗證 ────────────────────────────────────────────────

def _run_eval(rules_path: str, data_path: str, sample_n: int = 0) -> None:
    clf = DistilledClassifier.from_json(rules_path)
    clf.summary()

    lf = pl.scan_parquet(data_path) if data_path.endswith(".parquet") else pl.scan_csv(data_path)
    if sample_n:
        lf = lf.collect().sample(sample_n, seed=42).lazy()
    df = lf.collect()

    result = clf.predict(df)
    n_alert = result["is_alert"].sum()
    print(f"\n資料：{len(df)} 筆，告警：{n_alert}（{n_alert/len(df)*100:.1f}%）")

    if "Label" in result.columns:
        from sklearn.metrics import roc_auc_score
        y_true = (result["Label"] != "BENIGN").cast(pl.Int32).to_numpy()
        y_score = result["distill_score"].to_numpy()
        print(f"AUC-ROC：{roc_auc_score(y_true, y_score):.4f}")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="蒸餾規則推論驗證")
    p.add_argument("--rules",  required=True, help="蒸餾規則 JSON 路徑")
    p.add_argument("--data",   required=True, help="輸入 parquet / csv")
    p.add_argument("--sample", type=int, default=0, help="隨機抽樣筆數（0=全部）")
    args = p.parse_args()
    _run_eval(args.rules, args.data, args.sample)
