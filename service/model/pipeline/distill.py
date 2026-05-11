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
  pkt_cv     = Packet Length Std      / Packet Length Mean
  protocol   = Protocol               (直接使用)
  pkt_len_mean = Packet Length Mean   (直接使用)
"""
import json
from pathlib import Path

import numpy as np
import polars as pl

_FEATURE_COLUMN: dict[str, tuple[str, str | None]] = {
    "protocol": ("Protocol", None),
    "pkt_len_mean": ("Packet Length Mean", None),
    "fwd_max_q": ("Fwd Packet Length Max", "Fwd Packet Length Mean"),
    "sym_ratio":  ("Total Fwd Packets",     "Total Bwd Packets"),
    "pkt_cv":     ("Packet Length Std",     "Packet Length Mean"),
}

class DistilledClassifier:
    """
    5-feature binary lookup-table classifier。

    每個特徵與門檻比較得 1 bit，5 bits 組成 score_table 索引。

    Args:
        rules: 從蒸餾 JSON 解析出的 dict。
    """

    def __init__(self, rules: dict) -> None:
        self.threshold: int = rules["threshold"]
        self.bounds: list[dict] = rules["quantile_bounds"]
        self.score_table: np.ndarray = np.array(rules["score_table"], dtype=np.int32)
        expected = 2 ** len(self.bounds)
        if len(self.score_table) != expected:
            raise ValueError(
                f"score_table 長度 {len(self.score_table)} 與 2^{len(self.bounds)}={expected} 不符"
            )

    @classmethod
    def from_json(cls, path: str | Path) -> "DistilledClassifier":
        with open(path) as f:
            return cls(json.load(f))


    # ── 核心推論 ──────────────────────────────────────────────────

    def _build_index(self, df: pl.DataFrame) -> np.ndarray:
        """回傳 shape (N,) 的 0–31 整數索引陣列。"""
        idx = np.zeros(len(df), dtype=np.int64)

        for i, bound in enumerate(self.bounds):
            num_col, den_col = _FEATURE_COLUMN[bound["name"]]
            num = df[num_col].to_numpy(allow_copy=True).astype(np.int64)

            if bound["type"] == "absolute":
                bit = (num > np.int64(bound["value"]))
            elif bound["type"] == "ratio":
                if den_col is None:
                    bit = (num * bound["denom"]) > (bound["numer"])
                else:
                    den = df[den_col].to_numpy(allow_copy=True).astype(np.int64) + 1
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
