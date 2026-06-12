"""BaseTrainer：定義訓練器的共用介面與工具方法。"""
from abc import ABC, abstractmethod

import polars as pl
import polars.selectors as cs

from service.model.schema import ID_COLS, FEATURE_COLS


class BaseTrainer(ABC):

    @abstractmethod
    def fit(self, df: pl.DataFrame) -> None:
        """以傳入的 DataFrame 訓練模型。"""

    @abstractmethod
    def bundle(self) -> dict:
        """回傳可序列化的 dict，供 joblib.dump 使用。
        必須包含 "model_type" 鍵，以便 infer.py 自動偵測。
        """

    def save(self, path: str) -> None:
        import os
        from joblib import dump
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        dump(self.bundle(), path)
        print(f"模型已儲存 -> {path}")

    # ── 共用工具 ──────────────────────────────────────────────
    @staticmethod
    def resolve_feature_cols(df: pl.DataFrame) -> list[str]:
        """若 schema.FEATURE_COLS 已填入則使用，否則自動選所有數值欄位（排除 ID_COLS）。"""
        if FEATURE_COLS:
            available = set(df.columns)
            return [c for c in FEATURE_COLS if c in available]
        num_cols = df.select(cs.numeric()).columns
        return [c for c in num_cols if c not in ID_COLS]