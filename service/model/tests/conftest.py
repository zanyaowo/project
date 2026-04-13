"""
Shared fixtures for harness tests.

Tier 1 — feature_cols     : session-scoped, schema constants
Tier 2 — make_benign_df   : factory for synthetic BENIGN data
          make_attack_df   : factory for synthetic attack-shaped data
Tier 3 — trained_if_bundle: module-scoped, small IF trained on synthetic data
Tier 4 — real_parquet_available: sentinel for @pytest.mark.slow gates
"""
import numpy as np
import polars as pl
import pytest

from service.model.schema import FEATURE_COLS


# ── Tier 1 ────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def feature_cols() -> list[str]:
    return list(FEATURE_COLS)


# ── Tier 2 ────────────────────────────────────────────────────────────────────

@pytest.fixture
def make_benign_df(feature_cols):
    """Factory: make_benign_df(n=500, seed=0) -> pl.DataFrame
    均勻分布 [0, 100]，Label="BENIGN"。
    """
    def _factory(n: int = 500, seed: int = 0) -> pl.DataFrame:
        rng = np.random.default_rng(seed)
        # N(50, 5) 與 trained_if_bundle 使用相同分布，確保 FPR 測試有意義
        data = {col: rng.normal(loc=50.0, scale=5.0, size=n).clip(0, 100).tolist()
                for col in feature_cols}
        data["Label"] = ["BENIGN"] * n
        return pl.DataFrame(data)
    return _factory


@pytest.fixture
def make_attack_df(feature_cols):
    """Factory: make_attack_df(n=200, seed=0) -> pl.DataFrame
    IAT 欄位極端大、Bytes 欄位極端大、Down/Up 近零，模擬 DDoS flooding。
    """
    def _factory(n: int = 200, seed: int = 0) -> pl.DataFrame:
        rng = np.random.default_rng(seed)
        data = {}
        for col in feature_cols:
            if "IAT" in col:
                data[col] = rng.uniform(1e6, 1e8, size=n).tolist()
            elif "Bytes" in col:
                data[col] = rng.uniform(1e7, 1e9, size=n).tolist()
            elif "Down/Up" in col:
                data[col] = rng.uniform(0.0, 0.01, size=n).tolist()
            else:
                data[col] = rng.uniform(0.0, 100.0, size=n).tolist()
        data["Label"] = ["DDoS"] * n
        return pl.DataFrame(data)
    return _factory


# ── Tier 3 ────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def trained_if_bundle():
    """小型 IF bundle，module-scoped（每個 test 檔訓練一次）。
    n_estimators=50 加速測試；production 用 200。
    使用 N(50, 5) 窄常態分布訓練，讓 IF 學到緊密邊界，
    確保 1e7/1e8 等攻擊向量明確落在邊界外。
    """
    from service.model.pipeline.trainer.if_ import IsolationForestTrainer
    from service.model.schema import FEATURE_COLS
    rng = np.random.default_rng(42)
    data = {col: rng.normal(loc=50.0, scale=5.0, size=800).clip(0, 100).tolist()
            for col in FEATURE_COLS}
    data["Label"] = ["BENIGN"] * 800
    df = pl.DataFrame(data)
    trainer = IsolationForestTrainer(n_estimators=100, contamination=0.01, seed=42)
    trainer.fit(df)
    return trainer.bundle()


# ── Tier 4 ────────────────────────────────────────────────────────────────────

_REAL_PARQUET_TRAIN = "service/model/dataset/parquet_clean/train"
_REAL_PARQUET_TEST  = "service/model/dataset/parquet_clean/test"

@pytest.fixture(scope="session")
def real_parquet_available() -> bool:
    from pathlib import Path
    train_ok = any(Path(_REAL_PARQUET_TRAIN).glob("*.parquet")) if Path(_REAL_PARQUET_TRAIN).is_dir() else False
    test_ok  = any(Path(_REAL_PARQUET_TEST).glob("*.parquet"))  if Path(_REAL_PARQUET_TEST).is_dir()  else False
    return train_ok and test_ok