"""IsolationForestTrainer：無監督異常偵測，以 BENIGN 資料學習正常行為邊界。"""
import numpy as np
import polars as pl
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from service.model.pipeline.trainer.base import BaseTrainer


class IsolationForestTrainer(BaseTrainer):
    """
    訓練策略：
    - 預設只用 BENIGN 資料訓練（純正常行為建模）
    - anomaly_score = -model.score_samples(X)，值越大越可疑
    - threshold = quantile(train_scores, 1 - contamination)
    """

    def __init__(
        self,
        n_estimators: int = 200,
        contamination: float = 0.01,
        seed: int = 42,
        feature_cols: list[str] | None = None,
    ) -> None:
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.seed = seed
        self._forced_feature_cols = feature_cols

        self._scaler: StandardScaler | None = None
        self._model: IsolationForest | None = None
        self._feature_cols: list[str] = []
        self._threshold: float = 0.0

    # ── 主流程 ────────────────────────────────────────────────

    def fit(self, df: pl.DataFrame) -> None:
        """
        df 應為 BENIGN-only 資料（由 train.py 用 get_normal_sample_from_files 傳入）。
        """
        self._feature_cols = (
            [c for c in self._forced_feature_cols if c in df.columns]
            if self._forced_feature_cols is not None
            else self.resolve_feature_cols(df)
        )
        print(f"      特徵數：{len(self._feature_cols)}")

        X = df.select(self._feature_cols).to_numpy().astype(np.float32)

        self._scaler = StandardScaler()
        X = self._scaler.fit_transform(X)

        print(f"      訓練 IsolationForest（n_estimators={self.n_estimators}）...")
        self._model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=float(self.contamination),  # type: ignore[arg-type]
            random_state=self.seed,
            n_jobs=-1,
        )
        self._model.fit(X)

        scores = -self._model.score_samples(X)
        self._threshold = float(np.quantile(scores, 1.0 - self.contamination))
        alert_count = int((scores > self._threshold).sum())
        print(f"      訓練集 anomaly score 分位：p50={np.median(scores):.4f}, p99={np.quantile(scores,0.99):.4f}")
        print(f"      threshold={self._threshold:.6f}，訓練集觸發告警：{alert_count} / {len(scores)}")

    # ── 推論工具（供 infer.py 呼叫）──────────────────────────

    def score(self, df: pl.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        """
        回傳 (anomaly_scores, is_alert)。
        anomaly_score 越高越可疑；is_alert = score > threshold。
        """
        assert self._model is not None, "請先呼叫 fit()"
        X = df.select(self._feature_cols).to_numpy().astype(np.float32)
        X = self._scaler.transform(X)
        scores = -self._model.score_samples(X)
        is_alert = scores > self._threshold
        return scores, is_alert

    # ── 序列化 ────────────────────────────────────────────────

    def bundle(self) -> dict:
        return {
            "model_type": "if",
            "scaler": self._scaler,
            "model": self._model,
            "meta": {
                "feature_cols": self._feature_cols,
                "threshold": self._threshold,
                "contamination": self.contamination,
            },
        }
