"""RandomForestTrainer：有監督多分類，識別各種攻擊類型。"""
import numpy as np
import polars as pl
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import cross_val_score
from sklearn.preprocessing import LabelEncoder, StandardScaler

from service.model.pipeline.trainer.base import BaseTrainer


class RandomForestTrainer(BaseTrainer):

    def __init__(
        self,
        n_estimators: int = 200,
        seed: int = 42,
        cv_folds: int = 5,
    ) -> None:
        self.n_estimators = n_estimators
        self.seed = seed
        self.cv_folds = cv_folds

        self._scaler: StandardScaler | None = None
        self._model: RandomForestClassifier | None = None
        self._le: LabelEncoder | None = None
        self._feature_cols: list[str] = []
        self._cv_f1_mean: float = 0.0
        self._cv_f1_std: float = 0.0

    # ── 主流程 ────────────────────────────────────────────────

    def fit(self, df: pl.DataFrame) -> None:
        self._feature_cols = self.resolve_feature_cols(df)
        print(f"      特徵數：{len(self._feature_cols)}")

        X = df.select(self._feature_cols).to_numpy().astype(np.float32)
        y_raw = df["Label"].to_list()

        self._le = LabelEncoder()
        y = self._le.fit_transform(y_raw)
        classes: list[str] = list(self._le.classes_)  # type: ignore[assignment]
        print(f"      類別（{len(classes)} 種）：{classes}")

        self._scaler = StandardScaler()
        X = self._scaler.fit_transform(X)

        print(f"      訓練 RandomForestClassifier（n_estimators={self.n_estimators}）...")
        self._model = RandomForestClassifier(
            n_estimators=self.n_estimators,
            class_weight="balanced",
            random_state=self.seed,
            n_jobs=-1,
        )

        cv_scores = cross_val_score(
            self._model, X, y, cv=self.cv_folds, scoring="f1_macro", n_jobs=-1
        )
        self._cv_f1_mean = float(cv_scores.mean())
        self._cv_f1_std = float(cv_scores.std())
        print(f"      {self.cv_folds}-fold CV F1 macro: {self._cv_f1_mean:.4f} ± {self._cv_f1_std:.4f}")

        self._model.fit(X, y)
        y_pred = self._model.predict(X)
        print("\n      訓練集 classification report:")
        print(classification_report(y, y_pred, target_names=self._le.classes_))  # type: ignore[arg-type]

    # ── 推論工具（供 infer.py 呼叫）──────────────────────────

    def predict(self, df: pl.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        """回傳 (pred_labels: str array, pred_confidence: float array)。"""
        assert self._model is not None and self._scaler is not None and self._le is not None
        X = df.select(self._feature_cols).to_numpy().astype(np.float32)
        X = self._scaler.transform(X)
        y_pred = self._model.predict(X)
        pred_labels = self._le.inverse_transform(y_pred)
        proba: np.ndarray = np.array(self._model.predict_proba(X))  # type: ignore[arg-type]
        confidence = proba.max(axis=1).astype(np.float32)
        return pred_labels, confidence  # type: ignore[return-value]

    # ── 序列化 ────────────────────────────────────────────────

    def bundle(self) -> dict:
        assert self._le is not None
        classes: list[str] = list(self._le.classes_)  # type: ignore[assignment]
        return {
            "model_type": "rf",
            "scaler": self._scaler,
            "model": self._model,
            "meta": {
                "feature_cols": self._feature_cols,
                "label_encoder": self._le,
                "classes": classes,
                "cv_f1_macro_mean": self._cv_f1_mean,
                "cv_f1_macro_std": self._cv_f1_std,
            },
        }