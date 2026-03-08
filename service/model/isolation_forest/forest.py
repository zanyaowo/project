"""Isolation Forest：聚合多棵樹、計算 anomaly score、存取模型。"""
import numpy as np


class IsolationForest:
    def __init__(self, n_trees: int = 100, subsample_size: int = 256, random_state: int = None):
        pass

    def fit(self, X: np.ndarray) -> "IsolationForest":
        pass

    def anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        pass

    def threshold(self, X: np.ndarray, contamination: float) -> float:
        pass

    def save(self, path: str) -> None:
        pass

    @classmethod
    def load(cls, path: str) -> "IsolationForest":
        pass
