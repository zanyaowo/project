"""單棵 Isolation Tree：遞迴隨機分割、path length 計算。"""
import numpy as np


class _Node:
    def __init__(self):
        self.feature_idx = None
        self.split_value = None
        self.left  = None
        self.right = None
        self.size  = None   # leaf 才有意義


class IsolationTree:
    def __init__(self, height_limit: int):
        pass

    def fit(self, X: np.ndarray) -> "IsolationTree":
        pass

    def path_length(self, x: np.ndarray) -> float:
        pass

    def _build(self, X: np.ndarray, current_height: int) -> _Node:
        pass

    def _path_length_node(self, node: _Node, x: np.ndarray, current_height: int) -> float:
        pass
