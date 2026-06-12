import numpy as np

def drop_correlated(X: np.ndarray, feature_names: list[str], threshold: float = 0.9) -> tuple[np.ndarray, list[str]]:
    """移除與其他特徵相關係數 > threshold 的冗餘欄位（保留先出現的）。"""
    corr = np.corrcoef(X, rowvar=False)
    n = len(feature_names)
    to_drop = set()
    dropped_pairs: list[tuple[str, str, float]] = []
    for i in range(n):
        if i in to_drop:
            continue
        for j in range(i + 1, n):
            if j in to_drop:
                continue
            if abs(corr[i, j]) > threshold:
                to_drop.add(j)
                dropped_pairs.append((feature_names[i], feature_names[j], corr[i, j]))

    if dropped_pairs:
        print(f"{'保留':^20} {'捨棄':^20} {'相關係數':^10}")
        print("-" * 52)
        for f1, f2, c in sorted(dropped_pairs, key=lambda x: abs(x[2]), reverse=True):
            print(f"{f1:^20} {f2:^20} {c:^10.4f}")

    keep = [i for i in range(n) if i not in to_drop]
    print(f"\n相關性篩選：{n} → {len(keep)} 個特徵（移除 {len(to_drop)} 個）")
    return X[:, keep], [feature_names[i] for i in keep]