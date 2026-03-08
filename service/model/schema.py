"""全域常數：欄位定義、型別、路徑相關設定。"""

RAW_COLS = []
NUMERIC_RAW_COLS = []
STRING_TO_FLOAT_COLS = ["Flow Bytes/s", "Flow Packets/s"]
ID_COLS = ["Unnamed: 0", "Flow ID", "Source IP", "Destination IP", "Timestamp", " Label"]
FEATURE_COLS = []

PROTO_MOD = ...
SERVICE_MOD = ...
CLIP_UPPER_PERCENTILE = 0.999
