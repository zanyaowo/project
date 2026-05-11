"""全域常數：欄位定義、型別、路徑相關設定。"""

RAW_COLS = []
NUMERIC_RAW_COLS = []
STRING_TO_FLOAT_COLS = ["Flow Bytes/s", "Flow Packets/s"]
ID_COLS = ["Unnamed: 0", "Flow ID", "Source IP", "Destination IP", "Timestamp", "Label"]
FEATURE_COLS = [
    "Destination Port",
    "Fwd Packet Length Mean",
    "Bwd Header Length",
    "Packet Length Mean",
    "Bwd IAT Min",
    "Fwd Packet Length Min",
    "Down/Up Ratio",
    "Fwd Packet Length Max",
    "Bwd IAT Mean",
    "Total Length of Fwd Packets",
    "Flow IAT Mean",
    "Flow Packets/s",
    "Flow IAT Max",
    "Flow IAT Std",
    "Flow Duration",
    "Flow Bytes/s",
    "Fwd Header Length",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "Bwd Packets/s",
    "Fwd IAT Mean",
    "Total Fwd Packets",
    "Flow IAT Min",
    "act_data_pkt_fwd",
    "Protocol",
]

PROTO_MOD = 16    # Protocol hash bucket 數（TCP=6, UDP=17, ICMP=1，16 已足夠）
SERVICE_MOD = 64  # Service hash bucket 數
CLIP_UPPER_PERCENTILE = 0.999
