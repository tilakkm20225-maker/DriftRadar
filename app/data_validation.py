import numpy as np
import pandas as pd
from app.config import MIN_SAMPLES

def dataframe_to_features(frame: pd.DataFrame) -> dict[str, list[float]]:
    if frame.empty:
        raise ValueError("The CSV contains no data rows.")
    if len(frame.columns) == 0:
        raise ValueError("The CSV must contain feature columns.")
    if len(frame) < MIN_SAMPLES:
        raise ValueError(f"At least {MIN_SAMPLES} rows are required; received {len(frame)}.")

    features = {}
    for column in frame.columns:
        name = str(column).strip()
        if not name:
            raise ValueError("Feature column names cannot be empty.")
        if name in features:
            raise ValueError(f"Duplicate feature name: {name}")
        values = pd.to_numeric(frame[column], errors="coerce").to_numpy(dtype=float)
        if not np.isfinite(values).all():
            raise ValueError(f"Feature '{name}' contains missing, non-numeric, or infinite values.")
        features[name] = values.tolist()
    return features

def parse_csv_bytes(raw: bytes) -> dict[str, list[float]]:
    try:
        frame = pd.read_csv(pd.io.common.BytesIO(raw))
    except Exception as exc:
        raise ValueError(f"Could not read CSV: {exc}") from exc
    return dataframe_to_features(frame)
