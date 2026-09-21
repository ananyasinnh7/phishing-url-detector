"""Model training and deterministic artifact bootstrap."""
from __future__ import annotations

from pathlib import Path
import json
import joblib
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from .features import FEATURE_NAMES, extract_features

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "sample_urls.csv"
ARTIFACT_DIR = ROOT / "artifacts"
MODEL_PATH = ARTIFACT_DIR / "url_model.joblib"
META_PATH = ARTIFACT_DIR / "metadata.json"


def label_value(value: object) -> int:
    text = str(value).strip().lower()
    return 1 if text in {"1", "true", "phishing", "malicious", "suspicious", "bad"} else 0


def train_model(data_path: Path = DATA_PATH) -> dict:
    frame = pd.read_csv(data_path)
    if "url" not in frame.columns:
        raise ValueError("Dataset must contain a url column")
    label_column = next((c for c in ["label", "type", "status"] if c in frame.columns), None)
    if not label_column:
        raise ValueError("Dataset must contain label, type, or status")
    x = pd.DataFrame([extract_features(str(url)) for url in frame["url"]])[FEATURE_NAMES]
    y = frame[label_column].map(label_value)
    model = Pipeline([("scale", StandardScaler()), ("classifier", LogisticRegression(random_state=42, max_iter=1000))])
    model.fit(x, y)
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    META_PATH.write_text(json.dumps({"feature_names": FEATURE_NAMES}, indent=2))
    return {"model": model, "rows": len(frame)}


def ensure_model():
    if not MODEL_PATH.exists() or not META_PATH.exists():
        train_model()
    return joblib.load(MODEL_PATH)
