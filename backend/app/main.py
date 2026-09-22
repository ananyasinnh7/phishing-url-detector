"""FastAPI application for safe, offline URL scoring."""
from __future__ import annotations
from collections import Counter

import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from .features import extract_features, normalize_url, FEATURE_NAMES
from .model import ensure_model, DATA_PATH, label_value

app = FastAPI(title="Phishing URL Detector", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"], allow_methods=["*"], allow_headers=["*"])

class URLRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


def _segment_from_features(features: dict[str, float]) -> str:
    if features["has_ip"] > 0:
        return "ip-host"
    if features["is_shortener"] > 0:
        return "shortener"
    if features["uses_https"] == 0:
        return "http-no-tls"
    if features["suspicious_keyword_count"] > 0:
        return "keyword-risk"
    return "standard-https"


def _label_name(value: object) -> str:
    return "suspicious" if label_value(value) == 1 else "safe"

@app.get("/health")
def health():
    ensure_model()
    return {"status": "ok", "service": "phishing-url-detector"}

@app.post("/check-url")
def check_url(request: URLRequest):
    try:
        normalized = normalize_url(request.url)
        features = extract_features(normalized)
        model = ensure_model()
        values = [[features[name] for name in FEATURE_NAMES]]
        probability = float(model.predict_proba(values)[0][1])
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Model is not available") from exc

    suspicious = probability >= 0.5
    rules = [
        ("has_ip", "URL uses an IP address instead of a domain", features["has_ip"] > 0),
        ("uses_https", "URL does not use HTTPS", features["uses_https"] == 0),
        ("suspicious_keyword_count", "URL contains suspicious security or urgency keywords", features["suspicious_keyword_count"] > 0),
        ("is_shortener", "URL uses a link-shortening service", features["is_shortener"] > 0),
        ("special_char_count", "URL contains several obfuscation characters", features["special_char_count"] >= 3),
        ("url_length", "URL is unusually long", features["url_length"] > 100),
        ("subdomain_count", "URL contains multiple subdomains", features["subdomain_count"] >= 2),
    ]
    reasons = [{"feature": name, "message": msg, "impact": "risk"} for name, msg, condition in rules if condition][:5]
    if not reasons:
        reasons = [{"feature": "lexical_scan", "message": "No high-risk lexical indicators were found", "impact": "reassuring"}]
    return {"normalized_url": normalized, "verdict": "suspicious" if suspicious else "safe", "score": round(probability, 4), "confidence": round(max(probability, 1 - probability), 4), "reasons": reasons}


@app.get("/evaluation-data")
def evaluation_data():
    try:
        model = ensure_model()
        frame = pd.read_csv(DATA_PATH)
        if "url" not in frame.columns:
            raise ValueError("missing_url")
        label_column = next((name for name in ("label", "type", "status") if name in frame.columns), None)
        if not label_column:
            raise ValueError("missing_label")
        frame = frame.dropna(subset=["url"]).reset_index(drop=True)
        extracted = [extract_features(str(url)) for url in frame["url"]]
        values = [[features[name] for name in FEATURE_NAMES] for features in extracted]
        probabilities = model.predict_proba(values)[:, 1] if values else []
    except ValueError as exc:
        if str(exc) in {"missing_url", "missing_label"}:
            raise HTTPException(status_code=500, detail="Evaluation dataset is not in the expected format") from exc
        raise HTTPException(status_code=500, detail="Evaluation data could not be generated") from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Evaluation data could not be generated") from exc

    rows = []
    confusion = Counter()
    segment_counts = Counter()
    error_count = 0
    for idx, item in frame.iterrows():
        features = {name: float(extracted[idx][name]) for name in FEATURE_NAMES}
        actual_label = _label_name(item[label_column])
        predicted_label = "suspicious" if float(probabilities[idx]) >= 0.5 else "safe"
        error_flag = actual_label != predicted_label
        segment = _segment_from_features(features)
        rows.append({
            "url": str(item["url"]),
            "actual_label": actual_label,
            "predicted_label": predicted_label,
            "score": round(float(probabilities[idx]), 4),
            "error_flag": error_flag,
            "segment": segment,
            "feature_values": features,
        })
        confusion[(actual_label, predicted_label)] += 1
        segment_counts[segment] += 1
        error_count += int(error_flag)

    total_rows = len(rows)
    accuracy = 0.0 if total_rows == 0 else round((total_rows - error_count) / total_rows, 4)
    average_score = 0.0 if total_rows == 0 else round(sum(row["score"] for row in rows) / total_rows, 4)
    return {
        "dataset": "sample_urls.csv",
        "dataset_note": "Bundled sample evaluation dataset. Offline lexical evaluation only.",
        "feature_names": FEATURE_NAMES,
        "segment_options": ["All", *sorted(segment_counts.keys())],
        "summary": {
            "total_rows": total_rows,
            "accuracy": accuracy,
            "error_count": error_count,
            "error_rate": 0.0 if total_rows == 0 else round(error_count / total_rows, 4),
            "average_score": average_score,
            "confusion_matrix": {
                "actual_safe_predicted_safe": confusion[("safe", "safe")],
                "actual_safe_predicted_suspicious": confusion[("safe", "suspicious")],
                "actual_suspicious_predicted_safe": confusion[("suspicious", "safe")],
                "actual_suspicious_predicted_suspicious": confusion[("suspicious", "suspicious")],
            },
            "segment_counts": dict(segment_counts),
        },
        "rows": rows,
    }
