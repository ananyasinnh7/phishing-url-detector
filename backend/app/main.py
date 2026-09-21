"""FastAPI application for safe, offline URL scoring."""
from __future__ import annotations
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from .features import extract_features, normalize_url, FEATURE_NAMES
from .model import ensure_model

app = FastAPI(title="Phishing URL Detector", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"], allow_methods=["*"], allow_headers=["*"])

class URLRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)

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
