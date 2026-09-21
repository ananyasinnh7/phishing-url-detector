from fastapi.testclient import TestClient
from app.main import app
from app.features import extract_features, normalize_url

client = TestClient(app)

def test_normalization_and_features():
    url = normalize_url("example.com/login")
    features = extract_features(url)
    assert url.startswith("https://")
    assert features["suspicious_keyword_count"] >= 1

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_check_url_shape():
    response = client.post("/check-url", json={"url": "https://example.com"})
    assert response.status_code == 200
    body = response.json()
    assert {"normalized_url", "verdict", "score", "confidence", "reasons"} <= body.keys()
    assert body["verdict"] in {"safe", "suspicious"}
