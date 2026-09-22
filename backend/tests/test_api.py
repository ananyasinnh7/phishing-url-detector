from fastapi.testclient import TestClient
from unittest.mock import patch
from app.main import app
from app.features import extract_features, normalize_url, FEATURE_NAMES

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


def test_evaluation_data_shape():
    response = client.get("/evaluation-data")
    assert response.status_code == 200
    body = response.json()
    assert {"dataset", "dataset_note", "feature_names", "segment_options", "summary", "rows"} <= body.keys()
    assert body["segment_options"][0] == "All"
    assert {"total_rows", "accuracy", "error_count", "error_rate", "average_score", "confusion_matrix", "segment_counts"} <= body["summary"].keys()
    assert body["summary"]["total_rows"] == len(body["rows"])
    assert body["rows"]
    row = body["rows"][0]
    assert {"url", "actual_label", "predicted_label", "score", "error_flag", "segment", "feature_values"} <= row.keys()
    assert set(row["feature_values"].keys()) == set(FEATURE_NAMES)


def test_evaluation_data_model_errors_are_clean():
    with patch("app.main.ensure_model", side_effect=RuntimeError("/tmp/model-break")):
        response = client.get("/evaluation-data")
    assert response.status_code == 500
    detail = response.json()["detail"]
    assert detail == "Evaluation data could not be generated"
    assert "/" not in detail
