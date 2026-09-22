# Phishing URL Detector

An explainable, offline-first ML web application that classifies URLs as **safe** or **suspicious** using lexical URL features, scikit-learn, FastAPI, and React/Vite.

> Educational project only. A safe result is not a guarantee that a URL is safe. Do not open suspicious links.

## Structure

- `backend/app/` - FastAPI service, feature extraction, model bootstrap, and explanations
- `backend/data/sample_urls.csv` - small reproducible training dataset
- `backend/tests/` - API and feature tests
- `frontend/` - React/Vite interface with URL scanner and model-evaluation dashboard

## Quick start

### Backend

```bash
cd backend
python -m venv .venv
# macOS/Linux: source .venv/bin/activate
# Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

The API runs at `http://127.0.0.1:8000`. Model artifacts are generated automatically on first startup.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

The UI runs at `http://localhost:5173`. Copy `.env.example` to `.env` to configure `VITE_API_BASE_URL`.

The frontend includes two views:
- **URL Scanner**: existing single-URL lexical scan flow
- **Model Evaluation Dashboard**: interactive KPIs, confusion matrix, feature-level error trends, segment filtering, and evaluated sample rows loaded from the backend

### Tests and training

```bash
cd backend
pytest
python -m app.train --data data/sample_urls.csv
```

## API

`POST /check-url`

```json
{"url":"https://example.com/account"}
```

The response includes `normalized_url`, `verdict`, `score`, `confidence`, and human-readable `reasons`. The service never fetches, resolves, or executes submitted URLs.

`GET /evaluation-data`

Returns offline evaluation results generated from `backend/data/sample_urls.csv` using the local model and lexical features. Each row includes:
- `url`
- `actual_label`
- `predicted_label`
- `score`
- `error_flag`
- `segment`
- `feature_values` (all `FEATURE_NAMES`)

The response also includes summary metadata (`total_rows`, `accuracy`, `error_rate`, `average_score`, confusion counts, and segment counts) for dashboard KPIs. This endpoint is deterministic and does not use network telemetry.

## Dataset format

CSV files should contain a `url` column and one label column named `label`, `type`, or `status`. Supported labels include `safe`/`suspicious`, `benign`/`phishing`, and `0`/`1`, where `1` means suspicious.

Only a tiny sample dataset is included. WHOIS, DNS, and reputation services are optional future enhancements and are intentionally not required for reproducible offline inference.

## Limitations

This is a lexical detector, not a complete threat-intelligence system. Attackers can evade URL heuristics, benign sites can look unusual, and domains can change after training. Never treat the prediction as a security guarantee.
