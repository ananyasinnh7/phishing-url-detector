# Phishing URL Detector

An explainable, offline-first ML web application that classifies URLs as **safe** or **suspicious** using lexical URL features, scikit-learn, FastAPI, and React/Vite.

> Educational project only. A safe result is not a guarantee that a URL is safe. Do not open suspicious links.

## Structure

- `backend/app/` - FastAPI service, feature extraction, model bootstrap, and explanations
- `backend/data/sample_urls.csv` - small reproducible training dataset
- `backend/tests/` - API and feature tests
- `frontend/` - React/Vite interface

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

## Dataset format

CSV files should contain a `url` column and one label column named `label`, `type`, or `status`. Supported labels include `safe`/`suspicious`, `benign`/`phishing`, and `0`/`1`, where `1` means suspicious.

Only a tiny sample dataset is included. WHOIS, DNS, and reputation services are optional future enhancements and are intentionally not required for reproducible offline inference.

## Limitations

This is a lexical detector, not a complete threat-intelligence system. Attackers can evade URL heuristics, benign sites can look unusual, and domains can change after training. Never treat the prediction as a security guarantee.
