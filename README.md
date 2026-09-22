# SecureLens

SecureLens is a lightweight security-review tool for finding common security red flags in documents and configuration text.

## Current features

- FastAPI backend with health, scan, and review endpoints
- Deterministic rules for hardcoded secrets, private keys, insecure HTTP URLs, disabled TLS verification, debug mode, and permissive CORS
- LangGraph workflow that assigns an overall risk level (`low`, `medium`, `high`, or `critical`) and analyst brief
- React interface for pasted text or `.txt` uploads, with JSON report export
- Automated API and workflow tests

## Run locally

Create and activate a virtual environment:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
fastapi dev app/main.py --port 8010
```

In a second terminal, start the frontend:

```powershell
cd frontend
npm install
npm run dev
```

Open the local Vite URL (normally `http://localhost:5173`). The frontend calls the API at `http://127.0.0.1:8010`.

To point the frontend at another API, set `VITE_API_URL` to its `/api/review` endpoint before starting Vite.

## Scope

SecureLens is a deterministic first-pass review aid, not a substitute for a full security assessment. It never uploads content itself; the browser sends review text only to the configured API endpoint.

## Verify

```powershell
py -m pytest -q
cd frontend
npm run build
```
