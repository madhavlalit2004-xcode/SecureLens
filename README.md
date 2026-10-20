# SecureLens

SecureLens is a local-first security review workbench for configuration text and software delivery evidence. It combines deterministic checks with a phase-aware assessment draft so a human reviewer can investigate findings and decide what to do next.

> SecureLens is a first-pass review aid. Findings, control mappings, threat signals, and suggested actions require human validation. A clean result does not prove that a system is secure.

## What it does

- Scans text for hardcoded secret-like values, private keys, insecure HTTP URLs, disabled TLS verification, enabled debug mode, and permissive CORS.
- Runs a LangGraph assessment workflow for the requirements, design, development, testing, deployment, and operations phases.
- Produces a risk label, evidence-linked findings, draft threat signals, selected control mappings, retrieved policy context, and suggested review actions.
- Accepts pasted evidence or `.txt`, `.md`, `.csv`, `.json`, `.pdf`, `.docx`, and `.xlsx` files in the assessment workflow. Uploads are limited to 10 MB.
- Uses a React and TypeScript interface with a FastAPI backend.
- Can use a local Ollama model for an advisory narrative and local embeddings. The model does not set deterministic findings or approve a security gate. Without Ollama, the assessment continues with its deterministic pipeline and lexical retrieval.
- Saves assessment history, review decisions, remediation actions, and uploaded knowledge documents to a local SQLite database by default.

The built-in knowledge base contains a small set of illustrative policy snippets. Control mappings and retrieved excerpts are not a complete implementation or certification of OWASP ASVS, NIST SSDF, or any other framework.

## Requirements

- Python 3.10 or newer
- Node.js and npm
- Ollama is optional. To enable local model drafting and embeddings, install Ollama and pull the models configured in `.env.example`.

## Run locally

From the repository root, create and activate a virtual environment, then install the backend dependencies:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Start the API in the first terminal:

```powershell
fastapi dev app/main.py --port 8010
```

In a second terminal, install and start the frontend:

```powershell
cd frontend
npm install
npm run dev
```

Open the Vite URL shown in the terminal (normally `http://localhost:5173`). The frontend uses `http://127.0.0.1:8010/api` by default.

To use a different API base URL, set `VITE_API_BASE_URL` before starting Vite. It should point to the API prefix, such as `https://your-api.example.com/api`:

```powershell
$env:VITE_API_BASE_URL = "https://your-api.example.com/api"
npm run dev
```

The API's CORS configuration currently allows the default local Vite origins. Update it before hosting the frontend at another origin.

## Optional local Ollama setup

Copy `.env.example` to `.env` and adjust the model names if needed. The defaults use Ollama at `http://127.0.0.1:11434`, with `llama3.2` for the advisory review and `nomic-embed-text` for embeddings. Pull those models in Ollama before using them. If Ollama is unavailable, the app reports that status and continues without model-generated text or embeddings.

## Data handling

In the default local setup, the browser sends assessment text or an uploaded file to the local FastAPI API. Assessment results and uploaded knowledge documents are stored in the SQLite database at `data/securelens.db` by default. The optional Ollama calls also target a local service by default. If you point the frontend or Ollama configuration at another machine, submitted content may be sent to that machine. Do not use real credentials or sensitive production evidence in a public demo.

## API overview

- `GET /api/health` — service health
- `POST /api/scan` — deterministic scan
- `POST /api/review` — risk label and analyst brief
- `POST /api/assessments` — assessment from text
- `POST /api/assessments/upload` — assessment from an uploaded document
- `POST /api/knowledge/documents` — add a local policy document to the knowledge base
- `GET /api/assessments/{assessment_id}` — retrieve an assessment and its review state
- `POST /api/assessments/{assessment_id}/review` — record a human review decision
- `PATCH /api/remediations/{action_id}` — update a remediation action

Interactive API documentation is available at `http://127.0.0.1:8010/docs` while the local API is running.

## Verify

Run the backend tests and build the frontend:

```powershell
py -m pytest -q
cd frontend
npm run build
```

