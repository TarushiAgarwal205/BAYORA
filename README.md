# Bayora

Bayora is a project for building infrastructure for adversarial LLM security testing. Stage 1 establishes the application layout and a small demo API; its `/test` decision is a fixed demo stub and does not run a real security test.

## Policy

Option A allows Red Team to run explicitly approved security tests while denying access to Blue Team artifacts. Other unapproved operations are denied by default. This policy is recorded but not enforced yet.

## Setup

From the project root, install the pinned dependencies into the existing virtual environment:

```powershell
venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

## Run

```powershell
venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Open the dashboard at <http://127.0.0.1:8000/dashboard/>. Opening `frontend\index.html` directly from disk will not reach the API.

## Test

```powershell
venv\Scripts\python.exe -m pytest -q
```

## Layout

`backend/` contains the FastAPI app and configuration; `frontend/` contains the dashboard; `tests/` contains setup tests. `red/`, `blue/`, `llm/`, `audit/`, `policies/`, `reports/`, and `data/` reserve planned project areas. The `venv/` directory is the existing local Python environment.
