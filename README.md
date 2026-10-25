# Bayora

Bayora is a local prototype for adversarial LLM security testing. The current prototype includes a rules-based policy gateway, SQLite audit events, and a separate Blue Team service that stores one synthetic protected resource. It does not yet include a Red Team runner, a client LLM, Docker isolation, or production authentication.

## Policy and resource access

Rules are stored in `policies/rules.json`. Exact and prefix matches are supported; deny rules take precedence and unmatched requests default to DENY. Missing or invalid rules fail closed. Roles are self-declared by the caller, so this is not identity authentication.

- `POST /policy/decide` evaluates and records a policy decision only. It does not execute an operation; its audit outcome remains `NOT_EXECUTED` and verification remains `NOT_VERIFIED`.
- `POST /resource/read` evaluates the same policy before requesting the Blue service. A denied request is audited and never calls the resource service. An allowed request is recorded as pending before the gateway makes its authenticated service call.
- Blue serves only `blue:synthetic-confidential`, a clearly labelled dummy fixture with no real personal information. Direct service calls require the shared `BAYORA_BLUE_SERVICE_TOKEN`; a caller-provided role header is not accepted as authorization.
- A successful gateway response is returned only after the resource ID and content digest match the fixture's expected values. Audit fields separately record the policy decision, whether the read was observed as executed, the outcome, and verification. If the service or audit finalization fails, the gateway withholds the data.
- `GET /policy/rules`, `GET /audit/events`, and `GET /audit/events/{event_id}` expose the current rules and audit events.

Audit data is stored by default at `data/bayora_audit.sqlite3`; set `BAYORA_AUDIT_DB` to choose another path. The audit store adds `operation_executed` to an older database with a non-destructive SQLite column migration. It does not delete or recreate existing records. There is no hash chain or tamper-evident integrity verification.

The existing `POST /test` remains a fixed demo stub and is not a real security test. The dashboard design is unchanged and remains served at `/dashboard/`.

## Setup

From the project root, install the pinned dependencies into the existing virtual environment:

```powershell
venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

The Blue service and gateway must receive the same private `BAYORA_BLUE_SERVICE_TOKEN` in their process environments. Do not put a real token in `.env.example` or commit one. Open two PowerShell sessions in the project root, set that variable privately in each, then run:

```powershell
venv\Scripts\python.exe -m uvicorn blue.service:app --host 127.0.0.1 --port 8001
```

```powershell
venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000/dashboard/>. The internal Blue service listens only on loopback by default and is not exposed to the network by this run command.

## Test

```powershell
venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
git diff --check
```

Tests use temporary SQLite databases and in-process HTTP transports; they do not need a real token or a running Blue service.

## Current limits

- Gateway policy roles remain self-declared. A caller may claim the `blue` role at the gateway; shared-token protection limits direct calls to the Blue service but is not user authentication or robust isolation.
- The fixture and its expected digest are hardcoded prototype data. This is a local demonstration, not general resource protection.
- The shared service token is a basic process-level trust mechanism. No network segmentation, container isolation, rate limiting, or secret rotation is implemented.
- Audit records are SQLite rows without tamper evidence, hash chaining, or an integrity verifier.
- The Red Team runner, Client LLM integration, Docker Compose architecture, and real security controls remain unimplemented.
