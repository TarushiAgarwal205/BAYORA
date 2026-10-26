# Bayora

Bayora is a local prototype for adversarial LLM security testing. The current prototype includes a rules-based policy gateway, SQLite audit events, a separate Blue Team service with one synthetic protected resource, a policy-gated OpenRouter client, a fixed local Red Team check runner, and a basic Docker Compose setup. It does not include a complete container sandbox or production authentication.

## Policy and resource access

Rules are stored in `policies/rules.json`. Exact and prefix matches are supported; deny rules take precedence and unmatched requests default to DENY. Missing or invalid rules fail closed. `/resource/read` derives its role from a configured Gateway bearer token; `/policy/decide` and `/llm/generate` still accept caller-declared roles and do not authenticate callers.

- `POST /policy/decide` evaluates and records a policy decision only. It does not execute an operation; its audit outcome remains `NOT_EXECUTED` and verification remains `NOT_VERIFIED`.
- `POST /resource/read` evaluates the same policy before requesting the Blue service. A denied request is audited and never calls the resource service. An allowed request is recorded as pending before the gateway makes its authenticated service call.
- `POST /llm/generate` sends a user prompt to OpenRouter only when `policies/rules.json` allows `generate_client_response` for an explicitly approved test resource. It records the operation in SQLite and returns the model output separately from `security_outcome: NOT_EVALUATED` and `verification_result: NOT_VERIFIED`.
- Blue serves only `blue:synthetic-confidential`, a clearly labelled dummy fixture with no real personal information. Direct service calls require the shared `BAYORA_BLUE_SERVICE_TOKEN`; a caller-provided role header is not accepted as authorization.
- A successful gateway response is returned only after the resource ID and content digest match the fixture's expected values. Audit fields separately record the policy decision, whether the read was observed as executed, the outcome, and verification. If the service or audit finalization fails, the gateway withholds the data.
- `GET /policy/rules`, `GET /audit/events`, and `GET /audit/events/{event_id}` expose the current rules and audit events.

Protected resource reads require `Authorization: Bearer <caller-token>`. The Gateway maps the separate `BAYORA_GATEWAY_RED_TOKEN` and `BAYORA_GATEWAY_BLUE_TOKEN` environment credentials to server-side `red` and `blue` roles. The request body's `role` field remains accepted for compatibility but is ignored by `/resource/read`. Configure two different private values in `.env`; do not reuse `BAYORA_BLUE_SERVICE_TOKEN`. The host Red runner uses these credentials to run its allowed and denied resource cases. This is a prototype shared-token mechanism without user accounts, expiry, rotation, or production-grade identity verification.

Audit data is stored by default at `data/bayora_audit.sqlite3`; set `BAYORA_AUDIT_DB` to choose another path. The audit store adds `operation_executed` to an older database with a non-destructive SQLite column migration. It does not delete or recreate existing records. There is no hash chain or tamper-evident integrity verification.

The existing `POST /test` remains a fixed demo stub and is not a real security test. The dashboard design is unchanged and remains served at `/dashboard/`.

## Controlled Red Team checks

Start the Compose services as described below, then run the predefined local suite from the host:

```powershell
venv\Scripts\python.exe -m red.runner run
```

The runner accepts only HTTP URLs with a loopback IP address and runs four fixed cases: an allowed read of the synthetic fixture, a denied Red read, an invalid test identifier decision, and a policy-denied LLM request. Before the denied resource and LLM cases, it checks policy and audit evidence; if a DENY is not established, it skips that operation. It never calls the Blue service directly. Each report stores sanitized inputs, HTTP status/selected response fields, and audit evidence in the ignored `reports/red-runs/` directory. The allowed read is a positive control and its protected content is not copied into the report.

The `run` command prints a run ID. Retrieve the complete saved report with:

```powershell
venv\Scripts\python.exe -m red.runner show <run-id>
```

Results are `PASS` only when the expected HTTP result agrees with the audit event; missing or ambiguous audit evidence is `INCONCLUSIVE`. This fixed harness checks the current local gateway behavior. It is not a general attack runner or evidence of production security.

## Setup

### Docker Compose

Install and start Docker Desktop, then run these commands from the project root. Set private, distinct `BAYORA_BLUE_SERVICE_TOKEN`, `BAYORA_GATEWAY_RED_TOKEN`, and `BAYORA_GATEWAY_BLUE_TOKEN` values in the ignored `.env` file. The Blue service token is passed to the Gateway and Blue service; the caller tokens are passed only to the Gateway. Missing Gateway caller tokens leave protected reads unavailable (fail closed). Keep `.env` private. It is excluded by Git and Docker build contexts. `.env.example` contains placeholders only.

```powershell
docker compose build
docker compose up -d
```

The Gateway is published only on `127.0.0.1:8000`; open <http://127.0.0.1:8000/dashboard/>. Check health and dashboard HTTP status in PowerShell:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
(Invoke-WebRequest http://127.0.0.1:8000/dashboard/).StatusCode
```

Blue runs separately at `http://blue:8001` on the Compose network. Its port is not published to the host. The Gateway uses that service name for protected-resource requests. Compose mounts the existing host `data/` folder at `/app/data`, keeping `data/bayora_audit.sqlite3` as the active audit database across restarts.

Run the four fixed Red Team checks from the host using the existing virtual environment:

```powershell
venv\Scripts\python.exe -m red.runner run
```

View logs or stop the containers with:

```powershell
docker compose logs --tail=100
docker compose down
```

`BAYORA_OPENROUTER_API_KEY` is optional for startup. If set in `.env`, Compose passes it to the Gateway at runtime; it is not baked into the image. The default model is `openrouter/free`. Authorized prompts sent to OpenRouter may incur provider costs or rate limits; tests never make live provider calls.

The Compose bridge provides basic local service separation and routing only. It is not proof of a complete security sandbox, hardened isolation, or protection from a host administrator or compromised container.

To request a model response, send `POST /llm/generate` with `role`, `action`, `resource`, and `prompt`. Use `role: red`, `action: generate_client_response`, and one of the approved `test:*` resources from `policies/rules.json`. A DENY is audited and prevents the provider call. Model text is untrusted output and is never evidence that an attack was blocked or a resource was protected.

## Test

```powershell
venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
git diff --check
```

Tests use temporary SQLite databases and mocked or in-process HTTP transports; they do not need a real OpenRouter key, network access, paid model calls, or a running Blue service. The Red runner command above is an integration check and requires the Compose Gateway to be running.

## Current limits

- `/resource/read` derives `red` or `blue` from its configured bearer token, but these are shared prototype credentials without user identity, expiry, or rotation. `/policy/decide` and `/llm/generate` still accept caller-declared roles and are not authenticated by this resource-read change.
- The fixture and its expected digest are hardcoded prototype data. This is a local demonstration, not general resource protection.
- The shared service token is a basic process-level trust mechanism. Compose uses one local bridge network; it does not provide strong segmentation, a complete container sandbox, rate limiting, or secret rotation.
- Audit records are SQLite rows without tamper evidence, hash chaining, or an integrity verifier.
- OpenRouter behavior is verified with mocked HTTP responses only; no live provider call is claimed. Model output quality and safety are not verified.
- The runner covers only four predefined local cases. There is no general Red Team agent, test authoring interface, or broad security validation.
