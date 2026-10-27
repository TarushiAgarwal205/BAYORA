# Bayora

Bayora is a local prototype for policy-gated adversarial LLM testing. It includes a FastAPI Gateway, a separate Blue service with one synthetic protected fixture, an optional OpenRouter-backed LLM service, a fixed Red runner, SQLite audit records, anomaly indicators, role-scoped evidence summaries, and a Docker Compose deployment. It is not a production identity system or a complete container sandbox.

## Authorization and routes

The Gateway requires `Authorization: Bearer <token>` for protected, audit, and administrator routes. Red and Blue roles derive from `BAYORA_GATEWAY_RED_TOKEN` and `BAYORA_GATEWAY_BLUE_TOKEN`. Administrative features require the separate `BAYORA_GATEWAY_ADMIN_TOKEN`; it is optional for startup, but the admin console remains unavailable without it. Request-body `role` values do not establish identity or authority. Unauthenticated requests are rejected before policy evaluation and service calls. `/`, `/health`, and `/dashboard/` remain public local status/static routes.

Both supported ASGI imports, `backend.main:app` and the root compatibility import `main:app`, point to the same authenticated Gateway. For host development, bind it to loopback: `venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000`.

Policy rules in `policies/rules.json` deny by default, with explicit deny precedence. `/resource/read` evaluates policy before making an authenticated Blue-service request. Blue independently requires `BAYORA_BLUE_SERVICE_TOKEN`; direct calls without it are rejected. `/llm/generate` applies policy before calling the internal LLM service, which independently requires `BAYORA_LLM_SERVICE_TOKEN`. The Gateway maps caller credentials to roles; these shared prototype tokens have no user identity, expiry, or automated rotation and are not production-grade authentication.

`POST /policy/decide` records a decision but executes no protected operation. Resource and LLM responses keep policy decision, observed outcome, and verification status separate. Model output is not evidence of a security outcome. The existing `/test` endpoint remains a **DEMO STUB**, not a real security test.

## Administration, prompt inspection, scenarios, and incidents

The dashboard's administration panel and `/admin/*` APIs require the separately configured admin credential. The policy console supports validated rule create/update/enable/disable/delete and dry-run evaluation. Changes are audited as pending operations and finalized after atomic write and read-back checks. The manager preserves an enabled Red-to-Blue resource deny safeguard. Authentication and audit-integrity enforcement are not policy-editable. Compose mounts `policies/` and `reports/red-runs/` writable only for the Gateway paths that need persistence.

Every policy-allowed `/llm/generate` request is inspected before the provider call. The detector uses fixed pattern indicators, returns `ALLOW`, `DENY`, or `FLAG`, and blocks provider calls for flagged or denied prompts. Audit records keep prompt length and SHA-256 digest plus findings, never prompt text. Medium-severity handling and the repeated-denial threshold are configurable through `/admin/config`; prompt inspection, high-severity blocking, and anomaly detection remain required. These heuristics can produce false positives and misses and are not a model-based security guarantee.

The admin scenario library exposes and runs only the existing fixed local Red runner cases. Run artifacts are linked to a hash recorded in the audit chain; exports fail closed if the artifact hash does not match. Scenario results describe observed test results, not proof of general security. The admin incident workspace searches all audit roles, shows event details and matching policy/inspection/scenario evidence, and exports filtered JSON. Existing `/audit/events` routes remain scoped to the authenticated caller's role.

To enable the administration console locally, set a distinct high-entropy `BAYORA_GATEWAY_ADMIN_TOKEN` in ignored `.env`; `.env.example` intentionally leaves it blank. Do not reuse the Red or Blue caller token.

## Audit integrity

Audit events remain in `data/bayora_audit.sqlite3` by default. The store keeps decision, execution state, observed outcome, verification status, role, and session ID. It uses an additive SQLite migration for existing databases and retains existing rows. Audit event-list and event-detail APIs return only records for the authenticated role. An append-only SHA-256 snapshot chain and `GET /audit/integrity` detect changed, missing, or reordered event snapshots; audit reads and writes fail closed when verification detects a problem.

This is unkeyed hash-based tamper detection, not a tamper-proof or signed log. An actor able to rewrite the database can recompute the chain. Legacy rows are baselined once at first initialization, so their prior history cannot be verified. If an existing integrity table loses its initialization marker, startup fails closed instead of silently creating a new baseline. Operation verification remains `NOT_VERIFIED` unless independent evidence exists.

Authenticated `GET /audit/verify` returns a dashboard-friendly view of the same chain verifier. `GET /audit/anomalies` runs simple indicators over the caller's role-scoped events (repeated denials, traversal-like resource names, and session role-switch attempts). These are explainable indicators, not a trained detector or proof of an attack. `GET /audit/report` produces a role-scoped evidence summary with policy status, outcome counts, chain status, and anomaly indicators. Red-run summaries are omitted from role-scoped reports because runner files do not yet carry authenticated role ownership metadata. The dashboard sends the entered bearer token with protected requests and renders event/anomaly/report values as text.

## Red Team runner

Run the deterministic host suite with:

```powershell
venv\Scripts\python.exe -m red.runner run
```

It exercises four fixed cases against the loopback Gateway: an allowed synthetic-resource read, a denied read, an invalid test identifier, and a policy-denied LLM request. Reports include sanitized inputs, observed HTTP results, and available audit evidence; absent or ambiguous evidence is `INCONCLUSIVE`. The runner does not access Blue directly and does not make a provider call in the denied LLM case. Retrieve a saved report with `venv\Scripts\python.exe -m red.runner show <run-id>`.

## Local Docker setup

Configure separate private values for `BAYORA_BLUE_SERVICE_TOKEN`, `BAYORA_GATEWAY_RED_TOKEN`, `BAYORA_GATEWAY_BLUE_TOKEN`, and `BAYORA_LLM_SERVICE_TOKEN` in ignored `.env`. `.env.example` contains blank placeholders only. Do not reuse these credentials. `BAYORA_OPENROUTER_API_KEY` is optional for startup; without it, generation fails with a sanitized service error. The default model is `openrouter/free`. The provider key is supplied at runtime and is not copied into the image.

```powershell
docker compose config --quiet
docker compose build
docker compose up -d gateway blue llm
Invoke-RestMethod http://127.0.0.1:8000/health
(Invoke-WebRequest http://127.0.0.1:8000/dashboard/).StatusCode
venv\Scripts\python.exe -m red.runner run
docker compose logs --tail=100 gateway blue llm
docker compose down
```

Only Gateway is published, bound to `127.0.0.1:8000`; its published port does not require an ordinary external bridge. Blue and LLM ports are not published. Gateway shares separate internal networks with Red, Blue, and LLM. Red and Blue have no non-internal network attachment. LLM also has an ordinary egress bridge for OpenRouter, which currently allows general outbound connectivity rather than restricting traffic to that provider. The Gateway has no ordinary external network attachment in this Compose configuration; runtime egress and host-published access still need verification on Docker Desktop. Compose networking is a basic local boundary, not proof of isolation. Services run as non-root with all Linux capabilities dropped, `no-new-privileges`, read-only root filesystems, limited writable mounts/tmpfs, and CPU/memory/PID limits. These settings do not protect against host administrators, kernel/runtime vulnerabilities, or a compromised Gateway.

Compose bind-mounts the existing `data/` directory at `/app/data`, preserving SQLite audit storage across container restarts. It also mounts `reports/red-runs/` for Red-run reports.

## LLM behavior and tests

Authorized prompts may be sent to OpenRouter and may incur provider costs or rate limits. Automated tests mock provider HTTP responses and do not require a real key, network access, or paid calls. No successful live OpenRouter call is claimed. Model quality, safety, and prompt-injection resistance are not established.

```powershell
venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
venv\Scripts\python.exe -m pip check
git diff --check
```

Tests use isolated temporary SQLite databases. The host Red runner and Compose checks are separate integration checks requiring the Gateway to be running.

## Remaining limits

The Blue fixture and digest are hardcoded synthetic test data, not general resource protection. Caller bearer tokens are shared prototype credentials. Session IDs are bound to the first authenticated role recorded for that session; this is role-switch prevention, not per-user session isolation. The audit chain is unkeyed and cannot prevent a privileged database editor from rewriting history. Anomaly checks use a few fixed heuristics and can miss or misclassify activity. The fixed Red suite is not a general attacker. Model output is not independently evaluated as a security outcome, and Compose networking is not a validated deployment sandbox.
