# Bayora

Bayora is a local prototype for policy-gated adversarial LLM testing. It includes a FastAPI Gateway, a separate Blue service with one synthetic protected fixture, an optional OpenRouter-backed LLM service, a fixed Red runner, SQLite audit records, anomaly indicators, role-scoped evidence summaries, and a Docker Compose deployment. It is not a production identity system or a complete container sandbox.

## Authorization and routes

The Gateway requires `Authorization: Bearer <token>` for protected, audit, and administrator routes. Red and Blue roles derive from `BAYORA_GATEWAY_RED_TOKEN` and `BAYORA_GATEWAY_BLUE_TOKEN`. Administrative features require the separate `BAYORA_GATEWAY_ADMIN_TOKEN`; it is optional for startup, but the admin console remains unavailable without it. Request-body `role` values do not establish identity or authority. Unauthenticated requests are rejected before policy evaluation and service calls. `/`, `/health`, and `/dashboard/` remain public local status/static routes.

Both supported ASGI imports, `backend.main:app` and the root compatibility import `main:app`, point to the same authenticated Gateway. For host development, bind it to loopback: `venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000`.

Policy rules in `policies/rules.json` deny by default, with explicit deny precedence. `/resource/read` evaluates policy before making an authenticated Blue-service request. Blue independently requires `BAYORA_BLUE_SERVICE_TOKEN`; direct calls without it are rejected. `/llm/generate` applies policy before calling the internal LLM service, which independently requires `BAYORA_LLM_SERVICE_TOKEN`. The Gateway maps caller credentials to roles; these shared prototype tokens have no user identity, expiry, or automated rotation and are not production-grade authentication. Missing or invalid Gateway credentials generate a role-`unknown` denial audit event without recording credential values; if that audit write fails, the request remains denied with HTTP 503.

`POST /policy/decide` records a decision but executes no protected operation. Resource and LLM responses keep policy decision, observed outcome, and verification status separate. Model output is not evidence of a security outcome. The existing `/test` endpoint remains a **DEMO STUB**, not a real security test.

## Administration, prompt inspection, scenarios, and incidents

The dashboard's administration panel and `/admin/*` APIs require the separately configured admin credential. The policy console supports validated rule create/update/enable/disable/delete and dry-run evaluation. Changes are audited as pending operations and finalized after atomic write and read-back checks. The manager preserves an enabled Red-to-Blue resource deny safeguard. Authentication and audit-integrity enforcement are not policy-editable. Compose mounts `policies/` and `reports/red-runs/` writable only for Gateway paths that need persistence; the isolated Red container has neither mount and writes disposable runner output to its `/tmp` tmpfs.

Every policy-allowed `/llm/generate` request is inspected before the provider call. The detector uses fixed pattern indicators, returns `ALLOW`, `DENY`, or `FLAG`, and blocks provider calls for flagged or denied prompts. Audit records keep prompt length and SHA-256 digest plus findings, never prompt text. Medium-severity handling and the repeated-denial threshold are configurable through `/admin/config`; prompt inspection, high-severity blocking, and anomaly detection remain required. These heuristics can produce false positives and misses and are not a model-based security guarantee.

The admin scenario library exposes and runs only the existing fixed local Red runner cases. Run artifacts are linked to a hash recorded in the audit chain; exports fail closed if the artifact hash does not match. The runner validates saved report structure and count consistency and refuses to overwrite an existing run ID. Scenario results describe observed test results, not proof of general security. The admin incident workspace searches all audit roles, shows event details and matching policy/inspection/scenario evidence, and exports filtered JSON. Existing `/audit/events` routes remain scoped to the authenticated caller's role.

To enable the administration console locally, set a distinct high-entropy `BAYORA_GATEWAY_ADMIN_TOKEN` in ignored `.env`; `.env.example` intentionally leaves it blank. Do not reuse the Red or Blue caller token.

## Audit integrity

Audit events remain in `data/bayora_audit.sqlite3` by default. The store preserves the event schema and records decisions, operation state, outcomes, verification status, role, and session ID. Its SHA-256 revision chain detects event/snapshot mismatches, missing interior entries, and reordering. A separate persistent SQLite checkpoint stores a keyed HMAC of the current chain head. Paired deletion of the newest event and its chain entry is detected while the checkpoint and key remain intact. Audit reads and writes fail closed when the chain and checkpoint disagree or the checkpoint is missing, unauthenticated, or unavailable.

Set `BAYORA_AUDIT_CHECKPOINT_KEY` to a private random value of at least 32 bytes in the ignored `.env`; do not reuse an application token. Generate a 64-character hexadecimal value with `python -c "import secrets; print(secrets.token_hex(32))"` and place it in `.env` without sharing or committing it. The checkpoint path defaults beside the audit database for local development. Compose stores it in its own persistent named volume, separate from the bind-mounted audit database. New empty databases establish an initial checkpoint at startup. Existing databases without a checkpoint require an operator-reviewed, explicit baseline: `python -m backend.audit_checkpoint_cli bootstrap --approve-current-history`. That operation anchors only the current locally valid history; it cannot prove that history was truncated before the checkpoint was created.

SQLite commits each event revision before an atomic checkpoint compare-and-set advances one sequence. Writers are serialized with a cross-process lock; exact retries are idempotent. If the checkpoint update is interrupted, the audit database may be one revision ahead and all further audit operations fail closed. An operator may inspect the pending operation and explicitly approve exactly one valid extension with `python -m backend.audit_checkpoint_cli recover --approve-unanchored-revision`; larger gaps or mismatches require restoring a known consistent backup. Back up the database, checkpoint volume, and key as one coordinated set while the service is stopped, and restore them together. A missing or stale checkpoint is never silently recreated.

This is tamper detection across separate persistence locations, not a tamper-proof log. The Gateway process can access the checkpoint and HMAC key; a compromised Gateway or Docker host administrator can rewrite or re-anchor both stores. Restoring a matching older copy of both stores also cannot be detected without an additional remote monotonic anchor. Legacy history is trusted only as of explicit checkpoint bootstrap. If an existing integrity table loses its initialization marker, startup fails closed instead of silently creating a new baseline. Operation verification remains `NOT_VERIFIED` unless independent evidence exists.

Detecting database rollback requires the trusted checkpoint and its HMAC key to remain outside the attacker's rollback control. Separate files or volumes on the same host do not provide that protection if the same attacker can restore or replace them. The current local/Compose setup does not provide an independent monotonic anchor.

Authenticated `GET /audit/verify` returns a dashboard-friendly view of the same chain verifier. `GET /audit/anomalies` runs simple indicators over the caller's role-scoped events (repeated denials and traversal-like resource names). These are explainable indicators, not a trained detector or proof of an attack. `GET /audit/report` produces a role-scoped evidence summary with policy status, outcome counts, chain status, and anomaly indicators. Red-run summaries are omitted from role-scoped reports because runner files do not yet carry authenticated role ownership metadata. The dashboard sends the entered bearer token with protected requests and renders event/anomaly/report values as text.

`session_id` is a caller-supplied correlation label, not an identity credential. Audit records are scoped by the role derived from the authenticated bearer token. Reusing the same label under another role creates a separate role-scoped correlation namespace; it does not switch roles or block that role's operation. Shared role credentials cannot distinguish individual users, so this does not provide per-user session isolation.

## Red Team runner

Run the deterministic host suite with:

```powershell
venv\Scripts\python.exe -m red.runner run
```

It exercises four fixed cases against the loopback Gateway: an allowed synthetic-resource read, a denied read, an invalid test identifier, and a policy-denied LLM request. Reports include sanitized inputs, observed HTTP results, and available audit evidence; absent or ambiguous evidence is `INCONCLUSIVE`. The runner does not access Blue directly and does not make a provider call in the denied LLM case. Retrieve a saved report with `venv\Scripts\python.exe -m red.runner show <run-id>`.

## Local Docker setup

Configure separate private values for `BAYORA_BLUE_SERVICE_TOKEN`, `BAYORA_GATEWAY_RED_TOKEN`, `BAYORA_GATEWAY_BLUE_TOKEN`, `BAYORA_GATEWAY_ADMIN_TOKEN`, `BAYORA_LLM_SERVICE_TOKEN`, and `BAYORA_AUDIT_CHECKPOINT_KEY` in ignored `.env`. The checkpoint key must be at least 32 bytes; generate a new random value for this purpose and keep a protected backup. `.env.example` contains placeholders only. Do not reuse credentials. `BAYORA_OPENROUTER_API_KEY` is optional for startup; without it, generation fails with a sanitized service error. The default model is `openrouter/free`. The provider key is supplied at runtime and is not copied into the image.

```powershell
docker compose config --quiet
docker compose build
docker compose up -d gateway blue llm egress-proxy
Invoke-RestMethod http://127.0.0.1:8000/health
(Invoke-WebRequest http://127.0.0.1:8000/dashboard/).StatusCode
venv\Scripts\python.exe -m red.runner run
docker compose ps
docker compose logs --tail=100 gateway blue llm egress-proxy
```

## Verification snapshot (2026-10-28)

The hardening candidate at `95c60f17939fb3af7e802b56e79c0c92e9db2c77` was
built and exercised in a separately named, disposable Compose project using
synthetic credentials and a temporary verification-only overlay. The full
Python suite passed **233 tests** (one existing Starlette/httpx deprecation
warning), and all **24** saved legacy Red reports loaded. The live isolation
verifier reported **123 PASS, 0 FAIL, 11 UNVERIFIED**. Its unresolved checks
include seccomp profile identity and a positive LLM-egress probe against an
approved, reachable external test listener.

The live Red runner passed its three configured denial cases. A separate
controlled Gateway run with synthetic Red and Blue credentials passed all
four cases; observed policy decisions, HTTP outcomes, audit event IDs, and
the saved/reloaded run report were consistent. Runtime inspection confirmed
Red cannot reach Blue directly, the egress proxy rejects `CONNECT
example.invalid:443` with HTTP 403, and only Gateway publishes
`127.0.0.1:8000`. The five services ran as UID/GID `10001:10001` with no
effective capabilities, `NoNewPrivs=1`, active seccomp filter mode 2,
read-only root filesystems, and the configured CPU, memory, and PID cgroup
limits.

This evidence is limited to that isolated local run. No provider request was
made; approved external egress success, direct-LLM egress denial against a
positive external baseline, and named seccomp profile/rules remain
**UNVERIFIED**. The report counts do not establish production-grade
isolation, host compromise resistance, or external audit authenticity. See
[docs/ISOLATION_VERIFICATION.md](docs/ISOLATION_VERIFICATION.md) and
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for scope and deployment checks.

Follow [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for rollback guidance; do not
use a broad stack shutdown where unrelated or unidentified containers share
the deployment networks.

The Compose declaration publishes only Gateway on `127.0.0.1:8000`; Blue, LLM, Red, and the egress proxy have no declared published ports. Red and Blue use separate internal networks. Gateway also joins those networks and `llm-gateway`, plus the non-internal `gateway-host` bridge, so Gateway egress is not restricted by this topology. The egress proxy is the only service declared on the separate non-internal `llm-egress` bridge. The proxy accepts CONNECT only for `openrouter.ai:443`, resolves that hostname itself, and rejects non-public DNS answers. SNI is a routing check, not provider authentication; because TLS remains end-to-end, the proxy cannot inspect the encrypted HTTP authority or path. The LLM fails closed if its proxy URL is missing. These repository controls do not establish host-level egress enforcement, protect a compromised proxy/host, or prove provider connectivity.

In the 2026-10-28 candidate runtime, the Gateway loopback health check succeeded, Red could not connect directly to Blue, the LLM was attached only to internal networks, and the proxy rejected a prohibited synthetic CONNECT with HTTP 403. The candidate isolation verifier still reported **11 UNVERIFIED** checks; approved external egress success, direct-LLM denial against a positive external baseline, and seccomp profile identity remain unverified. Older runtime snapshots below are historical and do not describe the candidate stack. See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) and [docs/ISOLATION_VERIFICATION.md](docs/ISOLATION_VERIFICATION.md) for current evidence and the remaining controlled checks. The unexplained `bayora-port-test` container was not touched.

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for startup, environment variables, rollback readiness, and deployment-host verification steps.

Compose bind-mounts the existing `data/` directory at `/app/data`, preserving SQLite audit storage across container restarts, and uses a separate named `audit-checkpoint` volume. It mounts `reports/red-runs/` for Gateway-owned scenario artifacts, which are available only through authenticated admin routes. Red container reports are ephemeral and are not shared with Gateway artifacts. Back up and restore the audit database, checkpoint volume, and key together with the services stopped.

## LLM behavior and tests

Authorized prompts may be sent to OpenRouter through the egress proxy and may incur provider costs or rate limits. Automated tests mock provider HTTP responses and use synthetic proxy destinations; they do not require a real key, external network access, or paid calls. No successful live OpenRouter call is claimed. Model quality, safety, and prompt-injection resistance are not established.

```powershell
venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
venv\Scripts\python.exe -m pip check
git diff --check
```

Tests use isolated temporary SQLite databases. The host Red runner and Compose checks are separate integration checks requiring the Gateway to be running.

## Remaining limits

The Blue fixture and digest are hardcoded synthetic test data, not general resource protection. Caller bearer tokens are shared prototype credentials. Session IDs are role-scoped correlation labels and do not establish per-user ownership; users sharing a role credential remain indistinguishable. The audit revision chain is SHA-256 with a separate HMAC checkpoint; it detects a changed database head while the checkpoint and key remain intact, but does not protect against a compromised Gateway or host administrator, or rollback of a matching older database/checkpoint pair. Anomaly checks use a few fixed heuristics and can miss or misclassify activity. The fixed Red suite is not a general attacker. Model output is not independently evaluated as a security outcome, and Compose networking is not a validated deployment sandbox.
