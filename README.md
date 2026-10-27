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

Audit events remain in `data/bayora_audit.sqlite3` by default. The store preserves the event schema and records decisions, operation state, outcomes, verification status, role, and session ID. Its SHA-256 revision chain detects event/snapshot mismatches, missing interior entries, and reordering. A separate persistent SQLite checkpoint stores a keyed HMAC of the current chain head. Paired deletion of the newest event and its chain entry is detected while the checkpoint and key remain intact. Audit reads and writes fail closed when the chain and checkpoint disagree or the checkpoint is missing, unauthenticated, or unavailable.

Set `BAYORA_AUDIT_CHECKPOINT_KEY` to a private random value of at least 32 bytes in the ignored `.env`; do not reuse an application token. Generate a 64-character hexadecimal value with `python -c "import secrets; print(secrets.token_hex(32))"` and place it in `.env` without sharing or committing it. The checkpoint path defaults beside the audit database for local development. Compose stores it in its own persistent named volume, separate from the bind-mounted audit database. New empty databases establish an initial checkpoint at startup. Existing databases without a checkpoint require an operator-reviewed, explicit baseline: `python -m backend.audit_checkpoint_cli bootstrap --approve-current-history`. That operation anchors only the current locally valid history; it cannot prove that history was truncated before the checkpoint was created.

SQLite commits each event revision before an atomic checkpoint compare-and-set advances one sequence. Writers are serialized with a cross-process lock; exact retries are idempotent. If the checkpoint update is interrupted, the audit database may be one revision ahead and all further audit operations fail closed. An operator may inspect the pending operation and explicitly approve exactly one valid extension with `python -m backend.audit_checkpoint_cli recover --approve-unanchored-revision`; larger gaps or mismatches require restoring a known consistent backup. Back up the database, checkpoint volume, and key as one coordinated set while the service is stopped, and restore them together. A missing or stale checkpoint is never silently recreated.

This is tamper detection across separate persistence locations, not a tamper-proof log. The Gateway process can access the checkpoint and HMAC key; a compromised Gateway or Docker host administrator can rewrite or re-anchor both stores. Restoring a matching older copy of both stores also cannot be detected without an additional remote monotonic anchor. Legacy history is trusted only as of explicit checkpoint bootstrap. If an existing integrity table loses its initialization marker, startup fails closed instead of silently creating a new baseline. Operation verification remains `NOT_VERIFIED` unless independent evidence exists.

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
docker compose up -d gateway blue llm
Invoke-RestMethod http://127.0.0.1:8000/health
(Invoke-WebRequest http://127.0.0.1:8000/dashboard/).StatusCode
venv\Scripts\python.exe -m red.runner run
docker compose logs --tail=100 gateway blue llm
docker compose down
```

Only Gateway is published, bound to `127.0.0.1:8000`; its published port does not require an ordinary external bridge. Blue and LLM ports are not published. Gateway shares separate internal networks with Red, Blue, and LLM. Red and Blue have no non-internal network attachment. LLM also has an ordinary egress bridge for OpenRouter, which currently allows general outbound connectivity rather than restricting traffic to that provider. The Gateway has no ordinary external network attachment in this Compose configuration; runtime egress and host-published access still need verification on Docker Desktop. Compose networking is a basic local boundary, not proof of isolation. Services run as non-root with all Linux capabilities dropped, `no-new-privileges`, read-only root filesystems, limited writable mounts/tmpfs, and CPU/memory/PID limits. These settings do not protect against host administrators, kernel/runtime vulnerabilities, or a compromised Gateway.

Compose bind-mounts the existing `data/` directory at `/app/data`, preserving SQLite audit storage across container restarts, and uses a separate named `audit-checkpoint` volume. It also mounts `reports/red-runs/` for Red-run reports. Back up and restore the audit database, checkpoint volume, and key together with the services stopped.

## LLM behavior and tests

Authorized prompts may be sent to OpenRouter and may incur provider costs or rate limits. Automated tests mock provider HTTP responses and do not require a real key, network access, or paid calls. No successful live OpenRouter call is claimed. Model quality, safety, and prompt-injection resistance are not established.

```powershell
venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
venv\Scripts\python.exe -m pip check
git diff --check
```

Tests use isolated temporary SQLite databases. The host Red runner and Compose checks are separate integration checks requiring the Gateway to be running.

## Remaining limits

The Blue fixture and digest are hardcoded synthetic test data, not general resource protection. Caller bearer tokens are shared prototype credentials. Session IDs are role-scoped correlation labels and do not establish per-user ownership; users sharing a role credential remain indistinguishable. The audit chain is unkeyed and cannot prevent a privileged database editor from rewriting history. Anomaly checks use a few fixed heuristics and can miss or misclassify activity. The fixed Red suite is not a general attacker. Model output is not independently evaluated as a security outcome, and Compose networking is not a validated deployment sandbox.
