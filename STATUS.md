# Bayora status

Status updated 2026-10-27. The dashboard remains served at `/dashboard/`. **DEMO STUB: `/test` is not a real security test.**

| Component | Status |
|---|---|
| Credential-derived Gateway roles, protected routes, body-role spoofing rejection, session role-switch denial | IMPLEMENTED AND TESTED (shared prototype bearer tokens; no production user identity) |
| Blue synthetic resource and independent service-token check | IMPLEMENTED AND TESTED (one dummy fixture) |
| Default-deny policy engine and policy-gated Blue/LLM operations | IMPLEMENTED AND TESTED |
| Administrator policy console: validated CRUD, enable/disable, dry-run, audit, atomic persistence | IMPLEMENTED AND TESTED (required Red-to-Blue deny safeguard cannot be removed or disabled) |
| Prompt inspection before provider execution | IMPLEMENTED AND TESTED (fixed heuristics; DENY/FLAG block provider call; prompt content is not stored) |
| Security test scenario library, local runner integration, audited JSON evidence | IMPLEMENTED AND TESTED (four fixed scenarios; artifact hash checked against audit metadata) |
| Admin incident search, filtering, event detail, related evidence, JSON export | IMPLEMENTED AND TESTED (separate admin credential; audit integrity required) |
| Validated persistent detection configuration | IMPLEMENTED AND TESTED (only medium-severity action and denial threshold are tunable; required controls are immutable) |
| SQLite audit outcomes, role/session fields, integrity-chain verification | IMPLEMENTED AND TESTED (unkeyed SHA-256 chain; missing marker and tampering fail closed) |
| Anomaly indicators and evidence summaries | IMPLEMENTED AND TESTED (fixed heuristics, not comprehensive detection) |
| OpenRouter integration | IMPLEMENTED AND TESTED WITH MOCKS (no live provider request verified) |
| Compose Gateway, Blue, LLM, and Red services | CONFIGURED; Docker CLI unavailable in this environment, so Compose/runtime not verified |
| Non-root containers, read-only root filesystems, dropped capabilities, network segmentation, resource limits | CONFIGURED; runtime settings not verified in this pass |
| Production identity, user lifecycle, token expiry/rotation | NOT IMPLEMENTED |
| Signed/keyed immutable audit, production container sandbox, general-purpose Red Team agent | NOT IMPLEMENTED |

## Verification recorded for this update

- Full suite: `venv\Scripts\python.exe -m pytest -q -p no:cacheprovider --basetemp="$env:TEMP\bayora-final-tests"` — **101 passed, 1 Starlette/httpx deprecation warning**.
- Dependency check: `venv\Scripts\python.exe -m pip check` — **No broken requirements found**.
- Root import check confirmed `main:app` and `backend.main:app` are the same app.
- `git diff --check` — no whitespace errors; Git emitted access-denied notices for three pre-existing tracked `.pytest-tmp/` deletions and line-ending notices.
- Docker CLI was not available; Compose parsing, image builds, container startup, network behavior, and restart persistence were not verified.
- No live OpenRouter request was made. Frontend behavior is covered by source/API contract tests; no browser automation or JavaScript runtime was available.

## Limitations

Gateway and admin bearer tokens are shared prototype credentials without user accounts, expiry, or rotation. Prompt detection is deterministic pattern matching and may miss attacks or flag benign prompts. Scenario coverage is fixed and local. The audit chain is unkeyed, so a privileged database writer can recompute it. Model output and scenario results do not establish general security. Docker Compose supplies basic local network boundaries, not a complete sandbox. `/test` remains a demo stub.
