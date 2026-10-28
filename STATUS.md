# Bayora status

## Current candidate verification (2026-10-28)

This section is authoritative for hardening candidate
`95c60f17939fb3af7e802b56e79c0c92e9db2c77`; older status entries below are
historical snapshots and must not be used as evidence for this runtime.

| Feature area | Current status | Evidence / remaining limitation |
|---|---|---|
| Container isolation | IMPLEMENTED AND LIVE-VERIFIED for the isolated candidate stack | All five services ran non-root, with zero effective capabilities, `NoNewPrivs=1`, active seccomp mode 2, read-only root filesystems, and expected `/tmp` tmpfs. Seccomp profile identity/rules are not identified. |
| Network segmentation and LLM egress | PARTIALLY LIVE-VERIFIED | Red-to-Blue direct probe was unreachable; approved Gateway routes worked. The LLM was only on internal networks, the proxy alone had external-network membership, and prohibited CONNECT returned 403. Direct-LLM denial against a positive external baseline and approved external connectivity remain UNVERIFIED. |
| Resource governance | IMPLEMENTED AND LIVE-VERIFIED for configured cgroups | Effective CPU, memory, and PID cgroup values matched Compose for all five services. No sustained contention test was run. |
| Access and secret isolation | IMPLEMENTED AND TESTED | Synthetic live scenarios observed allowed Blue access and denied Red/protected and LLM-policy cases with matching audit event IDs. Shared prototype tokens are not production identity; no real secret was used. |
| Tamper-evident audit | IMPLEMENTED AND TESTED, limited guarantee | Audit integrity/checkpoint behavior is covered by the suite. Same-host compromise or rollback of matching database/checkpoint/key remains outside the guarantee; this is not a tamper-proof log. |
| Security monitoring | IMPLEMENTED AND TESTED | Existing audit/anomaly paths are included in the passing suite; detection uses limited heuristics, not comprehensive monitoring. |
| Isolation verification | IMPLEMENTED AND LIVE-VERIFIED WITH UNVERIFIED RESULTS | Run `a8ade081-2121-44c1-9835-77e1eee6a1c1`: 123 PASS, 0 FAIL, 11 UNVERIFIED, 98 INFO. UNVERIFIED is not success. |
| Evidence-backed security testing | IMPLEMENTED AND LIVE-VERIFIED for controlled scenarios | Red in-container run 3/3; host-side synthetic Red/Blue run 4/4 with observed responses, policy decisions, audit IDs, and saved report reload. No external provider call. |
| Verifiable results | IMPLEMENTED AND TESTED | Full suite passed 233 tests; all 24 saved legacy reports loaded. Reports are internally validated evidence, not proof of general security. |

Candidate full-suite command:
`venv\Scripts\python.exe -m pytest -q -p no:cacheprovider --basetemp <fresh-TEMP-directory>`
— **233 passed, 1 existing Starlette/httpx deprecation warning**.
`docker compose config --quiet` and all five image builds succeeded. The
candidate was tested in a separate Compose project; these results do not
assert that the main-branch deployment or production environment is live.
No provider request was made.

The candidate changes are published on
`copilot/bayora-security-verification-hardening`, but are not merged into
`main`. No pull request was opened because the available GitHub session is
unauthenticated and no PR-creation operation is available. A reviewed PR
targeting `main` is still required; no merge is claimed.

Status updated 2026-10-27. The dashboard remains served at `/dashboard/`. **DEMO STUB: `/test` is not a real security test.**

| Component | Status |
|---|---|
| Credential-derived Gateway roles, protected routes, body-role spoofing rejection, role-scoped session correlation | IMPLEMENTED AND TESTED (shared role credentials do not identify individual users; session IDs are not identity credentials) |
| Blue synthetic resource and independent service-token check | IMPLEMENTED AND TESTED (one dummy fixture) |
| Default-deny policy engine and policy-gated Blue/LLM operations | IMPLEMENTED AND TESTED |
| Administrator policy console: validated CRUD, enable/disable, dry-run, audit, atomic persistence | IMPLEMENTED AND TESTED (required Red-to-Blue deny safeguard cannot be removed or disabled) |
| Prompt inspection before provider execution | IMPLEMENTED AND TESTED (fixed heuristics; DENY/FLAG block provider call; prompt content is not stored) |
| Security test scenario library, local runner integration, audited JSON evidence | IMPLEMENTED AND TESTED (four fixed scenarios; artifact hash checked against audit metadata) |
| Admin incident search, filtering, event detail, related evidence, JSON export | IMPLEMENTED AND TESTED (separate admin credential; audit integrity required) |
| Validated persistent detection configuration | IMPLEMENTED AND TESTED (only medium-severity action and denial threshold are tunable; required controls are immutable) |
| SQLite audit outcomes, role/session fields, SHA-256 chain plus HMAC checkpoint | IMPLEMENTED AND TESTED (paired tail deletion detected while checkpoint/key remain intact; missing or mismatched state fails closed; Gateway/host compromise and matching-pair rollback remain out of scope) |
| Anomaly indicators and evidence summaries | IMPLEMENTED AND TESTED (fixed heuristics, not comprehensive detection) |
| OpenRouter integration | IMPLEMENTED AND TESTED WITH MOCKS (no live provider request verified) |
| Compose Gateway, Blue, LLM, and Red services | CONFIGURED; Gateway is attached only to internal service networks; Docker CLI unavailable, so runtime egress and published-port access are not verified |
| Non-root containers, read-only root filesystems, dropped capabilities, network segmentation, resource limits | CONFIGURED; runtime settings not verified in this pass |
| Production identity, user lifecycle, token expiry/rotation | NOT IMPLEMENTED |
| Signed/keyed immutable audit, production container sandbox, general-purpose Red Team agent | NOT IMPLEMENTED |

## Verification recorded for this update

- Full suite: `venv\Scripts\python.exe -m pytest -q -p no:cacheprovider --basetemp="$env:TEMP\bayora-final-tests"` — **101 passed, 1 Starlette/httpx deprecation warning**.
- Dependency check: `venv\Scripts\python.exe -m pip check` — **No broken requirements found**.
- Root import check confirmed `main:app` and `backend.main:app` are the same app.
- `git diff --check` — no whitespace errors; Git emitted access-denied notices for three pre-existing tracked `.pytest-tmp/` deletions and line-ending notices.
- Docker CLI was not available; Compose parsing, image builds, container startup, network behavior, and restart persistence were not verified. Current Compose configuration gives only the LLM service an ordinary egress bridge; it is not restricted to the OpenRouter hostname.
- No live OpenRouter request was made. Frontend behavior is covered by source/API contract tests; no browser automation or JavaScript runtime was available.

## Release verification follow-up — 2026-10-27

- Full suite: `venv\Scripts\python.exe -m pytest -q --basetemp .pytest-run-codex-20261027T222000Z -p no:cacheprovider` — **102 passed, 1 Starlette/httpx deprecation warning**. Two earlier full runs also passed 102 tests each.
- `venv\Scripts\python.exe -m pip check`: **No broken requirements found**.
- `git diff --check`: **exit 0**. Git printed access-denied notices for the three pre-existing `.pytest-tmp/` deletions; those paths were not read, restored, or changed.
- The current `compose.yaml` has one `driver: bridge` entry for `llm-egress`. Its other quoting and spacing changes remain user changes. The committed `origin/main` already had a single driver entry.
- Docker CLI is unavailable in this environment. Compose parsing, image builds, container startup, network behavior, health checks, and runtime integration remain **NOT VERIFIED**.
- Dependency security scanners and lint/type-check tools (`pip-audit`, Bandit, Ruff, mypy) are not installed; no packages were installed. No live OpenRouter request was made.
- The three `.pytest-run-codex-*` directories contain local test output and are ignored by the new narrow `.gitignore` rule; they were not deleted. The three pre-existing `.pytest-tmp/` deletions remain intact.

## Limitations

Gateway and admin bearer tokens are shared prototype credentials without user accounts, expiry, or rotation. Prompt detection is deterministic pattern matching and may miss attacks or flag benign prompts. Scenario coverage is fixed and local. The audit revision chain is SHA-256 with an HMAC checkpoint in separate persistent storage; it detects changes to the DB head while the checkpoint and key remain intact, but does not resist a compromised Gateway or host administrator, or rollback of a matching older database/checkpoint pair. Model output and scenario results do not establish general security. Docker Compose supplies basic local network boundaries, not a complete sandbox. `/test` remains a demo stub.

## Audit checkpoint update — 2026-10-28

- Full Python suite: **132 passed, 1 existing Starlette/httpx deprecation warning**.
- `venv\Scripts\python.exe -m pip check`: **No broken requirements found**.
- Scoped `git diff --check` for the audit feature files: **passed**. The full-tree check reports access denied on the three pre-existing `.pytest-tmp/` deletions, which were preserved.
- Docker CLI is unavailable, so Compose validation and container runtime verification were not performed.
- `BAYORA_AUDIT_CHECKPOINT_KEY` is not configured in the current local environment. Configure and back up a private key of at least 32 bytes before starting the Gateway with this feature.
