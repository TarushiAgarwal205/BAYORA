# BAYORA submission readiness

**Evidence baseline:** `79b8deded522c78c9224b33306b6952833dd530a`

**Verification checkout:** `verification/submission-readiness-79b8ded`

**Scope:** local prototype and evidence available at this commit. This is a
demonstration guide, not a production security certification.

## Six advertised security capabilities

| Capability | Classification | Evidence at this baseline | Limits |
|---|---|---|---|
| Container isolation | **Implemented but incompletely tested** | `compose.yaml` configures UID/GID `10001:10001`, read-only root filesystems, `cap_drop: ALL`, `no-new-privileges`, tmpfs restrictions, and PID limits. On this exact baseline, isolated Docker runtime probes observed non-root IDs, zero effective capabilities, `NoNewPrivs=1`, `Seccomp=2`, `/app` write denied, `/tmp` write allowed. | Compose does not select a named seccomp profile. The profile/rules are not identified. Production bind mounts remain writable. No claim is made about resistance to host/kernel/runtime compromise. |
| Network segmentation | **Implemented but incompletely tested** | Compose uses internal Red-Gateway, Blue-Gateway, and LLM-Gateway networks. Runtime checks on the baseline observed Red→Gateway, Gateway→Blue, Blue→Gateway health success and failed DNS resolution for Red→Blue, Red→LLM, Blue→Red. | Gateway also has a host-facing bridge; LLM has an egress bridge. External egress policy was not probed. Compose segmentation is a local boundary, not a complete isolation proof. |
| Resource governance | **Implemented and tested** | Compose sets CPU, memory, and PID limits. Runtime cgroups on this baseline matched those values: Gateway 1 CPU / 512 MiB / 128 PIDs; Blue, LLM, Red each 0.5 CPU / 256 MiB / 64 PIDs. A single `docker stats --no-stream` observation was captured. | A single idle/health-check sample is not a load, saturation, or resilience test. |
| Access and secret isolation | **Implemented but incompletely tested** | Application tests and isolated live probes verified credential-derived roles, rejection of a Red request claiming Blue, admin-only operations, and denial of attempts to disable mandatory inspection/policy safeguards. Service-to-service tokens are required for Blue/LLM calls. | Shared prototype bearer tokens have no per-user identity, expiry, or automated rotation. Host secret storage/ACLs and production secret lifecycle were not assessed. |
| Tamper-evident audit | **Implemented and tested** | SQLite SHA-256 snapshot-chain verification detects changed/deleted events, missing initialization marker, removed chain entries, and reordered chain entries. Reads/writes fail closed on detected corruption. | The chain is unkeyed and not externally anchored. A privileged database writer can recompute it. Legacy event history is only baselined at initial setup. |
| Security monitoring | **Implemented but incompletely tested** | Fixed indicators detect repeated denials, traversal-like resource names, and session role-switch attempts. Authenticated audit anomaly/report endpoints and admin incident/evidence flows are covered by tests. The fixed four-case runner produced 4 PASS, with expected/actual decisions and audit evidence, and exported JSON. | Indicators are small heuristics, not comprehensive detection. No alert delivery, continuous monitoring service, or live LLM safety claim is demonstrated. |

### Test-count scope

On this fresh checkout at the stated baseline, the complete committed project
suite returned **101 passed in 11.96s**. Exact command and result:

```powershell
$pytestTemp = Join-Path $env:TEMP ("bayora-submission-" + [guid]::NewGuid().ToString("N"))
python -m pytest -q -p no:cacheprovider --basetemp $pytestTemp
```

This command was rerun in this submission-readiness worktree. The unique
`--basetemp` avoids collisions with prior runs.

The security-verification worktree contains **four supplemental acceptance
tests**, separate from the committed baseline suite. Exact command and result:

```powershell
# Run from the BAYORA-security-verification worktree root.
$pytestTemp = Join-Path $env:TEMP ("bayora-supplemental-" + [guid]::NewGuid().ToString("N"))
python -m pytest -q -p no:cacheprovider --basetemp $pytestTemp tests/test_security_acceptance.py
```

Result: **4 passed in 0.85s**. Those tests check static Compose settings and
audit-chain entry removal/reordering; they are not added to the 101 baseline
count.

Codex has separately reported a newer **102-test** result. That result is
reported, not independently verified here: this worktree remains at the
101-test baseline commit, and no newer Codex checkout was used. Do not add the
reported 102 to either of the test results above or describe it as this agent's
run.

All automated LLM tests use fakes/mocks. The isolated live scenario run used
the denied LLM case; no provider call or external LLM request was made.

## Practical local demonstration

### Before the demo

1. Use a disposable local `.env`, excluded from Git. Set distinct high-entropy
   values for `BAYORA_BLUE_SERVICE_TOKEN`, `BAYORA_GATEWAY_RED_TOKEN`,
   `BAYORA_GATEWAY_BLUE_TOKEN`, `BAYORA_GATEWAY_ADMIN_TOKEN`, and
   `BAYORA_LLM_SERVICE_TOKEN`. Leave `BAYORA_OPENROUTER_API_KEY` unset for this
   demo. Do not display or paste token values into screenshots, terminal output,
   or the submission.
2. From the repository root, validate configuration and start only the
   Gateway, Blue fixture service, and LLM service:

   ```powershell
   docker compose config --quiet
   docker compose up -d gateway blue llm
   Invoke-RestMethod http://127.0.0.1:8000/health
   (Invoke-WebRequest http://127.0.0.1:8000/dashboard/).StatusCode
   ```

   Expected health response is `{"status":"healthy"}` and the dashboard status
   is HTTP 200. No OpenRouter key is needed for startup or the denied
   scenarios. Keep Docker logs private; do not capture environment output.

### Suggested 5–8 minute sequence

1. **Dashboard status and identity:** open
   <http://127.0.0.1:8000/dashboard/>. Enter the admin credential in the
   dashboard token field without recording it. Show policy, audit integrity,
   anomaly, report, and admin scenario panels. Explain that `/test` is a demo
   stub, not a security test.
2. **Policy allow and deny:** in the Policy & Resource Request Form, enter the
   Red caller token, select `run_approved_test` and
   `test:authorized_access`, then select `read_artifact` and
   `blue:synthetic-confidential`. Show the allow and deny decisions,
   respectively. The caller credential, not the untrusted body role, determines
   identity. When using `/policy/decide`, show `observed_outcome=NOT_EXECUTED`:
   it evaluates policy but does not execute a protected resource operation.
3. **Credential beats body role:** run the fixed Red resource-read check where
   the request claims Blue but uses the Red caller credential. Expected
   HTTP 403; expected audit role `red`, decision `DENY`,
   `operation_executed=0`, outcome `NOT_EXECUTED`. Do not send the allowed Blue
   positive-control response to a public screen recording; it contains the
   synthetic fixture.
4. **Mandatory controls:** as Red, try to open an admin route and show 403.
   As admin, attempt to disable `prompt_inspection_enabled` or the required
   `red-deny-blue-artifacts` rule; expected HTTP 422. Show that the rule
   remains present/enabled.
5. **Fixed scenario run and evidence export:** in the admin dashboard, open the
   scenario library, select all four fixed scenarios, run them, and export the
   latest JSON evidence. To use the API instead, securely prompt for the admin
   token (the input is masked and the token is not printed), then run:

   ```powershell
   $adminSecure = Read-Host 'Admin bearer token' -AsSecureString
   $adminToken = [System.Net.NetworkCredential]::new('', $adminSecure).Password
   $admin = @{ Authorization = "Bearer $adminToken" }
   Invoke-RestMethod http://127.0.0.1:8000/admin/scenarios -Headers $admin
   $run = Invoke-RestMethod http://127.0.0.1:8000/admin/scenarios/run `
     -Method Post -Headers $admin -ContentType 'application/json' `
     -Body '{"scenario_ids":["allowed-protected-resource","denied-red-resource-read","invalid-test-identifier","policy-denied-llm-generation"]}'
   $run.summary
   Invoke-RestMethod "http://127.0.0.1:8000/admin/scenarios/runs/$($run.run_id)/evidence" `
     -Headers $admin
   ```

   The documented request is for the admin-authenticated API. It runs the
   allow and deny examples against the local Gateway; the runner uses configured
   Red/Blue caller tokens. An independently observed isolated baseline run
   returned `PASS=4`, `FAIL=0`, `INCONCLUSIVE=0`. For a fresh live demo, report
   the actual returned counts rather than assuming this prior result repeats.
   Present expected fields, observed HTTP status, decision, and audit evidence.
   Do not imply this fixed suite proves general security. The denied LLM case
   is policy-blocked before provider invocation.
6. **Audit/monitoring:** show `GET /audit/integrity` as valid; show
   `/audit/anomalies` and `/audit/report` using the relevant authenticated
   role. For a dashboard flow, use its integrity/anomaly/report controls.
   Explain that the chain is unkeyed and alerts are simple indicators.
7. **Capture evidence:** capture a redacted screenshot of the dashboard status,
   policy decision, scenario summary, one denied event’s outcome fields,
   integrity status, and JSON export status. Blur/omit authorization headers,
   tokens, prompt text, host paths that reveal private user details, and any
   synthetic fixture body. Record the Git commit and the exact test command
   with the demo package.
8. **Stop services after the demo:**

   ```powershell
   docker compose down
   ```

   If persistent audit data must be retained for later review, do not delete
   `data/`; treat its contents as sensitive evidence.

### Expected evidence fields

- Allow policy decision: `decision=ALLOW`, `observed_outcome=NOT_EXECUTED`,
  `verification_result=NOT_VERIFIED`.
- Denied Red resource read: HTTP 403; audit `role=red`, `decision=DENY`,
  `operation_executed=0`, `observed_outcome=NOT_EXECUTED`.
- Allowed synthetic Blue positive control: HTTP 200; `decision=ALLOW`,
  `operation_executed=1`, `observed_outcome=SUCCEEDED`,
  `verification_result=VERIFIED`. Only show the sanitized outcome, not the
  fixture contents.
- Denied LLM case: HTTP 403; expected `DENY` and no operation execution. It
  must not invoke the provider when the policy preflight denies.
- Audit integrity: `valid=true` before tampering. Do not tamper with a demo or
  production database; tamper cases run only against temporary test databases.
- Scenario evidence: PASS/FAIL is an observed comparison to expected behavior,
  not a claim that the system is generally secure.

## Implemented behavior versus claims

- **Policy and protected resources:** default-deny evaluation, explicit deny
  precedence, authenticated Gateway roles, session role binding, and one
  synthetic Blue resource. This is not arbitrary resource protection.
- **Administration:** authenticated policy CRUD/dry-run with persistence and
  a required deny safeguard; security detection configuration only exposes
  mutable tuning fields. Mandatory inspection, high-severity blocking, and
  anomaly detection cannot be disabled through that config API.
- **Prompt inspection:** deterministic pattern heuristics run before provider
  call; prompt body is not persisted in audit. This does not establish model
  safety or reliable prompt-injection detection.
- **Scenarios and incidents:** four fixed local runner cases, audit-linked
  evidence, JSON export, and admin incident filters/details. This is not a
  general-purpose autonomous Red Team system.
- **Containers/networking:** Compose settings and local runtime behavior were
  exercised for baseline commit `79b8ded` in the separate
  `verification/security-acceptance-79b8ded` worktree. This is evidence for
  that exact Compose configuration only. The latest Gateway network
  configuration has not been independently checked or runtime-tested here.
  Codex has reported a newer network change and a 102-test result; neither the
  newer configuration nor its runtime behavior was tested from this baseline
  checkout. Do not claim that change passed runtime verification. Compose is
  not a hardened sandbox or a complete external-egress policy.
- **Audit:** detects tested changes/removals/order gaps when integrity history
  cannot also be rewritten. It is not signed, keyed, or immutable against a
  privileged database writer.

## Documentation freshness and remaining submission gaps

- `README.md` describes current route contracts and limitations.
- `STATUS.md` still contains an earlier note that Docker CLI/runtime was
  unavailable. That note is stale relative to the subsequent isolated Docker
  verification at the same commit; do not use it as the latest runtime result.
- `FINAL_VERIFICATION_REPORT.md` records prior work and has historical sections.
  Prefer the baseline and command/result evidence in this document and the
  separate security-verification report when citing those checks.
- Shared bearer tokens remain prototype authentication without user lifecycle,
  expiry, or automated rotation.
- The default Compose Gateway and LLM networks provide possible external
  egress paths; external destination policy was not tested.
- Compose does not pin a named seccomp profile. Runtime `Seccomp: 2` only
  establishes that a filter was active.
- Writable host bind mounts for database, policy, and reports are part of the
  current persistence/admin design. A compromised Gateway process may modify
  its writable policy mount.
- The unkeyed audit chain cannot prevent a privileged SQLite writer from
  recomputing history.
- No live OpenRouter call, production infrastructure, host secret ACL, browser
  automation, adversarial load test, or external network target was used for
  these results.

## Reproducible test commands

From the project root:

```powershell
python -m pytest -q -p no:cacheprovider --basetemp <writable-temp-dir>
python -m pip check
git diff --check
```

The test suite uses isolated SQLite files and mocked LLM clients. The
deterministic Red runner and live Docker network checks are separate
demonstrations requiring configured local services and private local
credentials. Never paste `.env` values into the report or screenshots.
