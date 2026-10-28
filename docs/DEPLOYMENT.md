# BAYORA deployment preparation

This guide separates repository controls from checks that must pass on the
deployment host. The current worktree is not a deployed release.

## Configuration

Create the ignored `.env` from `.env.example` and set separate values for:

- Required: `BAYORA_BLUE_SERVICE_TOKEN`, `BAYORA_GATEWAY_RED_TOKEN`,
  `BAYORA_GATEWAY_BLUE_TOKEN`, `BAYORA_LLM_SERVICE_TOKEN`, and
  `BAYORA_AUDIT_CHECKPOINT_KEY` (at least 32 random bytes).
- Optional: `BAYORA_GATEWAY_ADMIN_TOKEN`, `BAYORA_OPENROUTER_API_KEY`, and
  `BAYORA_LLM_MODEL` (defaults to `openrouter/free`). Without the OpenRouter
  key, LLM generation fails closed.
- Compose supplies `BAYORA_LLM_EGRESS_PROXY=http://egress-proxy:8080` to the
  LLM service. It is not a secret; do not override it with an unreviewed proxy.

Never print or commit `.env`, include it in diagnostic bundles, or use
production provider credentials in automated tests.

## Preflight and startup

Run from the reviewed deployment checkout in PowerShell:

```powershell
docker compose config --quiet
docker compose build
docker compose up -d gateway blue llm egress-proxy
docker compose ps
```

All required services must report healthy before continuing. Compose health
checks are Gateway `/health`, Blue `/health`, LLM `/health`, and a TCP listener
check for the egress proxy on port 8080. Only Gateway should publish a host
port, on `127.0.0.1:8000`; no other service should have a published host port.

The 2026-10-28 candidate verification recorded an effective Docker binding on
`127.0.0.1:8000` and a successful Gateway `/health` response from Windows
loopback. `/dashboard/` and service health checks also succeeded in the
isolated test project. This supersedes older snapshots below that found the
host publication inactive; those findings describe different, stopped
containers, not this candidate run. Port publication is inbound access and
does not establish network isolation or constrain Gateway outbound access.

## Runtime verification

From the checkout, inspect existing runtime state and local health paths:

```powershell
docker compose ps
docker compose logs --tail=100 gateway blue llm egress-proxy
venv\Scripts\python.exe -m scripts.verify_isolation --probe
```

The verifier prints a JSON `RUN` record with a unique run ID, UTC start time,
Compose target/file, probe mode, and optional controlled egress destination,
followed by a `SUMMARY` record carrying the same ID and per-status counts.
Capture its output with the deployment evidence; the verifier does not persist
a report automatically.

The verifier does not start or stop services. Require expected network
attachments, Gateway-to-Blue/LLM health success, no direct Red-to-Blue path,
and no unexpected peer on protected networks. A `bayora-port-test` peer has
previously been found on `bayora_blue-gateway`; identify its owner before any
network changes and do not disconnect it as part of this procedure.

The LLM must be attached only to internal `llm-gateway` and `llm-proxy`; only
`egress-proxy` may attach to `llm-egress`. The LLM client explicitly uses that
proxy. The proxy allows CONNECT only to `openrouter.ai:443`, checks public DNS
answers, and requires ClientHello SNI `openrouter.ai`. HTTP redirects are not
followed. The original TLS connection remains end-to-end between the LLM
client and provider. Since the proxy does not terminate TLS, it cannot inspect
the encrypted HTTP authority/path or independently enforce which OpenRouter
API routes are used. ClientHello SNI is a routing check, not provider
authentication; TLS certificate validation by the LLM client remains
essential. There is no host-level deny rule constraining the proxy's own
external connections, so code-level policy and Compose topology still require
runtime verification and do not resist a compromised proxy or host.

In the 2026-10-28 isolated candidate run, Red reached Gateway but could not
reach Blue directly; the LLM was attached only to internal `llm-gateway` and
`llm-proxy`, while only `egress-proxy` joined non-internal `llm-egress`. The
proxy returned HTTP 403 for `CONNECT example.invalid:443`. This verifies the
observed topology and prohibited-destination rejection in that run. It does
not verify that an approved external destination succeeds or that direct LLM
egress fails against a positive, deployment-owner-controlled listener. No
provider request was made. Older `bayora-*` runtime snapshots below refer to
other containers and are not evidence about the isolated candidate stack.

The optional direct-egress probe requires an IP and TCP port for a
deployment-owner-controlled public listener. The listener must be reachable
from `egress-proxy`; the verifier first checks that positive baseline and only
then interprets a direct LLM connection attempt. It reports timeout, missing
baseline, and other ambiguous results as **UNVERIFIED**. A reserved TEST-NET
address or an arbitrary unreachable address is not a valid positive baseline.
This probe makes no provider request and uses no credentials:

```powershell
venv\Scripts\python.exe -m scripts.verify_isolation --probe --egress-probe-ip $ProbeIp --egress-probe-port $ProbePort
```

A provider-positive test is separate: deployment-owner approval, an approved
non-production key, and a synthetic prompt are required. It may contact
OpenRouter and incur cost. Record only status and timing; never record
credentials or prompt content.

These runtime probes and Compose declarations do not protect against a
compromised egress-proxy process or Docker host. In the intended Compose
topology, the proxy is the LLM's sole external network path and its destination
policy is enforced by code. Host-level default-deny egress for the proxy itself
is not configured here.

## Candidate runtime evidence (2026-10-28)

The candidate commit `95c60f17939fb3af7e802b56e79c0c92e9db2c77` was built and
started under an isolated project name, with synthetic-only credentials and a
temporary overlay. Gateway, Blue, LLM, and egress proxy became healthy; Red
was running for controlled tests. Only Gateway published loopback port 8000.
The live verifier reported **123 PASS, 0 FAIL, 11 UNVERIFIED**. All five
containers reported UID/GID `10001:10001`, `CapEff=0`, `NoNewPrivs=1`,
`Seccomp=2`, read-only root filesystems, and effective cgroup limits matching
Compose: Gateway 1 CPU/512 MiB/128 PIDs; Blue, LLM, and Red 0.5 CPU/256
MiB/64 PIDs each; egress proxy 0.25 CPU/128 MiB/32 PIDs. Seccomp mode 2
confirms a filter is active but does not identify its profile or rules.

The verifier's remaining UNVERIFIED results include the absence of a named
seccomp profile and the lack of an approved, positively reachable external
listener for the LLM-egress baseline. The proxy's HTTP 403 for a synthetic
prohibited CONNECT was observed, but no approved external destination or
provider was contacted. The host-side synthetic Red/Blue scenario run passed
4/4; the in-container Red-configured run passed 3/3. These checks do not
establish production hardening or sustained resource behavior under load.

## Rollback readiness

The Compose file builds local images from the working tree and does not pin
immutable release image references. Before deployment, the deployment owner
must retain the last approved source/Compose release and the matching image
IDs or immutable image artifacts, along with secret references (not secret
values). Confirm that rollback material is available before promotion.

If a check fails, halt promotion and keep diagnostic evidence. With deployment
owner approval, redeploy the retained known-good Compose release and matching
images service-by-service, then repeat health and network checks before
restoring traffic. Do not use `docker compose down` as a rollback step: it can
stop unrelated working BAYORA services and may encounter the unidentified
`bayora-port-test` network peer. This repository does not currently provide an
automated immutable-image rollback command; if the owner cannot identify the
previous release artifacts, deployment is blocked until that rollback path is
prepared.

## Local regression checks

Use a fresh writable temporary directory on Windows rather than the existing
pytest temporary directories:

```powershell
$pytestBase = Join-Path $env:TEMP ("bayora-pytest-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $pytestBase | Out-Null
venv\Scripts\python.exe -m pytest -q -p no:cacheprovider --basetemp $pytestBase
git diff --check
```

Unit tests mock the provider path and do not establish Docker route enforcement
or successful provider connectivity. Do not claim deployment completion until
the target-host runtime checks above pass.

## Historical local repository checks

An earlier local check on 2026-10-28 reported **61 focused tests** and **157
full-suite tests** passed, with one existing Starlette/httpx deprecation
warning, and successful `pip check` and Python compilation. At that time the
Docker and Docker Compose CLIs were unavailable, so Compose validation and
runtime checks were not performed. Those tool-availability statements are a
historical snapshot, not the latest Compose result.

## Latest independent verification

This historical audit reported **157 tests passed** and
`docker compose config --quiet` passed. It found Windows Gateway access
blocked on port 8000, the running LLM attached to `bayora_llm-egress`, the
egress proxy absent, and Red stopped. Those observations were made against a
different runtime and are superseded for the hardening candidate by the
2026-10-28 candidate runtime evidence above; they do not describe the isolated
candidate project.
