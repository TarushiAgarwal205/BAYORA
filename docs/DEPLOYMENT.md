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

A prior runtime report recorded HTTP 200 from the Gateway's Windows loopback
health endpoint at `http://127.0.0.1:8000/health` and an effective Docker
mapping on `127.0.0.1:8000`. The latest independent audit instead reported
Windows host access as blocked. The chronology and current state cannot be
established from these conflicting reports, so current Gateway host access is
**NOT VERIFIED**. Verify the effective mapping and host `/health` response
again before enabling dependent users. Verify `/dashboard/` separately. Host
port publication is inbound access and does not establish Red/Blue network
isolation or constrain Gateway outbound access: Gateway is attached to the
non-internal `gateway-host` bridge, and its reachable destinations and egress
policy remain unverified.

## Runtime verification

From the checkout, inspect existing runtime state and local health paths:

```powershell
docker compose ps
docker compose logs --tail=100 gateway blue llm egress-proxy
venv\Scripts\python.exe -m scripts.verify_isolation --probe
```

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

The latest independent runtime audit found `bayora-llm-1` attached to
`bayora_llm-egress` while `bayora-egress-proxy-1` was absent. Runtime LLM
egress enforcement is therefore **NOT VERIFIED**. The Red container was
stopped, so normal Red-runner access to Gateway and isolation from Blue are
also **NOT VERIFIED**. The owner of `bayora-port-test` remains unknown; do not
change it or its network attachment without establishing ownership and
authorization.

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
policy is enforced by code; the latest runtime audit found that topology was
not in effect. Host-level default-deny egress for the proxy itself is not
configured here.

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

The latest independent audit reports **157 tests passed** and
`docker compose config --quiet` passed. Image build readiness was not reported
as verified. The audit still found Windows Gateway access blocked on port
8000, the running LLM attached to `bayora_llm-egress`, the egress proxy
container absent, and the Red container stopped. Runtime LLM egress
enforcement and normal Red-runner isolation remain **NOT VERIFIED**. These
results do not establish runtime isolation or successful provider traffic.
