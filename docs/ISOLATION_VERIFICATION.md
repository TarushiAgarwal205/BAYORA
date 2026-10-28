# BAYORA resource and isolation verification

## Latest candidate evidence (2026-10-28)

This section supersedes the older runtime snapshots later in this document
for the candidate commit `95c60f17939fb3af7e802b56e79c0c92e9db2c77`. The
candidate was built and run in a uniquely named, isolated Compose project with
synthetic credentials and a temporary verification overlay; the primary
BAYORA project, unrelated containers, networks, and volumes were not changed.
The verifier run `a8ade081-2121-44c1-9835-77e1eee6a1c1` reported **123 PASS,
0 FAIL, 11 UNVERIFIED, 98 INFO**. An UNVERIFIED result is not a pass.

Observed live evidence:

- Compose configuration validation and all five candidate image builds
  succeeded. Gateway, Blue, LLM, and egress proxy became healthy; Red was
  running for the tests.
- Only Gateway published a host port (`127.0.0.1:8000`); Windows loopback
  `/health` succeeded. Blue, LLM, Red, and egress proxy had no published
  ports.
- Red reached Gateway, but a direct Red-to-Blue probe failed with an explicit
  network-unreachable result while Blue's Gateway-mediated health path worked.
  The live Red runner's three configured cases passed. A separate host-side
  run with synthetic Red and Blue caller tokens passed all four cases, and its
  persisted report reloaded consistently with observed HTTP results, policy
  decisions, and audit event IDs.
- `CONNECT example.invalid:443` through the live egress proxy returned HTTP
  403. The LLM was attached only to internal `llm-gateway` and `llm-proxy`;
  only the proxy was attached to non-internal `llm-egress`.
- Each service ran as UID/GID `10001:10001`, with `CapEff=0`,
  `NoNewPrivs=1`, `Seccomp=2`, a read-only root filesystem, and observed
  cgroup v2 values matching Compose: Gateway `100000 100000` CPU,
  `536870912` bytes memory, 128 PIDs; Blue, LLM, Red `50000 100000`,
  `268435456` bytes, 64 PIDs; proxy `25000 100000`, `134217728` bytes,
  32 PIDs. These observations establish configured effective limits, not
  sustained contention behavior.

Unresolved: the verifier could not establish a named seccomp profile or rules,
and no deployment-owner-controlled, positively reachable external listener
was available to validate the LLM egress baseline and direct-LLM denial. The
proxy's prohibited-destination response was tested, but approved external
egress and provider connectivity were not tested; no provider request was
made. Compose network topology and an active seccomp filter do not prove
host-level egress enforcement or resistance to host compromise.

The full Python suite at this candidate passed **233 tests** with one existing
Starlette/httpx deprecation warning. The 24 legacy Red reports all loaded.
These software tests do not substitute for the live checks or resolve the
UNVERIFIED results.

## Scope and safety

This guide verifies static Compose settings and, when containers are already
running, their inspected Docker configuration. It does not create, restart,
stop, or remove containers. The verifier never prints environment variables
and does not send prompts or credentials to an external provider.

Run commands from the repository root. Results must be recorded with the
current Git commit, Docker/Compose versions, host OS, and whether the examined
containers were created from the current Compose file. Do not treat results
from a running stack as evidence for a newer Compose file unless the inspected
container configuration matches it.

## Commands

Static Compose validation only:

```powershell
docker compose config --quiet
```

Combined static and existing-container inspection:

```powershell
python scripts\verify_isolation.py
```

Optional read-only runtime probes against existing containers:

```powershell
python scripts\verify_isolation.py --probe
```

For a reproducible runtime check, use a disposable Docker host or isolated
Compose project with no production data or credentials. Start only the stack
you intend to inspect, then run the verifier without asking it to create or
change deployment state:

```powershell
docker compose config --quiet
docker compose up -d gateway blue llm
docker compose ps --all
python scripts\verify_isolation.py --probe
```

This sequence verifies the currently running Gateway, Blue, and LLM containers.
It does not start Red, so Red-to-Blue direct access remains UNVERIFIED unless
an already-running Red container is available. The verifier never starts Red
or creates a probe container. Run the same command after a reviewed deployment
change and record its commit and Docker environment; do not use evidence from
containers created from a different configuration as evidence for the new
deployment.

The optional probes read `/proc` and cgroup files, sample public local health
endpoints, and run `docker stats --no-stream`. They do not run a scenario, call
an external host, start a process-intensive workload, or change deployment
state. The Red-to-Blue probe runs only if a Red container is already running;
the verifier never starts one. A PASS from `docker inspect` means Docker reports
that setting on the container; it is not a substitute for kernel-level runtime
evidence. Compose declarations are reported as INFO when present, not as PASS
for effective enforcement. Missing required declarations are FAIL. Runtime
PASS results identify whether their evidence is Docker metadata, `/proc`,
cgroup, or a successful local health response.

The Red-to-Blue check probes Blue's Docker-reported private address directly
from an already-running Red container, rather than relying on an unresolved
service name. A successful HTTP response is FAIL. An explicit kernel
network/host-unreachable error is PASS. Timeouts, connection refusal, DNS
errors, missing probe output, or other ambiguous errors are UNVERIFIED; they
must not be treated as proof of network isolation.

Protected-network peer checks compare Docker's actual peer list with the
Compose services expected on each network. An unlisted container or a BAYORA
service attached to the wrong protected network is reported as FAIL. The
verifier does not disconnect unknown peers; have the deployment owner identify
them and coordinate any corrective deployment.

The script exits `0` only when there are no failed or unverified checks, `1`
when any check fails (even if other checks are also unverified), and `2` when
there are unverified checks but no failures. An UNVERIFIED result is never
counted as a pass.

## Resource governance

| Service | CPU quota | Memory limit | PID limit | Reservations |
|---|---:|---:|---:|---|
| Gateway | 1 CPU | 512 MiB | 128 | None configured |
| Blue | 0.5 CPU | 256 MiB | 64 | None configured |
| LLM | 0.5 CPU | 256 MiB | 64 | None configured |
| Egress proxy | 0.25 CPU | 128 MiB | 32 | None configured |
| Red | 0.5 CPU | 256 MiB | 64 | None configured |

These are Compose service-level `cpus`, `mem_limit`, and `pids_limit` values.
`docker compose config --quiet` confirms the local Compose implementation
accepts the resolved configuration. No `deploy.resources` reservations are
specified; orchestration-mode reservation behavior is therefore not claimed.
The verifier compares these values with the `HostConfig` in `docker inspect`.
With `--probe`, it also reads cgroup v2 `cpu.max`, `memory.max`, and `pids.max`
from existing containers when available. `docker stats --no-stream` records
one instantaneous utilization sample; it does not prove that the configured
limit is enforced under contention.

Do not run an unbounded CPU or memory stress test on a developer workstation or
on a shared BAYORA stack. A contention test requires an isolated disposable
VM/host, no production data or credentials, an externally imposed maximum
duration, monitoring of host and container health, and a predeclared stop
threshold below host exhaustion. Confirm no shared stack is in use first.
Without that controlled environment, record contention behavior as
UNVERIFIED.

## Container isolation

Static settings checked for each service:

- User `10001:10001`, not privileged, all capabilities dropped, and no
  capability additions.
- Read-only root filesystem and `no-new-privileges:true`.
- `/tmp` tmpfs with `noexec` and `nosuid`; the configured size is 8 MiB for
  `egress-proxy` and 16 MiB for the other applicable services.
- Service PID limit and CPU/memory constraints above.
- Whether a named seccomp profile appears in `security_opt`.

Runtime Docker inspection checks the user, privilege flag, read-only rootfs,
capability settings, security options, and limits. Optional `--probe` checks
effective UID/GID, `CapEff`, `NoNewPrivs`, seccomp mode, root and `/tmp` mount
flags, and cgroup v2 limits from inside an already-running container.
`Seccomp: 2` means a filter is active; it does not identify the active profile
or prove which syscalls it blocks. The current Compose file does not pin a
named profile. Bind mounts are separately writable where required; Gateway
policy/data/reports and Red reports must not be described as read-only merely
because the container root filesystem is read-only.

## Network isolation

Static Compose expectations:

- Red is attached only to `red-gateway`; Blue only to `blue-gateway`.
- Gateway joins the internal `red-gateway`, `blue-gateway`, and
  `llm-gateway` networks, plus the separate non-internal `gateway-host`
  bridge. This declared membership does not prove isolation or restrict
  Gateway outbound access.
- LLM joins `llm-gateway` and the internal `llm-proxy` network; the
  `egress-proxy` service joins `llm-proxy` and `llm-egress`.
- The Gateway is the only service with a host port, bound to
  `127.0.0.1:8000`; Blue, LLM, and Red have no published ports.
- The `llm-egress` network is an ordinary bridge used only by the
  `egress-proxy`. The proxy allows HTTPS CONNECT only to the configured
  OpenRouter hostname on port 443; this Compose/code policy is not runtime
  proof and does not constrain a compromised proxy container or Docker host.

Runtime network membership, non-Compose peers, and published bindings are
inspected from existing containers/networks. With `--probe`, local health requests check host-to-Gateway,
Gateway-to-Blue, Gateway-to-LLM, and Blue-to-Gateway. A running Red container is
required to check Red-to-Blue; otherwise this is UNVERIFIED. Network membership
alone does not prove reachability or denial.

The repository now declares a default-deny egress proxy boundary. Verify the
resolved Compose topology and running attachments, confirm LLM direct outbound
connections fail, and send a synthetic denied CONNECT request such as
`example.invalid:443` through the proxy. These checks require no credentials or
external calls. Provider reachability still requires an explicitly approved
deployment test; use a non-production provider credential and a synthetic
prompt, and account for provider traffic/cost. Do not claim provider-only
runtime enforcement based on static Compose or mocked tests.

## Results record

Record each result with category and actual evidence:

| Check | Expected | Actual result | Evidence type | Status |
|---|---|---|---|---|
| Compose parse | Valid resolved configuration | Fill from current command | Static | |
| Resource limits | Service values above | Fill from inspect/cgroup | Static/runtime | |
| Non-root/capabilities/no-new-privileges | Declared settings match runtime | Fill from inspect and optional `/proc` | Static/runtime | |
| Root filesystem and `/tmp` | Root read-only; tmpfs writable/noexec/nosuid | Fill from mountinfo | Static/runtime | |
| Seccomp | Filter active; profile identified if configured | Record mode and explicitly state profile identity | Runtime | |
| Red-to-Blue | Denied | Fill from probe; otherwise UNVERIFIED | Runtime | |
| Gateway-to-Blue/LLM | Health succeeds | Fill from local probes | Runtime | |
| Host publication | Only loopback Gateway port | Fill from inspected port bindings | Runtime | |
| Unlisted network peers | No unknown containers attached | Fill from Docker network inspection | Runtime | |
| LLM egress | Approved destinations only | Candidate: LLM on internal networks, proxy-only external network, prohibited CONNECT returned 403; positive external baseline and direct-LLM denial **UNVERIFIED** | Static/runtime | |
| Contention | Limits respected without host instability | Only with isolated bounded load test | Runtime | |

## Historical runtime inspection (2026-10-28; source HEAD `98ef19c`)

The verification artifact was added after the following read-only inspection.
The source HEAD was `98ef19c3fbfb3e386f88fd4d03535e56eb24f946`; the working tree
also had pre-existing local changes in `compose.yaml` (quoting/spacing only)
and a tracked `.pytest-tmp` fixture. Neither was edited by this verification
work. The runtime snapshot is not evidence for the current worktree or a later
redeployed container set:

- Repository commit inspected: `98ef19c3fbfb3e386f88fd4d03535e56eb24f946`.
- Host: Windows; Docker Engine `29.9.1`; Compose `5.6.0`.
- `docker compose config --quiet`: exit code 0. `python
  scripts\verify_isolation.py --probe` was also run; it returned exit code 1
  because it found three actionable failures, and reported
  `PASS=115`, `FAIL=3`, `UNVERIFIED=10`, `INFO=12`.
- Active containers were present, so no services were launched, restarted, or
  stopped. Docker inspection observed non-root UID/GID `10001:10001`,
  `Privileged=false`, read-only rootfs, `CapDrop=ALL`, no added capabilities,
  `no-new-privileges:true`, and the configured CPU/memory/PID HostConfig limits
  for Gateway, Blue, and LLM. Read-only in-container probes independently
  observed effective UID/GID `10001:10001`, `CapEff=0`, `NoNewPrivs=1`,
  `Seccomp=2`, a read-only `/` mount, and writable `/tmp` tmpfs with `noexec`
  and `nosuid` for those three running services. Red's container was stopped.
- Gateway HostConfig reported 1 CPU, 512 MiB, and 128 PIDs; Blue and LLM each
  reported 0.5 CPU, 256 MiB, and 64 PIDs. A single `docker stats --no-stream`
  sample observed Gateway 41.73 MiB / 3 PIDs, Blue 34.49 MiB / 3 PIDs, and
  LLM 38.54 MiB / 3 PIDs. The Gateway CPU sample was 0.27%; these instantaneous
  values are not a sustained-load or contention result. In-container cgroup
  reads matched Gateway `100000 100000` CPU quota, `536870912` byte memory,
  and 128 PIDs; Blue and LLM matched `50000 100000`, `268435456` bytes, and
  64 PIDs.
- At that inspection, Gateway was attached to `bayora_gateway-host`, which was
  not declared in the then-inspected Compose source. Runtime inspection showed
  only `127.0.0.1:8000` published for Gateway and no published ports for
  Blue/LLM. The LLM container was attached to the ordinary
  `bayora_llm-egress` bridge. These are historical attachments and do not
  establish the current runtime topology.
- Docker network inspection also found a running, non-Compose container named
  `bayora-port-test` attached to `bayora_blue-gateway`. Its image is `nginx`,
  it has no Docker Compose ownership labels, and its published-port list is
  empty; its owner and purpose were not established. The verifier reports it
  as an unexpected peer and does not send it traffic. The other inspected
  `port-test` container was on Docker's default `bridge`, not a BAYORA service
  network.
- Optional health probes at that inspection returned 200 for host-to-Gateway,
  Gateway-to-Blue, Gateway-to-LLM, and Blue-to-Gateway. Red-to-Blue direct
  reachability remained UNVERIFIED because no Red container was running; the
  verifier did not start one.
- **FAIL:** The LLM egress bridge is not a provider-destination allowlist.
  General external destinations are not restricted by this Compose config.
- **FAIL:** The active Gateway's extra `bayora_gateway-host` attachment differs
  from the current Compose declaration. Validate network behavior only after a
  coordinated deployment matches the inspected source configuration.
- **FAIL:** Unlisted container `bayora-port-test` is attached to the internal
  Blue/Gateway network. Confirm its owner and purpose; remove or detach it only
  through the responsible stack owner after confirming it is not in use.
- **UNVERIFIED:** Seccomp profile identity/rules (although `Seccomp=2` confirms
  filtering is active), Red-to-Blue traffic denial, provider-only egress,
  resource contention, and runtime behavior of containers started from the
  current Compose file.

No secrets, environment variable values, provider requests, or external
destinations were used in the inspection.

## Follow-up finding investigation

Read-only follow-up on 2026-10-27 confirmed the three network findings against
the same repository commit and the already-running Docker environment. The
repository HEAD remained
`98ef19c3fbfb3e386f88fd4d03535e56eb24f946` on branch `main`; the host was
Windows with Docker Engine `29.9.1` and Compose `5.6.0`. This is a separate
observation of the existing containers, not evidence for a fresh deployment.
No tests, network probes, Compose changes, or container lifecycle operations
were performed in this follow-up.

| Finding | Current disposition | Confirmed facts | Not established | Minimal next action |
|---|---|---|---|---|
| Extra Gateway `bayora_gateway-host` attachment | **Confirmed; unresolved runtime/source mismatch** | The running `bayora-gateway-1` container belongs to Compose project `bayora`, and its Docker Compose config-file label points to this checkout's `compose.yaml`. Docker reports four attachments, including `bayora_gateway-host`; the current working-tree Compose service declares only `red-gateway`, `blue-gateway`, and `llm-gateway`. The extra network is a non-internal bridge and has Gateway as its only current member. | Whether the attachment came from an older Compose file, manual attachment, or another approved operational requirement; whether any intended host/network access depends on it. Membership alone does not prove a reachable peer or exploitable path. | The deployment owner should compare the intended deployment manifest and confirm whether this attachment is required. If unintended, remove it from the deployment state in an approved maintenance window by reconciling/recreating the Gateway from the reviewed configuration. Do not detach it from the active container without owner approval. |
| `bayora-port-test` on `bayora_blue-gateway` | **Confirmed; ownership/action blocked** | Docker reports a running `nginx` container with no Compose project/service labels, attached to `bayora_blue-gateway` at `172.21.0.4`. Its inspected published-port list is empty. | Who created it, why it is attached, whether an operator is using it, and whether its service can reach any particular application endpoint; no traffic was sent. | The Docker/container owner should identify and authorize the container. If it is not required on this trust segment, disconnect it from `bayora_blue-gateway` during an approved change window (or remove it through its owning deployment); do not stop or disconnect it until its owner confirms it is safe. |
| LLM provider-specific egress | **Missing from Compose; effective host policy unverified** | The current working-tree `llm-egress` declaration is a regular `bridge` without an internal flag or destination allowlist. Runtime inspection reports `bayora_llm-egress` as `driver=bridge`, `internal=false`, with the LLM container attached. | Whether host firewall, endpoint, or upstream network policy independently restricts outbound traffic. No external or provider destination was contacted, so actual reachability and provider-only behavior were not tested. | If provider-only egress is a requirement, the deployment owner must provide a default-deny egress boundary (for example, an approved proxy/firewall destination allowlist) for the LLM service, then validate approved and blocked synthetic destinations in an isolated environment without credentials. Until then, provider-only egress remains unverified and must not be claimed. |

These dispositions do not change the earlier result counts (`PASS=115`,
`FAIL=3`, `UNVERIFIED=10`, `INFO=12`). The three findings remain failures of
the inspected configuration/runtime posture; no finding was resolved by this
read-only follow-up. Red-to-Blue denial and resource contention remain
unverified. No containers or networks were modified, and no user or Codex
changes were staged, committed, reverted, or discarded.

## Additional read-only ownership and policy investigation

On 2026-10-27, further read-only inspection was performed on the then-current
HEAD `cbc028add51295480c070766757f9d43617a9b95` (branch `main`) using the
Docker Desktop context and Engine `29.9.1`. This is a new snapshot; it does not
replace the earlier evidence recorded against
`98ef19c3fbfb3e386f88fd4d03535e56eb24f946`. The local `compose.yaml` changes
were quoting/spacing only; the committed and working-tree network declarations
both omit `gateway-host` from Gateway and define `llm-egress` as an ordinary
bridge. No containers, networks, or firewall rules were modified, and no
outbound connectivity tests were performed.

- **Gateway network — Compose origin confirmed; purpose only inferred.**
  Docker labels on `bayora_gateway-host` identify it as Compose network
  `gateway-host` in project `bayora`, created with Compose `5.6.0`; it is a
  non-internal bridge and Gateway is its only member. The running Gateway's
  Compose config-file label points to this checkout's `compose.yaml`, but its
  recorded service config hash (`cb976e81d16acb824a25aebfa12f70d47dba24b1b74cde46ba48a42b5a75f968`)
  differs from the current `docker compose config --hash gateway` result
  (`e519e5b24bc7e3a906f52f2aeb6a111835be43eb7c50d27f186d0db905f18112`).
  This supports a different resolved service configuration at container
  creation, but does not establish whether the difference came from an older
  Compose file, environment-dependent resolution, or a later attachment.
  The name and non-internal bridge are consistent with an intended Gateway
  external/host-network path, but that purpose and its owner are not proven.
  The deployment owner should confirm whether it remains required and identify
  the approved source configuration before any redeployment or detachment.
- **`bayora-port-test` — likely test container; owner unidentifiable.**
  Docker reports image `nginx`, creation time `2026-10-27T15:51:54Z`, no
  Compose project/service labels, no published host ports, and membership on
  `bayora_blue-gateway`. Its name and image are consistent with a temporary
  network/port test, but Docker metadata does not identify a creator, purpose,
  or operator. The safest next step is for the Docker operator to identify the
  owner and confirm whether it is still needed before an approved disconnect.
- **LLM egress — no provider allowlist found in the inspected configuration.**
  The checked-in `llm-egress` network is `driver: bridge`; Docker reports
  `internal=false`. The scoped repository search found no proxy, destination
  allowlist, or firewall/network-policy configuration. This establishes that
  provider-specific restriction is not demonstrated by the inspected BAYORA
  Compose/repository configuration. It does not rule out an independently
  managed Windows/Docker Desktop host firewall, endpoint control, or upstream
  network policy; those rules were not inspected.

To verify provider-only egress, the deployment owner must identify and provide
the enforcement point and its effective policy for the LLM container, including
allowed provider destinations, ports/protocols, DNS handling, and default-deny
behavior. Verification then requires a controlled isolated test showing an
approved synthetic destination succeeds and a prohibited synthetic destination
is blocked, with policy/log evidence and no credentials or sensitive prompts.
Until that evidence exists, provider-only egress remains **unverified**.

## Egress proxy implementation update (2026-10-28; historical snapshot)

The Compose source and LLM client now implement the following default-deny
boundary:

- `llm` is attached only to internal `llm-gateway` and `llm-proxy` networks.
- `egress-proxy` is the only Compose service attached to the ordinary
  `llm-egress` bridge. It shares internal `llm-proxy` with the LLM service.
- The LLM client requires `BAYORA_LLM_EGRESS_PROXY`; if it is unset, provider
  generation fails closed. Compose sets it to `http://egress-proxy:8080`.
- The project-built proxy accepts CONNECT only for `openrouter.ai:443`, resolves
  the provider name itself, rejects private, reserved, or mixed public/private
  DNS answers, and requires a bounded TLS ClientHello with exact
  `openrouter.ai` SNI before forwarding TLS bytes. It does not terminate TLS or
  inspect encrypted HTTP paths/authority; SNI is not provider authentication.
  The provider endpoint remains the existing OpenRouter URL; no additional
  provider hosts or third-party proxy images were added.
- Gateway-to-LLM connectivity remains on the separate internal
  `llm-gateway` network. The proxy has no provider API key or service token.

Focused mocked/unit tests passed 54 tests and the full suite passed 150 tests
(each with one existing Starlette/httpx deprecation warning). They establish
allowlist behavior and declared topology only; they do not establish Docker
route enforcement, a successful provider connection, or the absence of
host-managed egress policy. Docker/Compose CLI tools were unavailable in the
implementation environment, so Compose parsing, image build, and runtime
positive/negative egress checks remain unverified. The known Gateway host
publication failure also remains unresolved; this repository change did not
alter its port configuration. The unexplained `bayora-port-test` container was
not modified.

For deployment preparation, configure the existing required secrets and
optionally `BAYORA_OPENROUTER_API_KEY` in the ignored `.env`, then run:

```powershell
docker compose config --quiet
docker compose build
docker compose up -d gateway blue llm egress-proxy
docker compose ps
docker compose logs --tail=100 gateway blue llm egress-proxy
venv\Scripts\python.exe -m scripts.verify_isolation --probe
```

The local verifier must report the expected network attachments and healthy
required routes. For a no-external-call negative test, issue
`CONNECT example.invalid:443` from the LLM network to `egress-proxy:8080` and
expect HTTP 403. Direct-egress denial is a separate runtime check and requires
the verifier's owner-controlled, positively reachable public listener baseline.
Provider-positive testing is a separate deployment-owner action: approve a
non-production key and synthetic request before testing OpenRouter, and never
include credentials or sensitive prompts in diagnostics.

The no-external-call negative checks can be run after deployment with:

```powershell
docker compose exec -T llm python -c "import socket; s=socket.create_connection(('egress-proxy',8080),timeout=2); s.sendall(b'CONNECT example.invalid:443 HTTP/1.1\r\nHost: example.invalid:443\r\n\r\n'); print(s.recv(128).split(b'\r\n',1)[0].decode()); s.close()"
```

Expect HTTP 403 from the proxy. Do not treat failure to connect to a reserved
TEST-NET or arbitrary unreachable address as proof that direct egress is
blocked. For direct-egress verification, use the owner-controlled reachable
public listener and the verifier's positive-baseline procedure above. These
denial checks do not prove provider reachability. Confirm Gateway `/health`, Dashboard `/dashboard/`,
Blue/LLM health, and required Gateway-to-Blue/LLM routes with `--probe`. The
known Windows Gateway published-port failure must be resolved independently.

## Runtime follow-up (2026-10-28, repository HEAD `193cbae`; historical snapshot)

This read-only inspection used Docker Desktop's local Engine API because the
Docker and Docker Compose CLIs were unavailable. The Engine reported Docker
29.9.1. No service, firewall rule, or existing network was restarted or
changed. The only temporary container was a controlled Red-image probe and it
was removed after the check.

- **Gateway internal service:** Docker reported `bayora-gateway-1` running and
  healthy. Bounded checks from inside that container returned success for
  `http://127.0.0.1:8000/health` and `/dashboard/` (HTTP 200 checks).
- **Gateway host publication — release blocker:** `HostConfig.PortBindings`
  requests `127.0.0.1:8000`, but Docker's effective `NetworkSettings.Ports`
  was `8000/tcp: []`; the container list had no host binding, and Windows had
  no listener on port 8000. Direct host TCP, `/health`, and `/dashboard/`
  requests to `127.0.0.1:8000` were refused. WinHTTP reports direct access
  without a proxy. This narrows the failure to an inactive Docker Desktop port
  publication. Whether the cause is a stale container or an Engine/host
  forwarding fault remains undetermined: the Compose CLI was unavailable, so
  the effective current configuration could not be compared to the container
  config hash. No restart or firewall change was attempted.
- **Red-to-Blue — runtime probe passed for the configured Red network:** the
  actual `bayora-red-1` container was exited and its Docker-reported sole
  attachment was `bayora_red-gateway`. Blue was attached only to
  `bayora_blue-gateway`; Gateway bridged both. A temporary probe from the exact
  Red image, using UID/GID `10001:10001`, read-only rootfs, all capabilities
  dropped, `no-new-privileges`, and only `bayora_red-gateway`, received
  `ENETUNREACH` or `EHOSTUNREACH` connecting directly to Blue's private
  `172.21.0.2:8001`. Its request to `http://gateway:8000/health` returned 200.
  The probe exited successfully and was removed. This verifies the Red image
  on the recorded Red network path; the normal Red runner process itself was
  stopped during the check.
- **Unexpected Blue-network peer:** Docker still reports
  `bayora-port-test` (image `nginx`, no Compose service/project labels) on
  `bayora_blue-gateway`. Its owner and purpose remain unknown, so it was left
  untouched. Host configuration lists a requested `127.0.0.1:18001` mapping,
  while the effective port list has no host binding.
- **LLM provider egress — unresolved:** Docker reports `bayora_llm-egress` as
  a non-internal bridge with `bayora-llm-1` attached. The LLM also uses the
  internal `bayora_llm-gateway` network. No provider or prohibited external
  destination was contacted. Provider-only egress and actual OpenRouter
  connectivity remain unverified. A default-deny, domain-restricted egress
  proxy or equivalent host policy needs an identified, reviewed enforcement
  point and positive/negative validation in an isolated deployment before it
  can replace the current route safely.

At that time, the focused network/API tests passed **34 tests** with one Starlette
deprecation warning. The full suite passed **133 tests** with the same warning.
`docker compose config --quiet` could not run because the Docker Compose CLI is
unavailable; the Python environment also has no YAML parser. These test
results do not substitute for Compose parsing or the unperformed LLM egress
tests.

## Older independent audit (2026-10-28; superseded runtime snapshot)

That audit reports **157 tests passed** and `docker compose config
--quiet` passed. These results validate the test suite and Compose syntax at
that audit point; neither proves runtime isolation. The audit found:

- **Gateway host access — BLOCKED:** Windows access on port 8000 still fails.
- **LLM egress enforcement — NOT VERIFIED:** the running LLM is attached to
  `bayora_llm-egress`, and `bayora-egress-proxy-1` is absent. Direct-egress
  denial, proxy destination rejection in the running deployment, and approved
  provider connectivity were not established. No provider request is claimed.
- **Red-runner isolation — NOT VERIFIED:** the Red container is stopped, so
  normal Red-to-Gateway access and direct Red-to-Blue denial were not tested.
  The earlier probe was a historical result and does not establish the current
  normal Red runner boundary.
- **Blue and `bayora-port-test`:** the port-test owner's identity and
  authorization remain unknown. Leave it untouched until its owner and
  authorization are established; runtime Blue isolation is not established by
  the passing tests or Compose validation.

No fresher runtime evidence is recorded here. Gateway host access, current
service health and network attachments, LLM proxy enforcement, and normal
Red-runner routes therefore remain **NOT VERIFIED** for the current runtime.
The current owner and authorization status for `bayora-port-test` have not
been re-established; leave it untouched until they are.

The previous statement that Docker/Compose tools were unavailable and Compose
validation could not run applies only to the historical snapshot above; the
latest audit reports Compose configuration validation passed. Image build
status was not reported.
