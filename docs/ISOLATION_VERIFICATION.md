# BAYORA resource and isolation verification

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

The optional probes read `/proc` and cgroup files, sample public local health
endpoints, and run `docker stats --no-stream`. They do not run a scenario, call
an external host, start a process-intensive workload, or change deployment
state. The Red-to-Blue probe runs only if a Red container is already running;
the verifier never starts one. A PASS from `docker inspect` means Docker reports
that setting on the container; it is not a substitute for kernel-level runtime
evidence.

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
- `/tmp` tmpfs with `noexec`, `nosuid`, and a 16 MiB configured size.
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
- Gateway joins those internal networks and `llm-gateway`.
- LLM joins `llm-gateway` and `llm-egress`.
- The Gateway is the only service with a host port, bound to
  `127.0.0.1:8000`; Blue, LLM, and Red have no published ports.
- The `llm-egress` network is an ordinary bridge, not an internal network or
  provider-destination allowlist. Therefore, provider-only egress is **not
  configured or demonstrated**.

Runtime network membership, non-Compose peers, and published bindings are
inspected from existing containers/networks. With `--probe`, local health requests check host-to-Gateway,
Gateway-to-Blue, Gateway-to-LLM, and Blue-to-Gateway. A running Red container is
required to check Red-to-Blue; otherwise this is UNVERIFIED. Network membership
alone does not prove reachability or denial.

To establish LLM provider-only egress, implement an explicit egress boundary
(for example a controlled proxy/firewall allowlist), then verify the approved
destination and blocked destinations in an isolated runtime using synthetic
requests and no credentials. Do not claim provider-only restriction based on
the current bridge network. This verification does not probe arbitrary
external hosts.

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
| LLM egress | Approved destinations only | Current bridge has no provider allowlist | Static/runtime | |
| Contention | Limits respected without host instability | Only with isolated bounded load test | Runtime | |

## Current inspection evidence

The verification artifact was added after the following read-only inspection.
The source HEAD was `98ef19c3fbfb3e386f88fd4d03535e56eb24f946`; the working tree
also had pre-existing local changes in `compose.yaml` (quoting/spacing only)
and a tracked `.pytest-tmp` fixture. Neither was edited by this verification
work. The runtime snapshot is not evidence for a future commit or redeployed
container set:

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
- Active Gateway network membership included `bayora_gateway-host`, while the
  current working-tree Compose file does not declare that network or attach
  Gateway to it. The running containers therefore do not match the current
  working-tree network configuration; this is a runtime mismatch, not a reason
  to restart the stack during an active session. Runtime inspection showed only
  `127.0.0.1:8000` published for Gateway and no published ports for Blue/LLM.
  The LLM container is attached to the ordinary `bayora_llm-egress` bridge.
- Docker network inspection also found a running, non-Compose container named
  `bayora-port-test` attached to `bayora_blue-gateway`. Its image is `nginx`,
  it has no Docker Compose ownership labels, and its published-port list is
  empty; its owner and purpose were not established. The verifier reports it
  as an unexpected peer and does not send it traffic. The other inspected
  `port-test` container was on Docker's default `bridge`, not a BAYORA service
  network.
- Optional health probes returned 200 for host-to-Gateway, Gateway-to-Blue,
  Gateway-to-LLM, and Blue-to-Gateway. Red-to-Blue direct reachability remains
  UNVERIFIED because no Red container was running; the verifier did not start
  one.
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
