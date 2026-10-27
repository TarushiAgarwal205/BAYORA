"""Verify BAYORA Compose isolation without creating or stopping containers."""

import argparse
import ipaddress
import json
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVICES = {
    "gateway": {"cpus": 1.0, "memory": 536870912, "pids": 128},
    "blue": {"cpus": 0.5, "memory": 268435456, "pids": 64},
    "llm": {"cpus": 0.5, "memory": 268435456, "pids": 64},
    "red": {"cpus": 0.5, "memory": 268435456, "pids": 64},
}
SERVICE_NETWORKS = {
    "gateway": {"red-gateway", "blue-gateway", "llm-gateway"},
    "blue": {"blue-gateway"},
    "llm": {"llm-gateway", "llm-egress"},
    "red": {"red-gateway"},
}
NETWORK_SERVICES = {
    "red-gateway": {"gateway", "red"},
    "blue-gateway": {"gateway", "blue"},
    "llm-gateway": {"gateway", "llm"},
    "llm-egress": {"llm"},
}
EXPECTED_CAP_DROP = ["ALL"]
INSPECT_TEMPLATE = (
    "{{.Name}}|{{.State.Running}}|"
    "{{index .Config.Labels \"com.docker.compose.service\"}}|"
    "{{index .Config.Labels \"com.docker.compose.project\"}}|"
    "{{.Config.User}}|{{.HostConfig.Privileged}}|"
    "{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|"
    "{{json .HostConfig.CapAdd}}|{{json .HostConfig.SecurityOpt}}|"
    "{{.HostConfig.PidsLimit}}|{{.HostConfig.NanoCpus}}|"
    "{{.HostConfig.Memory}}|"
    "{{range $name, $network := .NetworkSettings.Networks}}{{$name}},{{end}}|"
    "{{range $name, $network := .NetworkSettings.Networks}}{{$name}}={{$network.IPAddress}},{{end}}|"
    "{{json .NetworkSettings.Ports}}|"
    "{{range .Mounts}}{{.Destination}}:rw={{.RW}},{{end}}"
)
PROBE_CODE = r"""
import errno
import json
import pathlib
import socket
import sys
import urllib.error
import urllib.request

def read(path):
    try:
        return pathlib.Path(path).read_text().strip()
    except OSError:
        return None

status = {}
for line in (read("/proc/self/status") or "").splitlines():
    if line.startswith(("Uid:", "Gid:", "CapEff:", "NoNewPrivs:", "Seccomp:")):
        key, value = line.split(":", 1)
        status[key] = value.strip().split()[0]

mounts = {}
for line in (read("/proc/self/mountinfo") or "").splitlines():
    fields = line.split()
    if len(fields) > 5 and fields[4] in ("/", "/tmp"):
        separator = fields.index("-")
        mounts[fields[4]] = {
            "options": fields[5].split(","),
            "super_options": fields[separator + 3].split(","),
            "filesystem": fields[separator + 1],
        }

result = {
    "status": status,
    "mounts": mounts,
    "cgroup": {
        "cpu.max": read("/sys/fs/cgroup/cpu.max"),
        "memory.max": read("/sys/fs/cgroup/memory.max"),
        "pids.max": read("/sys/fs/cgroup/pids.max"),
    },
    "http": {},
}
for url in sys.argv[1:]:
    try:
        with urllib.request.urlopen(url, timeout=2) as response:
            result["http"][url] = {"status": response.status}
    except urllib.error.HTTPError as error:
        result["http"][url] = {"status": error.code}
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        reason = getattr(error, "reason", error)
        if isinstance(reason, (TimeoutError, socket.timeout)):
            category = "timeout"
        elif isinstance(reason, OSError) and reason.errno in (
            errno.ENETUNREACH, errno.EHOSTUNREACH,
        ):
            category = "unreachable"
        elif isinstance(reason, ConnectionRefusedError):
            category = "connection_refused"
        elif isinstance(reason, socket.gaierror):
            category = "dns_error"
        else:
            category = "probe_error"
        result["http"][url] = {"error": category}
print(json.dumps(result, sort_keys=True))
"""
HOST_HEALTH_CODE = (
    "import urllib.request; "
    "response = urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2); "
    "raise SystemExit(0 if response.status == 200 and "
    "b'healthy' in response.read() else 1)"
)

COUNTS = {"PASS": 0, "FAIL": 0, "UNVERIFIED": 0, "INFO": 0}


def emit(status, check, detail):
    COUNTS[status] += 1
    print(f"[{status}] {check}: {detail}")


def run(command, *, timeout=30):
    return subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def load_compose_config():
    quiet = run(["docker", "compose", "config", "--quiet"])
    if quiet.returncode:
        return None
    result = run(["docker", "compose", "config", "--format", "json"])
    if result.returncode:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def check_static(config):
    emit("PASS", "Compose syntax", "`docker compose config --quiet` succeeded")
    services = config.get("services", {})
    networks = config.get("networks", {})

    for name, limits in SERVICES.items():
        service = services.get(name)
        if service is None:
            emit("FAIL", f"{name} service", "service is missing from resolved Compose config")
            continue

        checks = (
            ("non-root user", service.get("user") == "10001:10001", "user=10001:10001"),
            ("read-only root filesystem", service.get("read_only") is True, "read_only=true"),
            (
                "not privileged",
                service.get("privileged", False) is False,
                "privileged=false (Compose default if omitted)",
            ),
            ("all capabilities dropped", service.get("cap_drop") == EXPECTED_CAP_DROP, "cap_drop=ALL"),
            ("no added capabilities", not service.get("cap_add"), "cap_add is empty"),
            (
                "no-new-privileges",
                "no-new-privileges:true" in service.get("security_opt", []),
                "no-new-privileges:true",
            ),
            ("CPU limit", _number_equals(service.get("cpus"), limits["cpus"]), f"cpus={limits['cpus']}"),
            ("memory limit", _number_equals(service.get("mem_limit"), limits["memory"]), f"mem_limit={limits['memory']} bytes"),
            ("PID limit", service.get("pids_limit") == limits["pids"], f"pids_limit={limits['pids']}"),
        )
        for label, configured, expected in checks:
            emit(
                "INFO" if configured else "FAIL",
                f"{name} declared {label}",
                f"Compose declares {expected}; runtime enforcement is not established by this check"
                if configured else f"Compose must declare {expected}",
            )

        tmpfs_options = service.get("tmpfs") or []
        tmpfs_entry = next(
            (entry for entry in tmpfs_options if isinstance(entry, str) and entry.startswith("/tmp:")),
            "",
        )
        tmpfs_ok = all(option in tmpfs_entry for option in ("noexec", "nosuid", "size=16m"))
        emit(
            "INFO" if tmpfs_ok else "FAIL",
            f"{name} declared /tmp tmpfs",
            "Compose declares size=16m,noexec,nosuid; effective mount not verified"
            if tmpfs_ok else "Compose must declare /tmp tmpfs with size=16m,noexec,nosuid",
        )

        deploy_resources = (service.get("deploy") or {}).get("resources") or {}
        reservations = deploy_resources.get("reservations")
        if reservations:
            emit("INFO", f"{name} reservations", "deploy.resources reservations are present")
        else:
            emit("INFO", f"{name} reservations", "none configured; service-level limits are used by local Compose")

        seccomp = [
            option for option in service.get("security_opt") or []
            if option.startswith("seccomp=")
        ]
        if seccomp:
            emit("INFO", f"{name} seccomp", "custom profile declared; runtime profile identity still needs verification")
        else:
            emit("UNVERIFIED", f"{name} seccomp", "no named seccomp profile is pinned; active runtime filter/profile is not established by YAML")

        configured_networks = service.get("networks") or {}
        actual_networks = set(configured_networks)
        expected_networks = SERVICE_NETWORKS[name]
        emit(
            "INFO" if actual_networks == expected_networks else "FAIL",
            f"{name} declared network membership",
            f"Compose declares {','.join(sorted(actual_networks))}; runtime membership is checked separately"
            if actual_networks == expected_networks else
            f"expected Compose networks {','.join(sorted(expected_networks))}; found {','.join(sorted(actual_networks)) or 'none'}",
        )

    for name in ("red-gateway", "blue-gateway", "llm-gateway"):
        internal = networks.get(name, {}).get("internal") is True
        emit(
            "INFO" if internal else "FAIL",
            f"{name} declared internal network",
            "Compose declares internal=true; runtime enforcement is not established by this check"
            if internal else "Compose must declare internal=true",
        )

    egress = networks.get("llm-egress", {})
    if egress and egress.get("internal") is not True:
        emit("FAIL", "LLM provider-only egress", "Compose declares an ordinary bridge with no destination allowlist; add and runtime-test an explicit egress boundary")
    else:
        emit("UNVERIFIED", "LLM provider-only egress", "Compose does not establish a provider-specific allowlist; inspect and test the actual egress boundary")

    gateway_ports = services.get("gateway", {}).get("ports", [])
    expected_ports = [{"host_ip": "127.0.0.1", "target": 8000, "published": "8000", "protocol": "tcp"}]
    normalized_ports = [
        {
            "host_ip": port.get("host_ip", "0.0.0.0"),
            "target": port.get("target"),
            "published": str(port.get("published", "")),
            "protocol": port.get("protocol", "tcp"),
        }
        for port in gateway_ports
    ]
    emit(
        "INFO" if normalized_ports == expected_ports else "FAIL",
        "Gateway declared host publication",
        "Compose declares only 127.0.0.1:8000/tcp; runtime bindings are checked separately"
        if normalized_ports == expected_ports else f"expected only 127.0.0.1:8000/tcp; found {normalized_ports}",
    )
    for name in ("blue", "llm", "red"):
        published = services.get(name, {}).get("ports", [])
        emit(
            "INFO" if not published else "FAIL",
            f"{name} declared host publication",
            "Compose declares no host ports; runtime bindings are checked separately"
            if not published else f"Compose publishes host ports: {published}",
        )

    for name in ("gateway", "red"):
        mounts = services.get(name, {}).get("volumes", [])
        writable = sorted(
            mount["target"] for mount in mounts
            if isinstance(mount, dict) and mount.get("read_only") is not True
        )
        emit("INFO", f"{name} writable mounts", ",".join(writable) if writable else "none")


def parse_inspect_line(line):
    fields = line.split("|")
    if len(fields) != 17:
        return None
    try:
        return {
            "name": fields[0].lstrip("/"),
            "running": fields[1] == "true",
            "service": fields[2],
            "project": fields[3],
            "user": fields[4],
            "privileged": fields[5] == "true",
            "readonly": fields[6] == "true",
            "cap_drop": json.loads(fields[7]),
            "cap_add": json.loads(fields[8]),
            "security_opt": json.loads(fields[9]),
            "pids": int(fields[10]),
            "nano_cpus": int(fields[11]),
            "memory": int(fields[12]),
            "networks": {name for name in fields[13].split(",") if name},
            "network_ips": {
                name: address
                for item in fields[14].split(",") if "=" in item
                for name, address in (item.split("=", 1),)
            },
            "ports": json.loads(fields[15]),
            "mounts": fields[16],
        }
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


def inspect_containers(config):
    result = run(["docker", "compose", "ps", "--all", "--quiet"])
    if result.returncode:
        emit("UNVERIFIED", "runtime inspection", "Compose could not list project containers")
        return []
    ids = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not ids:
        emit("UNVERIFIED", "runtime inspection", "no existing project containers; this verifier does not start them")
        return []

    containers = []
    for container_id in ids:
        inspected = run(["docker", "inspect", "--format", INSPECT_TEMPLATE, container_id])
        parsed = parse_inspect_line(inspected.stdout.strip()) if inspected.returncode == 0 else None
        if parsed is None:
            emit("UNVERIFIED", "container inspect", "could not parse selected non-secret runtime fields")
            continue
        containers.append(parsed)

    active_by_service = {}
    for item in containers:
        name = item["service"]
        if name not in SERVICES:
            continue
        if not item["running"]:
            emit("UNVERIFIED", f"{name} runtime", "container exists but is stopped")
            continue
        active_by_service[name] = item
        limits = SERVICES[name]
        expected_networks = {
            (config.get("networks", {}).get(alias) or {}).get("name")
            or f"{item['project']}_{alias}"
            for alias in SERVICE_NETWORKS[name]
        }
        checks = (
            ("user", item["user"] == "10001:10001"),
            ("rootfs", item["readonly"]),
            ("privileged", not item["privileged"]),
            ("capabilities", item["cap_drop"] == EXPECTED_CAP_DROP and not item["cap_add"]),
            ("no-new-privileges", "no-new-privileges:true" in item["security_opt"]),
            ("PID limit", item["pids"] == limits["pids"]),
            ("CPU limit", item["nano_cpus"] == int(limits["cpus"] * 1_000_000_000)),
            ("memory limit", item["memory"] == limits["memory"]),
        )
        for label, passed in checks:
            emit(
                "PASS" if passed else "FAIL",
                f"{name} runtime {label}",
                "Docker inspect reports the expected container setting; kernel enforcement is not proved by inspect"
                if passed else "Docker inspect reports a mismatch; reconcile the running container with reviewed configuration",
            )
        extra_networks = item["networks"] - expected_networks
        missing_networks = expected_networks - item["networks"]
        if extra_networks or missing_networks:
            emit("FAIL", f"{name} runtime networks", f"unexpected attachments={','.join(sorted(extra_networks)) or 'none'}; missing expected attachments={','.join(sorted(missing_networks)) or 'none'}")
        else:
            emit("PASS", f"{name} runtime network membership", f"Docker reports expected attachments: {','.join(sorted(item['networks']))}; reachability is checked separately")
        published = []
        for port, bindings in item["ports"].items():
            for binding in bindings or []:
                published.append((
                    port,
                    binding.get("HostIp", ""),
                    str(binding.get("HostPort", "")),
                ))
        expected_published = (
            [("8000/tcp", "127.0.0.1", "8000")]
            if name == "gateway" else []
        )
        emit(
            "PASS" if sorted(published) == sorted(expected_published) else "FAIL",
            f"{name} runtime host publication",
            (
                "only 127.0.0.1:8000 is published"
                if name == "gateway" else "no host ports are published"
            ) if sorted(published) == sorted(expected_published) else f"unexpected bindings: {published}",
        )
        emit("INFO", f"{name} runtime mounts", item["mounts"] or "none")
        if not any(option.startswith("seccomp=") for option in item["security_opt"]):
            emit("UNVERIFIED", f"{name} runtime seccomp", "inspect does not identify the active default profile or prove its rules")

    for name in SERVICES:
        if name not in active_by_service:
            emit("UNVERIFIED", f"{name} active runtime", "no running service container was found")
    check_network_peers(containers, config)
    return list(active_by_service.values())


def check_network_peers(containers, config):
    project = next((item["project"] for item in containers if item["project"]), "")
    project = config.get("name") or project
    for alias, network_config in config.get("networks", {}).items():
        network_name = (network_config or {}).get("name") or f"{project}_{alias}"
        inspected = run(["docker", "network", "inspect", network_name])
        try:
            network = json.loads(inspected.stdout)[0] if inspected.returncode == 0 else None
        except (json.JSONDecodeError, IndexError, TypeError):
            network = None
        if network is None:
            emit("UNVERIFIED", f"{alias} peer inspection", "Docker could not inspect the resolved network")
            continue
        attached = network.get("Containers") or {}
        peers = {
            entry.get("Name", "")
            for entry in attached.values()
            if isinstance(entry, dict)
            if entry.get("Name")
        }
        expected_services = NETWORK_SERVICES.get(alias, set())
        expected_names = {
            item["name"] for item in containers
            if item["running"]
            and item["service"] in expected_services
            and network_name in item["networks"]
        }
        unexpected = sorted(peers - expected_names)
        missing = sorted(expected_names - peers)
        if unexpected or missing:
            emit(
                "FAIL",
                f"{alias} unexpected peers",
                f"unexpected={','.join(unexpected) or 'none'}; expected-but-not-listed={','.join(missing) or 'none'}",
            )
        else:
            emit(
                "PASS",
                f"{alias} peer membership",
                f"no unexpected attached containers; observed={','.join(sorted(peers)) or 'none'}",
            )


def run_read_only_probes(containers, config):
    by_service = {item["service"]: item for item in containers}
    if "gateway" in by_service:
        host = run([sys.executable, "-c", HOST_HEALTH_CODE])
        emit("PASS" if host.returncode == 0 else "FAIL", "host to Gateway health", "loopback /health returned healthy" if host.returncode == 0 else "loopback Gateway health probe failed while a Gateway container is running")
    else:
        emit("UNVERIFIED", "host to Gateway health", "no running Gateway container was found; verifier will not start one")

    for service, container in by_service.items():
        probe = run(["docker", "exec", container["name"], "python", "-c", PROBE_CODE])
        if probe.returncode:
            emit("UNVERIFIED", f"{service} in-container probe", "docker exec failed; effective process and cgroup settings were not observed")
            continue
        try:
            data = json.loads(probe.stdout)
        except (json.JSONDecodeError, TypeError):
            emit("UNVERIFIED", f"{service} in-container probe", "probe output was missing or invalid JSON")
            continue
        report_container_probe(service, data)

    gateway = by_service.get("gateway")
    blue = by_service.get("blue")
    red = by_service.get("red")
    if gateway:
        targets = ["http://blue:8001/health", "http://llm:8002/health"]
        probe = run(["docker", "exec", gateway["name"], "python", "-c", PROBE_CODE, *targets])
        if probe.returncode:
            emit("UNVERIFIED", "Gateway service connection probes", "docker exec failed; expected local service paths were not tested")
            data = None
        else:
            try:
                data = json.loads(probe.stdout)
            except (json.JSONDecodeError, TypeError):
                emit("UNVERIFIED", "Gateway service connection probes", "probe output was missing or invalid JSON")
                data = None
            if not isinstance(data, dict):
                emit("UNVERIFIED", "Gateway service connection probes", "probe output was not a JSON object")
                data = None
        for target in targets:
            http_results = data.get("http") if isinstance(data, dict) else None
            if not isinstance(http_results, dict) or target not in http_results:
                emit("UNVERIFIED", f"Gateway to {target}", "no target-specific response was observed")
                continue
            result = http_results[target]
            if not isinstance(result, dict):
                emit("UNVERIFIED", f"Gateway to {target}", "target response was malformed")
                continue
            passed = result.get("status") == 200
            emit(
                "PASS" if passed else "FAIL",
                f"Gateway to {target}",
                "local health endpoint returned HTTP 200" if passed
                else f"local health endpoint did not return HTTP 200: {result}",
            )
    else:
        emit("UNVERIFIED", "Gateway container probes", "no running Gateway container")

    if blue and gateway:
        target = "http://gateway:8000/health"
        probe = run(["docker", "exec", blue["name"], "python", "-c", PROBE_CODE, target])
        if probe.returncode:
            emit("UNVERIFIED", "Blue to Gateway", "docker exec failed; expected local service path was not tested")
        else:
            try:
                data = json.loads(probe.stdout)
            except (json.JSONDecodeError, TypeError):
                data = None
            http_results = data.get("http") if isinstance(data, dict) else None
            result = http_results.get(target) if isinstance(http_results, dict) else None
            if not isinstance(result, dict):
                result = None
            if result is None:
                emit("UNVERIFIED", "Blue to Gateway", "no target-specific response was observed")
            else:
                passed = result.get("status") == 200
                emit(
                    "PASS" if passed else "FAIL",
                    "Blue to Gateway",
                    "local health endpoint returned HTTP 200" if passed
                    else f"local health endpoint did not return HTTP 200: {result}",
                )
    else:
        emit("UNVERIFIED", "Blue to Gateway", "both containers must be running to test the intended path")

    if red and blue:
        blue_network = (config.get("networks", {}).get("blue-gateway") or {})
        network_name = (
            blue_network.get("name")
            or f"{blue['project']}_blue-gateway"
        )
        blue_ip = blue.get("network_ips", {}).get(network_name)
        if not blue_ip:
            emit("UNVERIFIED", "Red to Blue direct access", "Docker did not expose Blue's address on the protected Blue network")
            return
        try:
            parsed_ip = ipaddress.ip_address(blue_ip)
        except (TypeError, ValueError):
            emit("UNVERIFIED", "Red to Blue direct access", "Docker returned an invalid Blue network address")
            return
        if parsed_ip.is_global:
            emit("UNVERIFIED", "Red to Blue direct access", "Blue address is not local/private; refusing to probe")
            return
        target = f"http://{parsed_ip.compressed}:8001/health"
        probe = run(["docker", "exec", red["name"], "python", "-c", PROBE_CODE, target])
        try:
            data = json.loads(probe.stdout)
        except (json.JSONDecodeError, TypeError):
            data = {}
        if probe.returncode:
            emit("UNVERIFIED", "Red to Blue direct access", "in-container probe failed; no network-denial conclusion is possible")
            return
        http_results = data.get("http") if isinstance(data, dict) else None
        result = http_results.get(target) if isinstance(http_results, dict) else None
        if not isinstance(result, dict):
            result = {}
        status, detail = classify_red_blue_result(result)
        emit(status, "Red to Blue direct access", detail)
    else:
        emit("UNVERIFIED", "Red to Blue direct access", "running Red and Blue containers are required; the verifier will not start them")


def classify_red_blue_result(result):
    if not isinstance(result, dict):
        return "UNVERIFIED", "probe result is malformed; network isolation was not established"
    if "status" in result:
        return "FAIL", f"Blue returned HTTP {result['status']} to Red; network path is reachable"
    if result.get("error") == "unreachable":
        return "PASS", "kernel reported the private target as network/host unreachable"
    return (
        "UNVERIFIED",
        f"probe result {result.get('error', 'missing/ambiguous')!r} does not prove segmentation; timeout/refusal require separate diagnosis",
    )


def _number_equals(value, expected):
    try:
        return float(value) == float(expected)
    except (TypeError, ValueError):
        return False


def report_container_probe(service, data):
    if not isinstance(data, dict):
        data = {}
    status = data.get("status", {})
    if not isinstance(status, dict):
        status = {}
    expected_uid = "10001"
    uid = status.get("Uid", "").split()
    gid = status.get("Gid", "").split()
    ids_observed = bool(uid and gid)
    uid_gid_ok = ids_observed and uid[0] == expected_uid and gid[0] == expected_uid
    emit(
        "UNVERIFIED" if not ids_observed else "PASS" if uid_gid_ok else "FAIL",
        f"{service} effective UID/GID",
        "observed effective UID/GID 10001:10001" if uid_gid_ok
        else "UID/GID fields unavailable in /proc" if not ids_observed
        else f"observed UID/GID {uid[0]}:{gid[0]}, expected 10001:10001",
    )
    capabilities = status.get("CapEff")
    try:
        capabilities_zero = int(capabilities, 16) == 0 if capabilities is not None else None
    except (TypeError, ValueError):
        capabilities_zero = None
    emit(
        "UNVERIFIED" if capabilities_zero is None else "PASS" if capabilities_zero else "FAIL",
        f"{service} effective capabilities",
        "observed CapEff=0" if capabilities_zero is True
        else "CapEff unavailable or invalid in /proc" if capabilities_zero is None
        else f"observed nonzero CapEff={capabilities}",
    )
    no_new_privs = status.get("NoNewPrivs")
    emit(
        "UNVERIFIED" if no_new_privs is None else "PASS" if no_new_privs == "1" else "FAIL",
        f"{service} effective no-new-privileges",
        "observed NoNewPrivs=1" if no_new_privs == "1"
        else "NoNewPrivs unavailable in /proc" if no_new_privs is None
        else f"observed NoNewPrivs={no_new_privs}, expected 1",
    )
    seccomp = status.get("Seccomp")
    emit(
        "UNVERIFIED" if seccomp is None else "PASS" if seccomp == "2" else "FAIL",
        f"{service} active seccomp mode",
        "observed Seccomp=2 (filter active; profile identity/rules unknown)"
        if seccomp == "2" else "Seccomp unavailable in /proc" if seccomp is None
        else f"observed Seccomp={seccomp}; filtering mode 2 expected",
    )

    mounts = data.get("mounts", {})
    if not isinstance(mounts, dict):
        mounts = {}
    root = mounts.get("/")
    tmp = mounts.get("/tmp")
    root_readonly = root is not None and "ro" in root.get("options", [])
    root_observed = root is not None and "options" in root
    tmp_secure = (
        tmp is not None
        and tmp.get("filesystem") == "tmpfs"
        and "rw" in tmp.get("options", [])
        and "noexec" in tmp.get("options", []) + tmp.get("super_options", [])
        and "nosuid" in tmp.get("options", []) + tmp.get("super_options", [])
    )
    tmp_observed = tmp is not None and "filesystem" in tmp
    emit(
        "UNVERIFIED" if not root_observed else "PASS" if root_readonly else "FAIL",
        f"{service} effective root mount",
        "observed read-only root mount" if root_readonly
        else "root mount options unavailable" if not root_observed
        else "root mount is writable",
    )
    emit(
        "UNVERIFIED" if not tmp_observed else "PASS" if tmp_secure else "FAIL",
        f"{service} effective /tmp mount",
        "observed writable tmpfs with noexec,nosuid" if tmp_secure
        else "/tmp mount details unavailable" if not tmp_observed
        else "expected writable tmpfs with noexec,nosuid was not observed",
    )

    cgroup = data.get("cgroup", {})
    if not isinstance(cgroup, dict):
        cgroup = {}
    limits = SERVICES[service]
    cpu_expected = f"{int(limits['cpus'] * 100000)} 100000"
    _emit_observed_check(
        f"{service} effective cgroup CPU",
        cgroup.get("cpu.max"),
        cpu_expected,
    )
    _emit_observed_check(
        f"{service} effective cgroup memory",
        cgroup.get("memory.max"),
        str(limits["memory"]),
    )
    _emit_observed_check(
        f"{service} effective cgroup PIDs",
        cgroup.get("pids.max"),
        str(limits["pids"]),
    )


def _emit_observed_check(check, observed, expected):
    status = "UNVERIFIED" if observed is None else "PASS" if observed == expected else "FAIL"
    detail = (
        f"observed expected value {expected}"
        if observed == expected else
        "runtime value unavailable" if observed is None else
        f"observed {observed!r}, expected {expected!r}"
    )
    emit(status, check, detail)


def passive_stats(containers):
    names = [item["name"] for item in containers]
    if not names:
        emit("UNVERIFIED", "Docker stats", "no running containers to sample")
        return
    result = run([
        "docker", "stats", "--no-stream",
        "--format", "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.PIDs}}",
        *names,
    ])
    if result.returncode:
        emit("UNVERIFIED", "Docker stats", "passive usage snapshot unavailable")
        return
    for line in result.stdout.splitlines():
        name, cpu, memory, pids = (line.split("|", 3) + ["", "", "", ""])[:4]
        emit("INFO", f"{name} usage sample", f"CPU={cpu}; memory={memory}; PIDs={pids} (single sample, not a contention test)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--probe",
        action="store_true",
        help="make read-only health and /proc/cgroup probes in existing running containers",
    )
    args = parser.parse_args()

    if shutil.which("docker") is None:
        emit("UNVERIFIED", "Docker checks", "Docker CLI unavailable")
        print(f"SUMMARY {COUNTS}")
        return 2

    config = load_compose_config()
    if config is None:
        emit("UNVERIFIED", "Compose configuration", "config could not be resolved; verify required local .env settings without printing them")
        print(f"SUMMARY {COUNTS}")
        return 2
    check_static(config)
    containers = inspect_containers(config)
    passive_stats([item for item in containers if item["running"]])
    if args.probe:
        run_read_only_probes([item for item in containers if item["running"]], config)

    print(f"SUMMARY {COUNTS}")
    if COUNTS["FAIL"]:
        return 1
    if COUNTS["UNVERIFIED"]:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
