"""Verify BAYORA Compose isolation without creating or stopping containers."""

import argparse
import ipaddress
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]
SERVICES = {
    "gateway": {"cpus": 1.0, "memory": 536870912, "pids": 128},
    "blue": {"cpus": 0.5, "memory": 268435456, "pids": 64},
    "llm": {"cpus": 0.5, "memory": 268435456, "pids": 64},
    "egress-proxy": {"cpus": 0.25, "memory": 134217728, "pids": 32},
    "red": {"cpus": 0.5, "memory": 268435456, "pids": 64},
}
SERVICE_NETWORKS = {
    "gateway": {"red-gateway", "blue-gateway", "llm-gateway", "gateway-host"},
    "blue": {"blue-gateway"},
    "llm": {"llm-gateway", "llm-proxy"},
    "egress-proxy": {"llm-proxy", "llm-egress"},
    "red": {"red-gateway"},
}
NETWORK_SERVICES = {
    "red-gateway": {"gateway", "red"},
    "blue-gateway": {"gateway", "blue"},
    "llm-gateway": {"gateway", "llm"},
    "llm-proxy": {"llm", "egress-proxy"},
    "llm-egress": {"egress-proxy"},
    "gateway-host": {"gateway"},
}
EXPECTED_CAP_DROP = ["ALL"]
INSPECT_TEMPLATE = (
    "{{.Name}}|{{.State.Running}}|"
    "{{index .Config.Labels \"com.docker.compose.service\"}}|"
    "{{index .Config.Labels \"com.docker.compose.project\"}}|"
    "{{index .Config.Labels \"com.docker.compose.oneoff\"}}|"
    "{{.Config.User}}|{{.HostConfig.Privileged}}|"
    "{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|"
    "{{json .HostConfig.CapAdd}}|{{json .HostConfig.SecurityOpt}}|"
    "{{.HostConfig.PidsLimit}}|{{.HostConfig.NanoCpus}}|"
    "{{.HostConfig.Memory}}|"
    "{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.UTSMode}}|"
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

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None

opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    NoRedirect,
)

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
        with opener.open(url, timeout=2) as response:
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
HOST_HEALTH_CODE = r"""
import urllib.request

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None

opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    NoRedirect,
)
response = opener.open("http://127.0.0.1:8000/health", timeout=2)
raise SystemExit(
    0 if response.status == 200 and b"healthy" in response.read() else 1
)
"""
SOCKET_CONNECT_PROBE_CODE = r"""
import errno
import json
import socket
import sys

sock = socket.socket(socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(3)
code = sock.connect_ex((sys.argv[1], int(sys.argv[2])))
sock.close()
if code == 0:
    result = {"connected": True}
else:
    errors = {
        errno.ENETUNREACH: "network_unreachable",
        errno.EHOSTUNREACH: "host_unreachable",
        errno.ETIMEDOUT: "timeout",
        errno.ECONNREFUSED: "connection_refused",
    }
    result = {"connected": False, "error": errors.get(code, "socket_error")}
print(json.dumps(result, sort_keys=True))
"""

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
        expected_tmpfs_size = "8m" if name == "egress-proxy" else "16m"
        tmpfs_settings = set(tmpfs_entry.partition(":")[2].split(","))
        configured_sizes = {
            option for option in tmpfs_settings if option.startswith("size=")
        }
        tmpfs_ok = (
            {"noexec", "nosuid"} <= tmpfs_settings
            and not {"exec", "suid"} & tmpfs_settings
            and configured_sizes == {f"size={expected_tmpfs_size}"}
        )
        emit(
            "INFO" if tmpfs_ok else "FAIL",
            f"{name} declared /tmp tmpfs",
            f"Compose declares size={expected_tmpfs_size},noexec,nosuid; effective mount not verified"
            if tmpfs_ok else f"Compose must declare /tmp tmpfs with size={expected_tmpfs_size},noexec,nosuid",
        )

        for namespace, key in (("PID", "pid"), ("IPC", "ipc"), ("UTS", "uts")):
            mode = service.get(key) or ""
            unsafe = _namespace_mode_is_shared(mode)
            emit(
                "FAIL" if unsafe else "INFO",
                f"{name} declared {namespace} namespace",
                f"Compose requests shared namespace mode {mode!r}"
                if unsafe else
                "Compose does not request host/container namespace sharing; runtime mode is checked separately",
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

    for name in ("red-gateway", "blue-gateway", "llm-gateway", "llm-proxy"):
        internal = networks.get(name, {}).get("internal") is True
        emit(
            "INFO" if internal else "FAIL",
            f"{name} declared internal network",
            "Compose declares internal=true; runtime enforcement is not established by this check"
            if internal else "Compose must declare internal=true",
        )

    llm_networks = set((services.get("llm", {}).get("networks") or {}).keys())
    proxy_networks = set((services.get("egress-proxy", {}).get("networks") or {}).keys())
    llm_environment = services.get("llm", {}).get("environment") or {}
    other_egress_services = sorted(
        name for name, service in services.items()
        if name != "egress-proxy"
        and "llm-egress" in (service.get("networks") or {})
    )
    proxy_policy_declared = (
        llm_networks == {"llm-gateway", "llm-proxy"}
        and proxy_networks == {"llm-proxy", "llm-egress"}
        and not other_egress_services
        and networks.get("llm-proxy", {}).get("internal") is True
        and networks.get("llm-egress", {}).get("internal") is not True
        and llm_environment.get("BAYORA_LLM_EGRESS_PROXY") == "http://egress-proxy:8080"
    )
    emit(
        "INFO" if proxy_policy_declared else "FAIL",
        "LLM declared provider egress boundary",
        "LLM has only internal network attachments and uses the allowlist proxy; runtime enforcement and provider reachability still require isolated deployment tests"
        if proxy_policy_declared else
        "LLM must attach only to llm-gateway and internal llm-proxy; egress-proxy must be the only service on llm-egress and the configured proxy URL must be present"
        + (
            f"; other services attached to llm-egress: {','.join(other_egress_services)}"
            if other_egress_services else ""
        ),
    )

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
    for name in ("blue", "llm", "egress-proxy", "red"):
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
    if len(fields) != 21:
        return None
    try:
        return {
            "name": fields[0].lstrip("/"),
            "running": fields[1] == "true",
            "service": fields[2],
            "project": fields[3],
            "oneoff": fields[4].strip().lower() == "true",
            "user": fields[5],
            "privileged": fields[6] == "true",
            "readonly": fields[7] == "true",
            "cap_drop": json.loads(fields[8]),
            "cap_add": json.loads(fields[9]),
            "security_opt": json.loads(fields[10]),
            "pids": int(fields[11]),
            "nano_cpus": int(fields[12]),
            "memory": int(fields[13]),
            "pid_mode": fields[14],
            "ipc_mode": fields[15],
            "uts_mode": fields[16],
            "networks": {name for name in fields[17].split(",") if name},
            "network_ips": {
                name: address
                for item in fields[18].split(",") if "=" in item
                for name, address in (item.split("=", 1),)
            },
            "ports": json.loads(fields[19]),
            "mounts": fields[20],
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
        if item["oneoff"]:
            emit("INFO", f"{name} one-off container", "excluded from normal service runtime selection")
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
        report_namespace_modes(name, {
            "PID": item["pid_mode"],
            "IPC": item["ipc_mode"],
            "UTS": item["uts_mode"],
        })
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
            networks = json.loads(inspected.stdout) if inspected.returncode == 0 else None
            network = networks[0] if isinstance(networks, list) and len(networks) == 1 else None
        except (json.JSONDecodeError, IndexError, TypeError):
            network = None
        if not isinstance(network, dict):
            emit("UNVERIFIED", f"{alias} peer inspection", "Docker could not inspect the resolved network")
            continue
        attached = network.get("Containers")
        if (
            not isinstance(attached, dict)
            or any(
                not isinstance(entry, dict)
                or not isinstance(entry.get("Name"), str)
                or not entry["Name"]
                for entry in attached.values()
            )
        ):
            emit("UNVERIFIED", f"{alias} peer inspection", "Docker returned malformed network peer data")
            continue
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
            and not item.get("oneoff", False)
            and item["service"] in expected_services
            and network_name in item["networks"]
        }
        unexpected = sorted(peers - expected_names)
        missing = sorted(expected_names - peers)
        attached_services = {
            item["service"] for item in containers
            if item["running"]
            and not item.get("oneoff", False)
            and item["service"] in expected_services
            and network_name in item["networks"]
        }
        missing_services = sorted(expected_services - attached_services)
        if unexpected or missing:
            emit(
                "FAIL",
                f"{alias} unexpected peers",
                f"unexpected={','.join(unexpected) or 'none'}; expected-but-not-listed={','.join(missing) or 'none'}",
            )
        elif missing_services:
            emit(
                "UNVERIFIED",
                f"{alias} peer membership",
                "expected services are stopped or not attached: "
                + ",".join(missing_services),
            )
        else:
            emit(
                "PASS",
                f"{alias} peer membership",
                f"no unexpected attached containers; observed={','.join(sorted(peers)) or 'none'}",
            )


def run_read_only_probes(containers, config, *, egress_probe_ip=None,
                         egress_probe_port=None):
    by_service = {item["service"]: item for item in containers}
    blue_health_reachable = False
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
            if target == "http://blue:8001/health":
                blue_health_reachable = passed
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

    if red and gateway:
        target = "http://gateway:8000/health"
        probe = run(["docker", "exec", red["name"], "python", "-c", PROBE_CODE, target])
        if probe.returncode:
            emit("UNVERIFIED", "Red to Gateway", "docker exec failed; expected local service path was not tested")
        else:
            try:
                data = json.loads(probe.stdout)
            except (json.JSONDecodeError, TypeError):
                data = None
            http_results = data.get("http") if isinstance(data, dict) else None
            result = http_results.get(target) if isinstance(http_results, dict) else None
            if not isinstance(result, dict):
                emit("UNVERIFIED", "Red to Gateway", "no target-specific response was observed")
            else:
                passed = result.get("status") == 200
                emit(
                    "PASS" if passed else "FAIL",
                    "Red to Gateway",
                    "local health endpoint returned HTTP 200" if passed
                    else f"local health endpoint did not return HTTP 200: {result}",
                )
    else:
        emit("UNVERIFIED", "Red to Gateway", "running Red and Gateway containers are required; the verifier will not start them")

    _run_red_blue_probe(
        red,
        blue,
        config,
        blue_health_reachable=blue_health_reachable,
    )

    run_llm_egress_probe(by_service, egress_probe_ip, egress_probe_port)


def _run_red_blue_probe(red, blue, config, *, blue_health_reachable):
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
        status, detail = classify_red_blue_result(
            result,
            blue_health_reachable=blue_health_reachable,
        )
        emit(status, "Red to Blue direct access", detail)
    else:
        emit("UNVERIFIED", "Red to Blue direct access", "running Red and Blue containers are required; the verifier will not start them")


def classify_red_blue_result(result, *, blue_health_reachable=False):
    if not isinstance(result, dict):
        return "UNVERIFIED", "probe result is malformed; network isolation was not established"
    if "status" in result:
        status = result["status"]
        if isinstance(status, int) and not isinstance(status, bool) and 100 <= status <= 599:
            return "FAIL", f"Blue returned HTTP {status} to Red; network path is reachable"
        return "UNVERIFIED", "probe returned a malformed HTTP status; network isolation was not established"
    if result.get("error") == "unreachable":
        if not blue_health_reachable:
            return (
                "UNVERIFIED",
                "Blue health was not confirmed through Gateway; unreachable may reflect an unavailable target",
            )
        return "PASS", "kernel reported the private target as network/host unreachable"
    return (
        "UNVERIFIED",
        f"probe result {result.get('error', 'missing/ambiguous')!r} does not prove segmentation; timeout/refusal require separate diagnosis",
    )


def _namespace_mode_is_shared(mode):
    normalized = str(mode or "").strip().lower()
    return normalized == "host" or normalized.startswith("container:") or normalized == "shareable"


def report_namespace_modes(service, modes):
    for namespace, mode in modes.items():
        shared = _namespace_mode_is_shared(mode)
        emit(
            "FAIL" if shared else "PASS",
            f"{service} runtime {namespace} namespace",
            f"Docker reports shared namespace mode {mode!r}" if shared
            else f"Docker reports private/default namespace mode {mode!r}",
        )


def run_llm_egress_probe(by_service, destination_ip, destination_port):
    check = "LLM direct egress"
    if destination_ip is None and destination_port is None:
        emit(
            "UNVERIFIED", check,
            "no deployment-owner-controlled probe IP/port was supplied; no destination was tested",
        )
        return
    if destination_ip is None or destination_port is None:
        emit("UNVERIFIED", check, "both a controlled public probe IP and TCP port are required")
        return
    try:
        address = ipaddress.ip_address(destination_ip)
    except (TypeError, ValueError):
        emit("UNVERIFIED", check, "probe destination must be a public IP literal; DNS names are not accepted")
        return
    if not address.is_global or not isinstance(destination_port, int) or not 1 <= destination_port <= 65535:
        emit("UNVERIFIED", check, "probe destination must be a public IP and TCP port from 1 through 65535")
        return

    proxy = by_service.get("egress-proxy")
    llm = by_service.get("llm")
    if not proxy or not llm:
        emit("UNVERIFIED", check, "running egress-proxy and LLM containers are required; the verifier will not start them")
        return

    target = [str(address), str(destination_port)]
    baseline = run([
        "docker", "exec", proxy["name"], "python", "-c",
        SOCKET_CONNECT_PROBE_CODE, *target,
    ])
    if baseline.returncode:
        emit("UNVERIFIED", check, "positive-baseline probe failed to execute in egress-proxy")
        return
    try:
        baseline_result = json.loads(baseline.stdout)
    except (json.JSONDecodeError, TypeError):
        baseline_result = None
    if not isinstance(baseline_result, dict) or baseline_result.get("connected") is not True:
        error = baseline_result.get("error", "missing/invalid result") if isinstance(baseline_result, dict) else "missing/invalid result"
        emit("UNVERIFIED", check, f"probe endpoint was not positively reachable from egress-proxy ({error}); LLM result was not interpreted")
        return

    result = run([
        "docker", "exec", llm["name"], "python", "-c",
        SOCKET_CONNECT_PROBE_CODE, *target,
    ])
    if result.returncode:
        emit("UNVERIFIED", check, "LLM probe failed to execute after the positive baseline")
        return
    try:
        llm_result = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        llm_result = None
    status, detail = classify_llm_egress_result(baseline_result, llm_result)
    emit(status, check, detail)


def classify_llm_egress_result(baseline_result, llm_result):
    if not isinstance(baseline_result, dict) or baseline_result.get("connected") is not True:
        return "UNVERIFIED", "a positive egress-proxy baseline is required before interpreting the LLM result"
    if not isinstance(llm_result, dict):
        return "UNVERIFIED", "LLM probe result is missing or invalid"
    if llm_result.get("connected") is True:
        return "FAIL", "LLM connected directly to the controlled destination after the baseline succeeded"
    error = llm_result.get("error")
    if error == "connection_refused":
        return "FAIL", "the destination refused the LLM connection, which does not establish network isolation"
    if isinstance(error, str) and error in {"network_unreachable", "host_unreachable"}:
        return "PASS", "controlled destination was reachable from egress-proxy but the LLM received a kernel unreachable result"
    return "UNVERIFIED", f"LLM probe result {error!r} is inconclusive"


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
    parser.add_argument(
        "--egress-probe-ip",
        help="optional deployment-owner-controlled public IP for the LLM direct-egress probe (requires --probe and --egress-probe-port)",
    )
    parser.add_argument(
        "--egress-probe-port",
        type=int,
        help="TCP port of the controlled egress probe destination",
    )
    args = parser.parse_args()

    if (args.egress_probe_ip is not None or args.egress_probe_port is not None) and not args.probe:
        parser.error("--egress-probe-ip/--egress-probe-port require --probe")

    COUNTS.update({status: 0 for status in COUNTS})
    run_id = str(uuid4())
    print("RUN " + json.dumps({
        "run_id": run_id,
        "started_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "target": "local Compose project",
        "compose_file": "compose.yaml",
        "probe_enabled": args.probe,
        "egress_probe": (
            {
                "destination_ip": args.egress_probe_ip,
                "destination_port": args.egress_probe_port,
            }
            if args.egress_probe_ip is not None or args.egress_probe_port is not None
            else None
        ),
    }, sort_keys=True))

    if shutil.which("docker") is None:
        emit("UNVERIFIED", "Docker checks", "Docker CLI unavailable")
        print("SUMMARY " + json.dumps({"run_id": run_id, "counts": COUNTS}, sort_keys=True))
        return 2

    config = load_compose_config()
    if config is None:
        emit("UNVERIFIED", "Compose configuration", "config could not be resolved; verify required local .env settings without printing them")
        print("SUMMARY " + json.dumps({"run_id": run_id, "counts": COUNTS}, sort_keys=True))
        return 2
    check_static(config)
    containers = inspect_containers(config)
    passive_stats([item for item in containers if item["running"]])
    if args.probe:
        run_read_only_probes(
            [item for item in containers if item["running"]], config,
            egress_probe_ip=args.egress_probe_ip,
            egress_probe_port=args.egress_probe_port,
        )

    print("SUMMARY " + json.dumps({"run_id": run_id, "counts": COUNTS}, sort_keys=True))
    if COUNTS["FAIL"]:
        return 1
    if COUNTS["UNVERIFIED"]:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
