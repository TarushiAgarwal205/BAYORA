"""Verify BAYORA Compose isolation without creating or stopping containers."""

import argparse
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
    "{{json .NetworkSettings.Ports}}|"
    "{{range .Mounts}}{{.Destination}}:rw={{.RW}},{{end}}"
)
PROBE_CODE = r"""
import json
import pathlib
import sys
import urllib.error
import urllib.request

def read(path):
    try:
        return pathlib.Path(path).read_text().strip()
    except OSError:
        return None

status = {}
for line in read("/proc/self/status").splitlines():
    if line.startswith(("Uid:", "Gid:", "CapEff:", "NoNewPrivs:", "Seccomp:")):
        key, value = line.split(":", 1)
        status[key] = value.strip().split()[0]

mounts = {}
for line in read("/proc/self/mountinfo").splitlines():
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
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        result["http"][url] = {"error": type(error).__name__}
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
            ("non-root user", service.get("user") == "10001:10001"),
            ("read-only root filesystem", service.get("read_only") is True),
            ("not privileged", service.get("privileged", False) is False),
            ("all capabilities dropped", service.get("cap_drop") == EXPECTED_CAP_DROP),
            ("no added capabilities", not service.get("cap_add")),
            (
                "no-new-privileges",
                "no-new-privileges:true" in service.get("security_opt", []),
            ),
            ("CPU limit", float(service.get("cpus", 0)) == limits["cpus"]),
            ("memory limit", int(service.get("mem_limit", 0)) == limits["memory"]),
            ("PID limit", service.get("pids_limit") == limits["pids"]),
        )
        for label, passed in checks:
            emit("PASS" if passed else "FAIL", f"{name} {label}", "configuration matches" if passed else "missing or differs from expected")

        tmpfs_options = service.get("tmpfs", [])
        tmpfs_entry = next((entry for entry in tmpfs_options if entry.startswith("/tmp:")), "")
        tmpfs_ok = all(option in tmpfs_entry for option in ("noexec", "nosuid", "size=16m"))
        emit("PASS" if tmpfs_ok else "FAIL", f"{name} /tmp tmpfs", "bounded, noexec, nosuid" if tmpfs_ok else "expected tmpfs options are missing")

        deploy_resources = service.get("deploy", {}).get("resources", {})
        reservations = deploy_resources.get("reservations")
        if reservations:
            emit("INFO", f"{name} reservations", "deploy.resources reservations are present")
        else:
            emit("INFO", f"{name} reservations", "none configured; service-level limits are used by local Compose")

        seccomp = [
            option for option in service.get("security_opt", [])
            if option.startswith("seccomp=")
        ]
        if seccomp:
            emit("INFO", f"{name} seccomp", "custom profile declared; runtime profile identity still needs verification")
        else:
            emit("UNVERIFIED", f"{name} seccomp", "no named seccomp profile is pinned; active runtime filter/profile is not established by YAML")

        actual_networks = set(service.get("networks", []))
        expected_networks = SERVICE_NETWORKS[name]
        emit(
            "PASS" if actual_networks == expected_networks else "FAIL",
            f"{name} network membership",
            f"configured={','.join(sorted(actual_networks))}",
        )

    for name in ("red-gateway", "blue-gateway", "llm-gateway"):
        internal = networks.get(name, {}).get("internal") is True
        emit("PASS" if internal else "FAIL", f"{name} internal", "marked internal" if internal else "not marked internal")

    egress = networks.get("llm-egress", {})
    if egress and egress.get("internal") is not True:
        emit("FAIL", "LLM provider-only egress", "ordinary bridge permits general outbound connectivity; no destination allowlist is configured")
    else:
        emit("UNVERIFIED", "LLM provider-only egress", "no explicit provider-only egress policy could be confirmed")

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
        "PASS" if normalized_ports == expected_ports else "FAIL",
        "Gateway host publication",
        "only 127.0.0.1:8000/tcp is configured" if normalized_ports == expected_ports else f"unexpected publication entries: {normalized_ports}",
    )
    for name in ("blue", "llm", "red"):
        published = services.get(name, {}).get("ports", [])
        emit("PASS" if not published else "FAIL", f"{name} host publication", "no host ports configured" if not published else "host ports are published")

    for name in ("gateway", "red"):
        mounts = services.get(name, {}).get("volumes", [])
        writable = sorted(
            mount["target"] for mount in mounts
            if isinstance(mount, dict) and mount.get("read_only") is not True
        )
        emit("INFO", f"{name} writable mounts", ",".join(writable) if writable else "none")


def parse_inspect_line(line):
    fields = line.split("|")
    if len(fields) != 16:
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
            "ports": json.loads(fields[14]),
            "mounts": fields[15],
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
            config.get("networks", {}).get(alias, {}).get("name", f"{item['project']}_{alias}")
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
                "Docker inspect matches expected setting" if passed else "Docker inspect differs from expected setting",
            )
        extra_networks = item["networks"] - expected_networks
        missing_networks = expected_networks - item["networks"]
        if extra_networks or missing_networks:
            emit("FAIL", f"{name} runtime networks", f"extra={','.join(sorted(extra_networks)) or 'none'} missing={','.join(sorted(missing_networks)) or 'none'}")
        else:
            emit("PASS", f"{name} runtime networks", ",".join(sorted(item["networks"])))
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
    known_names = {item["name"] for item in containers}
    project = next((item["project"] for item in containers if item["project"]), "")
    project = config.get("name") or project
    for alias, network_config in config.get("networks", {}).items():
        network_name = network_config.get("name") or f"{project}_{alias}"
        inspected = run(["docker", "network", "inspect", network_name])
        try:
            network = json.loads(inspected.stdout)[0] if inspected.returncode == 0 else None
        except (json.JSONDecodeError, IndexError, TypeError):
            network = None
        if network is None:
            emit("UNVERIFIED", f"{alias} peer inspection", "Docker could not inspect the resolved network")
            continue
        peers = {
            entry.get("Name", "")
            for entry in network.get("Containers", {}).values()
            if entry.get("Name")
        }
        unexpected = sorted(peers - known_names)
        if unexpected:
            emit(
                "FAIL",
                f"{alias} unexpected peers",
                f"non-Compose containers attached: {','.join(unexpected)}",
            )
        else:
            emit("PASS", f"{alias} peer membership", "all attached containers belong to this Compose project")


def run_read_only_probes(containers):
    host = run([sys.executable, "-c", HOST_HEALTH_CODE])
    emit("PASS" if host.returncode == 0 else "FAIL", "host to Gateway health", "loopback /health returned healthy" if host.returncode == 0 else "loopback Gateway health probe failed")

    by_service = {item["service"]: item for item in containers}
    for service, container in by_service.items():
        probe = run(["docker", "exec", container["name"], "python", "-c", PROBE_CODE])
        try:
            data = json.loads(probe.stdout)
        except (json.JSONDecodeError, TypeError):
            data = {}
        if probe.returncode:
            emit("UNVERIFIED", f"{service} in-container probe", "read-only /proc and cgroup probe did not complete")
            continue
        report_container_probe(service, data)

    gateway = by_service.get("gateway")
    blue = by_service.get("blue")
    red = by_service.get("red")
    if gateway:
        targets = ["http://blue:8001/health", "http://llm:8002/health"]
        probe = run(["docker", "exec", gateway["name"], "python", "-c", PROBE_CODE, *targets])
        try:
            data = json.loads(probe.stdout)
        except (json.JSONDecodeError, TypeError):
            data = {}
        for target in targets:
            passed = data.get("http", {}).get(target, {}).get("status") == 200
            emit("PASS" if passed else "FAIL", f"Gateway to {target}", "health endpoint returned 200" if passed else "health endpoint was not verified")
    else:
        emit("UNVERIFIED", "Gateway container probes", "no running Gateway container")

    if blue and gateway:
        target = "http://gateway:8000/health"
        probe = run(["docker", "exec", blue["name"], "python", "-c", PROBE_CODE, target])
        try:
            data = json.loads(probe.stdout)
        except (json.JSONDecodeError, TypeError):
            data = {}
        passed = data.get("http", {}).get(target, {}).get("status") == 200
        emit("PASS" if passed else "FAIL", "Blue to Gateway", "health endpoint returned 200" if passed else "health endpoint was not verified")
    else:
        emit("UNVERIFIED", "Blue to Gateway", "both containers must be running to test the intended path")

    if red and blue:
        target = "http://blue:8001/health"
        probe = run(["docker", "exec", red["name"], "python", "-c", PROBE_CODE, target])
        try:
            data = json.loads(probe.stdout)
        except (json.JSONDecodeError, TypeError):
            data = {}
        denied = "error" in data.get("http", {}).get(target, {})
        emit("PASS" if denied else "FAIL", "Red to Blue direct health", "request failed as expected" if denied else "target was reachable or result was ambiguous")
    else:
        emit("UNVERIFIED", "Red to Blue direct health", "a running Red container is required; the verifier will not start one")


def report_container_probe(service, data):
    status = data.get("status", {})
    expected_uid = "10001"
    uid_ok = status.get("Uid", "").split()[0] == expected_uid if status.get("Uid") else False
    gid_ok = status.get("Gid", "").split()[0] == expected_uid if status.get("Gid") else False
    emit("PASS" if uid_ok and gid_ok else "FAIL", f"{service} effective UID/GID", "10001:10001" if uid_ok and gid_ok else "process IDs differ or could not be read")
    zero_caps = status.get("CapEff") == "0000000000000000"
    emit("PASS" if zero_caps else "FAIL", f"{service} effective capabilities", "CapEff is zero" if zero_caps else "CapEff is nonzero or could not be read")
    no_new_privs = status.get("NoNewPrivs") == "1"
    emit("PASS" if no_new_privs else "FAIL", f"{service} effective no-new-privileges", "NoNewPrivs=1" if no_new_privs else "NoNewPrivs is not 1 or could not be read")
    seccomp = status.get("Seccomp") == "2"
    emit("PASS" if seccomp else "UNVERIFIED", f"{service} active seccomp mode", "Seccomp=2 (filter active; profile identity/rules unknown)" if seccomp else "filter mode could not be verified")

    mounts = data.get("mounts", {})
    root = mounts.get("/")
    tmp = mounts.get("/tmp")
    root_readonly = root is not None and "ro" in root.get("options", [])
    tmp_secure = (
        tmp is not None
        and tmp.get("filesystem") == "tmpfs"
        and "rw" in tmp.get("options", [])
        and "noexec" in tmp.get("options", []) + tmp.get("super_options", [])
        and "nosuid" in tmp.get("options", []) + tmp.get("super_options", [])
    )
    emit("PASS" if root_readonly else "FAIL", f"{service} effective root mount", "read-only mount observed" if root_readonly else "read-only mount not verified")
    emit("PASS" if tmp_secure else "FAIL", f"{service} effective /tmp mount", "writable tmpfs with noexec,nosuid observed" if tmp_secure else "expected /tmp mount not verified")

    cgroup = data.get("cgroup", {})
    limits = SERVICES[service]
    cpu_expected = f"{int(limits['cpus'] * 100000)} 100000"
    cpu_ok = cgroup.get("cpu.max") == cpu_expected
    memory_ok = cgroup.get("memory.max") == str(limits["memory"])
    pids_ok = cgroup.get("pids.max") == str(limits["pids"])
    emit("PASS" if cpu_ok else "UNVERIFIED", f"{service} effective cgroup CPU", cgroup.get("cpu.max") or "cpu.max unavailable")
    emit("PASS" if memory_ok else "UNVERIFIED", f"{service} effective cgroup memory", cgroup.get("memory.max") or "memory.max unavailable")
    emit("PASS" if pids_ok else "UNVERIFIED", f"{service} effective cgroup PIDs", cgroup.get("pids.max") or "pids.max unavailable")


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
        run_read_only_probes([item for item in containers if item["running"]])

    print(f"SUMMARY {COUNTS}")
    if COUNTS["FAIL"]:
        return 1
    if COUNTS["UNVERIFIED"]:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
