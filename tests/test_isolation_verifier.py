import json
from types import SimpleNamespace

import pytest

from scripts import verify_isolation


def _service(networks):
    return {
        "user": "10001:10001",
        "read_only": True,
        "privileged": False,
        "cap_drop": ["ALL"],
        "cap_add": [],
        "security_opt": ["no-new-privileges:true"],
        "cpus": 0.5,
        "mem_limit": 268435456,
        "pids_limit": 64,
        "tmpfs": ["/tmp:rw,noexec,nosuid,size=16m,mode=1777"],
        "networks": {network: None for network in networks},
        "ports": [],
    }


def test_static_compose_declarations_are_info_not_runtime_pass(monkeypatch):
    results = []
    monkeypatch.setattr(verify_isolation, "emit", lambda *result: results.append(result))
    config = {
        "services": {
            "gateway": {
                **_service({"red-gateway", "blue-gateway", "llm-gateway"}),
                "cpus": 1.0,
                "mem_limit": 536870912,
                "pids_limit": 128,
                "ports": [{
                    "host_ip": "127.0.0.1",
                    "target": 8000,
                    "published": "8000",
                    "protocol": "tcp",
                }],
            },
            "blue": _service({"blue-gateway"}),
            "llm": _service({"llm-gateway", "llm-egress"}),
            "red": _service({"red-gateway"}),
        },
        "networks": {
            "red-gateway": {"internal": True},
            "blue-gateway": {"internal": True},
            "llm-gateway": {"internal": True},
            "llm-egress": {"driver": "bridge"},
        },
    }

    verify_isolation.check_static(config)

    statuses = {check: status for status, check, _detail in results}
    assert statuses["gateway declared non-root user"] == "INFO"
    assert statuses["gateway declared CPU limit"] == "INFO"
    details = {
        check: detail for _status, check, detail in results
    }
    assert "runtime enforcement is not established" in details["gateway declared non-root user"]


def test_static_compose_missing_isolation_setting_fails_with_action(monkeypatch):
    results = []
    monkeypatch.setattr(verify_isolation, "emit", lambda *result: results.append(result))
    service = _service({"red-gateway"})
    service["user"] = "0:0"
    config = {
        "services": {
            "gateway": service,
            "blue": _service({"blue-gateway"}),
            "llm": _service({"llm-gateway", "llm-egress"}),
            "red": _service({"red-gateway"}),
        },
        "networks": {
            "red-gateway": {"internal": True},
            "blue-gateway": {"internal": True},
            "llm-gateway": {"internal": True},
            "llm-egress": {"driver": "bridge"},
        },
    }

    verify_isolation.check_static(config)

    assert (
        "FAIL",
        "gateway declared non-root user",
        "Compose must declare user=10001:10001",
    ) in results


def test_protected_network_peer_check_flags_unlisted_and_misplaced_containers(monkeypatch):
    results = []
    network_data = [{
        "Containers": {
            "gateway-id": {"Name": "bayora-gateway-1"},
            "blue-id": {"Name": "bayora-blue-1"},
            "red-id": {"Name": "bayora-red-1"},
            "test-id": {"Name": "bayora-port-test"},
        }
    }]

    def fake_run(command, **_kwargs):
        assert command == ["docker", "network", "inspect", "bayora_blue-gateway"]
        return SimpleNamespace(returncode=0, stdout=json.dumps(network_data))

    monkeypatch.setattr(verify_isolation, "run", fake_run)
    monkeypatch.setattr(verify_isolation, "emit", lambda *result: results.append(result))
    containers = [
        {
            "name": "bayora-gateway-1",
            "service": "gateway",
            "project": "bayora",
            "running": True,
            "networks": {"bayora_blue-gateway"},
        },
        {
            "name": "bayora-blue-1",
            "service": "blue",
            "project": "bayora",
            "running": True,
            "networks": {"bayora_blue-gateway"},
        },
        {
            "name": "bayora-red-1",
            "service": "red",
            "project": "bayora",
            "running": True,
            "networks": {"bayora_blue-gateway"},
        },
    ]

    verify_isolation.check_network_peers(
        containers,
        {"name": "bayora", "networks": {"blue-gateway": {}}},
    )

    assert results == [(
        "FAIL",
        "blue-gateway unexpected peers",
        "unexpected=bayora-port-test,bayora-red-1; expected-but-not-listed=none",
    )]


@pytest.mark.parametrize(
    ("probe_result", "expected_status"),
    [
        ({"status": 200}, "FAIL"),
        ({"status": 403}, "FAIL"),
        ({"error": "unreachable"}, "PASS"),
        ({"error": "timeout"}, "UNVERIFIED"),
        ({"error": "connection_refused"}, "UNVERIFIED"),
        ({"error": "probe_error"}, "UNVERIFIED"),
        ({}, "UNVERIFIED"),
    ],
)
def test_red_blue_probe_never_treats_ambiguous_errors_as_isolation(
    probe_result, expected_status,
):
    status, _detail = verify_isolation.classify_red_blue_result(probe_result)
    assert status == expected_status


def test_inspect_parser_includes_runtime_network_addresses():
    line = (
        "/blue|true|blue|bayora|10001:10001|false|true|[\"ALL\"]|[]|"
        "[\"no-new-privileges:true\"]|64|500000000|268435456|"
        "bayora_blue-gateway,|bayora_blue-gateway=172.21.0.2,|"
        "{\"8001/tcp\":null}|/tmp:rw=true,"
    )

    parsed = verify_isolation.parse_inspect_line(line)

    assert parsed["network_ips"] == {"bayora_blue-gateway": "172.21.0.2"}
    assert parsed["networks"] == {"bayora_blue-gateway"}


def test_effective_runtime_probe_marks_unavailable_values_unverified(monkeypatch):
    results = []
    monkeypatch.setattr(verify_isolation, "emit", lambda *result: results.append(result))

    verify_isolation.report_container_probe("blue", {})

    assert results
    assert all(status == "UNVERIFIED" for status, _check, _detail in results)


def test_effective_runtime_limit_mismatch_fails(monkeypatch):
    results = []
    monkeypatch.setattr(verify_isolation, "emit", lambda *result: results.append(result))

    verify_isolation.report_container_probe("blue", {
        "status": {
            "Uid": "10001 10001 10001",
            "Gid": "10001 10001 10001",
            "CapEff": "0000000000000000",
            "NoNewPrivs": "1",
            "Seccomp": "2",
        },
        "mounts": {
            "/": {"options": ["ro"]},
            "/tmp": {
                "filesystem": "tmpfs",
                "options": ["rw", "noexec", "nosuid"],
                "super_options": [],
            },
        },
        "cgroup": {
            "cpu.max": "50000 100000",
            "memory.max": "536870912",
            "pids.max": "64",
        },
    })

    checks = {check: status for status, check, _detail in results}
    assert checks["blue effective cgroup CPU"] == "PASS"
    assert checks["blue effective cgroup memory"] == "FAIL"
    assert checks["blue effective cgroup PIDs"] == "PASS"


def test_red_probe_targets_docker_reported_private_ip_and_timeout_is_unverified(monkeypatch):
    results = []
    commands = []
    target = "http://172.21.0.2:8001/health"

    def fake_run(command, **_kwargs):
        commands.append(command)
        if target in command:
            output = {"http": {target: {"error": "timeout"}}}
        else:
            output = {"status": {}, "mounts": {}, "cgroup": {}, "http": {}}
        return SimpleNamespace(returncode=0, stdout=json.dumps(output))

    monkeypatch.setattr(verify_isolation, "run", fake_run)
    monkeypatch.setattr(verify_isolation, "emit", lambda *result: results.append(result))
    containers = [
        {
            "name": "bayora-red-1",
            "service": "red",
            "project": "bayora",
            "running": True,
            "networks": {"bayora_red-gateway"},
            "network_ips": {"bayora_red-gateway": "172.19.0.2"},
        },
        {
            "name": "bayora-blue-1",
            "service": "blue",
            "project": "bayora",
            "running": True,
            "networks": {"bayora_blue-gateway"},
            "network_ips": {"bayora_blue-gateway": "172.21.0.2"},
        },
    ]

    verify_isolation.run_read_only_probes(
        containers,
        {"networks": {"blue-gateway": {}}},
    )

    assert any(target in command for command in commands)
    assert (
        "UNVERIFIED",
        "Red to Blue direct access",
        "probe result 'timeout' does not prove segmentation; timeout/refusal require separate diagnosis",
    ) in results
