import io
import json
import sys
from contextlib import redirect_stdout
from types import SimpleNamespace
import urllib.error
import urllib.request

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
                **_service({"red-gateway", "blue-gateway", "llm-gateway", "gateway-host"}),
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
            "llm": {
                **_service({"llm-gateway", "llm-proxy"}),
                "environment": {"BAYORA_LLM_EGRESS_PROXY": "http://egress-proxy:8080"},
            },
            "egress-proxy": {
                **_service({"llm-proxy", "llm-egress"}),
                "tmpfs": ["/tmp:rw,noexec,nosuid,size=8m,mode=1777"],
            },
            "red": _service({"red-gateway"}),
        },
        "networks": {
            "red-gateway": {"internal": True},
            "blue-gateway": {"internal": True},
            "llm-gateway": {"internal": True},
            "llm-proxy": {"internal": True},
            "llm-egress": {"driver": "bridge"},
            "gateway-host": {"driver": "bridge"},
        },
    }

    verify_isolation.check_static(config)

    statuses = {check: status for status, check, _detail in results}
    assert statuses["gateway declared non-root user"] == "INFO"
    assert statuses["gateway declared CPU limit"] == "INFO"
    assert statuses["gateway declared /tmp tmpfs"] == "INFO"
    assert statuses["egress-proxy declared /tmp tmpfs"] == "INFO"
    details = {
        check: detail for _status, check, detail in results
    }
    assert "runtime enforcement is not established" in details["gateway declared non-root user"]
    assert statuses["LLM declared provider egress boundary"] == "INFO"


@pytest.mark.parametrize(
    ("service_name", "expected_size"),
    [("gateway", "16m"), ("egress-proxy", "8m")],
)
def test_static_tmpfs_uses_service_specific_size_and_security_options(
    monkeypatch, service_name, expected_size
):
    results = []
    monkeypatch.setattr(verify_isolation, "emit", lambda *result: results.append(result))
    config = {
        "services": {
            service_name: {
                "tmpfs": [
                    f"/tmp:rw,noexec,nosuid,size={expected_size},mode=1777"
                ],
            },
        },
        "networks": {},
    }

    verify_isolation.check_static(config)

    result = next(
        result for result in results
        if result[1] == f"{service_name} declared /tmp tmpfs"
    )
    assert result[0] == "INFO"
    assert f"size={expected_size},noexec,nosuid" in result[2]


@pytest.mark.parametrize(
    ("service_name", "expected_size", "missing_option"),
    [
        ("gateway", "16m", "noexec"),
        ("gateway", "16m", "nosuid"),
        ("egress-proxy", "8m", "noexec"),
        ("egress-proxy", "8m", "nosuid"),
    ],
)
def test_static_tmpfs_fails_when_required_security_option_is_missing(
    monkeypatch, service_name, expected_size, missing_option
):
    results = []
    monkeypatch.setattr(verify_isolation, "emit", lambda *result: results.append(result))
    options = ["rw", "noexec", "nosuid", f"size={expected_size}", "mode=1777"]
    options.remove(missing_option)
    config = {
        "services": {
            service_name: {"tmpfs": [f"/tmp:{','.join(options)}"]},
        },
        "networks": {},
    }

    verify_isolation.check_static(config)

    result = next(
        result for result in results
        if result[1] == f"{service_name} declared /tmp tmpfs"
    )
    assert result[0] == "FAIL"


@pytest.mark.parametrize(
    ("service_name", "expected_size", "conflict"),
    [
        ("gateway", "16m", "exec"),
        ("gateway", "16m", "suid"),
        ("egress-proxy", "8m", "exec"),
        ("egress-proxy", "8m", "suid"),
        ("gateway", "16m", "size=8m"),
        ("egress-proxy", "8m", "size=16m"),
    ],
)
def test_static_tmpfs_fails_on_contradictory_security_or_size_options(
    monkeypatch, service_name, expected_size, conflict
):
    results = []
    monkeypatch.setattr(verify_isolation, "emit", lambda *result: results.append(result))
    config = {
        "services": {
            service_name: {
                "tmpfs": [
                    f"/tmp:rw,noexec,nosuid,size={expected_size},{conflict},mode=1777"
                ],
            },
        },
        "networks": {},
    }

    verify_isolation.check_static(config)

    result = next(
        result for result in results
        if result[1] == f"{service_name} declared /tmp tmpfs"
    )
    assert result[0] == "FAIL"


def test_static_egress_boundary_fails_when_another_service_uses_llm_egress(monkeypatch):
    results = []
    monkeypatch.setattr(verify_isolation, "emit", lambda *result: results.append(result))
    config = {
        "services": {
            "gateway": {"networks": {}},
            "blue": {"networks": {"llm-egress": None}},
            "llm": {"networks": {}, "environment": {}},
            "egress-proxy": {"networks": {"llm-egress": None}},
            "red": {"networks": {}},
        },
        "networks": {
            "llm-proxy": {"internal": True},
            "llm-egress": {"driver": "bridge"},
        },
    }

    verify_isolation.check_static(config)

    boundary = next(
        result for result in results
        if result[1] == "LLM declared provider egress boundary"
    )
    assert boundary[0] == "FAIL"
    assert "other services attached to llm-egress: blue" in boundary[2]


def test_static_compose_missing_isolation_setting_fails_with_action(monkeypatch):
    results = []
    monkeypatch.setattr(verify_isolation, "emit", lambda *result: results.append(result))
    service = _service({"red-gateway"})
    service["user"] = "0:0"
    config = {
        "services": {
            "gateway": {
                **service,
                "networks": {
                    "red-gateway": None,
                    "blue-gateway": None,
                    "llm-gateway": None,
                    "gateway-host": None,
                },
            },
            "blue": _service({"blue-gateway"}),
            "llm": {
                **_service({"llm-gateway", "llm-proxy"}),
                "environment": {"BAYORA_LLM_EGRESS_PROXY": "http://egress-proxy:8080"},
            },
            "egress-proxy": _service({"llm-proxy", "llm-egress"}),
            "red": _service({"red-gateway"}),
        },
        "networks": {
            "red-gateway": {"internal": True},
            "blue-gateway": {"internal": True},
            "llm-gateway": {"internal": True},
            "llm-proxy": {"internal": True},
            "llm-egress": {"driver": "bridge"},
            "gateway-host": {"driver": "bridge"},
        },
    }

    verify_isolation.check_static(config)

    assert (
        "FAIL",
        "gateway declared non-root user",
        "Compose must declare user=10001:10001",
    ) in results


def test_network_membership_model_separates_red_blue_and_llm_egress():
    assert verify_isolation.SERVICE_NETWORKS["gateway"] == {
        "red-gateway", "blue-gateway", "llm-gateway", "gateway-host"
    }
    assert verify_isolation.SERVICE_NETWORKS["red"] == {"red-gateway"}
    assert verify_isolation.SERVICE_NETWORKS["blue"] == {"blue-gateway"}
    assert verify_isolation.SERVICE_NETWORKS["llm"] == {"llm-gateway", "llm-proxy"}
    assert verify_isolation.SERVICE_NETWORKS["egress-proxy"] == {
        "llm-proxy", "llm-egress"
    }
    assert "red" not in verify_isolation.NETWORK_SERVICES["blue-gateway"]
    assert "llm" not in verify_isolation.NETWORK_SERVICES["llm-egress"]
    assert verify_isolation.NETWORK_SERVICES["gateway-host"] == {"gateway"}


def test_gateway_host_network_peer_is_expected(monkeypatch):
    results = []

    def fake_run(command, **_kwargs):
        assert command == ["docker", "network", "inspect", "bayora_gateway-host"]
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps([{
                "Containers": {"gateway-id": {"Name": "bayora-gateway-1"}},
            }]),
        )

    monkeypatch.setattr(verify_isolation, "run", fake_run)
    monkeypatch.setattr(verify_isolation, "emit", lambda *result: results.append(result))
    containers = [{
        "name": "bayora-gateway-1",
        "service": "gateway",
        "project": "bayora",
        "running": True,
        "networks": {"bayora_gateway-host"},
    }]

    verify_isolation.check_network_peers(
        containers,
        {"name": "bayora", "networks": {"gateway-host": {}}},
    )

    assert results == [(
        "PASS",
        "gateway-host peer membership",
        "no unexpected attached containers; observed=bayora-gateway-1",
    )]


def test_network_peer_check_does_not_pass_when_expected_service_is_stopped(monkeypatch):
    results = []
    monkeypatch.setattr(
        verify_isolation,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=json.dumps([{
                "Containers": {"gateway-id": {"Name": "bayora-gateway-1"}},
            }]),
        ),
    )
    monkeypatch.setattr(verify_isolation, "emit", lambda *result: results.append(result))

    verify_isolation.check_network_peers(
        [{
            "name": "bayora-gateway-1",
            "service": "gateway",
            "project": "bayora",
            "running": True,
            "networks": {"bayora_blue-gateway"},
        }],
        {"name": "bayora", "networks": {"blue-gateway": {}}},
    )

    assert results == [(
        "UNVERIFIED",
        "blue-gateway peer membership",
        "expected services are stopped or not attached: blue",
    )]


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
    ("probe_result", "blue_health_reachable", "expected_status"),
    [
        ({"status": 200}, True, "FAIL"),
        ({"status": 403}, True, "FAIL"),
        ({"error": "unreachable"}, True, "PASS"),
        ({"error": "unreachable"}, False, "UNVERIFIED"),
        ({"error": "timeout"}, True, "UNVERIFIED"),
        ({"error": "connection_refused"}, True, "UNVERIFIED"),
        ({"error": "probe_error"}, True, "UNVERIFIED"),
        ({}, True, "UNVERIFIED"),
    ],
)
def test_red_blue_probe_never_treats_ambiguous_errors_as_isolation(
    probe_result, blue_health_reachable, expected_status,
):
    status, _detail = verify_isolation.classify_red_blue_result(
        probe_result,
        blue_health_reachable=blue_health_reachable,
    )
    assert status == expected_status


def test_container_http_probe_disables_proxies_and_does_not_follow_redirects(
    monkeypatch,
):
    target = "http://172.21.0.2:8001/health"
    handlers = []
    requests = []

    class FakeOpener:
        def open(self, url, timeout):
            requests.append((url, timeout))
            raise urllib.error.HTTPError(url, 302, "Found", {}, None)

    def fake_build_opener(*configured_handlers):
        handlers.extend(configured_handlers)
        return FakeOpener()

    monkeypatch.setattr(urllib.request, "build_opener", fake_build_opener)
    monkeypatch.setattr(sys, "argv", ["probe", target])
    output = io.StringIO()
    with redirect_stdout(output):
        exec(verify_isolation.PROBE_CODE, {})

    result = json.loads(output.getvalue())["http"][target]
    proxy_handler = next(
        handler for handler in handlers
        if isinstance(handler, urllib.request.ProxyHandler)
    )
    redirect_handler_type = next(
        handler for handler in handlers
        if isinstance(handler, type)
        and issubclass(handler, urllib.request.HTTPRedirectHandler)
    )
    redirect_handler = redirect_handler_type()

    assert proxy_handler.proxies == {}
    assert redirect_handler.redirect_request(None, None, 302, "", {}, "http://elsewhere/") is None
    assert requests == [(target, 2)]
    assert result == {"status": 302}
    assert verify_isolation.classify_red_blue_result(
        result,
        blue_health_reachable=True,
    )[0] == "FAIL"


def test_host_gateway_health_probe_disables_proxies_and_redirects(monkeypatch):
    handlers = []
    requests = []

    class FakeResponse:
        status = 200

        def read(self):
            return b'{"status":"healthy"}'

    class FakeOpener:
        def open(self, url, timeout):
            requests.append((url, timeout))
            return FakeResponse()

    def fake_build_opener(*configured_handlers):
        handlers.extend(configured_handlers)
        return FakeOpener()

    monkeypatch.setattr(urllib.request, "build_opener", fake_build_opener)
    namespace = {}
    try:
        exec(verify_isolation.HOST_HEALTH_CODE, namespace)
    except SystemExit as error:
        assert error.code == 0

    proxy_handler = next(
        handler for handler in handlers
        if isinstance(handler, urllib.request.ProxyHandler)
    )
    redirect_handler_type = next(
        handler for handler in handlers
        if isinstance(handler, type)
        and issubclass(handler, urllib.request.HTTPRedirectHandler)
    )
    redirect_handler = redirect_handler_type()
    assert proxy_handler.proxies == {}
    assert redirect_handler.redirect_request(None, None, 302, "", {}, "http://elsewhere/") is None
    assert requests == [("http://127.0.0.1:8000/health", 2)]


def test_inspect_parser_includes_runtime_network_addresses():
    line = (
        "/blue|true|blue|bayora|False|10001:10001|false|true|[\"ALL\"]|[]|"
        "[\"no-new-privileges:true\"]|64|500000000|268435456|private|private|private|"
        "bayora_blue-gateway,|bayora_blue-gateway=172.21.0.2,|"
        "{\"8001/tcp\":null}|/tmp:rw=true,"
    )

    parsed = verify_isolation.parse_inspect_line(line)

    assert parsed["network_ips"] == {"bayora_blue-gateway": "172.21.0.2"}
    assert parsed["networks"] == {"bayora_blue-gateway"}
    assert parsed["pid_mode"] == parsed["ipc_mode"] == parsed["uts_mode"] == "private"
    assert parsed["oneoff"] is False


def _inspect_line(name, service, *, oneoff):
    return (
        f"/{name}|true|{service}|bayora|{oneoff}|10001:10001|false|true|"
        "[\"ALL\"]|[]|[\"no-new-privileges:true\"]|64|500000000|268435456|"
        "private|private|private|bayora_red-gateway,|"
        "bayora_red-gateway=172.20.0.2,|{}|/tmp:rw=true,"
    )


@pytest.mark.parametrize(
    ("inspect_lines", "expected_names", "expected_active_status"),
    [
        ({"oneoff": _inspect_line("bayora-red-isolation-check", "red", oneoff="True")},
         set(), "UNVERIFIED"),
        ({"normal": _inspect_line("bayora-red-1", "red", oneoff="False"),
          "oneoff": _inspect_line("bayora-red-isolation-check", "red", oneoff="True")},
         {"bayora-red-1"}, None),
        ({"normal": _inspect_line("bayora-red-1", "red", oneoff="False")},
         {"bayora-red-1"}, None),
    ],
)
def test_inspect_containers_excludes_one_off_services_from_runtime_selection(
    monkeypatch, inspect_lines, expected_names, expected_active_status
):
    results = []
    commands = []

    def fake_run(command, **_kwargs):
        commands.append(command)
        if command[:4] == ["docker", "compose", "ps", "--all"]:
            ids = list(inspect_lines)
            return SimpleNamespace(returncode=0, stdout="\n".join(ids))
        if command[:2] == ["docker", "inspect"]:
            return SimpleNamespace(
                returncode=0,
                stdout=inspect_lines[command[-1]],
            )
        return SimpleNamespace(returncode=0, stdout="[]")

    monkeypatch.setattr(verify_isolation, "run", fake_run)
    monkeypatch.setattr(verify_isolation, "emit", lambda *result: results.append(result))
    monkeypatch.setattr(verify_isolation, "check_network_peers", lambda *_args: None)

    selected = verify_isolation.inspect_containers({"networks": {}})

    assert {item["name"] for item in selected if item["service"] == "red"} == expected_names
    active_red = [item for item in results if item[1] == "red active runtime"]
    if expected_active_status:
        assert active_red == [(
            "UNVERIFIED", "red active runtime", "no running service container was found"
        )]
        assert not any(item["service"] == "red" for item in selected)
    else:
        assert active_red == []
    if "oneoff" in inspect_lines:
        assert ("INFO", "red one-off container", "excluded from normal service runtime selection") in results


@pytest.mark.parametrize(
    ("namespace", "mode", "expected"),
    [
        ("PID", "host", "FAIL"),
        ("PID", "container:other", "FAIL"),
        ("IPC", "shareable", "FAIL"),
        ("UTS", "private", "PASS"),
        ("PID", "", "PASS"),
    ],
)
def test_runtime_namespace_sharing_is_detected(monkeypatch, namespace, mode, expected):
    results = []
    monkeypatch.setattr(verify_isolation, "emit", lambda *result: results.append(result))

    verify_isolation.report_namespace_modes("blue", {namespace: mode})

    assert results[0][0] == expected
    assert results[0][1] == f"blue runtime {namespace} namespace"


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


def test_red_probe_verifies_required_gateway_health_route(monkeypatch):
    results = []
    target = "http://gateway:8000/health"
    commands = []

    def fake_run(command, **_kwargs):
        commands.append(command)
        output = {"http": {target: {"status": 200}}} if target in command else {}
        return SimpleNamespace(returncode=0, stdout=json.dumps(output))

    monkeypatch.setattr(verify_isolation, "run", fake_run)
    monkeypatch.setattr(verify_isolation, "emit", lambda *result: results.append(result))
    containers = [
        {"name": "bayora-red-1", "service": "red"},
        {"name": "bayora-gateway-1", "service": "gateway"},
    ]

    verify_isolation.run_read_only_probes(containers, {"networks": {}})

    assert any(
        command[:4] == ["docker", "exec", "bayora-red-1", "python"]
        and target in command
        for command in commands
    )
    assert ("PASS", "Red to Gateway", "local health endpoint returned HTTP 200") in results


@pytest.mark.parametrize(
    ("blue_health_status", "expected_red_blue_status"),
    [(200, "PASS"), (503, "UNVERIFIED")],
)
def test_red_blue_unreachable_requires_gateway_confirmed_blue_health(
    monkeypatch, blue_health_status, expected_red_blue_status,
):
    results = []
    blue_target = "http://blue:8001/health"
    llm_target = "http://llm:8002/health"
    red_blue_target = "http://172.21.0.2:8001/health"
    red_gateway_target = "http://gateway:8000/health"

    def fake_run(command, **_kwargs):
        if blue_target in command:
            output = {"http": {
                blue_target: {"status": blue_health_status},
                llm_target: {"status": 200},
            }}
        elif red_blue_target in command:
            output = {"http": {red_blue_target: {"error": "unreachable"}}}
        elif red_gateway_target in command:
            output = {"http": {red_gateway_target: {"status": 200}}}
        else:
            output = {"status": {}, "mounts": {}, "cgroup": {}, "http": {}}
        return SimpleNamespace(returncode=0, stdout=json.dumps(output))

    monkeypatch.setattr(verify_isolation, "run", fake_run)
    monkeypatch.setattr(verify_isolation, "emit", lambda *result: results.append(result))
    containers = [
        {"name": "bayora-gateway-1", "service": "gateway"},
        {
            "name": "bayora-blue-1",
            "service": "blue",
            "project": "bayora",
            "network_ips": {"bayora_blue-gateway": "172.21.0.2"},
        },
        {
            "name": "bayora-red-1",
            "service": "red",
            "project": "bayora",
        },
    ]

    verify_isolation.run_read_only_probes(containers, {"networks": {}})

    red_blue = next(result for result in results if result[1] == "Red to Blue direct access")
    assert red_blue[0] == expected_red_blue_status


def test_stopped_red_is_unverified_and_is_not_probed(monkeypatch):
    results = []
    commands = []

    def fake_run(command, **_kwargs):
        commands.append(command)
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"status": {}, "mounts": {}, "cgroup": {}, "http": {}}),
        )

    monkeypatch.setattr(verify_isolation, "run", fake_run)
    monkeypatch.setattr(verify_isolation, "emit", lambda *result: results.append(result))
    containers = [
        {"name": "bayora-gateway-1", "service": "gateway"},
        {
            "name": "bayora-blue-1",
            "service": "blue",
            "project": "bayora",
            "network_ips": {"bayora_blue-gateway": "172.21.0.2"},
        },
    ]

    verify_isolation.run_read_only_probes(containers, {"networks": {}})

    assert not any("bayora-red-1" in command for command in commands)
    assert ("UNVERIFIED", "Red to Gateway", "running Red and Gateway containers are required; the verifier will not start them") in results
    assert ("UNVERIFIED", "Red to Blue direct access", "running Red and Blue containers are required; the verifier will not start them") in results


def test_llm_egress_probe_runs_once_when_red_blue_probe_exits_early(monkeypatch):
    results = []
    egress_calls = []

    def fake_run(command, **_kwargs):
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"status": {}, "mounts": {}, "cgroup": {}, "http": {}}),
        )

    def record_egress(*args):
        egress_calls.append(args)

    monkeypatch.setattr(verify_isolation, "run", fake_run)
    monkeypatch.setattr(verify_isolation, "emit", lambda *result: results.append(result))
    monkeypatch.setattr(verify_isolation, "run_llm_egress_probe", record_egress)
    containers = [
        {
            "name": "bayora-red-1",
            "service": "red",
            "project": "bayora",
            "network_ips": {},
        },
        {
            "name": "bayora-blue-1",
            "service": "blue",
            "project": "bayora",
            "network_ips": {},
        },
    ]

    verify_isolation.run_read_only_probes(
        containers,
        {"networks": {"blue-gateway": {}}},
        egress_probe_ip="203.0.113.8",
        egress_probe_port=443,
    )

    assert len(egress_calls) == 1
    assert egress_calls[0][1:] == ("203.0.113.8", 443)
    assert any(
        result[1] == "Red to Blue direct access"
        and result[0] == "UNVERIFIED"
        for result in results
    )


@pytest.mark.parametrize(
    ("baseline", "llm_result", "expected"),
    [
        ({"connected": False, "error": "timeout"}, {"error": "network_unreachable"}, "UNVERIFIED"),
        ({"connected": True}, {"error": "network_unreachable"}, "PASS"),
        ({"connected": True}, {"error": "timeout"}, "UNVERIFIED"),
        ({"connected": True}, {"error": "connection_refused"}, "FAIL"),
        ({"connected": True}, {"connected": True}, "FAIL"),
    ],
)
def test_llm_egress_result_requires_a_positive_baseline(baseline, llm_result, expected):
    status, _detail = verify_isolation.classify_llm_egress_result(baseline, llm_result)
    assert status == expected


def test_llm_egress_probe_skips_negative_result_when_positive_baseline_fails(monkeypatch):
    results = []
    commands = []

    def fake_run(command, **_kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout=json.dumps({"connected": False, "error": "timeout"}))

    monkeypatch.setattr(verify_isolation, "run", fake_run)
    monkeypatch.setattr(verify_isolation, "emit", lambda *result: results.append(result))

    verify_isolation.run_llm_egress_probe(
        {"egress-proxy": {"name": "bayora-egress-proxy-1"}, "llm": {"name": "bayora-llm-1"}},
        "8.8.8.8", 443,
    )

    assert len(commands) == 1
    assert commands[0][2] == "bayora-egress-proxy-1"
    assert results[0][0] == "UNVERIFIED"
    assert "not positively reachable" in results[0][2]


def test_llm_egress_probe_uses_same_destination_for_baseline_and_llm(monkeypatch):
    results = []
    commands = []

    def fake_run(command, **_kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout=json.dumps(
            {"connected": True} if command[2] == "proxy" else {"error": "network_unreachable"}
        ))

    monkeypatch.setattr(verify_isolation, "run", fake_run)
    monkeypatch.setattr(verify_isolation, "emit", lambda *result: results.append(result))

    verify_isolation.run_llm_egress_probe(
        {"egress-proxy": {"name": "proxy"}, "llm": {"name": "llm"}},
        "8.8.8.8", 443,
    )

    assert len(commands) == 2
    assert commands[0][-2:] == commands[1][-2:] == ["8.8.8.8", "443"]
    assert commands[0][2] == "proxy" and commands[1][2] == "llm"
    assert results[0][0] == "PASS"


@pytest.mark.parametrize(
    ("destination_ip", "destination_port"),
    [
        ("example.com", 443),
        ("127.0.0.1", 443),
        ("8.8.8.8", 0),
        ("8.8.8.8", 65536),
        (None, 443),
    ],
)
def test_llm_egress_probe_rejects_invalid_or_nonpublic_destinations(
    monkeypatch, destination_ip, destination_port,
):
    results = []
    monkeypatch.setattr(verify_isolation, "run", lambda *_args, **_kwargs: pytest.fail("invalid destination must not run a probe"))
    monkeypatch.setattr(verify_isolation, "emit", lambda *result: results.append(result))

    verify_isolation.run_llm_egress_probe(
        {"egress-proxy": {"name": "proxy"}, "llm": {"name": "llm"}},
        destination_ip, destination_port,
    )

    assert results[0][0] == "UNVERIFIED"
