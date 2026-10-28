import asyncio
import ipaddress
import socket

import httpx
import pytest
from fastapi.testclient import TestClient

from llm import egress_proxy
from llm.provider_policy import OPENROUTER_URL, PROVIDER_AUTHORITY, PROVIDER_HOST


class FakeWriter:
    def __init__(self):
        self.data = bytearray()
        self.closed = False

    def write(self, data):
        self.data.extend(data)

    async def drain(self):
        return None

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


def _run_proxy_request(request, monkeypatch, *, resolve=None, connect=None):
    async def run():
        reader = asyncio.StreamReader()
        reader.feed_data(request)
        reader.feed_eof()
        writer = FakeWriter()
        if resolve is not None:
            monkeypatch.setattr(egress_proxy, "resolve_provider_addresses", resolve)
        if connect is not None:
            monkeypatch.setattr(asyncio, "open_connection", connect)
        await egress_proxy.handle_client(reader, writer)
        return bytes(writer.data)

    return asyncio.run(run())


def _client_hello(sni, *, fragmented=False):
    name = sni.encode("ascii")
    sni_name = b"\x00" + len(name).to_bytes(2, "big") + name
    sni_list = len(sni_name).to_bytes(2, "big") + sni_name
    extension = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list
    body = (
        b"\x03\x03" + bytes(32) + b"\x00"
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + len(extension).to_bytes(2, "big") + extension
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    chunks = (handshake[:len(handshake) // 2], handshake[len(handshake) // 2:]) if fragmented else (handshake,)
    return b"".join(
        b"\x16\x03\x03" + len(chunk).to_bytes(2, "big") + chunk
        for chunk in chunks
    )


def test_provider_policy_and_proxy_allowlist_share_the_configured_host():
    assert httpx.URL(OPENROUTER_URL).host == PROVIDER_HOST
    assert PROVIDER_AUTHORITY == "openrouter.ai:443"


def test_connect_to_provider_is_tunneled_to_a_resolved_public_address(monkeypatch):
    observed = {}
    client_hello = _client_hello(PROVIDER_HOST, fragmented=True)

    async def resolve():
        observed["resolved"] = True
        return [ipaddress.ip_address("8.8.8.8")]

    async def connect(host, port):
        upstream_reader = asyncio.StreamReader()
        upstream_reader.feed_eof()
        upstream_writer = FakeWriter()
        observed["target"] = (host, port)
        observed["upstream_writer"] = upstream_writer
        return upstream_reader, upstream_writer

    response = _run_proxy_request(
        f"CONNECT {PROVIDER_AUTHORITY} HTTP/1.1\r\nHost: {PROVIDER_AUTHORITY}\r\n\r\n".encode()
        + client_hello,
        monkeypatch,
        resolve=resolve,
        connect=connect,
    )

    assert observed["resolved"] is True
    assert observed["target"] == ("8.8.8.8", 443)
    assert observed["upstream_writer"].data == client_hello
    assert response.startswith(b"HTTP/1.1 200 Connection Established\r\n")


def test_proxy_does_not_forward_tls_with_a_different_sni(monkeypatch):
    observed = {}

    async def resolve():
        return [ipaddress.ip_address("8.8.8.8")]

    async def connect(host, port):
        upstream_reader = asyncio.StreamReader()
        upstream_reader.feed_eof()
        upstream_writer = FakeWriter()
        observed["target"] = (host, port)
        observed["upstream_writer"] = upstream_writer
        return upstream_reader, upstream_writer

    _run_proxy_request(
        f"CONNECT {PROVIDER_AUTHORITY} HTTP/1.1\r\n\r\n".encode()
        + _client_hello("other.example"),
        monkeypatch,
        resolve=resolve,
        connect=connect,
    )

    assert observed["target"] == ("8.8.8.8", 443)
    assert observed["upstream_writer"].data == b""


def test_proxy_does_not_write_http_error_after_establishing_tunnel(monkeypatch):
    async def resolve():
        return [ipaddress.ip_address("8.8.8.8")]

    async def connect(_host, _port):
        upstream_reader = asyncio.StreamReader()
        upstream_reader.feed_eof()
        return upstream_reader, FakeWriter()

    monkeypatch.setattr(egress_proxy, "read_tls_client_hello", _raise_value_error)
    response = _run_proxy_request(
        f"CONNECT {PROVIDER_AUTHORITY} HTTP/1.1\r\n\r\n".encode(),
        monkeypatch,
        resolve=resolve,
        connect=connect,
    )

    assert response == b"HTTP/1.1 200 Connection Established\r\n\r\n"


def test_truncated_tls_handshake_closes_tunnel_without_plaintext_error(monkeypatch):
    upstream = {}

    async def resolve():
        return [ipaddress.ip_address("8.8.8.8")]

    async def connect(_host, _port):
        upstream_reader = asyncio.StreamReader()
        upstream_reader.feed_eof()
        upstream["writer"] = FakeWriter()
        return upstream_reader, upstream["writer"]

    response = _run_proxy_request(
        f"CONNECT {PROVIDER_AUTHORITY} HTTP/1.1\r\n\r\n".encode()
        + b"\x16\x03\x03\x00\x01\x01",
        monkeypatch,
        resolve=resolve,
        connect=connect,
    )

    assert response == b"HTTP/1.1 200 Connection Established\r\n\r\n"
    assert upstream["writer"].data == b""


async def _raise_value_error(_reader):
    raise ValueError("malformed client hello")


@pytest.mark.parametrize("sni", ["other.example", "openrouter.ai.evil.test"])
def test_client_hello_parser_returns_exact_sni_for_proxy_comparison(sni):
    assert egress_proxy.parse_client_hello_sni(_client_hello(sni)[5:]) == sni


def test_client_hello_without_sni_is_rejected():
    with pytest.raises(egress_proxy.TLSClientHelloError, match="no DNS host_name SNI"):
        egress_proxy.parse_client_hello_sni(_client_hello_without_sni()[5:])


def _client_hello_without_sni():
    body = (
        b"\x03\x03" + bytes(32) + b"\x00"
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + b"\x00\x00"
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


@pytest.mark.parametrize(
    "proxy_request",
    [
        b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        b"CONNECT openrouter.ai.evil.test:443 HTTP/1.1\r\n\r\n",
        b"CONNECT openrouter.ai:80 HTTP/1.1\r\n\r\n",
        b"GET https://openrouter.ai/ HTTP/1.1\r\n\r\n",
    ],
)
def test_proxy_denies_non_provider_and_non_connect_requests_before_dns(proxy_request, monkeypatch):
    async def unexpected_resolution():
        raise AssertionError("denied proxy target must not be resolved")

    response = _run_proxy_request(
        proxy_request, monkeypatch, resolve=unexpected_resolution
    )

    assert response.startswith(b"HTTP/1.1 403 Forbidden\r\n") or response.startswith(
        b"HTTP/1.1 405 Method Not Allowed\r\n"
    )


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.2", "169.254.1.1", "::1"])
def test_provider_dns_private_or_link_local_addresses_are_rejected(address):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    record = (family, socket.SOCK_STREAM, 6, "", (address, 443))

    with pytest.raises(OSError, match="non-public"):
        egress_proxy.public_addresses([record])


def test_mixed_public_and_private_provider_dns_answers_are_rejected():
    records = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.2", 443)),
    ]

    with pytest.raises(OSError, match="non-public"):
        egress_proxy.public_addresses(records)


def test_public_provider_addresses_are_deduplicated():
    records = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
    ]

    assert egress_proxy.public_addresses(records) == [ipaddress.ip_address("8.8.8.8")]


def test_proxy_rejects_oversized_request_headers(monkeypatch):
    request = (
        f"CONNECT {PROVIDER_AUTHORITY} HTTP/1.1\r\n".encode()
        + b"X-Test: "
        + b"a" * (egress_proxy.MAX_HEADER_BYTES + 1)
        + b"\r\n\r\n"
    )

    response = _run_proxy_request(request, monkeypatch)

    assert response.startswith(b"HTTP/1.1 431 Request Header Fields Too Large\r\n")


def test_llm_service_forwards_provider_request_through_mandatory_proxy(monkeypatch):
    from llm import service

    captured = {}

    class MockAsyncClient:
        def __init__(self, *, proxy, timeout, follow_redirects):
            captured["proxy"] = proxy
            captured["timeout"] = timeout
            captured["follow_redirects"] = follow_redirects

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def post(self, url, *, headers, json):
            captured["url"] = url
            captured["headers"] = headers
            captured["json"] = json
            return httpx.Response(200, json={
                "choices": [{"message": {"content": "synthetic response"}}]
            })

    monkeypatch.setattr(service, "API_KEY", "test-only-provider-key")
    monkeypatch.setattr(service, "SERVICE_TOKEN", "test-only-service-token")
    monkeypatch.setattr(service, "MODEL", "test/model")
    monkeypatch.setattr(service, "EGRESS_PROXY_URL", "http://egress-proxy:8080")
    monkeypatch.setattr(service.httpx, "AsyncClient", MockAsyncClient)

    with TestClient(service.app) as client:
        response = client.post(
            "/generate",
            json={"prompt": "synthetic prompt"},
            headers={"Authorization": "Bearer test-only-service-token"},
        )

    assert response.status_code == 200
    assert response.json() == {"model": "test/model", "content": "synthetic response"}
    assert captured["proxy"] == "http://egress-proxy:8080"
    assert captured["follow_redirects"] is False
    assert captured["url"] == OPENROUTER_URL
    assert captured["headers"]["Authorization"] == "Bearer test-only-provider-key"


def test_llm_service_fails_closed_when_egress_proxy_is_missing(monkeypatch):
    from llm import service

    def unexpected_client(**_kwargs):
        raise AssertionError("missing egress proxy must prevent any provider request")

    monkeypatch.setattr(service, "API_KEY", "test-only-provider-key")
    monkeypatch.setattr(service, "SERVICE_TOKEN", "test-only-service-token")
    monkeypatch.setattr(service, "EGRESS_PROXY_URL", "")
    monkeypatch.setattr(service.httpx, "AsyncClient", unexpected_client)

    with TestClient(service.app) as client:
        response = client.post(
            "/generate",
            json={"prompt": "synthetic prompt"},
            headers={"Authorization": "Bearer test-only-service-token"},
        )

    assert response.status_code == 503
    assert response.json() == {"detail": "LLM provider egress is not configured"}


def test_llm_service_rejects_provider_redirects_without_following_location(monkeypatch):
    from llm import service

    calls = []

    class MockAsyncClient:
        def __init__(self, *, proxy, timeout, follow_redirects):
            assert proxy == "http://egress-proxy:8080"
            assert follow_redirects is False

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def post(self, url, *, headers, json):
            calls.append(url)
            return httpx.Response(
                302,
                headers={"Location": "https://redirect.example.invalid/"},
            )

    monkeypatch.setattr(service, "API_KEY", "test-only-provider-key")
    monkeypatch.setattr(service, "SERVICE_TOKEN", "test-only-service-token")
    monkeypatch.setattr(service, "EGRESS_PROXY_URL", "http://egress-proxy:8080")
    monkeypatch.setattr(service.httpx, "AsyncClient", MockAsyncClient)

    with TestClient(service.app) as client:
        response = client.post(
            "/generate",
            json={"prompt": "synthetic prompt"},
            headers={"Authorization": "Bearer test-only-service-token"},
        )

    assert response.status_code == 502
    assert response.json() == {"detail": "LLM provider request failed"}
    assert calls == [OPENROUTER_URL]
