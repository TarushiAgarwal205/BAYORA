"""Default-deny HTTP CONNECT proxy for the configured OpenRouter endpoint."""

import asyncio
import ipaddress
import socket

from llm.provider_policy import PROVIDER_AUTHORITY, PROVIDER_HOST, PROVIDER_PORT


LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8080
MAX_HEADER_BYTES = 16 * 1024
REQUEST_TIMEOUT_SECONDS = 5
CONNECT_TIMEOUT_SECONDS = 10
RELAY_BUFFER_BYTES = 64 * 1024
MAX_TLS_RECORD_BYTES = 18_432
MAX_CLIENT_HELLO_BYTES = 64 * 1024
MAX_CLIENT_HELLO_RECORDS = 8
TLS_HELLO_TIMEOUT_SECONDS = 10


class ProxyRequestError(Exception):
    def __init__(self, status, reason):
        self.status = status
        self.reason = reason


class TLSClientHelloError(Exception):
    pass


def parse_client_hello_sni(handshake):
    """Parse a bounded TLS ClientHello and return its single DNS SNI name."""
    if len(handshake) < 4 or handshake[0] != 1:
        raise TLSClientHelloError("not a TLS ClientHello")
    message_length = int.from_bytes(handshake[1:4], "big")
    if message_length > MAX_CLIENT_HELLO_BYTES or len(handshake) < message_length + 4:
        raise TLSClientHelloError("invalid TLS ClientHello length")
    body = handshake[4:4 + message_length]
    offset = 34  # legacy_version and random

    def take(length):
        nonlocal offset
        if length < 0 or offset + length > len(body):
            raise TLSClientHelloError("truncated TLS ClientHello")
        value = body[offset:offset + length]
        offset += length
        return value

    session_length = take(1)[0]
    if session_length > 32:
        raise TLSClientHelloError("invalid TLS session id")
    take(session_length)
    cipher_length = int.from_bytes(take(2), "big")
    if cipher_length < 2 or cipher_length % 2:
        raise TLSClientHelloError("invalid TLS cipher list")
    take(cipher_length)
    compression_length = take(1)[0]
    if not compression_length:
        raise TLSClientHelloError("invalid TLS compression list")
    take(compression_length)

    if offset == len(body):
        raise TLSClientHelloError("TLS ClientHello has no SNI extension")
    extensions_length = int.from_bytes(take(2), "big")
    if offset + extensions_length != len(body):
        raise TLSClientHelloError("invalid TLS extensions length")
    extensions_end = offset + extensions_length
    sni = None
    sni_extension_seen = False
    while offset < extensions_end:
        extension_type = int.from_bytes(take(2), "big")
        extension_length = int.from_bytes(take(2), "big")
        extension = take(extension_length)
        if extension_type != 0:
            continue
        if sni_extension_seen or len(extension) < 2:
            raise TLSClientHelloError("invalid duplicate SNI extension")
        sni_extension_seen = True
        names_length = int.from_bytes(extension[:2], "big")
        if names_length != len(extension) - 2:
            raise TLSClientHelloError("invalid SNI list length")
        cursor = 2
        while cursor < len(extension):
            if cursor + 3 > len(extension):
                raise TLSClientHelloError("truncated SNI entry")
            name_type = extension[cursor]
            name_length = int.from_bytes(extension[cursor + 1:cursor + 3], "big")
            cursor += 3
            if cursor + name_length > len(extension):
                raise TLSClientHelloError("truncated SNI name")
            name_bytes = extension[cursor:cursor + name_length]
            cursor += name_length
            if name_type == 0:
                if sni is not None:
                    raise TLSClientHelloError("multiple host_name SNI entries")
                try:
                    sni = name_bytes.decode("ascii").lower()
                except UnicodeDecodeError:
                    raise TLSClientHelloError("non-ASCII host_name SNI") from None
        if cursor != len(extension):
            raise TLSClientHelloError("invalid SNI extension")
    if sni is None:
        raise TLSClientHelloError("TLS ClientHello has no DNS host_name SNI")
    return sni


async def read_tls_client_hello(reader):
    """Read complete TLS records through ClientHello, retaining their wire bytes."""
    wire = bytearray()
    handshake = bytearray()
    for _ in range(MAX_CLIENT_HELLO_RECORDS):
        header = await reader.readexactly(5)
        content_type, major, minor = header[:3]
        record_length = int.from_bytes(header[3:5], "big")
        if content_type != 22 or major != 3 or minor not in {1, 2, 3, 4}:
            raise TLSClientHelloError("invalid TLS handshake record")
        if record_length == 0 or record_length > MAX_TLS_RECORD_BYTES:
            raise TLSClientHelloError("invalid TLS record length")
        payload = await reader.readexactly(record_length)
        wire.extend(header)
        wire.extend(payload)
        handshake.extend(payload)
        if len(handshake) >= 4:
            message_length = int.from_bytes(handshake[1:4], "big")
            if handshake[0] != 1 or message_length > MAX_CLIENT_HELLO_BYTES:
                raise TLSClientHelloError("invalid TLS ClientHello")
            if len(handshake) >= message_length + 4:
                return bytes(wire), bytes(handshake[:message_length + 4])
    raise TLSClientHelloError("TLS ClientHello spans too many records")


def public_addresses(records):
    """Return unique public addresses; reject mixed/private DNS answers."""
    addresses = set()
    for record in records:
        address_text = record[4][0].split("%", 1)[0]
        address = ipaddress.ip_address(address_text)
        if not address.is_global:
            raise OSError("provider DNS returned a non-public address")
        addresses.add(address)
    if not addresses:
        raise OSError("provider DNS returned no addresses")
    return sorted(addresses, key=lambda item: (item.version, item.packed))


async def resolve_provider_addresses():
    loop = asyncio.get_running_loop()
    records = await loop.getaddrinfo(
        PROVIDER_HOST,
        PROVIDER_PORT,
        type=socket.SOCK_STREAM,
    )
    return public_addresses(records)


async def relay(source, destination):
    while True:
        chunk = await source.read(RELAY_BUFFER_BYTES)
        if not chunk:
            return
        destination.write(chunk)
        await destination.drain()


async def tunnel(client_reader, client_writer, upstream_reader, upstream_writer):
    tasks = {
        asyncio.create_task(relay(client_reader, upstream_writer)),
        asyncio.create_task(relay(upstream_reader, client_writer)),
    }
    _done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


async def respond(writer, status, reason):
    payload = (
        f"HTTP/1.1 {status} {reason}\r\n"
        "Connection: close\r\n"
        "Content-Length: 0\r\n\r\n".encode("ascii")
    )
    writer.write(payload)
    await writer.drain()


async def read_connect_request(reader):
    line = await asyncio.wait_for(
        reader.readline(), timeout=REQUEST_TIMEOUT_SECONDS
    )
    if not line or len(line) > 4096 or not line.endswith(b"\r\n"):
        raise ProxyRequestError(400, "Bad Request")
    try:
        method, authority, version = line.decode("ascii").strip().split()
    except (UnicodeDecodeError, ValueError):
        raise ProxyRequestError(400, "Bad Request") from None
    if method.upper() != "CONNECT" or version not in {"HTTP/1.0", "HTTP/1.1"}:
        raise ProxyRequestError(405, "Method Not Allowed")
    if authority.lower() != PROVIDER_AUTHORITY:
        raise ProxyRequestError(403, "Forbidden")

    header_bytes = 0
    while True:
        header = await asyncio.wait_for(
            reader.readline(), timeout=REQUEST_TIMEOUT_SECONDS
        )
        header_bytes += len(header)
        if not header or not header.endswith(b"\r\n"):
            raise ProxyRequestError(400, "Bad Request")
        if header_bytes > MAX_HEADER_BYTES:
            raise ProxyRequestError(431, "Request Header Fields Too Large")
        if header == b"\r\n":
            return
        if b":" not in header:
            raise ProxyRequestError(400, "Bad Request")


async def handle_client(reader, writer):
    upstream_writer = None
    response_started = False
    try:
        await read_connect_request(reader)
        addresses = await asyncio.wait_for(
            resolve_provider_addresses(), timeout=CONNECT_TIMEOUT_SECONDS
        )
        upstream = None
        for address in addresses:
            try:
                upstream = await asyncio.wait_for(
                    asyncio.open_connection(str(address), PROVIDER_PORT),
                    timeout=CONNECT_TIMEOUT_SECONDS,
                )
                break
            except (OSError, asyncio.TimeoutError):
                continue
        if upstream is None:
            await respond(writer, 502, "Bad Gateway")
            response_started = True
            return

        upstream_reader, upstream_writer = upstream
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        response_started = True
        client_hello_wire, client_hello = await asyncio.wait_for(
            read_tls_client_hello(reader), timeout=TLS_HELLO_TIMEOUT_SECONDS
        )
        if parse_client_hello_sni(client_hello) != PROVIDER_HOST:
            return
        upstream_writer.write(client_hello_wire)
        await upstream_writer.drain()
        await tunnel(reader, writer, upstream_reader, upstream_writer)
    except ProxyRequestError as error:
        await respond(writer, error.status, error.reason)
        response_started = True
    except (TLSClientHelloError, asyncio.IncompleteReadError):
        pass
    except ValueError:
        if not response_started:
            await respond(writer, 431, "Request Header Fields Too Large")
            response_started = True
    except (OSError, asyncio.TimeoutError):
        if not response_started:
            await respond(writer, 502, "Bad Gateway")
    finally:
        if upstream_writer is not None:
            upstream_writer.close()
            try:
                await upstream_writer.wait_closed()
            except (OSError, asyncio.CancelledError):
                pass
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, asyncio.CancelledError):
            pass


async def serve():
    server = await asyncio.start_server(
        handle_client,
        LISTEN_HOST,
        LISTEN_PORT,
        limit=MAX_HEADER_BYTES,
        backlog=64,
    )
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(serve())
