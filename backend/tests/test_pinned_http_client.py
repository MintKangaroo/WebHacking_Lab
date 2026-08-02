"""Local-only tests for DNS-pinned, bounded HTTP transport."""

import asyncio

import pytest

from webhacking_lab.domain.exceptions import ResponseLimitError, UpstreamRequestError
from webhacking_lab.http_client.client import HttpxPinnedSender, SingleHopSender


async def _serve_once(body: bytes) -> tuple[asyncio.AbstractServer, int]:
    async def handler(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        await reader.readuntil(b"\r\n\r\n")
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Content-Type: text/plain\r\nConnection: close\r\n\r\n"
            + body
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    socket = server.sockets[0]
    return server, int(socket.getsockname()[1])


@pytest.mark.asyncio
async def test_dns_pinned_sender_reads_a_bounded_local_response() -> None:
    server, port = await _serve_once(b"approved response")
    try:
        result = await HttpxPinnedSender(
            timeout_seconds=1,
            max_response_bytes=1024,
        ).send(
            method="GET",
            url=f"http://localhost:{port}/allowed",
            headers=[("Accept", "text/plain")],
            resolved_ips=["127.0.0.1"],
            expected_hostname="localhost",
        )
    finally:
        server.close()
        await server.wait_closed()
    assert result.status_code == 200
    assert result.body == b"approved response"
    assert result.elapsed_ms >= 0


@pytest.mark.asyncio
async def test_dns_pinned_sender_stops_at_response_limit() -> None:
    server, port = await _serve_once(b"x" * 128)
    try:
        with pytest.raises(ResponseLimitError):
            await HttpxPinnedSender(
                timeout_seconds=1,
                max_response_bytes=1024,
            ).send(
                method="GET",
                url=f"http://localhost:{port}/large",
                headers=[],
                resolved_ips=["127.0.0.1"],
                expected_hostname="localhost",
                max_response_bytes=32,
            )
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_dns_pin_mismatch_and_base_sender_fail_closed() -> None:
    sender = HttpxPinnedSender(timeout_seconds=0.2, max_response_bytes=128)
    with pytest.raises(UpstreamRequestError):
        await sender.send(
            method="GET",
            url="http://localhost:9/",
            headers=[],
            resolved_ips=["127.0.0.1"],
            expected_hostname="different.example",
        )
    with pytest.raises(NotImplementedError):
        await SingleHopSender().send(
            method="GET",
            url="http://localhost/",
            headers=[],
            resolved_ips=["127.0.0.1"],
            expected_hostname="localhost",
        )
