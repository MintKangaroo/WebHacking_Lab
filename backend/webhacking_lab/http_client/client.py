"""DNS-pinned, single-hop HTTP transport for approved requests."""

import ssl
from collections.abc import Iterable
from dataclasses import dataclass
from time import perf_counter

import httpcore
import httpx

from webhacking_lab.domain.exceptions import (
    ResponseLimitError,
    UpstreamRequestError,
)


@dataclass(frozen=True, slots=True)
class TransportResult:
    """Bounded result from exactly one HTTP exchange."""

    status_code: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes
    elapsed_ms: float


class SingleHopSender:
    """Protocol-shaped base used to replace network I/O in tests."""

    async def send(
        self,
        *,
        method: str,
        url: str,
        headers: list[tuple[str, str]],
        resolved_ips: list[str],
        expected_hostname: str,
    ) -> TransportResult:
        """Send one request without following redirects."""

        raise NotImplementedError


class PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Connect only to addresses returned by the already-approved DNS check."""

    def __init__(self, expected_hostname: str, resolved_ips: Iterable[str]) -> None:
        self._expected_hostname = expected_hostname.lower().rstrip(".")
        self._resolved_ips = tuple(resolved_ips)
        self._backend = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109 - required httpcore interface
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        """Replace the hostname with one approved IP while preserving TLS SNI."""

        if host.lower().rstrip(".") != self._expected_hostname or not self._resolved_ips:
            raise httpcore.ConnectError("Connection target was not DNS-pinned")
        last_error: Exception | None = None
        for address in self._resolved_ips:
            try:
                return await self._backend.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as error:
                last_error = error
        raise httpcore.ConnectError("All approved target addresses failed") from last_error

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,  # noqa: ASYNC109 - required httpcore interface
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        """Refuse Unix sockets because scoped URLs are HTTP(S) network targets."""

        del path, timeout, socket_options
        raise httpcore.UnsupportedProtocol("Unix sockets are not supported")

    async def sleep(self, seconds: float) -> None:
        """Delegate protocol backoff without blocking the event loop."""

        await self._backend.sleep(seconds)


class PinnedAsyncTransport(httpx.AsyncHTTPTransport):
    """HTTPX transport backed by a DNS-pinned httpcore connection pool."""

    def __init__(self, expected_hostname: str, resolved_ips: list[str]) -> None:
        super().__init__(verify=True, http1=True, http2=False, retries=0)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl.create_default_context(),
            max_connections=1,
            max_keepalive_connections=0,
            http1=True,
            http2=False,
            retries=0,
            network_backend=PinnedNetworkBackend(expected_hostname, resolved_ips),
        )


class HttpxPinnedSender(SingleHopSender):
    """Send bounded requests with TLS verification and environment proxies disabled."""

    def __init__(self, *, timeout_seconds: float, max_response_bytes: int) -> None:
        self._timeout_seconds = timeout_seconds
        self._max_response_bytes = max_response_bytes

    async def send(
        self,
        *,
        method: str,
        url: str,
        headers: list[tuple[str, str]],
        resolved_ips: list[str],
        expected_hostname: str,
    ) -> TransportResult:
        """Send one redirect-disabled exchange and stop at the byte ceiling."""

        transport = PinnedAsyncTransport(expected_hostname, resolved_ips)
        timeout = httpx.Timeout(self._timeout_seconds)
        started = perf_counter()
        try:
            async with (
                httpx.AsyncClient(
                    transport=transport,
                    follow_redirects=False,
                    trust_env=False,
                    timeout=timeout,
                ) as client,
                client.stream(method, url, headers=headers) as response,
            ):
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > self._max_response_bytes:
                        raise ResponseLimitError("Response exceeded the configured size limit")
                return TransportResult(
                    status_code=response.status_code,
                    reason=response.reason_phrase,
                    headers=list(response.headers.multi_items()),
                    body=bytes(body),
                    elapsed_ms=(perf_counter() - started) * 1000,
                )
        except ResponseLimitError:
            raise
        except httpx.TimeoutException as error:
            raise UpstreamRequestError("Approved request timed out") from error
        except httpx.HTTPError as error:
            raise UpstreamRequestError("Approved request could not be completed") from error
