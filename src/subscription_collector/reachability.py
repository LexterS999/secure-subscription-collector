"""TCP reachability checks for profile servers.

Every unique endpoint behind the collected profiles is probed over TCP with a
one-second deadline. Once the connection is established, the probe tries to
confirm application-level liveness by requesting the Cloudflare trace endpoint
(``/cdn-cgi/trace``) and falls back to the Google-style ``/generate_204``
connectivity path. Domains that cannot be resolved by the system resolver get
one fallback attempt through the Google DNS-over-HTTPS service.

Hysteria2 endpoints are exempt: the protocol runs over QUIC/UDP, so a TCP
handshake cannot prove or disprove availability and would reject healthy
servers. Their reachability is verified by the user in the Android client.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from collections.abc import Sequence
from dataclasses import dataclass

import httpx

from .config_loader import ReachabilityConfig
from .models import Profile, Protocol

_TRACE_PATH = "/cdn-cgi/trace"
_FALLBACK_PATH = "/generate_204"
_DOH_ENDPOINT = "https://dns.google/resolve"
_PROBE_USER_AGENT = "secure-subscription-collector/0.1"


@dataclass(frozen=True, order=True, slots=True)
class Endpoint:
    """One unique transport address extracted from collected profiles."""

    host: str
    port: int
    use_tls: bool
    server_name: str


@dataclass(frozen=True, slots=True)
class EndpointProbe:
    """Redacted outcome of one reachability attempt with handshake latency."""

    host: str
    port: int
    use_tls: bool
    server_name: str
    responded: bool
    method: str
    latency_ms: int | None = None


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def endpoint_of(profile: Profile) -> Endpoint | None:
    """Return the TCP endpoint to probe, or ``None`` for UDP-based protocols."""
    if profile.protocol is Protocol.HYSTERIA2:
        return None
    use_tls = profile.security in {"tls", "reality"}
    server_name = profile.params.get("sni", "")
    return Endpoint(profile.server.lower(), profile.port, use_tls, server_name)


def _ssl_context(endpoint: Endpoint) -> ssl.SSLContext | None:
    if not endpoint.use_tls:
        return None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _sni_hostname(endpoint: Endpoint) -> str | None:
    """SNI for the TLS handshake; omitted for IP literals and plain connections."""
    if not endpoint.use_tls:
        return None
    if not endpoint.server_name or _is_ip_literal(endpoint.server_name):
        return None
    return endpoint.server_name


async def _resolve_via_doh(
    endpoint: Endpoint, dns_fallback_client: httpx.AsyncClient
) -> str | None:
    """Resolve a domain through the Google DNS-over-HTTPS JSON API."""
    try:
        response = await dns_fallback_client.get(
            _DOH_ENDPOINT,
            params={"name": endpoint.host, "type": "A"},
        )
        payload = response.json()
    except (httpx.HTTPError, ValueError):
        return None
    answers = payload.get("Answer")
    if not isinstance(answers, list):
        return None
    for answer in answers:
        if answer.get("type") == 1 and isinstance(answer.get("data"), str):
            return answer["data"]
    return None


async def _http_round_trip(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    endpoint: Endpoint,
    path: str,
    timeout: float,
) -> bool:
    """Send one HTTP request and confirm that any response bytes arrive in time."""
    host_header = endpoint.server_name or endpoint.host
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"User-Agent: {_PROBE_USER_AGENT}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    try:
        writer.write(request.encode("ascii"))
        await asyncio.wait_for(writer.drain(), timeout)
        data = await asyncio.wait_for(reader.read(256), timeout)
    except (TimeoutError, OSError, ssl.SSLError):
        return False
    return bool(data)


async def probe_endpoint(
    endpoint: Endpoint,
    timeout: float,
    dns_fallback_client: httpx.AsyncClient | None = None,
) -> EndpointProbe:
    """Probe one endpoint over TCP/TLS and confirm liveness within the deadline."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    context = _ssl_context(endpoint)
    server_name = _sni_hostname(endpoint)
    handshake_started = loop.time()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                endpoint.host, endpoint.port, ssl=context, server_hostname=server_name
            ),
            timeout,
        )
    except socket.gaierror:
        resolved = None
        if dns_fallback_client is not None and not _is_ip_literal(endpoint.host):
            resolved = await _resolve_via_doh(endpoint, dns_fallback_client)
        if resolved is None:
            return EndpointProbe(
                endpoint.host,
                endpoint.port,
                endpoint.use_tls,
                endpoint.server_name,
                False,
                "tcp",
            )
        remaining = max(0.0, deadline - loop.time())
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    resolved, endpoint.port, ssl=context, server_hostname=server_name
                ),
                remaining,
            )
        except (TimeoutError, OSError, ssl.SSLError):
            return EndpointProbe(
                endpoint.host,
                endpoint.port,
                endpoint.use_tls,
                endpoint.server_name,
                False,
                "tcp",
            )
    except (TimeoutError, OSError, ssl.SSLError):
        return EndpointProbe(
            endpoint.host, endpoint.port, endpoint.use_tls, endpoint.server_name, False, "tcp"
        )
    latency_ms = round((loop.time() - handshake_started) * 1000)

    method = "tcp"
    for path, label in (
        (_TRACE_PATH, "cloudflare_trace"),
        (_FALLBACK_PATH, "google_generate_204"),
    ):
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        if await _http_round_trip(reader, writer, endpoint, path, remaining):
            method = label
            break
    writer.close()
    return EndpointProbe(
        endpoint.host,
        endpoint.port,
        endpoint.use_tls,
        endpoint.server_name,
        True,
        method,
        latency_ms,
    )


async def probe_endpoints(
    endpoints: Sequence[Endpoint],
    settings: ReachabilityConfig,
    dns_fallback_client: httpx.AsyncClient | None = None,
) -> dict[Endpoint, EndpointProbe]:
    """Probe endpoints in batches, bounded by the configured worker count."""
    outcomes: dict[Endpoint, EndpointProbe] = {}
    if not endpoints:
        return outcomes
    owned_client = dns_fallback_client is None
    if owned_client:
        dns_fallback_client = httpx.AsyncClient(timeout=2.0)
    semaphore = asyncio.Semaphore(settings.workers)
    timeout = settings.timeout_ms / 1000

    async def guarded(item: Endpoint) -> tuple[Endpoint, EndpointProbe]:
        async with semaphore:
            return item, await probe_endpoint(item, timeout, dns_fallback_client)

    try:
        for start in range(0, len(endpoints), settings.batch_size):
            batch = endpoints[start : start + settings.batch_size]
            for endpoint, probe in await asyncio.gather(*(guarded(item) for item in batch)):
                outcomes[endpoint] = probe
    finally:
        if owned_client:
            await dns_fallback_client.aclose()
    return outcomes
