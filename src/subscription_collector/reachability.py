"""Deep TCP reachability checks for profile servers.

Every unique endpoint behind the collected profiles is probed over TCP with a
per-attempt deadline. A probe is no longer a single shot: each endpoint is
attempted ``attempts`` times (default three) with a short retry delay, and the
results are aggregated into a median handshake latency, a success ratio and a
stability verdict. Once a connection is established, the probe confirms
application-level liveness by requesting the Cloudflare trace endpoint
(``/cdn-cgi/trace``) and falls back to the Google-style ``/generate_204``
connectivity path. Successful TLS handshakes additionally record the negotiated
TLS version and cipher for deeper endpoint analytics. Domains that cannot be
resolved by the system resolver get one fallback attempt through the Google
DNS-over-HTTPS service, and the resolution path is reported.

Hysteria2 endpoints are exempt: the protocol runs over QUIC/UDP, so a TCP
handshake cannot prove or disprove availability and would reject healthy
servers. Their reachability is verified by the user in the Android client.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import statistics
from collections.abc import Sequence
from dataclasses import dataclass

import httpx

from .config_loader import ReachabilityConfig
from .models import Profile, Protocol

_TRACE_PATH = "/cdn-cgi/trace"
_FALLBACK_PATH = "/generate_204"
_DOH_ENDPOINT = "https://dns.google/resolve"
_PROBE_USER_AGENT = "secure-subscription-collector/0.1"

_METHOD_RANK = {"tcp": 0, "google_generate_204": 1, "cloudflare_trace": 2}

GRADE_EXCELLENT = "excellent"
GRADE_GOOD = "good"
GRADE_FAIR = "fair"
GRADE_UNRESPONSIVE = "unresponsive"


@dataclass(frozen=True, order=True, slots=True)
class Endpoint:
    """One unique transport address extracted from collected profiles."""

    host: str
    port: int
    use_tls: bool
    server_name: str


@dataclass(frozen=True, slots=True)
class EndpointProbe:
    """Redacted outcome of one deep reachability check.

    The first seven fields keep their historical positional order; the rest are
    aggregation results across attempts.
    """

    host: str
    port: int
    use_tls: bool
    server_name: str
    responded: bool
    method: str
    latency_ms: int | None = None
    attempts_made: int = 0
    successful_attempts: int = 0
    latencies_ms: tuple[int, ...] = ()
    stable: bool = False
    resolution: str = "system"
    tls_version: str | None = None
    tls_cipher: str | None = None


def latency_grade(latency_ms: int | None, excellent_ms: int, good_ms: int) -> str:
    """Grade an aggregated handshake latency against the configured thresholds."""
    if latency_ms is None:
        return GRADE_UNRESPONSIVE
    if latency_ms <= excellent_ms:
        return GRADE_EXCELLENT
    if latency_ms <= good_ms:
        return GRADE_GOOD
    return GRADE_FAIR


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


def _tls_metadata(writer: asyncio.StreamWriter) -> tuple[str | None, str | None]:
    """Best-effort negotiated TLS version and cipher from an open connection."""
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        if ssl_object is None:
            return None, None
        cipher = ssl_object.cipher()
        return ssl_object.version(), cipher[0] if cipher else None
    except (OSError, ValueError, AttributeError):
        return None, None


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


@dataclass(frozen=True, slots=True)
class _AttemptOutcome:
    responded: bool
    method: str = "tcp"
    latency_ms: int | None = None
    resolution: str = "system"
    tls_version: str | None = None
    tls_cipher: str | None = None


async def _attempt_once(
    endpoint: Endpoint,
    timeout: float,
    dns_fallback_client: httpx.AsyncClient | None = None,
) -> _AttemptOutcome:
    """One full attempt: connect (with DoH fallback), then confirm liveness."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    context = _ssl_context(endpoint)
    server_name = _sni_hostname(endpoint)
    handshake_started = loop.time()
    resolution = "system"
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
            if resolved is not None:
                resolution = "doh"
        if resolved is None:
            return _AttemptOutcome(False)
        remaining = max(0.0, deadline - loop.time())
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    resolved, endpoint.port, ssl=context, server_hostname=server_name
                ),
                remaining,
            )
        except (TimeoutError, OSError, ssl.SSLError):
            return _AttemptOutcome(False, resolution=resolution)
    except (TimeoutError, OSError, ssl.SSLError):
        return _AttemptOutcome(False)

    latency_ms = round((loop.time() - handshake_started) * 1000)
    tls_version, tls_cipher = _tls_metadata(writer)

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
    return _AttemptOutcome(True, method, latency_ms, resolution, tls_version, tls_cipher)


def _aggregate(
    endpoint: Endpoint, outcomes: Sequence[_AttemptOutcome]
) -> EndpointProbe:
    """Fold per-attempt outcomes into one redacted aggregate probe result."""
    latencies = tuple(
        outcome.latency_ms
        for outcome in outcomes
        if outcome.responded and outcome.latency_ms is not None
    )
    responded_outcomes = [outcome for outcome in outcomes if outcome.responded]
    best_method = "tcp"
    for outcome in responded_outcomes:
        if _METHOD_RANK.get(outcome.method, 0) > _METHOD_RANK.get(best_method, 0):
            best_method = outcome.method
    resolutions = [outcome.resolution for outcome in outcomes]
    resolution = "doh" if "doh" in resolutions else "system"
    tls_versions = {outcome.tls_version for outcome in responded_outcomes if outcome.tls_version}
    tls_ciphers = {outcome.tls_cipher for outcome in responded_outcomes if outcome.tls_cipher}
    median_latency = round(statistics.median(latencies)) if latencies else None
    return EndpointProbe(
        endpoint.host,
        endpoint.port,
        endpoint.use_tls,
        endpoint.server_name,
        responded=bool(responded_outcomes),
        method=best_method,
        latency_ms=median_latency,
        attempts_made=len(outcomes),
        successful_attempts=len(responded_outcomes),
        latencies_ms=latencies,
        stable=len(responded_outcomes) == len(outcomes),
        resolution=resolution,
        tls_version=tls_versions.pop() if len(tls_versions) == 1 else None,
        tls_cipher=tls_ciphers.pop() if len(tls_ciphers) == 1 else None,
    )


async def probe_endpoint(
    endpoint: Endpoint,
    timeout: float,
    dns_fallback_client: httpx.AsyncClient | None = None,
    *,
    attempts: int = 1,
    retry_delay_seconds: float = 0.0,
) -> EndpointProbe:
    """Probe one endpoint over TCP/TLS, retrying transient failures."""
    outcomes: list[_AttemptOutcome] = []
    for attempt in range(max(attempts, 1)):
        if attempt:
            await asyncio.sleep(retry_delay_seconds)
        outcomes.append(await _attempt_once(endpoint, timeout, dns_fallback_client))
    return _aggregate(endpoint, outcomes)


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
    retry_delay_seconds = settings.retry_delay_ms / 1000

    async def guarded(item: Endpoint) -> tuple[Endpoint, EndpointProbe]:
        async with semaphore:
            return item, await probe_endpoint(
                item,
                timeout,
                dns_fallback_client,
                attempts=settings.attempts,
                retry_delay_seconds=retry_delay_seconds,
            )

    try:
        for start in range(0, len(endpoints), settings.batch_size):
            batch = endpoints[start : start + settings.batch_size]
            for endpoint, probe in await asyncio.gather(*(guarded(item) for item in batch)):
                outcomes[endpoint] = probe
    finally:
        if owned_client:
            await dns_fallback_client.aclose()
    return outcomes
