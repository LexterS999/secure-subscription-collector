import asyncio

from subscription_collector.config_loader import IpValidationConfig


def _settings() -> IpValidationConfig:
    return IpValidationConfig(
        ip_echo_urls=(
            "https://first-ip.example/",
            "https://second-ip.example/",
        ),
        http_check_urls=("https://status.example/generate_204",),
        accepted_http_statuses=(200, 204, 301, 302, 307),
        timeout_seconds=1.0,
        config_test_timeout_seconds=2.0,
        startup_timeout_seconds=1.0,
        request_concurrency=1,
        batch_size=1,
        batch_concurrency=1,
        listener_poll_interval_seconds=0.01,
        process_shutdown_timeout_seconds=0.1,
        connection_max_connections=1,
        connection_max_keepalive_connections=0,
    )


def test_probe_uses_second_ip_echo_service_after_first_failure(monkeypatch) -> None:
    from subscription_collector import probe

    calls: list[str] = []

    async def request_ip(_client, url: str, _timeout: float):
        calls.append(url)
        if url.endswith("first-ip.example/"):
            return None, "timeout"
        return 42, None

    async def request_http(_client, _url: str, _timeout: float, _accepted_statuses):
        raise AssertionError("HTTP fallback must not run after successful IP confirmation")

    monkeypatch.setattr(probe, "_request_public_ip", request_ip)
    monkeypatch.setattr(probe, "_request_http_status", request_http)

    result = asyncio.run(probe._probe_client(object(), _settings()))

    assert result.passed is True
    assert result.successes == 1
    assert result.median_latency_ms == 42
    assert result.error_category is None
    assert calls == ["https://first-ip.example/", "https://second-ip.example/"]


def test_probe_accepts_http_confirmation_when_all_ip_echo_services_fail(monkeypatch) -> None:
    from subscription_collector import probe

    async def request_ip(_client, _url: str, _timeout: float):
        return None, "timeout"

    async def request_http(_client, url: str, _timeout: float, accepted_statuses):
        assert url == "https://status.example/generate_204"
        assert accepted_statuses == (200, 204, 301, 302, 307)
        return 55, None

    monkeypatch.setattr(probe, "_request_public_ip", request_ip)
    monkeypatch.setattr(probe, "_request_http_status", request_http)

    result = asyncio.run(probe._probe_client(object(), _settings()))

    assert result.passed is True
    assert result.successes == 1
    assert result.median_latency_ms == 55
    assert result.error_category is None
