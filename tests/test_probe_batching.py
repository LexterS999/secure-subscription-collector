import asyncio

from subscription_collector.cli import _validate_profiles, build_parser
from subscription_collector.models import ProbeResult, RunStats
from subscription_collector.parser import parse_profile


def _profile(index: int):
    profile = parse_profile(
        "trojan://correct-horse@node"
        f"{index}.example.org:443?security=tls&sni=www.example.com&fp=chrome&type=tcp#node-{index}",
        "https://source.example/list",
    )
    assert profile is not None
    return profile


def test_validation_limits_concurrent_xray_batches_and_keeps_all_results() -> None:
    """Catches a scheduler that serialises batches or starts unlimited Xray processes."""

    async def exercise() -> tuple[list[list[str]], int]:
        four_batches_started = asyncio.Event()
        release_batches = asyncio.Event()
        started_batches: list[list[str]] = []

        async def batch_runner(profiles):
            started_batches.append([profile.server for profile in profiles])
            if len(started_batches) == 4:
                four_batches_started.set()
            await release_batches.wait()
            return [ProbeResult(True, 1, 1) for _ in profiles]

        task = asyncio.create_task(
            _validate_profiles(
                [_profile(index) for index in range(1, 11)],
                batch_runner=batch_runner,
                batch_concurrency=4,
                batch_size=2,
                stats=RunStats(),
            )
        )
        await asyncio.wait_for(four_batches_started.wait(), timeout=1)
        assert len(started_batches) == 4
        release_batches.set()
        accepted = await task
        return started_batches, len(accepted)

    started_batches, accepted_count = asyncio.run(exercise())

    assert started_batches == [
        ["node1.example.org", "node2.example.org"],
        ["node3.example.org", "node4.example.org"],
        ["node5.example.org", "node6.example.org"],
        ["node7.example.org", "node8.example.org"],
        ["node9.example.org", "node10.example.org"],
    ]
    assert accepted_count == 10


def test_command_options_defer_throughput_settings_to_config_yaml() -> None:
    """Catches reintroduction of built-in throughput defaults or a separate TCP precheck."""

    args = build_parser().parse_args(["--xray-path", "/tmp/xray"])

    assert args.probe_timeout_seconds is None
    assert args.probe_startup_timeout_seconds is None
    assert args.source_concurrency is None
    assert args.analysis_workers is None
    assert args.analysis_batch_size is None
    assert args.probe_concurrency is None
    assert args.probe_batch_size is None
    assert args.probe_batch_concurrency is None
