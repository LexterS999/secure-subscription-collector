import asyncio

from subscription_collector.cli import (
    _filter_tcp_reachable_profiles,
    _validate_profiles,
    build_parser,
)
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
    """Catches scheduler changes that either serialise batches or start unbounded Xray processes."""

    async def exercise() -> tuple[list[list[str]], int]:
        two_batches_started = asyncio.Event()
        release_batches = asyncio.Event()
        started_batches: list[list[str]] = []
        active_batches = 0
        max_active_batches = 0

        async def batch_runner(profiles):
            nonlocal active_batches, max_active_batches
            active_batches += 1
            max_active_batches = max(max_active_batches, active_batches)
            started_batches.append([profile.server for profile in profiles])
            if len(started_batches) == 2:
                two_batches_started.set()
            await release_batches.wait()
            active_batches -= 1
            return [ProbeResult(True, 1, 1) for _ in profiles]

        task = asyncio.create_task(
            _validate_profiles(
                [_profile(index) for index in range(1, 6)],
                batch_runner=batch_runner,
                batch_concurrency=2,
                batch_size=2,
                stats=RunStats(),
            )
        )
        await asyncio.wait_for(two_batches_started.wait(), timeout=1)
        assert len(started_batches) == 2
        release_batches.set()
        accepted = await task
        return started_batches, len(accepted)

    started_batches, accepted_count = asyncio.run(exercise())

    assert started_batches == [
        ["node1.example.org", "node2.example.org"],
        ["node3.example.org", "node4.example.org"],
        ["node5.example.org"],
    ]
    assert accepted_count == 5


def test_command_defaults_enable_fail_fast_high_throughput_validation() -> None:
    """Catches defaults that allow slow profile probes to throttle the collection run."""

    args = build_parser().parse_args(["--xray-path", "/tmp/xray"])

    assert args.probe_timeout_seconds == 0.75
    assert args.probe_startup_timeout_seconds == 1.0
    assert args.source_concurrency == 32
    assert args.analysis_workers == 120
    assert args.analysis_batch_size == 1024
    assert args.probe_concurrency == 32
    assert args.probe_batch_size == 256
    assert args.probe_batch_concurrency == 2
    assert args.tcp_precheck_timeout_seconds == 0.35
    assert args.tcp_precheck_concurrency == 256


def test_tcp_precheck_filter_keeps_reachable_profiles_and_counts_early_rejections() -> None:
    """Catches unreachable TCP profiles reaching Xray batches despite prechecking."""

    async def exercise():
        stats = RunStats()

        async def runner(profile):
            return "tcp_unreachable" if profile.server == "node1.example.org" else None

        kept = await _filter_tcp_reachable_profiles(
            [_profile(1), _profile(2)],
            runner=runner,
            concurrency=2,
            stats=stats,
        )
        return kept, stats

    kept, stats = asyncio.run(exercise())

    assert [profile.server for profile in kept] == ["node2.example.org"]
    assert stats.excluded == {"tcp_unreachable": 1}
