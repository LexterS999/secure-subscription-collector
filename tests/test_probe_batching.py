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


def test_validation_processes_one_async_batch_before_starting_the_next() -> None:
    """Catches unbounded task scheduling that starts a later batch before the current one ends."""

    async def exercise() -> tuple[list[str], list[str], int]:
        first_batch_started = asyncio.Event()
        release_first_batch = asyncio.Event()
        later_batch_started = asyncio.Event()
        started: list[str] = []
        completed: list[str] = []

        async def runner(profile):
            started.append(profile.server)
            if profile.server in {"node1.example.org", "node2.example.org"}:
                if {"node1.example.org", "node2.example.org"}.issubset(started):
                    first_batch_started.set()
                await release_first_batch.wait()
            else:
                later_batch_started.set()
            completed.append(profile.server)
            return ProbeResult(True, 2, 1)

        task = asyncio.create_task(
            _validate_profiles(
                [_profile(index) for index in range(1, 5)],
                runner=runner,
                concurrency=2,
                batch_size=2,
                stats=RunStats(),
            )
        )
        await asyncio.wait_for(first_batch_started.wait(), timeout=1)
        assert later_batch_started.is_set() is False
        release_first_batch.set()
        accepted = await task
        return started, completed, len(accepted)

    started, completed, accepted_count = asyncio.run(exercise())

    assert started[:2] == ["node1.example.org", "node2.example.org"]
    assert set(completed) == {
        "node1.example.org",
        "node2.example.org",
        "node3.example.org",
        "node4.example.org",
    }
    assert accepted_count == 4


def test_command_defaults_limit_response_time_and_enable_high_parallelism() -> None:
    """Catches CLI defaults that keep source loading or profile validation unnecessarily serial."""

    args = build_parser().parse_args(["--xray-path", "/tmp/xray"])

    assert args.probe_timeout_seconds == 3.0
    assert args.probe_startup_timeout_seconds == 5.0
    assert args.source_concurrency == 32
    assert args.analysis_workers == 32
    assert args.analysis_batch_size == 1024
    assert args.probe_concurrency == 8
    assert args.probe_batch_size == 32
