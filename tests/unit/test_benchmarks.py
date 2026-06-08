"""Tests for the benchmark suite (issue #78)."""

from __future__ import annotations

import json

import pytest


def test_benchmark_runs_smoke(tmp_path):
    """Smoke test: benchmark produces valid JSON output with all required keys."""
    import asyncio

    from cmcp_gateway.benchmarks import _run

    result = asyncio.run(_run(provider="software-only", calls=50, out_dir=None))

    assert result["provider"] == "software-only"
    assert result["calls_measured"] == 50
    assert result["policy_rules_count"] == 12

    for key in ("cedar_eval_us", "audit_entry_us", "end_to_end_us"):
        assert key in result
        stats = result[key]
        assert "p50" in stats
        assert "p95" in stats
        assert "p99" in stats
        assert stats["p50"] > 0
        assert stats["p99"] >= stats["p95"] >= stats["p50"]


def test_benchmark_writes_output_file(tmp_path):
    """Benchmark writes a timestamped JSON file to the output directory."""
    import asyncio

    from cmcp_gateway.benchmarks import _run

    asyncio.run(_run(provider="software-only", calls=20, out_dir=tmp_path))

    files = list(tmp_path.glob("software-only-*.json"))
    assert len(files) == 1
    data = json.loads(files[0].read_text())
    assert data["provider"] == "software-only"
    assert data["calls_measured"] == 20


def test_benchmark_percentile():
    from cmcp_gateway.benchmarks import _percentile

    data = list(range(1, 101))  # 1..100
    assert _percentile(data, 50) == pytest.approx(50.5, abs=1)
    assert _percentile(data, 95) == pytest.approx(95.5, abs=1)
    assert _percentile(data, 99) == pytest.approx(99.01, abs=1)


def test_benchmark_stats():
    from cmcp_gateway.benchmarks import _stats

    data = [float(i) for i in range(1, 101)]
    s = _stats(data)
    assert s["p50"] > 0
    assert s["p99"] >= s["p95"] >= s["p50"]


def test_benchmark_catalog_is_usable():
    """Benchmark catalog fixture has the benchmark tool and a stable hash."""
    from cmcp_gateway.benchmarks import _make_catalog

    catalog = _make_catalog()
    assert "benchmark.tool" in catalog.entries
    assert catalog.catalog_hash.startswith("sha256:")
