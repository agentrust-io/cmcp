"""
cMCP performance experiment for the cMCP paper (evaluation section).

Produces two honest, deterministic result sets from the shipped cmcp_runtime:

  1. Latency breakdown (Cedar eval / audit append / end-to-end) at a fixed
     12-rule bundle, reusing the shipped cmcp_runtime.benchmarks helpers.
     Reports p50/p95/p99, mean, and derived single-thread throughput.

  2. Cedar-eval latency vs. Cedar rule count: a scaling sweep that builds
     policy bundles with N permit rules (plus 2 forbid rules) for a range of
     N, and measures per-call Cedar evaluation latency through the real
     PolicyEvaluator -> AGT CedarBackend (cedarpy native mode).

All numbers come from wall-clock time.perf_counter() on this host in
software-only TEE mode. No hardware TEE is used. Nothing is fabricated.

Run (from this paper directory), with agentrust-io/cmcp at commit 6f12cce
installed in the active environment (pip install -e <cmcp checkout>). The
published numbers used 8,000 measured and 1,000 warmup calls:
  PYTHONUTF8=1 python experiments/perf/run.py --calls 8000 --warmup 1000

Results are written to experiments/results/perf-<date>.json.
"""

from __future__ import annotations

import argparse
import json
import statistics
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Import shipped cmcp_runtime. If not importable, install the cMCP checkout
# or set PYTHONPATH to its src directory.
from cmcp_runtime import benchmarks as bench
from cmcp_runtime.config import AttestationConfig, Config, EnforcementMode, TEEProvider
from cmcp_runtime.policy.bundle import load_policy_bundle
from cmcp_runtime.policy.evaluator import PolicyEvaluator

# Context passed to every Cedar evaluation. Matches the shipped benchmark's
# context so the sweep is directly comparable to the latency breakdown.
_CTX: dict[str, Any] = {
    "tool_name": "benchmark.tool",
    "arguments": bench._TOOL_ARGUMENTS,
    "server_identity": "https://benchmark.example.com/mcp",
    "compliance_domain": "external",
    "baa_covered": True,
    "destination_class": "external",
    "session_max_sensitivity": "public",
}


def _percentiles(samples: list[float]) -> dict[str, float]:
    s = sorted(samples)
    return {
        "p50": round(bench._percentile(s, 50), 2),
        "p95": round(bench._percentile(s, 95), 2),
        "p99": round(bench._percentile(s, 99), 2),
        "mean": round(statistics.fmean(s), 2),
        "min": round(s[0], 2),
    }


def _make_rule_bundle(bundle_dir: Path, n_permit: int) -> Any:
    """Build a Cedar bundle with n_permit permit rules + 2 forbid rules.

    Same rule shape as cmcp_runtime.benchmarks so counts are comparable.
    """
    permits = "\n".join(
        "permit (principal, action, resource) when { true };"
        for _ in range(n_permit)
    )
    forbids = (
        "forbid (principal, action, resource) when { false };\n"
        "forbid (principal, action, resource) when { false };"
    )
    policies = permits + "\n" + forbids + "\n"
    (bundle_dir / "manifest.json").write_text(json.dumps(bench._MANIFEST))
    (bundle_dir / "benchmark.cedar").write_text(policies)
    (bundle_dir / "schema.cedarschema").write_text(bench._CEDAR_SCHEMA)
    return load_policy_bundle(str(bundle_dir))


def _bench_cedar_for_bundle(bundle: Any, calls: int, warmup: int) -> list[float]:
    config = Config(
        attestation=AttestationConfig(
            provider=TEEProvider.SOFTWARE_ONLY,
            enforcement_mode=EnforcementMode.ENFORCING,
        )
    )
    evaluator = PolicyEvaluator(bundle=bundle, config=config)
    with bench._quiet():
        for _ in range(warmup):
            evaluator.evaluate(_CTX)
        samples: list[float] = []
        for _ in range(calls):
            t0 = time.perf_counter()
            evaluator.evaluate(_CTX)
            samples.append((time.perf_counter() - t0) * 1_000_000)
    return samples


def run_rule_sweep(rule_counts: list[int], calls: int, warmup: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for n in rule_counts:
        with tempfile.TemporaryDirectory() as tmp:
            bdir = Path(tmp) / "policy"
            bdir.mkdir()
            bundle = _make_rule_bundle(bdir, n_permit=n)
            samples = _bench_cedar_for_bundle(bundle, calls, warmup)
        total_rules = n + 2  # permits + 2 forbids, matching benchmarks.py counting
        pct = _percentiles(samples)
        thr = round(1_000_000 / pct["mean"], 1) if pct["mean"] else 0.0
        row = {"rules": total_rules, "permit_rules": n, "cedar_eval_us": pct, "throughput_eval_per_s": thr}
        rows.append(row)
        print(
            f"  rules={total_rules:>4}  p50={pct['p50']:>8.1f}us  "
            f"p99={pct['p99']:>8.1f}us  mean={pct['mean']:>8.1f}us  "
            f"thr={thr:>8.1f}/s",
            flush=True,
        )
    return rows


def run_latency_breakdown(calls: int, warmup: int) -> dict[str, Any]:
    """Latency breakdown at the shipped 12-rule bundle, with mean+throughput."""
    with tempfile.TemporaryDirectory() as tmp:
        bdir = Path(tmp) / "policy"
        bdir.mkdir()
        bundle = bench._make_bundle(bdir)
    catalog = bench._make_catalog()
    proxy, evaluator = bench._make_proxy(bundle, catalog)

    from cmcp_runtime.audit.chain import AuditChain

    fresh_chain = AuditChain(session_id=str(uuid.uuid4()))

    with bench._quiet():
        bench._bench_cedar(evaluator, warmup)
        bench._bench_audit_entry(fresh_chain, warmup)

    cedar = bench._bench_cedar(evaluator, calls)
    audit = bench._bench_audit_entry(fresh_chain, calls)

    out = {
        "policy_rules_count": 12,
        "calls_measured": calls,
        "cedar_eval_us": _percentiles(cedar),
        "audit_entry_us": _percentiles(audit),
    }
    out["cedar_throughput_eval_per_s"] = (
        round(1_000_000 / out["cedar_eval_us"]["mean"], 1)
        if out["cedar_eval_us"]["mean"]
        else 0.0
    )
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="cMCP paper performance experiment")
    ap.add_argument("--calls", type=int, default=20000, help="measured calls per config")
    ap.add_argument("--warmup", type=int, default=2000, help="warmup calls per config")
    ap.add_argument(
        "--rule-counts",
        type=int,
        nargs="+",
        default=[2, 5, 12, 25, 50, 100, 200, 400],
        help="permit-rule counts for the scaling sweep (2 forbid rules added to each)",
    )
    ap.add_argument("--out", type=Path, default=None, help="output JSON path")
    args = ap.parse_args()

    import cmcp_runtime

    print("cMCP paper performance experiment", flush=True)
    print(f"  cmcp_runtime: {cmcp_runtime.__file__}", flush=True)
    print(f"  calls={args.calls} warmup={args.warmup}", flush=True)

    print("\n[Latency breakdown @ 12-rule bundle]", flush=True)
    breakdown = run_latency_breakdown(args.calls, args.warmup)
    print(json.dumps(breakdown, indent=2), flush=True)

    print("\n[Cedar eval latency vs. rule count]", flush=True)
    sweep = run_rule_sweep(args.rule_counts, args.calls, args.warmup)

    result = {
        "experiment": "cmcp-perf",
        "provider": "software-only",
        "hardware_tee": False,
        "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "python": __import__("platform").python_version(),
        "platform": __import__("platform").platform(),
        "cedar_backend": "cedarpy (native, mode=auto)",
        "calls_measured": args.calls,
        "warmup": args.warmup,
        "latency_breakdown": breakdown,
        "rule_count_sweep": sweep,
    }

    out_path = args.out
    if out_path is None:
        today = datetime.now(UTC).strftime("%Y-%m-%d")
        out_dir = Path(__file__).resolve().parent.parent / "results"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"perf-{today}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2))
    print(f"\nResults written to {out_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
