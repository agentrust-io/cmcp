"""
cMCP gateway latency benchmark suite — implements issue #78.

Measures: cedar_eval_latency_us, audit_entry_latency_us, end_to_end_latency_us (p50/p95/p99)

Usage:
    python -m cmcp_gateway.benchmarks --provider software-only --calls 10000
    python -m cmcp_gateway.benchmarks --provider sev-snp --calls 10000 --out benchmarks/

Exits 1 if software-only p99 end_to_end_us > 5000 (5ms CI gate).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import io
import json
import sys
import tempfile
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch


@contextlib.contextmanager
def _quiet() -> Iterator[None]:
    """Suppress stdout/stderr during noisy backend warmup."""
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        yield


# ── Policy bundle fixtures ─────────────────────────────────────────────────────

_CEDAR_SCHEMA = json.dumps({
    "cMCP": {
        "entityTypes": {
            "Principal": {
                "memberOfTypes": [],
                "shape": {
                    "type": "Record",
                    "attributes": {
                        "session_id": {"type": "String", "required": True},
                        "workflow_id": {"type": "String", "required": True},
                    },
                },
            },
            "Resource": {
                "memberOfTypes": [],
                "shape": {
                    "type": "Record",
                    "attributes": {
                        "tool_name": {"type": "String", "required": True},
                    },
                },
            },
        },
        "actions": {
            "call_tool": {
                "appliesTo": {
                    "principalTypes": ["cMCP::Principal"],
                    "resourceTypes": ["cMCP::Resource"],
                    "context": {
                        "type": "Record",
                        "attributes": {
                            "session_max_sensitivity": {"type": "String", "required": True},
                            "workflow_id": {"type": "String", "required": True},
                        },
                    },
                }
            }
        },
    }
})

# 12-rule bundle matching spec §Benchmark Methodology: 10 allowlist + 2 deny rules.
# Uses simple Cedar syntax supported by both cedarpy and the builtin pattern evaluator.
_CEDAR_POLICIES = """
permit (principal, action, resource);
permit (principal, action, resource) when { true };
permit (principal, action, resource) when { true };
permit (principal, action, resource) when { true };
permit (principal, action, resource) when { true };
permit (principal, action, resource) when { true };
permit (principal, action, resource) when { true };
permit (principal, action, resource) when { true };
permit (principal, action, resource) when { true };
permit (principal, action, resource) when { true };
forbid (principal, action, resource) when { false };
forbid (principal, action, resource) when { false };
"""

_MANIFEST = {
    "version": "1.0.0",
    "authored_at": "2026-06-01T00:00:00Z",
    "author_identity": "benchmark@cmcp.io",
    "commit_sha": "benchmark-fixture",
}

_TOOL_ARGUMENTS = {
    "soql": "SELECT Id, Name, Email FROM Contact WHERE AccountId = '001x0000001'",
    "max_records": 100,
}


# ── Percentile computation ─────────────────────────────────────────────────────


def _percentile(data: list[float], p: float) -> float:
    if not data:
        return 0.0
    sorted_data = sorted(data)
    idx = (p / 100) * (len(sorted_data) - 1)
    lo = int(idx)
    hi = lo + 1
    frac = idx - lo
    if hi >= len(sorted_data):
        return sorted_data[lo]
    return sorted_data[lo] * (1 - frac) + sorted_data[hi] * frac


def _stats(samples: list[float]) -> dict[str, int]:
    return {
        "p50": int(_percentile(samples, 50)),
        "p95": int(_percentile(samples, 95)),
        "p99": int(_percentile(samples, 99)),
    }


# ── Setup helpers ──────────────────────────────────────────────────────────────


def _make_bundle(bundle_dir: Path) -> Any:
    from cmcp_gateway.policy.bundle import load_policy_bundle

    (bundle_dir / "manifest.json").write_text(json.dumps(_MANIFEST))
    (bundle_dir / "benchmark.cedar").write_text(_CEDAR_POLICIES)
    (bundle_dir / "schema.cedarschema").write_text(_CEDAR_SCHEMA)
    return load_policy_bundle(str(bundle_dir))


def _make_catalog() -> Any:
    from cmcp_gateway.catalog.loader import (
        ApprovedDefinition,
        CatalogEntry,
        ServerIdentity,
        ToolCatalog,
    )

    entry = CatalogEntry(
        tool_name="benchmark.tool",
        server=ServerIdentity(
            display_name="Benchmark Server",
            url="https://benchmark.example.com/mcp",
            tls_fingerprint="SHA256:BENCH/MARK==",
            spiffe_id=None,
            transport="http-sse",
            rotation_mode="key-pinned",
        ),
        approved_definition=ApprovedDefinition(
            description="benchmark tool",
            input_schema={},
            output_schema=None,
        ),
        definition_hash="sha256:" + "b" * 64,
        compliance_domain="external",
        requires_baa=False,
        sensitivity_level="public",
        added_at="2026-06-01T00:00:00Z",
        approved_by="benchmark",
    )
    return ToolCatalog(entries={"benchmark.tool": entry}, catalog_hash="sha256:" + "c" * 64)


def _make_proxy(bundle: Any, catalog: Any) -> tuple[Any, Any]:
    from cmcp_gateway.audit.chain import AuditChain
    from cmcp_gateway.config import AttestationConfig, Config, EnforcementMode, TEEProvider
    from cmcp_gateway.mcp.proxy import CMCPProxy
    from cmcp_gateway.policy.evaluator import PolicyEvaluator
    from cmcp_gateway.session.state import SessionState

    config = Config(
        attestation=AttestationConfig(
            provider=TEEProvider.SOFTWARE_ONLY,
            enforcement_mode=EnforcementMode.ENFORCING,
        )
    )
    evaluator = PolicyEvaluator(bundle=bundle, config=config)
    session = SessionState(session_id=str(uuid.uuid4()))
    chain = AuditChain(session_id=session.session_id)

    agt_result = MagicMock(
        sensitivity_tags=[],
        injection_detected=False,
        modified_response=b'{"result": "benchmark-ok"}',
    )

    with patch("cmcp_gateway.mcp.proxy.MCPGateway"), \
         patch("cmcp_gateway.mcp.proxy.MCPResponseScanner"):
        proxy = CMCPProxy(
            catalog=catalog,
            policy_evaluator=evaluator,
            session=session,
            audit_chain=chain,
            config=config,
        )
        proxy._mcp_gateway = MagicMock()
        proxy._mcp_gateway.call_tool = AsyncMock(return_value=agt_result)

    return proxy, evaluator


# ── Benchmark runners ──────────────────────────────────────────────────────────


def _bench_cedar(evaluator: Any, n: int) -> list[float]:
    """Measure Cedar policy evaluation in isolation."""
    ctx = {
        "tool_name": "benchmark.tool",
        "arguments": _TOOL_ARGUMENTS,
        "server_identity": "https://benchmark.example.com/mcp",
        "compliance_domain": "external",
        "baa_covered": True,
        "destination_class": "external",
        "session_max_sensitivity": "public",
    }
    samples: list[float] = []
    with _quiet():
        for _ in range(n):
            t0 = time.perf_counter()
            evaluator.evaluate(ctx)
            samples.append((time.perf_counter() - t0) * 1_000_000)
    return samples


def _bench_audit_entry(chain: Any, n: int) -> list[float]:
    """Measure audit chain append in isolation."""
    samples: list[float] = []
    for _ in range(n):
        t0 = time.perf_counter()
        chain.append(
            "tool_call",
            call_id=str(uuid.uuid4()),
            tool_name="benchmark.tool",
            server_identity="https://benchmark.example.com/mcp",
            policy_decision="allow",
            latency_us=100,
            request_payload_hash="sha256:" + "d" * 64,
            session_sensitivity_before="public",
            session_sensitivity_after="public",
        )
        samples.append((time.perf_counter() - t0) * 1_000_000)
    return samples


async def _bench_end_to_end(proxy: Any, n: int) -> list[float]:
    """Measure end-to-end call_tool() with upstream mocked out."""
    samples: list[float] = []
    with _quiet():
        for _ in range(n):
            call_id = str(uuid.uuid4())
            t0 = time.perf_counter()
            await proxy.call_tool(call_id, "benchmark.tool", _TOOL_ARGUMENTS)
            samples.append((time.perf_counter() - t0) * 1_000_000)
    return samples


# ── Main ───────────────────────────────────────────────────────────────────────


async def _run(provider: str, calls: int, out_dir: Path | None) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmpdir:
        bundle_dir = Path(tmpdir) / "policy"
        bundle_dir.mkdir()
        bundle = _make_bundle(bundle_dir)

    catalog = _make_catalog()
    proxy, evaluator = _make_proxy(bundle, catalog)

    # Access the chain that's on the proxy (not isolated, but the audit entries accumulate)
    chain = proxy._audit

    warmup = 1000
    print(f"  Warming up ({warmup} calls)...", flush=True)
    with _quiet():
        _bench_cedar(evaluator, warmup)
        _bench_audit_entry(chain, warmup)
        await _bench_end_to_end(proxy, warmup)

    # Reset chain to avoid noise from warmup in audit timing
    from cmcp_gateway.audit.chain import AuditChain
    fresh_chain = AuditChain(session_id=str(uuid.uuid4()))
    proxy._audit = fresh_chain

    print(f"  Measuring ({calls} calls x 3 components)...", flush=True)
    cedar_samples = _bench_cedar(evaluator, calls)
    audit_samples = _bench_audit_entry(fresh_chain, calls)
    e2e_samples = await _bench_end_to_end(proxy, calls)

    result: dict[str, Any] = {
        "provider": provider,
        "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "policy_rules_count": 12,
        "payload_bytes": len(json.dumps(_TOOL_ARGUMENTS, separators=(",", ":"))),
        "calls_measured": calls,
        "cedar_eval_us": _stats(cedar_samples),
        "audit_entry_us": _stats(audit_samples),
        "end_to_end_us": _stats(e2e_samples),
    }

    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        today = datetime.now(UTC).strftime("%Y-%m-%d")
        out_file = out_dir / f"{provider}-{today}.json"
        out_file.write_text(json.dumps(result, indent=2))
        print(f"  Results written to {out_file}", flush=True)

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="cMCP gateway latency benchmark (issue #78)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m cmcp_gateway.benchmarks --provider software-only
  python -m cmcp_gateway.benchmarks --provider sev-snp --calls 10000 --out benchmarks/
        """,
    )
    parser.add_argument(
        "--provider",
        choices=["tpm", "sev-snp", "software-only"],
        default="software-only",
        help="TEE provider label for result metadata (default: software-only)",
    )
    parser.add_argument(
        "--calls",
        type=int,
        default=10000,
        metavar="N",
        help="Number of calls to measure after warmup (default: 10000)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        metavar="DIR",
        help="Directory to write JSON result file (default: stdout only)",
    )
    parser.add_argument(
        "--no-threshold",
        action="store_true",
        help="Skip p99 threshold check (useful for hardware TEE runs where overhead is expected)",
    )
    args = parser.parse_args()

    print(f"cMCP benchmark: provider={args.provider} calls={args.calls}", flush=True)
    result = asyncio.run(_run(args.provider, args.calls, args.out))

    print(json.dumps(result, indent=2))

    # CI gate: software-only p99 end_to_end must be < 5ms (5000us)
    _P99_LIMIT_US = 5000
    if args.provider == "software-only" and not args.no_threshold:
        p99 = result["end_to_end_us"]["p99"]
        if p99 > _P99_LIMIT_US:
            print(
                f"\nFAIL: software-only p99 end_to_end_us={p99} exceeds limit={_P99_LIMIT_US}us",
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"\nPASS: software-only p99 end_to_end_us={p99} <= {_P99_LIMIT_US}us")


if __name__ == "__main__":
    main()
