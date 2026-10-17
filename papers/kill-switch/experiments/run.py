"""Observed shutdown exercise. All network listeners bind to loopback; no cloud use.

Run with a cmcp development environment and --source pointing to its clean pinned
checkout. This drives real startup, signed identity, Cedar, HTTP transport, durable
storage, session closing, and receipt verification. The tool and all keys are local.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import importlib.metadata
import json
import os
import platform
import socket
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

PIN = "9db65b589610eb4e8455003197de592636678203"
IDENTITY = "spiffe://evaluation.example/agent/worker"
BEARER = "local-evaluation-agent"
OPERATOR = "local-evaluation-operator"
DEFINITION = {
    "description": "Record a public evaluation marker",
    "input_schema": {"type": "object"},
}


def write(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


@contextmanager
def temporary_workspace():
    # Cleanup failures remain failures; retry transient Windows file-handle release.
    workspace = tempfile.TemporaryDirectory(prefix="kill-switch-")
    try:
        yield workspace.name
    finally:
        for attempt in range(20):
            try:
                workspace.cleanup()
                break
            except PermissionError:
                if attempt == 19:
                    raise
                time.sleep(0.5)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Tool(BaseHTTPRequestHandler):
    effects: ClassVar[list[str]] = []
    lock = threading.Lock()
    entered = threading.Event()
    release = threading.Event()

    def log_message(self, *args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if body["method"] == "tools/list":
            result = {
                "tools": [
                    {
                        "name": "observe.tool",
                        "description": DEFINITION["description"],
                        "inputSchema": DEFINITION["input_schema"],
                    }
                ]
            }
        else:
            args = body["params"]["arguments"]
            if args.get("hold"):
                self.entered.set()
                if not self.release.wait(15):
                    raise TimeoutError("evaluator did not release held tool")
            with self.lock:
                self.effects.append(args["marker"])
            result = {"content": [{"type": "text", "text": args["marker"]}]}
        payload = json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def prepare(root, tool_port, gateway_port):
    import yaml
    from cmcp_runtime.agent_manifest import SIGNED_FIELDS, signing_pre_image
    from cmcp_runtime.catalog.loader import load_catalog
    from cmcp_runtime.policy.bundle import load_policy_bundle
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    policy = root / "policy"
    policy.mkdir()
    write(
        policy / "manifest.json",
        {
            "version": "1.0.0",
            "authored_at": "2026-09-19T00:00:00Z",
            "author_identity": "evaluation@example.com",
            "commit_sha": PIN,
        },
    )
    (policy / "allow.cedar").write_text("permit(principal, action, resource);\n")
    (policy / "schema.cedarschema").write_text('{"cMCP": {}}')
    canonical = json.dumps(DEFINITION, sort_keys=True, separators=(",", ":")).encode()
    write(
        root / "catalog.json",
        [
            {
                "tool_name": "observe.tool",
                "server": {
                    "display_name": "Observed local tool",
                    "url": f"http://127.0.0.1:{tool_port}/mcp",
                    "tls_fingerprint": "SHA256:AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
                    "transport": "http-sse",
                },
                "approved_definition": DEFINITION,
                "definition_hash": "sha256:" + hashlib.sha256(canonical).hexdigest(),
                "compliance_domain": "external",
                "requires_baa": False,
                "sensitivity_level": "public",
                "added_at": "2026-09-19T00:00:00Z",
                "approved_by": "local-evaluator",
            }
        ],
    )
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    kid = hashlib.sha256(pub).hexdigest()

    def b64(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    manifest = {
        "@context": "https://agentmanifest.agentrust-io.com/v0.1/context.json",
        "@type": "AgentManifest",
        "manifest_id": "0197739a-8c00-7000-8000-000000000001",
        "agent_id": IDENTITY,
        "version": "0.1",
        "issued_at": "2026-09-19T00:00:00Z",
        "expires_at": "2099-09-10T00:00:00Z",
        "issuer": "spiffe://evaluation.example/issuer",
        "crypto_profile": "standard",
        "artifacts": {
            "system_prompt": {"hash": "sha256:" + "a" * 64},
            "model_identity": {
                "version": "no-model-evaluation",
                "deployment_type": "api",
            },
            "policy_bundle": {
                "hash": load_policy_bundle(str(policy)).bundle_hash,
                "policy_language": "cedar",
            },
            "tool_manifest": {
                "catalog_hash": load_catalog(str(root / "catalog.json")).catalog_hash,
                "tools": [],
            },
        },
        "delegation_chain": [],
    }
    manifest["signature"] = {
        "algorithm": "Ed25519",
        "key_id": kid,
        "key_type": "software",
        "signed_at": "2026-09-19T00:00:00Z",
        "signed_fields": list(SIGNED_FIELDS),
        "signature_value": b64(key.sign(signing_pre_image(manifest))),
    }
    write(root / "identity.json", manifest)
    write(
        root / "anchor.json",
        {"algorithm": "Ed25519", "key_id": kid, "public_key_base64url": b64(pub)},
    )
    config = {
        "listen_addr": f"127.0.0.1:{gateway_port}",
        "policy_bundle_path": str(policy),
        "catalog_path": str(root / "catalog.json"),
        "audit_db_path": str(root / "audit.db"),
        "attestation": {"provider": "software-only", "enforcement_mode": "enforcing"},
        "agent_manifest": {
            "path": str(root / "identity.json"),
            "trust_anchor_path": str(root / "anchor.json"),
            "authenticated_subject": IDENTITY,
        },
        "kill_switch": {
            "enabled": True,
            "window_seconds": 300,
            "deny_rate_threshold": 0.9,
            "min_calls": 5,
        },
    }
    (root / "config.yaml").write_text(yaml.safe_dump(config), encoding="utf-8")
    return config


@contextmanager
def gateway(root, source, port, mutation, label, result_dir):
    if mutation == "forget-block" and label != "restarted":
        mutation = "none"
    import httpx

    env = {k: v for k, v in os.environ.items() if not k.startswith("CMCP_")}
    env.update(
        CMCP_DEV_MODE="1",
        CMCP_BEARER_TOKEN=BEARER,
        CMCP_OPERATOR_TOKEN=OPERATOR,
        CMCP_SESSION_CLOSE_DRAIN_SECONDS="10",
        PYTHONPATH=str(source / "src"),
    )
    with (result_dir / f"{label}-gateway.log").open("wb") as log:
        proc = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).with_name("gateway.py")),
                str(root / "config.yaml"),
                "--mutation",
                mutation,
            ],
            cwd=root,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            for _ in range(120):
                if proc.poll() is not None:
                    raise RuntimeError(f"gateway exited {proc.returncode}; see {label}-gateway.log")
                try:
                    response = httpx.get(f"http://127.0.0.1:{port}/readyz", timeout=0.3)
                    if response.status_code in (200, 503):
                        break
                except httpx.TransportError:
                    pass
                time.sleep(0.1)
            else:
                raise TimeoutError("gateway did not listen")
            yield proc
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)


def exercise(source, result_dir, mutation):
    import httpx
    import jsonschema
    from cmcp_verify import verify_kill_switch_refusal

    observations = []

    def check(name, condition, **detail):
        observations.append({"id": name, "passed": bool(condition), **detail})
        write(result_dir / "observations.json", observations)
        if not condition:
            raise AssertionError(name)

    def call(client, marker, name="observe.tool", **args):
        return client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": marker,
                "method": "tools/call",
                "params": {"name": name, "arguments": {"marker": marker, **args}},
            },
        )

    Tool.effects = []
    Tool.entered.clear()
    Tool.release.clear()
    tool = ThreadingHTTPServer(("127.0.0.1", 0), Tool)
    thread = threading.Thread(target=tool.serve_forever, daemon=True)
    thread.start()
    port = free_port()
    operator = {"Authorization": f"Bearer {OPERATOR}"}
    try:
        with temporary_workspace() as temp:
            root = Path(temp)
            prepare(root, tool.server_port, port)
            with httpx.Client(
                base_url=f"http://127.0.0.1:{port}",
                headers={"Authorization": f"Bearer {BEARER}"},
                timeout=20,
            ) as client:
                with gateway(root, source, port, mutation, "first", result_dir):
                    before = call(client, "before-trip")
                    check(
                        "allowed-tool-effect",
                        before.status_code == 200 and Tool.effects == ["before-trip"],
                        status=before.status_code,
                        body=before.json(),
                    )
                    bad = client.post(
                        "/kill-switch/trip",
                        json={"reason": "evaluation", "authorized_by": "evaluator"},
                    )
                    check(
                        "agent-cannot-trip",
                        bad.status_code == 401,
                        status=bad.status_code,
                    )
                    # Hold a real tool call while an operator begins closing the gateway.
                    with __import__(
                        "concurrent.futures", fromlist=["ThreadPoolExecutor"]
                    ).ThreadPoolExecutor() as pool:
                        pending = pool.submit(call, client, "in-flight-effect", hold=True)
                        check("tool-admitted-before-trip", Tool.entered.wait(5))
                        trip = pool.submit(
                            client.post,
                            "/kill-switch/trip",
                            headers=operator,
                            json={"reason": "evaluation", "authorized_by": "evaluator"},
                        )
                        # The API exposes no drain-start notification. Allow the local
                        # operator request to enter; record scheduling as a harness limit.
                        time.sleep(0.3)
                        ready = client.get("/readyz")
                        observations.append(
                            {
                                "id": "readiness-during-drain",
                                "status": ready.status_code,
                            }
                        )
                        later = pool.submit(call, client, "during-drain")
                        time.sleep(0.3)
                        check(
                            "new-call-has-no-effect-during-drain",
                            "during-drain" not in Tool.effects,
                        )
                        Tool.release.set()
                        inflight = pending.result(timeout=10)
                        closed = trip.result(timeout=10)
                        refused = later.result(timeout=10)
                        check(
                            "queued-call-refused-after-drain",
                            refused.status_code == 403 and "during-drain" not in Tool.effects,
                            status=refused.status_code,
                        )
                    check(
                        "in-flight-effect-can-complete",
                        inflight.status_code == 200 and "in-flight-effect" in Tool.effects,
                    )
                    check(
                        "operator-trip-closes",
                        closed.status_code == 200,
                        status=closed.status_code,
                    )
                    claim = closed.json()["claim"]
                    write(result_dir / "claim.json", claim)
                    check(
                        "signed-trigger-is-operator",
                        claim["gateway"]["kill_switch"]["trigger"] == "operator",
                    )
                    count = len(Tool.effects)
                    refused = call(client, "after-trip")
                    receipt = refused.json()["error"]["data"]["receipt"]
                    write(result_dir / "refusal.json", receipt)
                    check(
                        "post-trip-no-tool-effect",
                        refused.status_code == 403 and len(Tool.effects) == count,
                    )
                    checked = verify_kill_switch_refusal(receipt, claim)
                    check("receipt-verifies", checked.valid, errors=checked.errors)
                    altered = copy.deepcopy(receipt)
                    altered["agent_id"] = "spiffe://evaluation.example/other"
                    check(
                        "tampered-receipt-rejected",
                        not verify_kill_switch_refusal(altered, claim).valid,
                    )
                    altered_claim = copy.deepcopy(claim)
                    altered_claim["gateway"]["kill_switch"]["min_calls"] = 1
                    check(
                        "tampered-claim-rejected",
                        not verify_kill_switch_refusal(receipt, altered_claim).valid,
                    )
                    # Exercise the recorded whole-claim schema limitation, without masking it.
                    schema = json.loads((source / "schemas/trace-claim.schema.json").read_text())
                    schema_errors = [
                        e.message
                        for e in jsonschema.Draft202012Validator(schema).iter_errors(claim)
                    ]
                    observations.append(
                        {
                            "id": "whole-claim-schema",
                            "observation": "rejected" if schema_errors else "accepted",
                            "errors": schema_errors,
                        }
                    )
                    # Deliberately bypass the gateway to demonstrate the scope boundary.
                    direct = httpx.post(
                        f"http://127.0.0.1:{tool.server_port}/mcp",
                        json={
                            "jsonrpc": "2.0",
                            "id": "bypass",
                            "method": "tools/call",
                            "params": {
                                "name": "observe.tool",
                                "arguments": {"marker": "bypass-effect"},
                            },
                        },
                    )
                    check(
                        "bypass-counterexample",
                        direct.status_code == 200 and "bypass-effect" in Tool.effects,
                    )
                    denied = client.post(
                        "/kill-switch/unblock",
                        json={
                            "agent_id": IDENTITY,
                            "reason": "evaluation",
                            "authorized_by": "evaluator",
                        },
                    )
                    check("agent-cannot-unblock", denied.status_code == 401)
                with gateway(root, source, port, mutation, "restarted", result_dir):
                    count = len(Tool.effects)
                    refused = call(client, "after-restart")
                    check(
                        "restart-retains-block",
                        refused.status_code == 403 and len(Tool.effects) == count,
                        status=refused.status_code,
                    )
                    restart_receipt = refused.json()["error"]["data"]["receipt"]
                    write(result_dir / "restart-refusal.json", restart_receipt)
                    check(
                        "restart-receipt-not-bound-to-old-claim",
                        not verify_kill_switch_refusal(restart_receipt, claim).valid,
                        has_claim_digest="claim_digest" in restart_receipt,
                    )
                    resumed = client.post(
                        "/kill-switch/unblock",
                        headers=operator,
                        json={
                            "agent_id": IDENTITY,
                            "reason": "evaluation complete",
                            "authorized_by": "evaluator",
                        },
                    )
                    check(
                        "operator-recovers",
                        resumed.status_code == 200,
                        status=resumed.status_code,
                    )
                    result = call(client, "after-recovery")
                    check(
                        "recovered-tool-effect",
                        result.status_code == 200 and "after-recovery" in Tool.effects,
                    )
                    check(
                        "old-receipt-still-verifies-after-recovery",
                        verify_kill_switch_refusal(receipt, claim).valid,
                    )
                    # Recovery recorded an allow; close and restart to make window empty.
                with gateway(root, source, port, mutation, "automatic", result_dir):
                    for i in range(5):
                        result = call(client, f"deny-{i}", name="absent.tool")
                        check(f"automatic-deny-{i}", result.status_code == 403)
                    refused = call(client, "after-auto")
                    code = refused.json().get("error", {}).get("data", {}).get("error_code")
                    check(
                        "automatic-trip-refuses-allowed-tool",
                        code == "KILL_SWITCH_TRIPPED" and "after-auto" not in Tool.effects,
                        error_code=code,
                    )
                    auto_receipt = refused.json()["error"]["data"]["receipt"]
                    auto_claim = client.get(
                        f"/sessions/{auto_receipt['session_id']}/trace-claim"
                    ).json()
                    write(result_dir / "automatic-claim.json", auto_claim)
                    check(
                        "automatic-receipt-verifies",
                        verify_kill_switch_refusal(auto_receipt, auto_claim).valid,
                    )
                    check(
                        "signed-trigger-is-deny-rate",
                        auto_claim["gateway"]["kill_switch"]["trigger"] == "deny_rate",
                    )
            write(result_dir / "tool-effects.json", Tool.effects)
            write(result_dir / "observations.json", observations)
    finally:
        Tool.release.set()
        tool.shutdown()
        tool.server_close()
    return observations


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--source", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--mutation", choices=["none", "forget-block", "disable-auto"], default="none")
    a = p.parse_args()
    source = a.source.resolve()
    head = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    if (
        head != PIN
        or subprocess.check_output(
            ["git", "-C", str(source), "diff", "HEAD", "--", "src", "tests"]
        ).strip()
    ):
        raise SystemExit("source must match the clean pinned revision")
    sys.path.insert(0, str(source / "src"))
    import cmcp_runtime

    if not Path(cmcp_runtime.__file__).resolve().is_relative_to(source):
        raise SystemExit("wrong cmcp import")
    a.output.mkdir(parents=True, exist_ok=False)
    metadata = {
        "source": head,
        "python": platform.python_version(),
        "platform": platform.system(),
        "mutation": a.mutation,
        "hardware_attestation": False,
        "independent_operator": False,
        "dependencies": {
            n: importlib.metadata.version(n)
            for n in [
                "cmcp-runtime",
                "agent-manifest",
                "agentrust-trace",
                "cryptography",
                "cedarpy",
                "httpx",
                "jsonschema",
                "uvicorn",
            ]
        },
        "harness_sha256": {
            f.name: hashlib.sha256(f.read_bytes()).hexdigest()
            for f in Path(__file__).parent.glob("*.py")
        },
    }
    try:
        observations = exercise(source, a.output, a.mutation)
        metadata.update(outcome="pass", checks=sum("passed" in o for o in observations))
    except Exception as exc:
        metadata.update(outcome="fail", error=f"{type(exc).__name__}: {exc}")
        raise
    finally:
        write(a.output / "run.json", metadata)


if __name__ == "__main__":
    main()
