"""Exercise the Markdown tutorial's files, requests, and verification gate."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace

import httpx

ROOT = Path(__file__).resolve().parents[1]
CLI = [sys.executable, "-c", "from cmcp_runtime.cli import main; main()"]


def blocks(path):
    return re.findall(r"^```[^\n]*\n(.*?)^```", path.read_text(encoding="utf-8-sig"), re.M | re.S)


def wait_for_server(url, process):
    for _ in range(80):
        if process.poll() is not None:
            raise RuntimeError("Tutorial server exited before readiness")
        try:
            httpx.get(url, timeout=1)
            return
        except httpx.ConnectError:
            time.sleep(.25)
    raise TimeoutError(url)


def main():
    snippets = blocks(ROOT / "docs/quickstart.md")
    tutorial = blocks(ROOT / "docs/tutorials/verifying-a-trace-claim.md")
    environment = dict(os.environ, CMCP_DEV_MODE="1", PYTHONIOENCODING="utf-8")
    # Tokenless localhost is the documented path, regardless of caller settings.
    environment.pop("CMCP_BEARER_TOKEN", None)
    with tempfile.TemporaryDirectory(prefix="cmcp-docs-") as temporary:
        work = Path(temporary)
        (work / "policies").mkdir()
        def save(name, text):
            (work / name).write_text(text, encoding="utf-8")
        save("cmcp-config.yaml", next(b for b in snippets if b.startswith("attestation:")))
        save("policies/manifest.json", next(b for b in snippets if b.startswith('{\n  "version"')))
        save("policies/demo.cedar", next(b for b in snippets if b.startswith("// Rule 1")))
        save("policies/schema.cedarschema", next(b for b in snippets if b.startswith('{"cMCP"')))
        save("catalog.json", next(b for b in snippets if b.startswith("[\n")))
        pins = next(b for b in snippets if 'Path("approved-hashes.json")' in b)
        pins = pins.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        subprocess.run([sys.executable, "-c", pins], cwd=work, env=environment, check=True)
        mock = next(b for b in snippets if "cat > mock_upstream.py" in b)
        mock = mock.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        save("mock_upstream.py", mock)
        with (work / "runtime.log").open("w", encoding="utf-8") as log:
            processes = []
            try:
                runtime = subprocess.Popen(CLI + ["start", "--config", "cmcp-config.yaml"], cwd=work, env=environment, stdout=log, stderr=log)
                processes.append(runtime)
                wait_for_server("http://localhost:8443/health", runtime)
                requests = [json.loads(re.search(r"-d '(.*?)'", b, re.S)[1]) for b in snippets if "curl -i -X POST" in b]
                denied = httpx.post("http://localhost:8443/mcp", json=requests[0])
                assert denied.status_code == 403 and "POLICY_DENY" in denied.text, denied.text
                upstream = subprocess.Popen([sys.executable, "mock_upstream.py"], cwd=work, env=environment, stdout=log, stderr=log)
                processes.append(upstream)
                wait_for_server("http://localhost:9001", upstream)
                allowed = httpx.post("http://localhost:8443/mcp", json=requests[1])
                assert allowed.status_code == 200 and "mock response" in allowed.text, allowed.text
                audit = httpx.get("http://localhost:8443/audit/export?session_id=demo-session-001").json()
                sid = audit["entries"][0]["session_id"]
                response = httpx.post(f"http://localhost:8443/sessions/{sid}/close")
                response.raise_for_status()
                claim = response.json()
                summary = claim["gateway"]["call_summary"]
                assert summary["tool_calls_total"] == 2 and summary["tool_calls_allowed"] == 1 and summary["tool_calls_denied"] == 1, summary
                save("claim.json", json.dumps(claim))
                hashes = json.loads((work / "approved-hashes.json").read_text())
                result = subprocess.run(CLI + ["verify", "claim.json", "--policy-hash", hashes["policy_bundle_hash"], "--catalog-hash", hashes["tool_catalog_hash"]], cwd=work, env=environment, capture_output=True, text=True, encoding="utf-8")
                assert result.returncode == 1 and "partially_verified" in result.stdout, result.stdout + result.stderr
                for name in ("schema", "signature", "policy_bundle.hash", "tool_catalog.hash", "attestation_freshness", "audit_chain"):
                    assert re.search(re.escape(name) + r"\s+PASS", result.stdout), result.stdout
                inspection = next(b for b in tutorial if 'print(f"Status:' in b)
                subprocess.run([sys.executable, "-c", inspection], cwd=work, env=environment, check=True)
                gate = next(b for b in tutorial if "def verify_session_claim" in b)
                result = subprocess.run([sys.executable, "-c", gate], cwd=work, env=environment, capture_output=True, text=True)
                assert result.returncode != 0 and "CLAIM REJECTED: partially_verified" in result.stderr, result.stdout + result.stderr
                # The consumer must reject a fresh partial result regardless of cause.
                namespace = {"__name__": "tutorial_test"}
                exec(compile(gate, "documented acceptance gate", "exec"), namespace)
                for status, fields in [("partially_verified", ["hardware_attestation"]), ("partially_verified", ["policy_bundle.hash"]), ("unverified", ["signature"])]:
                    verdict = SimpleNamespace(status=SimpleNamespace(value=status), unverified_fields=fields, is_attestation_fresh=True, failure_reason=None, details={})
                    namespace["verify_trace_claim"] = lambda *args, verdict=verdict: verdict
                    try:
                        namespace["verify_session_claim"](work / "claim.json", work / "approved-hashes.json")
                    except SystemExit:
                        pass
                    else:
                        raise AssertionError(f"Consumer accepted {status}: {fields}")
                print("PASS: documented deny, allow, two-call summary, independently pinned software verification, and consumer rejection cases")
            finally:
                for process in reversed(processes):
                    if os.name == "nt":
                        # Windows venv launchers have a child interpreter holding SQLite.
                        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], check=True, capture_output=True)
                    else:
                        process.terminate()
                    process.wait(timeout=15)
                log.flush()
                if sys.exc_info()[0]:
                    print((work / "runtime.log").read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
