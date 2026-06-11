"""Tests for CMCPProxy._forward_to_upstream against a real local HTTP server."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import MagicMock, patch

import pytest

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.catalog.loader import (
    ApprovedDefinition,
    CatalogEntry,
    ServerIdentity,
    ToolCatalog,
)
from cmcp_runtime.config import AttestationConfig, Config, EnforcementMode
from cmcp_runtime.errors import UpstreamToolError, UpstreamUnavailable
from cmcp_runtime.session.state import SessionState


class _MockMCPHandler(BaseHTTPRequestHandler):
    """Serves canned JSON-RPC responses; behavior keyed on tool name."""

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        request = json.loads(self.rfile.read(length))
        tool = request["params"]["name"]
        if tool == "test.fail":
            body = {
                "jsonrpc": "2.0",
                "id": request["id"],
                "error": {"code": -32000, "message": "tool exploded"},
            }
        else:
            body = {
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": {
                    "content": [{"type": "text", "text": f"echo:{tool}"}]
                },
            }
        payload = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):  # silence test output
        pass


@pytest.fixture(scope="module")
def mock_server():
    server = HTTPServer(("127.0.0.1", 0), _MockMCPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/mcp"
    server.shutdown()


def _make_proxy(server_url: str):
    from cmcp_runtime.mcp.proxy import CMCPProxy

    entry = CatalogEntry(
        tool_name="test.echo",
        server=ServerIdentity(
            display_name="Mock",
            url=server_url,
            tls_fingerprint="SHA256:" + "A" * 43 + "=",
            spiffe_id=None,
            transport="http-sse",
            rotation_mode="key-pinned",
        ),
        approved_definition=ApprovedDefinition(
            description="echo", input_schema={"type": "object"}, output_schema=None
        ),
        definition_hash="sha256:" + "0" * 64,
        compliance_domain="public",
        requires_baa=False,
        sensitivity_level="public",
        added_at="2026-06-10T00:00:00Z",
        approved_by="test",
    )
    catalog = ToolCatalog(
        entries={"test.echo": entry, "test.fail": entry},
        catalog_hash="sha256:" + "1" * 64,
    )
    config = Config(attestation=AttestationConfig(enforcement_mode=EnforcementMode.ENFORCING))
    session = SessionState(session_id="fwd-test")
    chain = AuditChain("fwd-test")
    with patch("cmcp_runtime.mcp.proxy.MCPGateway"), \
         patch("cmcp_runtime.mcp.proxy.MCPResponseScanner"):
        proxy = CMCPProxy(
            catalog=catalog,
            policy_evaluator=MagicMock(),
            session=session,
            audit_chain=chain,
            config=config,
        )
    return proxy, entry


@pytest.mark.asyncio
async def test_forward_returns_text_content(mock_server):
    proxy, entry = _make_proxy(mock_server)
    text = await proxy._forward_to_upstream("c1", entry, "test.echo", {"message": "hi"})
    assert text == "echo:test.echo"


@pytest.mark.asyncio
async def test_forward_raises_on_jsonrpc_error(mock_server):
    proxy, entry = _make_proxy(mock_server)
    with pytest.raises(UpstreamToolError, match="tool exploded"):
        await proxy._forward_to_upstream("c1", entry, "test.fail", {})


@pytest.mark.asyncio
async def test_forward_raises_when_unreachable():
    proxy, entry = _make_proxy("http://127.0.0.1:1/mcp")
    with pytest.raises(UpstreamUnavailable):
        await proxy._forward_to_upstream("c1", entry, "test.echo", {})
