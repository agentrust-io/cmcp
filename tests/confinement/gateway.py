"""Real cMCP, real Cedar, real stdio peer; no transport or policy mocks."""

import sys
from pathlib import Path
from uuid import uuid4

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.catalog.loader import (
    ApprovedDefinition,
    CatalogEntry,
    ServerIdentity,
    ToolCatalog,
)
from cmcp_runtime.config import Config
from cmcp_runtime.mcp.proxy import CMCPProxy
from cmcp_runtime.mcp.stdio import StdioSpawn, measure_executable
from cmcp_runtime.policy.bundle import PolicyBundle, PolicyManifest
from cmcp_runtime.policy.evaluator import PolicyEvaluator
from cmcp_runtime.session.state import SessionState
from cmcp_runtime.sink_policy import SinkPolicy


def make_gateway(sink: Path, *, public_ceiling="public", audit_store=None, audit_sinks=None):
    upstream = Path(__file__).with_name("upstream.py").resolve()
    spawn = StdioSpawn(sys.executable, (str(upstream), str(sink)),
                       measure_executable(str(upstream)), str(upstream))
    server = ServerIdentity("synthetic sink", "", "", None, "stdio", "key-pinned", spawn)
    entries = {name: CatalogEntry(
        name, server, ApprovedDefinition("record synthetic data", {"type": "object"}, None),
        "sha256:" + "0" * 64, "internal", False, "public", "2026-09-18", "fixture",
    ) for name in ("permitted.tool", "public.tool")}
    config = Config(sink_policy=SinkPolicy({
        "permitted.tool": "confidential", "public.tool": public_ceiling,
    }, "confidential"))
    session = SessionState(uuid4().hex, max_sensitivity="confidential")
    audit = AuditChain(session.session_id, store=audit_store, sinks=audit_sinks)
    bundle = PolicyBundle(
        PolicyManifest("1.0.0", "2026-09-18T00:00:00Z", "fixture", "fixture"),
        {"allow.cedar": "permit(principal, action, resource);"}, '{"cMCP": {}}',
        "sha256:" + "1" * 64,
    )
    proxy = CMCPProxy(ToolCatalog(entries, "sha256:" + "2" * 64),
                      PolicyEvaluator(bundle, config), session, audit, config)

    async def dispatch(tool, arguments):
        result = await proxy.call_tool(uuid4().hex, tool, arguments)
        return {"allowed": result.allowed, "response": result.response}

    return proxy, dispatch
