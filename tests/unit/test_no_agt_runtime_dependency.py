"""Prove cMCP runtime modules do not import AGT/agent_os."""

from __future__ import annotations

import subprocess
import sys


def test_runtime_imports_when_agent_os_is_blocked() -> None:
    code = r'''
import sys

class BlockAgentOS:
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "agent_os" or fullname.startswith("agent_os."):
            raise ImportError(f"blocked runtime dependency: {fullname}")
        return None

sys.meta_path.insert(0, BlockAgentOS())
import cmcp_runtime.catalog.scanner
import cmcp_runtime.inspection.pipeline
import cmcp_runtime.mcp.proxy
import cmcp_runtime.mcp.server
import cmcp_runtime.runtime_gateway
'''
    completed = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
