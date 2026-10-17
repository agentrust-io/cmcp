"""Store persistence and scope: a recorded block survives reopening the same store, is absent
from an independent store, and an explicit unblock is visible on the next connection.

Usage: store_scope.py SCRATCH   (run with the pinned cMCP source on PYTHONPATH)
"""
import json
from pathlib import Path
import sys


def shutdown(scratch: Path) -> dict:
    from cmcp_runtime.kill_switch import KillSwitchBlockStore
    path = scratch / "blocks.db"
    first = KillSwitchBlockStore(path)
    first.block("agent-a", reason="synthetic experiment")
    seen = []
    for _ in range(20):
        reopened = KillSwitchBlockStore(path)
        seen.append(reopened.is_blocked("agent-a"))
        reopened._conn.close()
    assert all(seen)
    other = KillSwitchBlockStore(scratch / "independent.db")
    independent = other.is_blocked("agent-a")
    assert not independent
    assert first.unblock("agent-a")
    resumed = KillSwitchBlockStore(path)
    assert not resumed.is_blocked("agent-a")
    first._conn.close()
    other._conn.close()
    resumed._conn.close()
    return {"reopened_stores": 20, "blocks_retained": sum(seen),
            "independent_store_blocked": independent, "explicit_unblock_visible": True,
            "limit": "A different store is not covered; this is not a global identity shutdown."}


if __name__ == "__main__":
    scratch = Path(sys.argv[1])
    scratch.mkdir(parents=True)
    print(json.dumps(shutdown(scratch), indent=2))
