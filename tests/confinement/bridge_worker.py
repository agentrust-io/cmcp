"""Synthetic bridge process killed by an independent lifecycle observer."""

import asyncio
import json
import sys
from pathlib import Path

from examples.confinement import adapter

from tests.confinement.gateway import make_gateway


class NoWatchdog:
    """Test-only causal mutation; never selected by the reference adapter."""

    process = None

    def __init__(self, command):
        pass

    async def start(self):
        pass

    async def pulse(self):
        await asyncio.Future()

    async def close(self):
        pass


async def main():
    if sys.argv[3] == "unguarded":
        adapter.LeaseWatchdog = NoWatchdog
    root = Path(sys.argv[2])
    sandbox = adapter.DockerSandbox(sys.argv[1])
    proxy, dispatch = make_gateway(root / "sink.jsonl")
    try:
        await sandbox.create()
        initial = json.loads(sys.stdin.readline())

        async def observed_dispatch(tool, arguments):
            result = await dispatch(tool, arguments)
            watchdog = sandbox._watchdog.process
            (root / "ready.json").write_text(json.dumps({
                "container": sandbox.name, "watchdog": watchdog.pid if watchdog else None,
            }))
            return result

        await sandbox.execute(initial, observed_dispatch,
                              {"permitted": "permitted.tool", "public": "public.tool"}, timeout=60)
    finally:
        await proxy.aclose()
        await sandbox.remove()


if __name__ == "__main__":
    asyncio.run(main())
