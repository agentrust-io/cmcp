"""Launch the pinned, unmodified cMCP startup path; mutations are evaluator controls."""

import argparse
import os


def main():
    p = argparse.ArgumentParser()
    p.add_argument("config")
    p.add_argument("--mutation", choices=["none", "forget-block", "disable-auto"], default="none")
    a = p.parse_args()
    # Set before importing the configuration module, which freezes development mode.
    os.environ["CMCP_DEV_MODE"] = "1"
    import uvicorn
    from cmcp_runtime.cli import build_server
    from cmcp_runtime.kill_switch import KillSwitchBlockStore, KillSwitchEvaluator
    from cmcp_runtime.startup import run_startup

    if a.mutation == "forget-block":
        KillSwitchBlockStore.is_blocked = lambda self, identity: False
    elif a.mutation == "disable-auto":
        KillSwitchEvaluator.evaluate = lambda self, identity: False
    ctx = run_startup(a.config)
    server = build_server(ctx)
    host, port = ctx.config.listen_addr.rsplit(":", 1)
    uvicorn.run(server.app, host=host, port=int(port), log_level="warning")


if __name__ == "__main__":
    main()
