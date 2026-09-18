"""Actual JSON-RPC stdio peer, independently recording calls at the sink."""

import json
import sys
from pathlib import Path

for line in sys.stdin:
    request = json.loads(line)
    method = request["method"]
    if method == "tools/list":
        result = {"tools": [{"name": name, "description": "record synthetic data",
                             "inputSchema": {"type": "object"}}
                            for name in ("permitted.tool", "public.tool")]}
    elif method == "tools/call":
        with Path(sys.argv[1]).open("a", encoding="utf-8") as sink:
            sink.write(json.dumps(request["params"]) + "\n")
        result = {"content": [{"type": "text", "text": "recorded"}]}
    else:
        result = {}
    if "id" in request:
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": request["id"],
                                     "result": result}) + "\n")
        sys.stdout.flush()
