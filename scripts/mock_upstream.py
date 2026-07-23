#!/usr/bin/env python3
"""Minimal mock MCP upstream server for the cMCP quickstart and docker-compose demo.

Listens for JSON-RPC `tools/call` requests over HTTP POST and returns a canned
result. It exists so the quickstart's "allowed call" step has a real upstream to
forward to; it is not part of the runtime and must not be used in production.

Usage:
    python scripts/mock_upstream.py [--host HOST] [--port PORT]

Defaults to 0.0.0.0:9001, which matches the catalog entries shipped in
examples/ and docs/quickstart.md.
"""
from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class MockMCPHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args) -> None:  # silence per-request logging
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        try:
            msg = json.loads(raw)
        except (ValueError, TypeError):
            msg = {}

        params = msg.get("params", {}) if isinstance(msg, dict) else {}
        tool_name = params.get("name", "unknown")
        arguments = params.get("arguments", {})
        text = f"mock upstream: {tool_name} called with {json.dumps(arguments, sort_keys=True)}"

        response = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": msg.get("id") if isinstance(msg, dict) else None,
                "result": {"content": [{"type": "text", "text": text}]},
            }
        ).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock MCP upstream for the cMCP demo")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9001)
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), MockMCPHandler)
    print(f"mock upstream listening on {args.host}:{args.port}/mcp", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
