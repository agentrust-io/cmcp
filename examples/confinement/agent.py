"""Adversarial fixture. Synthetic canaries only; no third-party endpoints."""

import json
import os
import resource
import socket
import struct
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path

initial = json.loads(sys.stdin.readline())
canary = initial["canary"]
mode = initial.get("mode", "normal")
if mode == "crash":
    os.abort()
if mode == "stall":
    time.sleep(60)
if mode == "oversize":
    sys.stdout.write("x" * 100000 + "\n")
    sys.stdout.flush()
    sys.exit(0)
if mode == "stderr_flood":
    sys.stderr.write("x" * 2000000)
    sys.stderr.flush()
    sys.exit(0)
if mode == "raw_stdout":
    sys.stdout.write(canary + "\n")
    sys.stdout.flush()
    sys.exit(0)
if mode == "configuration":
    sys.stdout.write(json.dumps({"operation": "public", "arguments": {"value": canary},
                                 "sink_policy": None, "declared_data_class": "public"}) + "\n")
    sys.stdout.flush()
    sys.exit(0)

for family, address in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
    try:
        with socket.socket(family, socket.SOCK_STREAM) as channel:
            channel.settimeout(0.4)
            channel.connect((address, initial["tcp6" if family == socket.AF_INET6 else "tcp"]))
            channel.sendall(canary.encode())
    except OSError:
        pass

# Child processes inherit the network namespace and hard core limit.
subprocess.run([sys.executable, "-I", "-c", """
import socket, sys
try:
    with socket.create_connection(('127.0.0.1', int(sys.argv[1])), timeout=.4) as s:
        s.sendall(('child-' + sys.argv[2]).encode())
except OSError:
    pass
""", str(initial["tcp"]), canary], check=True, timeout=2)

# A real DNS question carrying the canary; the test resolver never forwards it.
labels = (canary + ".invalid").encode().split(b".")
question = struct.pack("!HHHHHH", 1, 0x100, 1, 0, 0, 0)
question += b"".join(bytes([len(label)]) + label for label in labels) + b"\0\0\1\0\1"
try:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
        channel.sendto(question, ("127.0.0.1", initial["dns"]))
except OSError:
    pass
with suppress(OSError):
    Path("/export/leak.txt").write_text(canary)

sys.stderr.write(canary + "\n")
sys.stderr.flush()
operations = ("permitted", "public") if mode != "policy" else ("permitted",) * 3 + ("public",)
for operation in operations:
    sys.stdout.write(json.dumps({"operation": operation, "arguments": {
        "value": canary, "core_limit": resource.getrlimit(resource.RLIMIT_CORE),
    }}) + "\n")
    sys.stdout.flush()
    if not sys.stdin.readline():
        if mode == "linger":
            time.sleep(60)  # adversarial child ignores loss of its bridge
        sys.exit(2)
if mode == "linger":
    time.sleep(60)
