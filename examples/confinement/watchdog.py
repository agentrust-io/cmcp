"""Independent, plaintext-free lease watcher for a running agent container.

The bridge holds the only write end of stdin. EOF or a missed heartbeat stops
the container even when the bridge cannot execute its finally block.
"""

import os
import select
import subprocess
import sys

LEASE_SECONDS = 2.0


def main():
    command = sys.argv[1:]
    # Arguments are supplied only by the trusted adapter; never by the agent.
    sys.stdout.buffer.write(b"ready\n")
    sys.stdout.buffer.flush()
    while True:
        ready, _, _ = select.select([sys.stdin.fileno()], [], [], LEASE_SECONDS)
        if not ready or os.read(sys.stdin.fileno(), 1) != b".":
            break
        try:
            sys.stdout.buffer.write(b".")
            sys.stdout.buffer.flush()
        except OSError:
            break
    # A surviving, responsive host/daemon is required. Retry transient failure;
    # never log Docker output (nor accept payloads on this channel).
    for _ in range(3):
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    timeout=5, check=False)
            if result.returncode == 0:
                return 0
        except (OSError, subprocess.TimeoutExpired):
            pass
    return 1


if __name__ == "__main__":
    sys.exit(main())
