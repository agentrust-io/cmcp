"""Compare changed generated requirement locks without installing dependencies."""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from check_lock_delta import check_delta, parse_lock


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    scope_file = root / "tools/lock-delta-scope.json"
    excluded = json.loads(scope_file.read_text()) if scope_file.exists() else {}
    changed = subprocess.check_output(
        ["git", "diff", "--name-only", "-z", args.base, "HEAD", "--", "requirements"],
        cwd=root,
    ).decode().split("\0")
    for relative in changed:
        if not relative.endswith(".txt"):
            continue
        if relative in excluded:
            print(f"OUT OF SCOPE {relative}: {excluded[relative]}")
            continue
        path = root / relative
        if not path.is_file():
            raise ValueError(f"deleted lock requires explicit maintainer review: {relative}")
        after = path.read_text(encoding="utf-8")
        previous = subprocess.run(
            ["git", "show", f"{args.base}:{relative}"],
            cwd=root, capture_output=True, text=True, check=False,
        )
        if previous.returncode:
            parse_lock(after)
            print(f"NEW {relative}: structure only; no prior dependency baseline")
        else:
            print(f"PASS {relative}: changed packages {check_delta(previous.stdout, after)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
