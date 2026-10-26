"""Check universal hash-lock structure and optionally resolve two target platforms.

This checks a declared subset of uv/pip-compile output, not arbitrary pip syntax.
Removal or marker changes require an explicit --allow-removed package review.
It does not authenticate package publishers or decide whether upgrades are safe.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

PIN = re.compile(r"^([A-Za-z0-9_.-]+)(\[[^]]+\])?==([^\s;]+)(.*)$")
HASH = re.compile(r"--hash=sha256:[0-9a-f]{64}(?=\s|$)")


def parse_lock(text):
    lines = []
    current = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        current += " " + line.removesuffix("\\").strip()
        if not line.endswith("\\"):
            lines.append(current.strip())
            current = ""
    if current:
        raise ValueError("unterminated lock entry")
    result = {}
    for line in lines:
        match = PIN.fullmatch(line)
        if not match:
            raise ValueError("expected an exact version pin with SHA-256 hashes")
        name, extras, version, tail = match.groups()
        name = re.sub(r"[-_.]+", "-", name).lower()
        extras = tuple(sorted((extras or "").strip("[]").lower().split(",")))
        hashes = HASH.findall(tail)
        if not hashes:
            raise ValueError(f"{name}: missing SHA-256 hash")
        marker = HASH.sub("", tail).strip()
        if marker and not marker.startswith(";"):
            raise ValueError(f"{name}: unsupported lock option or malformed hash")
        marker = " ".join(marker.split())
        key = (name, extras, marker)
        if key in result:
            raise ValueError(f"duplicate pin: {name} {marker}")
        result[key] = version
    if not result:
        raise ValueError("empty lock")
    return result


def check_delta(before, after, allowed=()):
    old, new = parse_lock(before), parse_lock(after)
    allowed = {re.sub(r"[-_.]+", "-", name).lower() for name in allowed}
    missing = sorted(key for key in old.keys() - new.keys() if key[0] not in allowed)
    if missing:
        raise ValueError(f"removed pins or changed platform markers: {missing}")
    return sorted({key[0] for key in new if old.get(key) != new[key]})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", help="existing git revision to compare")
    parser.add_argument("--allow-removed", action="append", default=[])
    parser.add_argument("--resolve", action="store_true", help="requires uv and package network access")
    parser.add_argument("--python-version", default="3.11")
    parser.add_argument("locks", nargs="+", type=Path)
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    for path in args.locks:
        absolute = (root / path).resolve()
        relative = absolute.relative_to(root).as_posix()
        after = absolute.read_text(encoding="utf-8")
        parse_lock(after)
        if args.base:
            previous = subprocess.run(["git", "show", f"{args.base}:{relative}"], cwd=root,
                                      capture_output=True, text=True, check=False)
            if previous.returncode:
                raise ValueError(f"cannot read base lock {relative}; review new locks separately")
            changed = check_delta(previous.stdout, after, args.allow_removed)
            print(f"{relative}: changed packages {changed}")
        if args.resolve:
            # Each resolution uses an isolated interpreter context and ignores
            # the reviewer's already-installed packages. No package is installed.
            with tempfile.TemporaryDirectory(prefix="lock-resolution-") as directory:
                venv.EnvBuilder(with_pip=False).create(directory)
                python = Path(directory) / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
                for platform in ("x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"):
                    subprocess.run(["uv", "pip", "install", "--python", str(python), "--dry-run",
                                    "--require-hashes", "--python-version",
                                    args.python_version, "--python-platform", platform,
                                    "-r", str(absolute)], check=True, cwd=root)
        print(f"PASS {relative}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        raise SystemExit(1) from None
