"""Pytest configuration for this suite.

Guards a silent failure mode rather than testing anything itself.

pytest puts the source tree on the path, so an in-process import always finds
this tree. A test that shells out does not get that: a plain
``subprocess.run([sys.executable, ...])`` resolves the distribution the normal
way, and with a released wheel also installed it finds site-packages. The
subprocess then exercises a published version while the suite reports a pass,
which is how a tutorial test in this repo family graded against an old schema
and looked green.

CI installs the package editable, so the subprocess resolves back into the tree
and this check is a no-op there. Locally it turns a wrong answer into a loud one.

A package that is not importable from a subprocess at all is fine: that is the
path-only setup, not a shadowing install, and the suite still runs.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys
import textwrap

import pytest

#: Packages this suite is meant to exercise from source.
_PACKAGES_UNDER_TEST = ("cmcp_runtime", "cmcp_verify",)

#: Repository root, resolved from this file.
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

_PROBE = textwrap.dedent(
    """
    import importlib, sys
    try:
        m = importlib.import_module(sys.argv[1])
    except Exception:
        print("")
    else:
        print(getattr(m, "__file__", "") or "")
    """
)


def _subprocess_origin(package: str) -> pathlib.Path | None:
    """Where a fresh interpreter finds ``package``, or None if it cannot."""
    try:
        done = subprocess.run(
            [sys.executable, "-c", _PROBE, package],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    origin = done.stdout.strip()
    return pathlib.Path(origin).resolve() if origin else None


def pytest_configure(config: pytest.Config) -> None:
    for name in _PACKAGES_UNDER_TEST:
        origin = _subprocess_origin(name)
        if origin is None:
            continue  # not importable from a subprocess; nothing can shadow
        if _REPO_ROOT not in origin.parents:
            raise pytest.UsageError(
                f"{name} resolves to {origin} in a subprocess, outside "
                f"{_REPO_ROOT}. Any test that shells out would exercise that "
                "installed distribution instead of this working tree. Install "
                f"editable (pip install -e .) or uninstall the shadowing {name}."
            )
