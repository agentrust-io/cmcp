"""Pytest configuration for this suite.

Guards two silent failure modes rather than testing anything itself.

**A shadowing install.** pytest puts the source tree on the path, so an in-process import always finds
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

**The host TPM.** cMCP opens ``ESAPI()`` with the default TCTI, which resolves to
``/dev/tpmrm0`` on a machine that has one. CI installs no tpm2-pytss, so there
the import fails and the code under test degrades. A developer who installs the
``tpm`` extra gets a different suite: tests that expect the degraded path define
and extend NV indexes on their real TPM instead, which on a dual-boot laptop is a
TPM another operating system also keeps keys in. So any ESAPI context that is not
a simulator is refused. ``CMCP_TESTS_ALLOW_HOST_TPM=1`` lifts that for a
deliberate hardware run.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import textwrap
from typing import Any

import pytest

#: Packages this suite is meant to exercise from source.
_PACKAGES_UNDER_TEST = (
    "cmcp_runtime",
    "cmcp_verify",
)

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
            check=False,  # a non-zero exit just means "cannot import", handled below
        )
    except (OSError, subprocess.SubprocessError):
        return None
    origin = done.stdout.strip()
    return pathlib.Path(origin).resolve() if origin else None


#: TCTIs that reach a simulator and never a device.
_SIMULATOR_TCTIS = frozenset({"swtpm", "mssim"})


def _tcti_name(tcti: Any) -> str | None:
    """The TCTI module an ESAPI context would load, or None for the default."""
    if tcti is None:
        return None
    if isinstance(tcti, str):
        return tcti.split(":", 1)[0]
    return getattr(tcti, "name", None)


def _refuse_host_tpm() -> None:
    """Make every non-simulator ESAPI context fail, as a missing TPM would."""
    if os.environ.get("CMCP_TESTS_ALLOW_HOST_TPM") == "1":
        return
    try:
        from tpm2_pytss.ESAPI import ESAPI
    except ImportError:
        return  # nothing can reach a TPM

    original = ESAPI.__init__

    def guarded(self: Any, tcti: Any = None) -> None:
        name = _tcti_name(tcti)
        if name not in _SIMULATOR_TCTIS:
            raise RuntimeError(
                f"the test suite refused an ESAPI context on TCTI {name or 'default'}: "
                "only swtpm and mssim are allowed. Set CMCP_TESTS_ALLOW_HOST_TPM=1 "
                "for a deliberate hardware run."
            )
        original(self, tcti)

    ESAPI.__init__ = guarded  # type: ignore[method-assign]


def pytest_configure(config: pytest.Config) -> None:
    _refuse_host_tpm()
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
