"""Throwaway swtpm instances for tests that need real TPM 2.0 semantics.

Each instance has its own state directory and TCP port pair, and starts with
``startup-clear`` so no TPM2_Startup is needed. A context is only handed out after
the TPM it reaches reports swtpm's manufacturer, so a routing mistake fails rather
than running against a device. tests/conftest.py separately refuses any
non-simulator TCTI.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

_SWTPM_MANUFACTURER = b"IBM"


def swtpm_available() -> bool:
    if shutil.which("swtpm") is None:
        return False
    try:
        import tpm2_pytss  # noqa: F401
    except ImportError:
        return False
    return True


def _free_port_pair() -> int:
    """A port whose successor is free too: swtpm's control channel is port + 1."""
    for _ in range(50):
        with socket.socket() as first:
            first.bind(("127.0.0.1", 0))
            port = int(first.getsockname()[1])
            with socket.socket() as second:
                try:
                    second.bind(("127.0.0.1", port + 1))
                except OSError:
                    continue
        return port
    raise RuntimeError("no free port pair for swtpm")


class Swtpm:
    """One swtpm process. ``restart`` keeps its state, like a host reboot."""

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        self.port = _free_port_pair()
        self.tcti = f"swtpm:host=127.0.0.1,port={self.port}"
        self._proc: subprocess.Popen[bytes] | None = None

    def start(self) -> Swtpm:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._proc = subprocess.Popen(  # noqa: S603 - fixed argv, test-only
            [
                "swtpm",
                "socket",
                "--tpm2",
                "--tpmstate",
                f"dir={self.state_dir}",
                "--server",
                f"type=tcp,port={self.port}",
                "--ctrl",
                f"type=tcp,port={self.port + 1}",
                "--flags",
                "not-need-init,startup-clear",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 10
        while True:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    self.stop()
                    raise RuntimeError("swtpm did not start") from None
                time.sleep(0.05)
        return self

    def stop(self) -> None:
        if self._proc is not None:
            self._proc.terminate()
            self._proc.wait(timeout=10)
            self._proc = None

    def restart(self) -> None:
        self.stop()
        self.start()

    def context(self) -> Any:
        """An ESAPI context on this instance, after checking it is swtpm."""
        from tpm2_pytss.constants import TPM2_CAP, TPM2_PT
        from tpm2_pytss.ESAPI import ESAPI

        ectx = ESAPI(self.tcti)
        _more, data = ectx.get_capability(TPM2_CAP.TPM_PROPERTIES, TPM2_PT.MANUFACTURER, 1)
        manufacturer = int(data.data.tpmProperties[0].value).to_bytes(4, "big")
        if not manufacturer.startswith(_SWTPM_MANUFACTURER):
            ectx.close()
            raise RuntimeError(f"refusing a TPM whose manufacturer is {manufacturer!r}")
        return ectx
