"""The suite-wide refusal of host TPM contexts (tests/conftest.py)."""

from __future__ import annotations

import pytest

ESAPI = pytest.importorskip("tpm2_pytss.ESAPI").ESAPI


@pytest.mark.parametrize("tcti", [None, "device:/dev/tpmrm0", "device", "tabrmd"])
def test_a_context_that_could_reach_a_device_is_refused(tcti: str | None) -> None:
    with pytest.raises(RuntimeError, match="refused an ESAPI context"):
        ESAPI(tcti)


def test_a_simulator_context_is_not_refused_by_the_guard() -> None:
    """Nothing listens on this port, so tpm2-tss fails to connect, not the guard."""
    with pytest.raises(Exception) as excinfo:
        ESAPI("swtpm:host=127.0.0.1,port=1")
    assert "refused an ESAPI context" not in str(excinfo.value)
