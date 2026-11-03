"""Exercise the real load boundary without requiring tpm2-pytss or a TPM."""

from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, call

import pytest

from cmcp_runtime.tee import seal


class LoadError(RuntimeError):
    def __init__(self, rc: int) -> None:
        super().__init__(f"load failed: {rc:#x}")
        self.rc = rc
        # Mirror tpm2-pytss' format-one error normalization, including its
        # low-bit normalization for errors originating in a TSS layer.
        self.error = 0x80 + (rc & 0x3F) if rc & 0x80 else rc


@pytest.fixture
def context(monkeypatch: pytest.MonkeyPatch) -> Mock:
    constants = ModuleType("tpm2_pytss.constants")
    constants.ESYS_TR = SimpleNamespace(PASSWORD=0)  # type: ignore[attr-defined]
    constants.TPM2_EO = SimpleNamespace(EQ=0)  # type: ignore[attr-defined]
    constants.TPM2_SE = SimpleNamespace(POLICY=0)  # type: ignore[attr-defined]
    constants.TPMA_SESSION = SimpleNamespace(ENCRYPT=1)  # type: ignore[attr-defined]
    types = ModuleType("tpm2_pytss.types")
    types.TPM2B_PRIVATE = Mock(unmarshal=Mock(return_value=("private", 0)))  # type: ignore[attr-defined]
    types.TPM2B_PUBLIC = Mock(unmarshal=Mock(return_value=("public", 0)))  # type: ignore[attr-defined]
    types.TPM2B_OPERAND = Mock(side_effect=lambda value: value)  # type: ignore[attr-defined]
    for module in (ModuleType("tpm2_pytss"), constants, types):
        monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setattr(seal, "_storage_parent", Mock(return_value="parent"))
    monkeypatch.setattr(seal, "_salted_session", Mock(return_value="session"))
    return Mock(load=Mock(return_value="object"), unseal=Mock(return_value=b"x" * 32))


def _blob() -> seal.SealedBlob:
    return seal.SealedBlob(digest=b"d" * 32, private=b"private", public=b"public")


@pytest.mark.parametrize(
    "fault",
    [
        LoadError(0x902),  # TPM_RC_OBJECT_MEMORY
        LoadError(0x922),  # TPM_RC_RETRY
        OSError("transport unavailable"),
        RuntimeError("unknown load failure"),
        LoadError(0x000A01DF),  # TSS-layer error with the same low bits
        LoadError(0x09F),  # integrity code without attribution to inPrivate
    ],
)
def test_load_failure_is_unavailable_unless_private_integrity_failed(
    context: Mock, fault: Exception
) -> None:
    context.load.side_effect = fault
    with pytest.raises(seal.SealedKeyUnavailable, match="could not load") as caught:
        seal._unseal(context, _blob(), "gate")
    assert caught.value.__cause__ is fault
    context.policy_nv.assert_not_called()
    context.unseal.assert_not_called()
    assert context.flush_context.call_args_list == [call("parent")]


def test_private_integrity_failure_preserves_the_custody_diagnostic(context: Mock) -> None:
    fault = LoadError(0x1DF)
    context.load.side_effect = fault
    with pytest.raises(seal.SealedKeyTpmChanged, match="does not load") as caught:
        seal._unseal(context, _blob(), "gate")
    assert caught.value.__cause__ is fault
    context.policy_nv.assert_not_called()
    context.unseal.assert_not_called()
    assert context.flush_context.call_args_list == [call("parent")]


def test_successful_load_still_unseals_and_releases_all_handles(context: Mock) -> None:
    assert seal._unseal(context, _blob(), "gate") == b"x" * 32
    context.load.assert_called_once_with("parent", "private", "public")
    context.policy_nv.assert_called_once()
    context.unseal.assert_called_once_with("object", session1="session")
    assert context.flush_context.call_args_list == [call("session"), call("object"), call("parent")]
