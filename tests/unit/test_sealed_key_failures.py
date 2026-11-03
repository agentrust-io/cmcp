"""Sealed signing key failures that need no TPM (#462).

These are the refusals that happen before the TPM is asked anything: bad inputs, a
store that does not fit, a platform without the lock, a host without tpm2-pytss.
What the TPM itself refuses is in tests/integration/test_sealed_signing_key_swtpm.py.
"""

from __future__ import annotations

import hashlib
import logging
import sys
from pathlib import Path

import pytest

from cmcp_runtime.tee import seal
from cmcp_runtime.tee.seal import (
    HeldSealedKey,
    OpenedKey,
    SealedBlob,
    SealedKeyMissing,
    SealedKeyPublicKeyMismatch,
    SealedKeyStore,
    SealedKeyUnavailable,
    StoreContents,
)

_SEED = b"\x01" * 32
_PUBLIC = seal.ed25519_public_key(_SEED)
_DIGEST = hashlib.sha256(b"gateway").digest()

_linux_only = pytest.mark.skipif(sys.platform == "win32", reason="the TPM tier is Linux-only")


def _store(tmp_path: Path) -> SealedKeyStore:
    store = SealedKeyStore(tmp_path / "sealed")
    blob = SealedBlob(digest=_DIGEST, private=b"p", public=b"q")
    store.write(StoreContents(seal.DEFAULT_GATE_NV_INDEX, _PUBLIC, (blob,)))
    return store


def test_a_gate_handle_outside_the_nv_range_is_refused() -> None:
    with pytest.raises(ValueError, match="not a TPM NV handle"):
        seal.gate_nv_public_bytes(0x81000001)


def test_an_unreadable_store_is_a_sealed_key_error(tmp_path: Path) -> None:
    store = SealedKeyStore(tmp_path)
    store.path.mkdir()  # a directory where the file should be
    with pytest.raises(SealedKeyUnavailable, match="could not be read"):
        store.read()


def test_without_flock_the_store_refuses_to_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(seal.sys, "platform", "win32")
    with pytest.raises(SealedKeyUnavailable, match="Linux-only"):
        SealedKeyStore(tmp_path).acquire()


def test_an_error_without_a_readable_response_code_is_not_a_digest_mismatch() -> None:
    """Only a policy refusal may be reported as a mismatch; anything unreadable is not."""
    error = RuntimeError("odd")
    error.error = "not-a-number"  # type: ignore[attr-defined]
    assert seal._is_policy_refusal(error) is False


def test_a_store_made_for_another_gate_index_is_refused(tmp_path: Path) -> None:
    contents = _store(tmp_path).read()
    assert contents is not None
    with pytest.raises(SealedKeyUnavailable, match="different gate index"):
        seal._check_store_gate(contents, seal.DEFAULT_GATE_NV_INDEX + 1)


def test_resealing_refuses_before_the_tpm_without_a_store_or_with_another_key(
    tmp_path: Path,
) -> None:
    # No ESAPI context is passed: each refusal has to come before the TPM is used.
    empty = SealedKeyStore(tmp_path / "none")
    with pytest.raises(SealedKeyMissing):
        seal.reseal_held_key(None, empty, _SEED, _DIGEST)
    with pytest.raises(SealedKeyMissing):
        seal.reseal_stored_key(None, empty, _DIGEST)
    with pytest.raises(SealedKeyPublicKeyMismatch):
        seal.reseal_held_key(None, _store(tmp_path), b"\x02" * 32, _DIGEST)


@_linux_only
def test_a_held_key_reseals_nothing_for_its_own_digest_and_never_prints_its_seed(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    held = HeldSealedKey(store, store.acquire(), OpenedKey(_SEED, _PUBLIC, False), _DIGEST)
    try:
        assert held.reseal(None, _DIGEST) is False
        assert _SEED.hex() not in repr(held)
    finally:
        held.release()


@_linux_only
def test_startup_without_tpm2_pytss_refuses_to_unseal(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cmcp_runtime.startup import _finish_sealed_start, _SealedStart
    from cmcp_runtime.tee.measurement import GatewayMeasurement

    monkeypatch.setitem(sys.modules, "tpm2_pytss", None)  # as on a host without it
    monkeypatch.setitem(sys.modules, "tpm2_pytss.ESAPI", None)
    store = SealedKeyStore(tmp_path / "sealed")
    start = _SealedStart(store, store.acquire(), _PUBLIC, None)
    try:
        with caplog.at_level(logging.CRITICAL), pytest.raises(SystemExit) as exc:
            _finish_sealed_start(start, GatewayMeasurement(_DIGEST, {}))
    finally:
        start.lock.release()
    assert exc.value.code == 1
    assert "SEALED_KEY_UNAVAILABLE" in caplog.text
    assert "tpm2-pytss is required" in caplog.text
