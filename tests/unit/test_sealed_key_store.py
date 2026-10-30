"""The sealed-key store, lock and policy computation, without a TPM (#462)."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path

import pytest

from cmcp_runtime.tee import seal
from cmcp_runtime.tee.seal import (
    MAX_BLOBS,
    SealedBlob,
    SealedKeyLocked,
    SealedKeyStore,
    SealedKeyUnavailable,
    StoreContents,
)

_PUBLIC = seal.ed25519_public_key(b"\x01" * 32)


def _blob(tag: bytes) -> SealedBlob:
    return SealedBlob(digest=hashlib.sha256(tag).digest(), private=b"p" + tag, public=b"q" + tag)


def test_the_gate_name_and_policy_are_pinned() -> None:
    """Both are computed without a TPM, and a sealed blob's policy depends on them.

    Changing either silently orphans every blob already sealed, so they are pinned.
    The swtpm suite checks the same two values against a real TPM.
    """
    assert seal.gate_nv_public_bytes(written=True).hex() == "01500433000b2206000200000020"
    assert seal.gate_nv_name().hex() == (
        "000bdefc8525f61ba7069c41d01c7a1028b6338901d94b1a17aa0cfa15843e77e9f2"
    )
    assert seal.policy_nv_digest(bytes(32)).hex() == (
        "6a642e0d8c47a4820674c91c3168d55eb704ab98da24f3977027a8d3f85d7a92"
    )


def test_a_digest_that_is_not_32_bytes_is_rejected() -> None:
    with pytest.raises(ValueError):
        seal.policy_nv_digest(b"short")


def test_the_store_round_trips_and_keeps_two_blobs(tmp_path: Path) -> None:
    store = SealedKeyStore(tmp_path / "sealed")
    assert store.read() is None
    contents = StoreContents(seal.DEFAULT_GATE_NV_INDEX, _PUBLIC, (_blob(b"a"),))
    for tag in (b"b", b"c"):
        contents = contents.with_blob(_blob(tag))
    store.write(contents)

    read = store.read()
    assert read == contents
    assert len(read.blobs) == MAX_BLOBS  # type: ignore[union-attr]
    assert [b.digest for b in read.blobs] == [_blob(b"b").digest, _blob(b"c").digest]  # type: ignore[union-attr]


def test_resealing_to_a_known_digest_replaces_it_rather_than_duplicating() -> None:
    contents = StoreContents(seal.DEFAULT_GATE_NV_INDEX, _PUBLIC, (_blob(b"a"), _blob(b"b")))
    again = contents.with_blob(SealedBlob(_blob(b"a").digest, b"new", b"new"))
    assert [b.digest for b in again.blobs] == [_blob(b"b").digest, _blob(b"a").digest]
    assert again.blob_for(_blob(b"a").digest).private == b"new"  # type: ignore[union-attr]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_the_store_file_is_owner_only_and_leaves_no_temporary(tmp_path: Path) -> None:
    store = SealedKeyStore(tmp_path / "sealed")
    store.write(StoreContents(seal.DEFAULT_GATE_NV_INDEX, _PUBLIC, (_blob(b"a"),)))
    assert stat.S_IMODE(os.stat(store.path).st_mode) == 0o600
    assert sorted(p.name for p in store.directory.iterdir()) == [seal.STORE_FILENAME]


@pytest.mark.parametrize(
    "payload",
    [
        "not json",
        json.dumps({"version": 2, "gate_index": "0x01500433", "public_key": "", "blobs": []}),
        json.dumps({"version": 1, "gate_index": "0x01500433", "public_key": "00", "blobs": []}),
        json.dumps(
            {"version": 1, "gate_index": "0x01500433", "public_key": _PUBLIC.hex(), "blobs": []}
        ),
        json.dumps({"version": 1}),
    ],
)
def test_a_malformed_store_is_an_error_not_an_empty_store(tmp_path: Path, payload: str) -> None:
    """Reading it as empty would let startup provision a second key."""
    store = SealedKeyStore(tmp_path)
    store.path.write_text(payload)
    with pytest.raises(SealedKeyUnavailable):
        store.read()


@pytest.mark.skipif(sys.platform == "win32", reason="the TPM tier is Linux-only")
def test_a_second_process_cannot_hold_the_store(tmp_path: Path) -> None:
    """S11. flock is per open file description, so a second open in one process
    behaves like a second process."""
    store = SealedKeyStore(tmp_path / "sealed")
    held = store.acquire()
    with pytest.raises(SealedKeyLocked):
        SealedKeyStore(tmp_path / "sealed").acquire()
    held.release()
    SealedKeyStore(tmp_path / "sealed").acquire().release()


def test_an_opened_key_never_prints_its_seed() -> None:
    opened = seal.OpenedKey(seed=b"\xab" * 32, public_key=_PUBLIC, provisioned=False)
    assert ("ab" * 32) not in repr(opened)
    assert ("ab" * 32) not in str(opened)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_an_unusable_directory_is_a_sealed_key_error(tmp_path: Path) -> None:
    """Startup reports SEALED_KEY_UNAVAILABLE rather than a raw OSError traceback."""
    if os.geteuid() == 0:
        pytest.skip("root ignores directory permissions")
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    try:
        store = SealedKeyStore(locked / "sealed")
        with pytest.raises(SealedKeyUnavailable, match="directory could not be used"):
            store.acquire()
        with pytest.raises(SealedKeyUnavailable, match="could not be written"):
            store.write(StoreContents(seal.DEFAULT_GATE_NV_INDEX, _PUBLIC, (_blob(b"a"),)))
    finally:
        locked.chmod(0o700)
