"""The TRACE signing key, sealed to the gateway measurement on the TPM tier (#462).

The key is an Ed25519 seed sealed under ``TPM2_PolicyNV(gate == digest)``, where the
gate is an ordinary NV index that holds the current gateway digest. It is not sealed
to the measurement index itself: that index is a ``TPM_NT_EXTEND`` chain that moves
on every start, and ``PolicyNV`` compares one exact value, so a key sealed to it
would match a single position in the chain and be lost on the next restart.

One start is: extend and certify the measurement as before, write the computed
digest into the gate, unseal, then overwrite the gate with a sentinel. Between
starts the gate holds the sentinel, so another process with TPM access cannot
unseal passively; it has to write the gate itself, which needs owner
authorization. The gate is per TPM, so there is one sealed gateway per TPM.

What this guarantees: the blob is useless on any other TPM; a gateway whose
measured inputs differ from the sealed digest, with its measurement code intact,
does not get the key; and the key survives restarts, so a relying party can pin it.

What it does not: anyone who can issue owner-authorized TPM commands can write an
approved digest into the gate and unseal, and on Azure guest root can. A modified
gateway that reports the approved digest gets the key. The key is sealed data, so
nothing in the evidence can show that it is sealed.

The storage parent is recreated from a fixed template on every use and never made
persistent. Sessions that carry the seed are salted with that parent and encrypt
the parameter, so the seed does not cross the TPM interface in clear.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cmcp_runtime.errors import CMCPError

logger = logging.getLogger(__name__)

#: Next to the measurement index (0x01500432) in the owner range.
DEFAULT_GATE_NV_INDEX = 0x01500433

STORE_FILENAME = "sealed-signing-key.json"
LOCK_FILENAME = "sealed-signing-key.lock"
STORE_VERSION = 1

#: The current blob and the one before it, so a rollback to the previous build
#: still unseals.
MAX_BLOBS = 2

SEED_SIZE = 32

#: What the gate holds between starts. Never a gateway digest: those are
#: SHA-256 outputs over a domain-separated input, so a collision with this value
#: is not a practical concern.
GATE_SENTINEL = hashlib.sha256(b"cmcp-seal-gate-closed-v1").digest()

_GATE_SIZE = 32
_GATE_NAME_ALG = 0x000B  # TPM2_ALG_SHA256
_TPMA_NV_OWNERWRITE = 0x00000002
_TPMA_NV_OWNERREAD = 0x00020000
_TPMA_NV_AUTHREAD = 0x00040000
_TPMA_NV_NO_DA = 0x02000000
_TPMA_NV_WRITTEN = 0x20000000
#: An ordinary index: TPM_NT_ORDINARY is zero, so no type bits are set.
GATE_BASE_ATTRIBUTES = _TPMA_NV_OWNERWRITE | _TPMA_NV_OWNERREAD | _TPMA_NV_AUTHREAD | _TPMA_NV_NO_DA
GATE_WRITTEN_ATTRIBUTES = GATE_BASE_ATTRIBUTES | _TPMA_NV_WRITTEN

_TPM_CC_POLICY_NV = 0x00000149
_TPM_EO_EQ = 0x0000
#: TPM 2.0 Part 2 response codes, as tpm2-pytss reports them in ``error``: the base
#: code without the format-one parameter, handle or session number.
_TPM_RC_POLICY = 0x126
_TPM_RC_POLICY_FAIL = 0x09D
_TPM_RC_HANDLE = 0x08B
# TPM2_Load: TPM_RC_INTEGRITY attributed to inPrivate (parameter 1).
_TPM_RC_LOAD_INTEGRITY = 0x1DF


class SealedKeyError(CMCPError):
    """Base for the sealed-key startup failures. Each subclass has its own code."""

    code = "SEALED_KEY_UNAVAILABLE"
    http_status = 500


class SealedKeyUnavailable(SealedKeyError):
    """The TPM, the library or the store could not be used at all."""

    code = "SEALED_KEY_UNAVAILABLE"


class SealedKeyDigestMismatch(SealedKeyError):
    """No blob is sealed to this gateway digest, or the TPM refused the unseal."""

    code = "SEALED_KEY_DIGEST_MISMATCH"


class SealedKeyTpmChanged(SealedKeyError):
    """The gate is absent or the blob fails integrity under this TPM's parent."""

    code = "SEALED_KEY_TPM_CHANGED"


class SealedKeyMissing(SealedKeyError):
    """This TPM has a gate but there is no sealed blob for it."""

    code = "SEALED_KEY_MISSING"


class SealedKeyPublicKeyMismatch(SealedKeyError):
    """The stored public key does not match the unsealed secret."""

    code = "SEALED_KEY_PUBLIC_KEY_MISMATCH"


class SealedKeyLocked(SealedKeyError):
    """Another process holds the sealed-key state directory."""

    code = "SEALED_KEY_LOCKED"


# --- the gate's Name and the policy, computed without a TPM ---------------------------


def gate_nv_public_bytes(index: int = DEFAULT_GATE_NV_INDEX, *, written: bool = True) -> bytes:
    """Marshal the gate's ``TPMS_NV_PUBLIC``: same layout as the measurement index."""
    if not 0x01000000 <= index <= 0x01FFFFFF:
        raise ValueError(f"index is not a TPM NV handle: {index:#x}")
    attributes = GATE_WRITTEN_ATTRIBUTES if written else GATE_BASE_ATTRIBUTES
    return struct.pack(">IHIH", index, _GATE_NAME_ALG, attributes, 0) + struct.pack(
        ">H", _GATE_SIZE
    )


def gate_nv_name(index: int = DEFAULT_GATE_NV_INDEX, *, written: bool = True) -> bytes:
    """The gate's Name; written by default, which is the form ``PolicyNV`` binds.

    The WRITTEN bit is part of the Name, and the gate is always written before a
    policy session runs against it. The unwritten form only identifies a gate whose
    provisioning stopped between its definition and its first write.
    """
    public = gate_nv_public_bytes(index, written=written)
    return struct.pack(">H", _GATE_NAME_ALG) + hashlib.sha256(public).digest()


def policy_nv_digest(digest: bytes, index: int = DEFAULT_GATE_NV_INDEX) -> bytes:
    """``PolicyNV(gate == digest)`` from an empty policy, per TPM 2.0 Part 3.

    ``args = H(operandB || offset || operation)``, then
    ``policy = H(0^32 || TPM_CC_PolicyNV || args || nvIndex.Name)``. Computing it in
    software is what lets a key be resealed to a digest no gateway has produced yet.
    """
    if len(digest) != _GATE_SIZE:
        raise ValueError("a gateway digest is 32 bytes")
    args = hashlib.sha256(digest + struct.pack(">HH", 0, _TPM_EO_EQ)).digest()
    return hashlib.sha256(
        bytes(32) + struct.pack(">I", _TPM_CC_POLICY_NV) + args + gate_nv_name(index)
    ).digest()


def ed25519_public_key(seed: bytes) -> bytes:
    """The raw public key for a 32-byte Ed25519 seed."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


# --- the store -------------------------------------------------------------------------


@dataclass(frozen=True)
class SealedBlob:
    """One TPM2_Create result: the seed sealed to one gateway digest."""

    digest: bytes
    private: bytes  # marshalled TPM2B_PRIVATE
    public: bytes  # marshalled TPM2B_PUBLIC


@dataclass(frozen=True)
class StoreContents:
    gate_index: int
    public_key: bytes
    blobs: tuple[SealedBlob, ...]  # oldest first

    def blob_for(self, digest: bytes) -> SealedBlob | None:
        for blob in self.blobs:
            if blob.digest == digest:
                return blob
        return None

    def with_blob(self, blob: SealedBlob) -> StoreContents:
        """Add or replace ``blob``, keeping at most :data:`MAX_BLOBS`."""
        kept = tuple(b for b in self.blobs if b.digest != blob.digest)
        return StoreContents(self.gate_index, self.public_key, (kept + (blob,))[-MAX_BLOBS:])


class StoreLock:
    """An exclusive lock on the state directory, held until released."""

    def __init__(self, handle: Any) -> None:
        self._handle = handle

    def release(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None


class SealedKeyStore:
    """The sealed blobs and public key, in one JSON file in a state directory.

    Nothing in it is secret: a blob only unseals on the TPM that created it and only
    under its policy. It is still integrity-relevant, which is why the public key
    is checked against the unsealed secret rather than trusted.
    """

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)
        self.path = self.directory / STORE_FILENAME
        self.lock_path = self.directory / LOCK_FILENAME

    def read(self) -> StoreContents | None:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise SealedKeyUnavailable(
                "the sealed signing key store could not be read", detail=f"{self.path}: {exc}"
            ) from exc
        try:
            data = json.loads(raw)
            if data["version"] != STORE_VERSION:
                raise ValueError(f"unsupported version {data['version']!r}")
            contents = StoreContents(
                gate_index=int(data["gate_index"], 16),
                public_key=bytes.fromhex(data["public_key"]),
                blobs=tuple(
                    SealedBlob(
                        digest=bytes.fromhex(b["digest"]),
                        private=bytes.fromhex(b["private"]),
                        public=bytes.fromhex(b["public"]),
                    )
                    for b in data["blobs"]
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise SealedKeyUnavailable(
                "the sealed signing key store is malformed", detail=f"{self.path}: {exc}"
            ) from exc
        if len(contents.public_key) != 32 or not contents.blobs:
            raise SealedKeyUnavailable(
                "the sealed signing key store has no usable key", detail=str(self.path)
            )
        return contents

    def write(self, contents: StoreContents) -> None:
        """Replace the store atomically: write, fsync, rename, fsync the directory."""
        try:
            self._write(contents)
        except OSError as exc:
            raise SealedKeyUnavailable(
                "the sealed signing key store could not be written", detail=f"{self.path}: {exc}"
            ) from exc

    def _write(self, contents: StoreContents) -> None:
        payload = {
            "version": STORE_VERSION,
            "gate_index": f"{contents.gate_index:#010x}",
            "public_key": contents.public_key.hex(),
            "blobs": [
                {"digest": b.digest.hex(), "private": b.private.hex(), "public": b.public.hex()}
                for b in contents.blobs
            ],
        }
        self.directory.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
        if hasattr(os, "O_DIRECTORY"):
            dir_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)

    def acquire(self) -> StoreLock:
        """Lock the directory, or raise :class:`SealedKeyLocked` if it is held.

        Two processes sharing one store would share one gate, and an interleaved
        open-unseal-close sequence lets one of them read the other's gate value.
        """
        if sys.platform == "win32":  # also tells mypy fcntl below is POSIX-only
            raise SealedKeyUnavailable("sealing needs fcntl, so it is Linux-only")
        import fcntl

        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            handle = open(self.lock_path, "w")  # noqa: SIM115 - held for the lock's lifetime
        except OSError as exc:
            raise SealedKeyUnavailable(
                "the sealed signing key directory could not be used",
                detail=f"{self.lock_path}: {exc}",
            ) from exc
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            handle.close()
            raise SealedKeyLocked(
                "another process holds the sealed signing key", detail=str(self.directory)
            ) from exc
        return StoreLock(handle)


# --- TPM primitives ----------------------------------------------------------------------


def _storage_parent(ectx: Any) -> Any:
    """The storage parent: one fixed template under the owner hierarchy.

    The same template and owner seed give the same key, so it is recreated on every
    use rather than made persistent. With an owner password set, a process without
    it cannot create the parent and so cannot load the blob.
    """
    from tpm2_pytss.constants import ESYS_TR, TPMA_OBJECT
    from tpm2_pytss.types import TPM2B_PUBLIC

    attributes = (
        TPMA_OBJECT.USERWITHAUTH
        | TPMA_OBJECT.RESTRICTED
        | TPMA_OBJECT.DECRYPT
        | TPMA_OBJECT.FIXEDTPM
        | TPMA_OBJECT.FIXEDPARENT
        | TPMA_OBJECT.SENSITIVEDATAORIGIN
        | TPMA_OBJECT.NODA
    )
    try:
        handle, *_ = ectx.create_primary(
            None, TPM2B_PUBLIC.parse("ecc256:aes128cfb", objectAttributes=attributes), ESYS_TR.OWNER
        )
    except Exception as exc:  # noqa: BLE001
        raise SealedKeyUnavailable(
            "the storage parent could not be created; an owner password may be set",
            detail=str(exc),
        ) from exc
    return handle


def _salted_session(ectx: Any, parent: Any, session_type: Any, attributes: Any) -> Any:
    """A session salted with ``parent`` that encrypts one parameter with AES-128-CFB."""
    from tpm2_pytss.constants import ESYS_TR, TPM2_ALG, TPMA_SESSION
    from tpm2_pytss.types import TPMT_SYM_DEF, TPMU_SYM_KEY_BITS, TPMU_SYM_MODE

    symmetric = TPMT_SYM_DEF(
        algorithm=TPM2_ALG.AES,
        keyBits=TPMU_SYM_KEY_BITS(aes=128),
        mode=TPMU_SYM_MODE(aes=TPM2_ALG.CFB),
    )
    try:
        session = ectx.start_auth_session(
            parent, ESYS_TR.NONE, session_type, symmetric, TPM2_ALG.SHA256
        )
        ectx.trsess_set_attributes(session, TPMA_SESSION.CONTINUESESSION | attributes)
    except Exception as exc:  # noqa: BLE001
        raise SealedKeyUnavailable("a TPM session could not be started", detail=str(exc)) from exc
    return session


def _is_policy_refusal(exc: Exception) -> bool:
    """Whether the TPM refused because the gate does not hold the blob's digest.

    That is ``TPM_RC_POLICY`` from ``PolicyNV`` when the comparison fails, or
    ``TPM_RC_POLICY_FAIL`` from the unseal when the session's policy is not the
    blob's. Any other failure is the TPM failing, not a mismatch, and reporting it
    as one would send an operator to reseal for nothing.
    """
    return _tpm_error(exc) in (_TPM_RC_POLICY, _TPM_RC_POLICY_FAIL)


def _tpm_error(exc: Exception) -> int | None:
    """The TPM response code tpm2-pytss attached to ``exc``, or None if it has none."""
    error = getattr(exc, "error", None)
    try:
        return None if error is None else int(error)
    except (TypeError, ValueError):
        return None


def _gate_handle(ectx: Any, index: int) -> Any | None:
    """The gate's handle, or None when the TPM says the index is not defined.

    Only ``TPM_RC_HANDLE`` means that. A TPM that fails to answer is not a TPM
    without a gate: reading it as one would report SEALED_KEY_TPM_CHANGED, whose
    remedy is a new key, for a TPM that is only unavailable.
    """
    try:
        return ectx.tr_from_tpmpublic(index)
    except Exception as exc:  # noqa: BLE001
        if _tpm_error(exc) == _TPM_RC_HANDLE:
            logger.debug("gate NV index %#x is not defined: %s", index, exc)
            return None
        raise SealedKeyUnavailable(
            "the gate NV index could not be read", detail=f"index={index:#x}: {exc}"
        ) from exc


def _gate_name(ectx: Any, handle: Any, index: int) -> bytes:
    try:
        _public, name = ectx.nv_read_public(handle)
    except Exception as exc:  # noqa: BLE001
        raise SealedKeyUnavailable(
            "the gate NV index could not be read", detail=f"index={index:#x}: {exc}"
        ) from exc
    return bytes(name)


def _check_gate(ectx: Any, handle: Any, index: int) -> None:
    """Fail unless the gate is the exact written profile ``policy_nv_digest`` assumes.

    The Name binding already makes a different index useless for unsealing; this
    turns that into a clear error instead of a refused unseal.
    """
    name = _gate_name(ectx, handle, index)
    if name != gate_nv_name(index):
        raise SealedKeyUnavailable(
            "the gate NV index does not match the sealed-key profile",
            detail=f"index={index:#x} Name={bytes(name).hex()} expected={gate_nv_name(index).hex()}",
        )


def _define_gate(ectx: Any, index: int) -> Any:
    from tpm2_pytss.constants import ESYS_TR, TPM2_ALG
    from tpm2_pytss.types import TPM2B_DIGEST, TPM2B_NV_PUBLIC, TPMS_NV_PUBLIC

    public = TPM2B_NV_PUBLIC(
        nvPublic=TPMS_NV_PUBLIC(
            nvIndex=index,
            nameAlg=TPM2_ALG.SHA256,
            attributes=GATE_BASE_ATTRIBUTES,
            authPolicy=TPM2B_DIGEST(),
            dataSize=_GATE_SIZE,
        )
    )
    try:
        return ectx.nv_define_space(None, public, auth_handle=ESYS_TR.OWNER)
    except Exception as exc:  # noqa: BLE001
        raise SealedKeyUnavailable(
            "the gate NV index could not be defined", detail=f"index={index:#x}: {exc}"
        ) from exc


def _write_gate(ectx: Any, gate: Any, value: bytes) -> None:
    from tpm2_pytss.constants import ESYS_TR

    try:
        ectx.nv_write(gate, value, 0, auth_handle=ESYS_TR.OWNER)
    except Exception as exc:  # noqa: BLE001
        raise SealedKeyUnavailable(
            "the gate NV index could not be written; an owner password may be set",
            detail=str(exc),
        ) from exc


def _seal(ectx: Any, seed: bytes, digest: bytes, index: int) -> SealedBlob:
    """Seal ``seed`` under ``PolicyNV(gate == digest)``. Needs no policy session."""
    from tpm2_pytss.constants import ESYS_TR, TPM2_ALG, TPM2_SE, TPMA_OBJECT, TPMA_SESSION
    from tpm2_pytss.types import (
        TPM2B_DIGEST,
        TPM2B_PUBLIC,
        TPM2B_SENSITIVE_CREATE,
        TPM2B_SENSITIVE_DATA,
        TPMS_SENSITIVE_CREATE,
        TPMT_PUBLIC,
    )

    # No USERWITHAUTH, so the policy is the only way to authorize the unseal.
    template = TPMT_PUBLIC(
        type=TPM2_ALG.KEYEDHASH,
        nameAlg=TPM2_ALG.SHA256,
        objectAttributes=TPMA_OBJECT.FIXEDTPM | TPMA_OBJECT.FIXEDPARENT | TPMA_OBJECT.NODA,
        authPolicy=TPM2B_DIGEST(policy_nv_digest(digest, index)),
    )
    template.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG.NULL
    sensitive = TPM2B_SENSITIVE_CREATE(
        sensitive=TPMS_SENSITIVE_CREATE(data=TPM2B_SENSITIVE_DATA(seed))
    )
    parent = _storage_parent(ectx)
    try:
        session = _salted_session(ectx, parent, TPM2_SE.HMAC, TPMA_SESSION.DECRYPT)
        try:
            private, public, *_ = ectx.create(
                parent,
                sensitive,
                TPM2B_PUBLIC(publicArea=template),
                session1=ESYS_TR.PASSWORD,
                session2=session,
            )
        except Exception as exc:  # noqa: BLE001
            raise SealedKeyUnavailable("the TPM could not seal the key", detail=str(exc)) from exc
        finally:
            ectx.flush_context(session)
    finally:
        ectx.flush_context(parent)
    return SealedBlob(digest=digest, private=private.marshal(), public=public.marshal())


def _unseal(ectx: Any, blob: SealedBlob, gate: Any) -> bytes:
    """Load ``blob`` and unseal it under ``PolicyNV`` against the gate's current value."""
    from tpm2_pytss.constants import ESYS_TR, TPM2_EO, TPM2_SE, TPMA_SESSION
    from tpm2_pytss.types import TPM2B_OPERAND, TPM2B_PRIVATE, TPM2B_PUBLIC

    try:
        private = TPM2B_PRIVATE.unmarshal(blob.private)[0]
        public = TPM2B_PUBLIC.unmarshal(blob.public)[0]
    except Exception as exc:  # noqa: BLE001
        raise SealedKeyUnavailable("the sealed blob is malformed", detail=str(exc)) from exc
    parent = _storage_parent(ectx)
    try:
        try:
            obj = ectx.load(parent, private, public)
        except Exception as exc:  # noqa: BLE001
            # A resource/transport failure says nothing about the key's custody.
            # Match the complete TPM response: a TSS-layer error must not alias it.
            if getattr(exc, "rc", None) == _TPM_RC_LOAD_INTEGRITY:
                raise SealedKeyTpmChanged(
                    "the sealed blob does not load on this TPM: its integrity check failed; "
                    "another host, a cleared TPM, or an altered store",
                    detail=str(exc),
                ) from exc
            raise SealedKeyUnavailable(
                "the TPM could not load the sealed signing key", detail=str(exc)
            ) from exc
        try:
            session = _salted_session(ectx, parent, TPM2_SE.POLICY, TPMA_SESSION.ENCRYPT)
            try:
                try:
                    ectx.policy_nv(
                        gate,
                        gate,
                        session,
                        TPM2B_OPERAND(blob.digest),
                        TPM2_EO.EQ,
                        session1=ESYS_TR.PASSWORD,
                    )
                    secret = bytes(ectx.unseal(obj, session1=session))
                except Exception as exc:  # noqa: BLE001
                    if _is_policy_refusal(exc):
                        raise SealedKeyDigestMismatch(
                            "the TPM refused to unseal the signing key under this digest",
                            detail=str(exc),
                        ) from exc
                    raise SealedKeyUnavailable(
                        "the TPM failed while unsealing the signing key", detail=str(exc)
                    ) from exc
            finally:
                ectx.flush_context(session)
        finally:
            ectx.flush_context(obj)
    finally:
        ectx.flush_context(parent)
    if len(secret) != SEED_SIZE:
        raise SealedKeyUnavailable("the unsealed secret is not an Ed25519 seed")
    return secret


def _open_gate_and_unseal(ectx: Any, blob: SealedBlob, gate: Any) -> bytes:
    """Write the blob's digest into the gate, unseal, and close the gate again."""
    _write_gate(ectx, gate, blob.digest)
    try:
        return _unseal(ectx, blob, gate)
    finally:
        _write_gate(ectx, gate, GATE_SENTINEL)


# --- the operations ------------------------------------------------------------------------


@dataclass(frozen=True)
class OpenedKey:
    """The signing key a gateway start obtained."""

    seed: bytes
    public_key: bytes
    provisioned: bool  # True on the first start on this TPM

    def __repr__(self) -> str:  # never print the seed
        return (
            f"OpenedKey(public_key={self.public_key.hex()[:16]}..., provisioned={self.provisioned})"
        )


def stored_public_key(store: SealedKeyStore) -> bytes | None:
    """The sealed key's public half, readable before anything is unsealed."""
    contents = store.read()
    return contents.public_key if contents is not None else None


def _check_blob_policy(blob: SealedBlob, index: int) -> None:
    """Refuse a blob whose own policy is not ``PolicyNV`` over its label.

    The label in the store is not trusted: the TPM enforces the policy in the blob's
    public area whatever the label says. Checking it here gives the mismatch its own
    error before the gate is touched.
    """
    from tpm2_pytss.types import TPM2B_PUBLIC

    try:
        public = TPM2B_PUBLIC.unmarshal(blob.public)[0].publicArea
    except Exception as exc:  # noqa: BLE001
        raise SealedKeyUnavailable("the sealed blob is malformed", detail=str(exc)) from exc
    if bytes(public.authPolicy) != policy_nv_digest(blob.digest, index):
        raise SealedKeyDigestMismatch(
            "the sealed blob's policy does not match the digest it is stored under",
            detail=f"digest={blob.digest.hex()}",
        )


def _check_store_gate(contents: StoreContents, gate_index: int) -> None:
    if contents.gate_index != gate_index:
        raise SealedKeyUnavailable(
            "the sealed key was created for a different gate index",
            detail=f"stored={contents.gate_index:#x} configured={gate_index:#x}",
        )


def open_sealed_key(
    ectx: Any,
    store: SealedKeyStore,
    digest: bytes,
    *,
    gate_index: int = DEFAULT_GATE_NV_INDEX,
    seed_if_new: bytes | None = None,
) -> OpenedKey:
    """Provision or unseal the signing key for a gateway whose digest is ``digest``.

    A key is minted only on a TPM with no gate and no store. Every other state is
    either a successful unseal or one of the distinct errors; nothing is minted to
    recover from them, because minting on a mismatch would hand a changed gateway a
    working key and sealing would enforce nothing.

    ``seed_if_new`` is the seed to provision with. Startup passes one because the
    public key goes into the attestation nonce before this runs; it is ignored
    unless this call provisions.
    """
    contents = store.read()
    gate = _gate_handle(ectx, gate_index)

    if contents is None and gate is None:
        seed = seed_if_new if seed_if_new is not None else os.urandom(SEED_SIZE)
        if len(seed) != SEED_SIZE:  # before the TPM is touched, so a bad seed defines no gate
            raise ValueError("an Ed25519 seed is 32 bytes")
        gate = _define_gate(ectx, gate_index)
        _write_gate(ectx, gate, GATE_SENTINEL)
        _check_gate(ectx, gate, gate_index)
        public_key = ed25519_public_key(seed)
        first = _seal(ectx, seed, digest, gate_index)
        store.write(StoreContents(gate_index, public_key, (first,)))
        logger.info("Sealed signing key provisioned: %s...", public_key.hex()[:16])
        return OpenedKey(seed, public_key, provisioned=True)
    if contents is None:
        raise SealedKeyMissing(
            "this TPM has a sealed-key gate but there is no sealed key for it; "
            "restore the store or run `cmcp key rotate`",
            detail=str(store.path),
        )
    if gate is None:
        raise SealedKeyTpmChanged(
            "a sealed key exists but this TPM has no gate: another host, or the TPM was cleared",
            detail=f"index={gate_index:#x}",
        )
    _check_store_gate(contents, gate_index)
    _check_gate(ectx, gate, gate_index)

    blob = contents.blob_for(digest)
    if blob is None:
        raise SealedKeyDigestMismatch(
            "no sealed key exists for this gateway digest; reseal it before starting "
            "a changed gateway",
            detail=(
                f"digest={digest.hex()} sealed="
                + ",".join(b.digest.hex()[:16] for b in contents.blobs)
            ),
        )
    _check_blob_policy(blob, gate_index)
    seed = _open_gate_and_unseal(ectx, blob, gate)
    public_key = ed25519_public_key(seed)
    if public_key != contents.public_key:
        raise SealedKeyPublicKeyMismatch(
            "the stored public key does not match the sealed secret",
            detail=f"stored={contents.public_key.hex()[:16]} unsealed={public_key.hex()[:16]}",
        )
    return OpenedKey(seed, public_key, provisioned=False)


def reseal_held_key(
    ectx: Any,
    store: SealedKeyStore,
    seed: bytes,
    digest: bytes,
    *,
    gate_index: int = DEFAULT_GATE_NV_INDEX,
) -> None:
    """Seal a key this process already holds to another digest. Unseals nothing."""
    contents = store.read()
    if contents is None:
        raise SealedKeyMissing("there is no sealed key store to add to", detail=str(store.path))
    _check_store_gate(contents, gate_index)
    if ed25519_public_key(seed) != contents.public_key:
        raise SealedKeyPublicKeyMismatch("the held key is not the stored key")
    store.write(contents.with_blob(_seal(ectx, seed, digest, gate_index)))


def reseal_stored_key(
    ectx: Any,
    store: SealedKeyStore,
    to_digest: bytes,
    *,
    gate_index: int = DEFAULT_GATE_NV_INDEX,
) -> bytes:
    """``cmcp key reseal``: unseal the newest blob under its own digest, seal to another.

    For an upgrade, run before starting the new build. It opens the gate to the
    stored digest, which needs owner authorization, and keeps the key unchanged.
    """
    contents = store.read()
    if contents is None:
        raise SealedKeyMissing("there is no sealed key to reseal", detail=str(store.path))
    _check_store_gate(contents, gate_index)
    gate = _gate_handle(ectx, gate_index)
    if gate is None:
        raise SealedKeyTpmChanged(
            "this TPM has no sealed-key gate", detail=f"index={gate_index:#x}"
        )
    _check_gate(ectx, gate, gate_index)
    blob = contents.blobs[-1]
    _check_blob_policy(blob, gate_index)
    seed = _open_gate_and_unseal(ectx, blob, gate)
    if ed25519_public_key(seed) != contents.public_key:
        raise SealedKeyPublicKeyMismatch("the stored public key does not match the sealed secret")
    store.write(contents.with_blob(_seal(ectx, seed, to_digest, gate_index)))
    return contents.public_key


def rotate_sealed_key(
    ectx: Any,
    store: SealedKeyStore,
    digest: bytes,
    *,
    gate_index: int = DEFAULT_GATE_NV_INDEX,
) -> bytes:
    """``cmcp key rotate``: replace the key with a new one sealed to ``digest``.

    Also the recovery when the store is gone. Every previous blob is dropped, since
    they hold the old key. Relying parties pinning the old key must be told.
    """
    gate = _gate_handle(ectx, gate_index)
    if gate is None:
        gate = _define_gate(ectx, gate_index)
        _write_gate(ectx, gate, GATE_SENTINEL)
    elif _gate_name(ectx, gate, gate_index) == gate_nv_name(gate_index, written=False):
        # Provisioning stopped between defining the gate and its first write, which
        # startup reports as SEALED_KEY_MISSING with this command as the remedy. Only
        # this exact template is finished here; any other index is refused below.
        _write_gate(ectx, gate, GATE_SENTINEL)
    _check_gate(ectx, gate, gate_index)
    seed = os.urandom(SEED_SIZE)
    public_key = ed25519_public_key(seed)
    store.write(StoreContents(gate_index, public_key, (_seal(ectx, seed, digest, gate_index),)))
    logger.info("Sealed signing key rotated: %s...", public_key.hex()[:16])
    return public_key


# --- the running gateway ---------------------------------------------------------------


class HeldSealedKey:
    """The unsealed key for the life of a gateway process, and its store lock.

    Keeps the seed so a verified policy reload can seal it to the new digest
    without unsealing anything, and keeps the lock so no other process can open
    the same gate while this one runs.
    """

    def __init__(
        self,
        store: SealedKeyStore,
        lock: StoreLock,
        opened: OpenedKey,
        digest: bytes,
        gate_index: int = DEFAULT_GATE_NV_INDEX,
    ) -> None:
        self.store = store
        self.public_key = opened.public_key
        self.provisioned = opened.provisioned
        self.gate_index = gate_index
        self.sealed_digest = digest
        self._lock = lock
        self._seed = opened.seed

    @property
    def seed(self) -> bytes:
        return self._seed

    def reseal(self, ectx: Any, digest: bytes) -> bool:
        """Seal the held key to ``digest``. False when it already is."""
        if digest == self.sealed_digest:
            return False
        reseal_held_key(ectx, self.store, self._seed, digest, gate_index=self.gate_index)
        self.sealed_digest = digest
        return True

    def release(self) -> None:
        self._lock.release()

    def __repr__(self) -> str:
        return f"HeldSealedKey(public_key={self.public_key.hex()[:16]}..., store={self.store.path})"


def reseal_after_reload(ctx: Any) -> bool:
    """After a verified policy reload, seal the held key to the gateway's new digest.

    ``ctx`` is a :class:`~cmcp_runtime.startup.RuntimeContext`, typed loosely to keep
    this module free of an import cycle back through startup.

    A reload that changes the bundle has passed the pinned signing key or the
    pinned hash, and only then does the evaluator call back. The new digest takes
    code and config from the startup measurement and recomputes only policy, so a
    file changed on disk outside a reload is not sealed in. The bundle is read once,
    and that read is sealed only if its canonical hash is the bundle the store
    accepted: a write after verification is refused, not sealed to. Returns True
    when a new blob was written. A refusal or failure is logged and swallowed: the
    gateway keeps serving with the key it holds, and the next start fails with
    ``SEALED_KEY_DIGEST_MISMATCH`` until ``cmcp key reseal`` is run.
    """
    held = getattr(ctx, "sealed_key", None)
    measured = getattr(ctx, "gateway_measurement", None)
    if held is None or measured is None:
        return False

    from cmcp_runtime.policy.bundle import bundle_hash_of_files
    from cmcp_runtime.tee.measurement import (
        measurement_from_components,
        policy_digest_of_files,
        read_policy_files,
    )

    try:
        files = read_policy_files(ctx.config.policy_bundle_path)
        accepted = ctx.policy_bundle.bundle.bundle_hash
        if bundle_hash_of_files(files) != accepted:
            logger.warning(
                "#462: the policy bundle on disk is not the one the reload verified "
                "(%s), so the signing key is not resealed; the next start will refuse "
                "with SEALED_KEY_DIGEST_MISMATCH until `cmcp key reseal` is run",
                accepted,
            )
            return False
        digest = measurement_from_components(
            {
                "code": measured.components["code"],
                "policy": policy_digest_of_files(files),
                "config": measured.components["config"],
            }
        ).digest
        if digest == held.sealed_digest:
            return False
        from tpm2_pytss.ESAPI import ESAPI

        with ESAPI() as ectx:
            held.reseal(ectx, digest)
    except Exception as exc:  # noqa: BLE001 - enforcement must not depend on the TPM
        logger.warning(
            "#462: the signing key could not be resealed after a policy reload, so "
            "the next start will refuse with SEALED_KEY_DIGEST_MISMATCH until "
            "`cmcp key reseal` is run: %s: %s",
            type(exc).__name__,
            exc,
        )
        return False
    logger.info("#462: signing key resealed to the reloaded digest %s", digest.hex()[:16])
    return True
