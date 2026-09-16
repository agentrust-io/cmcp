"""Measure the gateway into a TPM NV extend index (issue #432, RFC #439 P2).

PCRs 0 through 7 cover firmware, option ROMs, boot configuration, and the
bootloader. They do not cover the cMCP gateway, its policy bundle, or its
effective configuration, so replacing any of those produced an identical
measurement and the TPM enforced nothing about the thing the TPM path exists to
protect.

## Why an NV extend index and not an application PCR

Per the TCG PC Client Platform TPM Profile, PCR 23 is Application Support and PCR
16 is Debug, and **both are resettable from locality 0**. An adversary with local
code execution can reset PCR 23 and re-extend a value of their choosing, which is
precisely the adversary this tier exists to address, so an application PCR is
advisory rather than tamper-resistant. An NV index defined with ``TPM_NT_EXTEND``
is not resettable from locality 0.

## What this actually guarantees, and what it does not

``TPM_NT_EXTEND`` writes are one-way: ``new = H(old || data)``. An adversary who
can call ``TPM2_NV_Extend`` can therefore append values but **cannot set the index
to a chosen value** without finding a preimage. That is what makes the measurement
meaningful without depending on a write policy.

Owner authorization remains a hard limit. ``TPM2_NV_UndefineSpace`` followed by a
fresh define resets the index, and guest root holds owner auth on an Azure VM. The
collector now rejects any existing object whose complete public area and returned
Name do not match the configured extend profile, but that deterministic Name binds
an object *template*, not a unique object incarnation. ``TPMA_NV_WRITTEN`` is clear
only until the recreated object is first written; after that, the recreated object
has the same Name as the prior one. A stateless remote verifier therefore cannot
detect every undefine/recreate/reset sequence. Anti-rollback or continuity across
such a reset needs verifier-maintained state or a definition controlled by an
authorization hierarchy the guest cannot reset. This path proves a correctly
signed transition for the configured public template, not persistent object
identity or tamper-proof history.

## Validated on hardware

Exercised on a real Azure Trusted Launch vTPM (``Standard_D2s_v7``, eastus2,
2026-08-01): the index was defined with ``TPM_NT_EXTEND`` (confirmed by reading
``TPM_NT = 4`` back out of the public area), extends accumulated as
``H(old || data)`` across successive calls, an existing index was reused rather
than redefined, and **a plain ``TPM2_NV_Write`` to it was refused by the TPM**,
which validates the append-only behavior of that particular index incarnation.

The certify path was validated in the same session, after that run found two
defects in it: the ``nv_certify`` call omitted the required ``in_scheme`` and
``size`` arguments, and a freshly provisioned index cannot be certified at all. Both
are fixed; the platform AK does sign an NV certify, and its signed field layout
matched the value read from the hardware index. That run exercised cMCP's
then-local parser. The current adapter delegates to Agent Manifest, with the
committed swtpm reference pair independently exercising that parser boundary but
making no new hardware-provenance claim. See docs/testing/hardware-validation.md.

## Predictability is deliberately left to the verifier

Because extends accumulate and NV is persistent across reboots, the index value
after N gateway starts is a hash chain over all N digests, not ``H(0 ||
gateway_digest)``. A verifier therefore cannot recompute the expected value from
the current gateway digest alone. Continuity (``after == H(before || digest)``) is
what is checkable instead, which is the same hash-chain idiom cMCP already uses for
the audit log.

## Signed evidence

An NV read is not covered by any signature, so on its own the index value is a
local integrity control: a compromised gateway could report anything.
:func:`certify_and_extend_gateway_measurement` closes that with two
``TPM2_NV_Certify`` calls bracketing the extend. ``TPM2_NV_Certify`` signs only the
*current* value and cannot attest to a previous one, so one certify would be
uncheckable for the reason above; two give TPM-signed values whose relation a
verifier can appraise with no state and nothing collector-asserted. Appraisal is in
:mod:`cmcp_verify.nv_certify`.

Reading the index and committing the result into a quote's qualifying data would
*not* work: the collector would be asserting the value it read, and a compromised
gateway is the adversary.

:func:`extend_gateway_measurement` remains for the unsigned path, used where no
attestation key is available to certify with.
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
from dataclasses import dataclass
from importlib.metadata import Distribution, distributions
from pathlib import Path
from typing import Any

from cmcp_runtime.errors import CMCPError
from cmcp_verify.nv_policy import (
    DEFAULT_MEASUREMENT_NV_INDEX,
    MEASUREMENT_NV_BASE_ATTRIBUTES,
    MEASUREMENT_NV_NAME_ALG,
    MEASUREMENT_NV_SIZE,
    MEASUREMENT_NV_WRITTEN_ATTRIBUTES,
    measurement_nv_name,
)

logger = logging.getLogger(__name__)

# An extend index holds exactly one digest of its nameAlg, which is SHA-256 here.
_EXTEND_INDEX_SIZE = MEASUREMENT_NV_SIZE

# A freshly defined extend index is *uninitialised*, and TPM2_NV_Certify on an
# uninitialised index fails with TPM_RC_NV_UNINITIALIZED. So on the very first start
# there would be no pre-value to certify at all. Seeding the index once at provision
# time makes the pre-certify always possible, which keeps the verifier's
# post == H(pre || digest) check free of a first-boot special case. The seed value is
# irrelevant to security: the pre-certify signs whatever the index holds, and the
# verifier only checks the relation between the two certified values.
_INDEX_SEED = hashlib.sha256(b"cmcp-nv-index-initialised-v1").digest()

# Domain separator, versioned because the digest is compared across builds.
_DIGEST_PREFIX = b"cmcp-gateway-measurement-v1"

# Config keys never measured: they carry secrets, or they vary per process without
# changing what code or policy is running.
_CONFIG_SECRET_KEYS = frozenset({"bearer_token"})


class MeasurementUnavailable(CMCPError):
    """The gateway could not be measured, so there is nothing to extend."""

    code = "MEASUREMENT_UNAVAILABLE"
    http_status = 500


@dataclass(frozen=True)
class GatewayMeasurement:
    """The digest extended into the NV index, plus the inputs that produced it.

    ``components`` exists so a mismatch is debuggable. Without it a verifier only
    learns that the gateway changed, never which of code, policy, or config did,
    which is the same complaint #433 makes about bare PCR digests.
    """

    digest: bytes
    components: dict[str, str]

    @property
    def digest_hex(self) -> str:
        return "sha256:" + self.digest.hex()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def code_digest() -> str:
    """Digest every installed distribution by its recorded per-file hashes.

    Uses the ``RECORD`` metadata pip already writes, which lists a hash per
    installed file. That covers dependencies, not just cMCP's own packages: a
    swapped transitive package is the more likely supply-chain path and measuring
    only cMCP's own source would report an identical digest for it.

    Raises :class:`MeasurementUnavailable` when a distribution has no ``RECORD``
    (an editable or ``pth``-based install). That failure is deliberate rather than
    skipped: silently measuring a subset would report a confident digest over an
    unknown amount of code.
    """
    entries: list[str] = []
    missing: list[str] = []

    for dist in sorted(distributions(), key=_dist_sort_key):
        name = dist.metadata["Name"] or "unknown"
        version = dist.version
        file_hashes = _record_hashes(dist)
        if file_hashes is None:
            missing.append(f"{name} {version}")
            continue
        entries.append(
            json.dumps(
                {"name": name, "version": version, "files": file_hashes},
                separators=(",", ":"),
                sort_keys=True,
            )
        )

    if missing:
        raise MeasurementUnavailable(
            "the gateway cannot be measured: some installed distributions have no "
            "RECORD metadata, so their contents are unknown",
            detail=(
                f"{len(missing)} distribution(s) without RECORD: {', '.join(sorted(missing)[:5])}"
                f"{' ...' if len(missing) > 5 else ''}. This is normal for an editable "
                "install ('pip install -e'); measure a wheel or sdist install instead."
            ),
        )
    if not entries:
        raise MeasurementUnavailable(
            "the gateway cannot be measured: no installed distributions were found"
        )

    return _sha256_hex("\n".join(entries).encode())


def _dist_sort_key(dist: Distribution) -> tuple[str, str]:
    """Sort by (name, version) so the digest does not depend on scan order."""
    return ((dist.metadata["Name"] or "").lower(), dist.version or "")


def _record_hashes(dist: Distribution) -> dict[str, str] | None:
    """Return ``{path: hash}`` from a distribution's RECORD, or None if absent.

    RECORD is CSV: ``path,hash,size``, where hash is ``<algo>=<urlsafe-b64-nopad>``.
    Entries with an empty hash (RECORD itself, and generated scripts) are kept with
    an explicit marker rather than dropped, so a file gaining or losing a hash is
    visible in the digest instead of silently ignored.
    """
    try:
        record = dist.read_text("RECORD")
    except Exception as exc:  # noqa: BLE001 - unreadable metadata reads as absent
        logger.debug("RECORD unreadable for %s: %s", dist.metadata["Name"], exc)
        return None
    if not record:
        return None

    hashes: dict[str, str] = {}
    for row in csv.reader(record.splitlines()):
        if not row:
            continue
        path = row[0]
        digest = row[1] if len(row) > 1 and row[1] else "<none>"
        hashes[path] = digest
    return hashes or None


def policy_digest(policy_bundle_path: str) -> str:
    """Digest the policy bundle's file bytes.

    Deliberately independent of ``load_policy_bundle``'s canonical bundle hash:
    that runs at startup step 4, while the measurement has to be extended before
    the attestation report is produced at step 2. This reads bytes off disk and
    needs nothing validated first.
    """
    root = Path(policy_bundle_path)
    if not root.exists():
        raise MeasurementUnavailable(
            "the policy bundle path does not exist, so policy cannot be measured",
            detail=f"path={policy_bundle_path}",
        )

    files = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
    if not files:
        raise MeasurementUnavailable(
            "the policy bundle directory is empty, so policy cannot be measured",
            detail=f"path={policy_bundle_path}",
        )

    parts = [
        json.dumps(
            {
                "path": p.relative_to(root).as_posix() if root.is_dir() else p.name,
                "sha256": _sha256_hex(p.read_bytes()),
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        for p in files
    ]
    return _sha256_hex("\n".join(parts).encode())


def config_digest(config: Any) -> str:
    """Digest the effective configuration, excluding secrets.

    The bearer token is excluded: it authenticates callers rather than describing
    what is running, and extending a secret's digest into an index that is read
    back in evidence would leak an oracle for it.
    """
    return _sha256_hex(
        json.dumps(_config_payload(config), separators=(",", ":"), sort_keys=True).encode()
    )


def _config_payload(value: Any, *, _depth: int = 0) -> Any:
    """Reduce a config dataclass to canonical JSON, dropping secret keys."""
    if _depth > 8:
        return "<max-depth>"
    if hasattr(value, "__dataclass_fields__"):
        return {
            name: _config_payload(getattr(value, name), _depth=_depth + 1)
            for name in sorted(value.__dataclass_fields__)
            if name not in _CONFIG_SECRET_KEYS
        }
    if isinstance(value, dict):
        return {
            str(k): _config_payload(v, _depth=_depth + 1)
            for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))
            if str(k) not in _CONFIG_SECRET_KEYS
        }
    if isinstance(value, list | tuple):
        return [_config_payload(v, _depth=_depth + 1) for v in value]
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    # Enums and anything else: their stable string form.
    return getattr(value, "value", None) if hasattr(value, "value") else str(value)


def gateway_measurement(config: Any) -> GatewayMeasurement:
    """Compute the digest over installed code, the policy bundle, and the config."""
    components = {
        "code": code_digest(),
        "policy": policy_digest(config.policy_bundle_path),
        "config": config_digest(config),
    }
    canonical = json.dumps(components, separators=(",", ":"), sort_keys=True).encode()
    return GatewayMeasurement(
        digest=hashlib.sha256(_DIGEST_PREFIX + b"|" + canonical).digest(),
        components=components,
    )


@dataclass(frozen=True)
class ExtendResult:
    """The NV index state around a measurement extend.

    ``before`` and ``after`` are both returned so a relying party can check
    ``after == H(before || digest)`` rather than needing to predict an absolute
    value, which is impossible once extends accumulate across reboots.
    """

    index: int
    before: bytes
    after: bytes
    provisioned: bool  # True when this call had to define the index first

    def chains_from(self, digest: bytes) -> bool:
        """True when ``after`` is ``before`` extended by ``digest``.

        ``TPM_NT_EXTEND`` computes ``H(old || data)`` with the index's nameAlg,
        which this module always defines as SHA-256.
        """
        return self.after == hashlib.sha256(self.before + digest).digest()


def extend_gateway_measurement(
    ectx: Any, measurement: GatewayMeasurement, *, index: int = DEFAULT_MEASUREMENT_NV_INDEX
) -> ExtendResult:
    """Extend ``measurement`` into the NV index, defining it first if absent.

    Returns the value before and after. Raises :class:`MeasurementUnavailable` if
    the index cannot be defined, extended, or read back, so a gateway never
    proceeds believing it was measured when it was not.
    """

    provisioned = False
    handle = _nv_handle(ectx, index)
    if handle is None:
        _define_extend_index(ectx, index)
        provisioned = True
        handle = _nv_handle(ectx, index)
        if handle is None:
            raise MeasurementUnavailable(
                "the measurement NV index could not be read back after defining it",
                detail=f"index={index:#x}",
            )
        _validate_measurement_nv_public(ectx, handle, index, written=False)
    else:
        # A handle at the configured location is not sufficient.  Its Name commits
        # the handle, algorithm, complete attribute set, authorization policy and
        # size; accepting a different public area here would let an ordinary or
        # otherwise attacker-controlled NV index stand in for TPM_NT_EXTEND.
        _validate_measurement_nv_public(ectx, handle, index, written=True)

    before = _read_extend_index(ectx, handle)
    _extend(ectx, handle, measurement.digest, index)
    _validate_measurement_nv_public(ectx, handle, index, written=True)
    after = _read_extend_index(ectx, handle)
    result = ExtendResult(index=index, before=before, after=after, provisioned=provisioned)

    if not result.chains_from(measurement.digest):
        raise MeasurementUnavailable(
            "the NV index value does not chain from its previous value, so the "
            "measurement that was written is not the one computed",
            detail=(
                f"index={index:#x} before={before.hex()} after={after.hex()} "
                f"digest={measurement.digest.hex()}"
            ),
        )
    logger.info(
        "Gateway measured into NV %#x (%s): %s -> %s",
        index,
        "provisioned" if provisioned else "existing index",
        before.hex()[:16],
        after.hex()[:16],
    )
    return result


@dataclass(frozen=True)
class CertifiedExtend:
    """A TPM-signed proof that the gateway measurement was extended.

    Both certify blobs are signed by the TPM, so a relying party can check
    ``post_contents == H(pre_contents || digest)`` without trusting anything the
    collector says. See :mod:`cmcp_verify.nv_certify` for the appraisal.
    """

    extend: ExtendResult
    pre_attest: bytes
    pre_signature: bytes
    post_attest: bytes
    post_signature: bytes


def certify_and_extend_gateway_measurement(
    ectx: Any,
    measurement: GatewayMeasurement,
    *,
    sign_handle: Any,
    nonce: bytes,
    index: int = DEFAULT_MEASUREMENT_NV_INDEX,
) -> CertifiedExtend:
    """Certify the index, extend it, and certify again.

    ``TPM2_NV_Certify`` signs only the index's *current* value and cannot attest to
    a previous one. Since extends accumulate and NV is persistent, a single certify
    is uncheckable: there is no absolute value a verifier could expect. Two
    certifies bracketing the extend give two TPM-signed values whose relation is
    verifiable, with nothing collector-asserted and no verifier-side state.

    The two calls commit different qualifying data (``pre`` and ``post``), so each
    blob's role is signed rather than inferred from its position in the envelope.

    ``sign_handle`` must be the platform attestation key, so the signature chains to
    a vendor root. Raises :class:`MeasurementUnavailable` on any TPM fault, because
    a gateway must not proceed believing its measurement is attested when it is not.
    """
    from cmcp_verify.nv_certify import PHASE_POST, PHASE_PRE, certify_qualifying_data

    handle = _nv_handle(ectx, index)
    provisioned = False
    if handle is None:
        _define_extend_index(ectx, index)
        provisioned = True
        handle = _nv_handle(ectx, index)
        if handle is None:
            raise MeasurementUnavailable(
                "the measurement NV index could not be read back after defining it",
                detail=f"index={index:#x}",
            )
        _validate_measurement_nv_public(ectx, handle, index, written=False)
    else:
        _validate_measurement_nv_public(ectx, handle, index, written=True)

    if provisioned:
        # See _INDEX_SEED: an uninitialised index cannot be certified.
        _extend(ectx, handle, _INDEX_SEED, index)
        _validate_measurement_nv_public(ectx, handle, index, written=True)

    pre_attest, pre_sig = _certify_nv(
        ectx, handle, sign_handle, certify_qualifying_data(nonce, PHASE_PRE), phase="pre"
    )
    before = _read_extend_index(ectx, handle)
    _extend(ectx, handle, measurement.digest, index)
    _validate_measurement_nv_public(ectx, handle, index, written=True)
    after = _read_extend_index(ectx, handle)
    post_attest, post_sig = _certify_nv(
        ectx, handle, sign_handle, certify_qualifying_data(nonce, PHASE_POST), phase="post"
    )

    result = ExtendResult(index=index, before=before, after=after, provisioned=provisioned)
    if not result.chains_from(measurement.digest):
        raise MeasurementUnavailable(
            "the NV index value does not chain from its previous value, so the "
            "measurement that was written is not the one computed",
            detail=(
                f"index={index:#x} before={before.hex()} after={after.hex()} "
                f"digest={measurement.digest.hex()}"
            ),
        )
    logger.info(
        "Gateway measurement certified into NV %#x (%s): %s -> %s",
        index,
        "provisioned" if provisioned else "existing index",
        before.hex()[:16],
        after.hex()[:16],
    )
    return CertifiedExtend(
        extend=result,
        pre_attest=pre_attest,
        pre_signature=pre_sig,
        post_attest=post_attest,
        post_signature=post_sig,
    )


def _certify_nv(
    ectx: Any, nv_handle: Any, sign_handle: Any, qualifying_data: bytes, *, phase: str
) -> tuple[bytes, bytes]:
    """Run TPM2_NV_Certify and return the marshalled (attest, signature).

    ``in_scheme`` and ``size`` are required positional arguments, not optional:
    omitting them raises a ``TypeError`` before the TPM is ever reached, which is how
    the first hardware run failed. A NULL scheme means "use the signing key's own
    scheme", which for the Azure platform AK is RSASSA/SHA-256.
    """
    from tpm2_pytss.constants import ESYS_TR, TPM2_ALG
    from tpm2_pytss.types import TPM2B_DATA, TPMT_SIG_SCHEME

    try:
        attest, signature = ectx.nv_certify(
            sign_handle,
            nv_handle,
            TPM2B_DATA(qualifying_data),
            TPMT_SIG_SCHEME(scheme=TPM2_ALG.NULL),
            _EXTEND_INDEX_SIZE,
            0,
            auth_handle=ESYS_TR.OWNER,
        )
    except Exception as exc:  # noqa: BLE001
        raise MeasurementUnavailable(
            f"TPM2_NV_Certify ({phase}) failed, so the measurement is not attested",
            detail=f"{type(exc).__name__}: {exc}",
        ) from exc
    return bytes(attest.attestationData), bytes(signature.marshal())


def _extend(ectx: Any, handle: Any, digest: bytes, index: int) -> None:
    """Extend the measurement digest into the index."""
    from tpm2_pytss.constants import ESYS_TR

    try:
        ectx.nv_extend(handle, digest, auth_handle=ESYS_TR.OWNER)
    except Exception as exc:  # noqa: BLE001
        raise MeasurementUnavailable(
            "TPM2_NV_Extend failed, so the gateway is not measured",
            detail=f"index={index:#x}: {type(exc).__name__}: {exc}",
        ) from exc


def _nv_handle(ectx: Any, index: int) -> Any | None:
    """Return an ESYS handle for a defined NV index, or None when undefined."""
    try:
        return ectx.tr_from_tpmpublic(index)
    except Exception as exc:  # noqa: BLE001 - an undefined index is expected
        logger.debug("NV index %#x is not defined: %s", index, exc)
        return None


def _validate_measurement_nv_public(ectx: Any, handle: Any, index: int, *, written: bool) -> None:
    """Fail unless ``handle`` names the exact cMCP measurement-index profile.

    ``tr_from_tpmpublic(index)`` proves only that *some* object occupies the handle.
    The security property depends on the complete public area: SHA-256, the
    ``TPM_NT_EXTEND`` type, the exact owner/read/no-DA policy, no ``authPolicy``, and
    a single digest-sized value.  The TPM-managed ``WRITTEN`` bit is clear directly
    after definition and set after the first extend, so callers state which phase
    they are validating.  The returned Name is checked as well as the fields; that
    is the value subsequently signed by ``TPM2_NV_Certify``.
    """
    expected_attributes = (
        MEASUREMENT_NV_WRITTEN_ATTRIBUTES if written else MEASUREMENT_NV_BASE_ATTRIBUTES
    )
    expected_name = measurement_nv_name(index, written=written)

    try:
        public_2b, returned_name_2b = ectx.nv_read_public(handle)
        public = public_2b.nvPublic
        observed_index = int(public.nvIndex)
        observed_name_alg = int(public.nameAlg)
        observed_attributes = int(public.attributes)
        observed_auth_policy = bytes(public.authPolicy)
        observed_size = int(public.dataSize)
        observed_name = bytes(returned_name_2b)
    except Exception as exc:  # noqa: BLE001
        raise MeasurementUnavailable(
            "the measurement NV index public area could not be validated",
            detail=f"index={index:#x}: {type(exc).__name__}: {exc}",
        ) from exc

    mismatches: list[str] = []
    if observed_index != index:
        mismatches.append(f"nvIndex={observed_index:#x} expected={index:#x}")
    if observed_name_alg != MEASUREMENT_NV_NAME_ALG:
        mismatches.append(f"nameAlg={observed_name_alg:#x} expected={MEASUREMENT_NV_NAME_ALG:#x}")
    if observed_attributes != expected_attributes:
        mismatches.append(f"attributes={observed_attributes:#x} expected={expected_attributes:#x}")
    if observed_auth_policy != b"":
        mismatches.append("authPolicy is not empty")
    if observed_size != MEASUREMENT_NV_SIZE:
        mismatches.append(f"dataSize={observed_size} expected={MEASUREMENT_NV_SIZE}")
    if observed_name != expected_name:
        mismatches.append(f"Name={observed_name.hex()} expected={expected_name.hex()}")

    if mismatches:
        raise MeasurementUnavailable(
            "the existing NV index does not match the authorized measurement profile",
            detail=f"index={index:#x}: {'; '.join(mismatches)}",
        )


def _read_extend_index(ectx: Any, handle: Any) -> bytes:
    """Read an extend index's current digest, treating never-written as all zeroes.

    A freshly defined extend index reads back as ``TPM_RC_NV_UNINITIALIZED`` until
    its first write, which is the same starting state as a reset PCR, so it is
    reported as zeroes rather than as an error.
    """
    try:
        value = bytes(ectx.nv_read(handle, MEASUREMENT_NV_SIZE, 0))
    except Exception as exc:  # noqa: BLE001
        if _is_nv_uninitialized(exc):
            logger.debug("NV index reads as uninitialized: %s", exc)
            return bytes(MEASUREMENT_NV_SIZE)
        raise MeasurementUnavailable(
            "the measurement NV index value could not be read",
            detail=f"{type(exc).__name__}: {exc}",
        ) from exc
    if len(value) != MEASUREMENT_NV_SIZE:
        raise MeasurementUnavailable(
            "the measurement NV index returned a truncated value",
            detail=f"size={len(value)} expected={MEASUREMENT_NV_SIZE}",
        )
    return value


def _is_nv_uninitialized(exc: Exception) -> bool:
    """Recognize only TPM_RC_NV_UNINITIALIZED, not arbitrary read failures."""
    rc = getattr(exc, "rc", None)
    if rc is None:
        return False
    try:
        from tpm2_pytss.constants import TPM2_RC

        return int(rc) & 0xFFFF == int(TPM2_RC.NV_UNINITIALIZED)
    except (ImportError, AttributeError, TypeError, ValueError):
        return False


def _define_extend_index(ectx: Any, index: int) -> None:
    """Define ``index`` as a ``TPM_NT_EXTEND`` index under the owner hierarchy.

    ``TPM_NT_EXTEND`` is the whole point: writes hash into the existing value
    instead of replacing it, so the index cannot be set to a chosen value and it is
    not resettable from locality 0 the way PCR 16 and PCR 23 are.
    """
    from tpm2_pytss.constants import ESYS_TR, TPM2_ALG, TPM2_NT, TPMA_NV
    from tpm2_pytss.types import TPM2B_DIGEST, TPM2B_NV_PUBLIC, TPMS_NV_PUBLIC

    # TPM_NT is a 4-bit field inside TPMA_NV, so it is OR'd in rather than named in
    # the attribute string. Keeping it explicit is the point: TPM_NT_EXTEND is the
    # single attribute this whole design rests on.
    attributes = TPMA_NV.parse("ownerwrite|ownerread|authread|no_da") | (int(TPM2_NT.EXTEND) << 4)
    nv_public = TPM2B_NV_PUBLIC(
        nvPublic=TPMS_NV_PUBLIC(
            nvIndex=index,
            nameAlg=TPM2_ALG.SHA256,
            attributes=attributes,
            authPolicy=TPM2B_DIGEST(),
            dataSize=_EXTEND_INDEX_SIZE,
        )
    )
    try:
        ectx.nv_define_space(None, nv_public, auth_handle=ESYS_TR.OWNER)
    except Exception as exc:  # noqa: BLE001
        raise MeasurementUnavailable(
            "the measurement NV index could not be defined",
            detail=f"index={index:#x}: {type(exc).__name__}: {exc}",
        ) from exc
