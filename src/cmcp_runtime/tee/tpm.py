"""TPM 2.0 TEE provider: implements issue #83."""

from __future__ import annotations

import hashlib
import logging
import subprocess  # nosec B404
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cmcp_runtime.tee.base import AttestationReport, TEEProvider

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    pass

try:
    import tpm2_pytss

    _TSS2_AVAILABLE = True
except ImportError:
    tpm2_pytss = None
    _TSS2_AVAILABLE = False

_TPM_DEVICES = [Path("/dev/tpm0"), Path("/dev/tpmrm0")]
# PCR selection quoted alongside the measurement.
_QUOTE_PCR_SELECTION = "sha256:0,1,2,3,4,5,6,7"

# Platforms that provision an attestation key expose it at a persistent handle with a
# certificate in NV. Azure Trusted Launch uses these two; both are TCG-conventional
# ranges rather than Azure inventions, so the probe is harmless elsewhere.
_PLATFORM_AK_HANDLE = 0x81000003
_PLATFORM_AK_CERT_NV_INDEX = 0x01C101D0

# Walking the certificate AIA extension is what lets a relying party verify offline
# later: the chain travels with the evidence instead of being fetched at audit time.
_AIA_FETCH_TIMEOUT_SECONDS = 5
_AIA_MAX_DEPTH = 4

# TPM2_NV_Read is bounded by TPM2_PT_NV_BUFFER_MAX; query it and cap by this.
_NV_READ_CHUNK_BYTES = 512
_TPM2_CAP_TPM_PROPERTIES = 0x00000006
_TPM2_PT_NV_BUFFER_MAX = 0x0000012B


class TPMProvider(TEEProvider):
    """TPM 2.0 attestation provider using tpm2-pytss or subprocess fallback."""

    def provider_name(self) -> str:
        return "tpm"

    def detect(self) -> bool:
        """Return True if a TPM device file exists and is readable on Linux."""
        try:
            if sys.platform != "linux":
                return False
            return any(dev.exists() for dev in _TPM_DEVICES)
        except Exception:  # noqa: BLE001
            return False

    def get_attestation_report(self, nonce: bytes) -> AttestationReport:
        """
        Produce a TPM 2.0 PCR-based attestation report.

        Tries tpm2-pytss ESAPI first, then falls back to tpm2_pcrread subprocess.
        """
        if _TSS2_AVAILABLE:
            return self._report_via_tss2(nonce)
        return self._report_via_subprocess(nonce)

    # ── tpm2-pytss path ───────────────────────────────────────────────────────

    def _report_via_tss2(self, nonce: bytes) -> AttestationReport:
        from tpm2_pytss.ESAPI import ESAPI
        from tpm2_pytss.types import (
            TPM2B_DATA,
            TPML_PCR_SELECTION,
        )

        with ESAPI() as ectx:
            # Try SHA-256 first; fall back to SHA-1
            measurement_note: str | None = None
            raw_pcrs: list[bytes] = []

            try:
                pcr_sel = TPML_PCR_SELECTION.parse("sha256:0,1,2,3,4,5,6,7")
                _, _, digests = ectx.pcr_read(pcr_sel)
                for digest in digests.digests:
                    raw_pcrs.append(bytes(digest))
            except Exception as exc:  # noqa: BLE001
                # Fall back to SHA-1
                logger.warning("SHA-256 PCR read failed (%s)", exc)
                measurement_note = "sha1-bank-fallback"
                logger.warning(
                    "TPM SHA-1 fallback: SHA-256 PCR bank unavailable. "
                    "Downgrading attestation to software-only. "
                    "TRACE Claim will not present as hardware-attested."
                )
                pcr_sel = TPML_PCR_SELECTION.parse("sha1:0,1,2,3,4,5,6,7")
                _, _, digests = ectx.pcr_read(pcr_sel)
                raw_pcrs = []
                for digest in digests.digests:
                    raw_pcrs.append(bytes(digest))

            # Ensure we got 8 PCRs
            if len(raw_pcrs) < 8:
                raise RuntimeError(
                    f"TPM device found but could not read PCRs: got {len(raw_pcrs)}, expected 8"
                )

            concatenated = b"".join(raw_pcrs[:8])
            measurement = "sha256:" + hashlib.sha256(concatenated).hexdigest()

            # TPM2_Quote over the same PCR selection, signed by a restricted
            # signing key. Without the signature the attest blob proves nothing:
            # every field in it is attacker-controllable.
            raw_evidence: bytes | None = None
            quote_signature: bytes | None = None
            attestation_key_pem: bytes | None = None
            attestation_key_chain_pem: bytes | None = None
            ak_handle = None
            self._last_key_was_transient = False
            transient_ak = False
            try:
                ak_handle, ak_public, attestation_key_chain_pem = self._attestation_key(ectx)
                quoted, signature = ectx.quote(
                    ak_handle,
                    _QUOTE_PCR_SELECTION,
                    TPM2B_DATA(nonce[:32]),
                )
                raw_evidence = bytes(quoted.attestationData)
                quote_signature = signature.marshal()
                attestation_key_pem = ak_public.to_pem()
                transient_ak = self._last_key_was_transient
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "TPM quote unavailable (%s); the report will carry an unsigned "
                    "PCR read as its only evidence.",
                    exc,
                )
                raw_evidence = None
                quote_signature = None
                attestation_key_pem = None
                attestation_key_chain_pem = None
            finally:
                if ak_handle is not None and transient_ak:
                    try:
                        ectx.flush_context(ak_handle)
                    except Exception as exc:  # noqa: BLE001
                        logger.debug("flushing the attestation key failed: %s", exc)

        measurement_note = self._downgrade_note(measurement_note, raw_evidence)
        effective_provider = (
            self.provider_name() if measurement_note is None else "software-only"
        )
        return AttestationReport(
            provider=effective_provider,
            measurement=measurement,
            report_data=nonce.hex(),
            raw_evidence=raw_evidence,
            attestation_generated_at=datetime.now(tz=UTC),
            attestation_validity_seconds=3600,
            measurement_note=measurement_note,
            quote_signature=quote_signature,
            attestation_key_pem=attestation_key_pem,
            attestation_key_chain_pem=attestation_key_chain_pem,
        )

    def _attestation_key(self, ectx: Any) -> tuple[Any, Any, bytes | None]:
        """
        Return (handle, public, chain_pem) for the key that will sign the quote.

        Prefers the platform attestation key: a key the platform provisioned and
        certified, at a persistent handle with its certificate in NV. That key is the
        only one whose signature says anything about where it lives, because the
        certificate chains to a vendor root.

        Falls back to a transient restricted signing key when the platform provides
        none. That path still produces a verifiable signature but no provenance, and
        the caller reports it without a chain so it cannot be mistaken for the
        stronger tier.
        """
        cert_der = self._read_nv(ectx, _PLATFORM_AK_CERT_NV_INDEX)
        if cert_der is not None:
            try:
                handle = ectx.tr_from_tpmpublic(_PLATFORM_AK_HANDLE)
                public, _, _ = ectx.read_public(handle)
                chain = self._chain_from_leaf(cert_der)
                if self._certifies(chain, public):
                    logger.info(
                        "Using the platform attestation key at 0x%X with its "
                        "certificate from NV 0x%X.",
                        _PLATFORM_AK_HANDLE,
                        _PLATFORM_AK_CERT_NV_INDEX,
                    )
                    return handle, public, chain
                logger.warning(
                    "The certificate at NV 0x%X does not certify the key at 0x%X; "
                    "falling back to a transient attestation key.",
                    _PLATFORM_AK_CERT_NV_INDEX,
                    _PLATFORM_AK_HANDLE,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Platform attestation key unusable (%s); falling back to a "
                    "transient key.",
                    exc,
                )

        handle, public = self._create_attestation_key(ectx)
        self._last_key_was_transient = True
        return handle, public, None

    @staticmethod
    def _read_nv(ectx: Any, index: int) -> bytes | None:
        """
        Read an NV index in full, returning None when it is not defined or readable.

        TPM2_NV_Read is bounded by TPM2_PT_NV_BUFFER_MAX, so an index larger than that
        must be read in chunks. Requesting the whole thing at once fails with
        TPM_RC_VALUE on the size parameter, which is why a certificate of 1596 bytes
        cannot be fetched in a single call even though the index is plainly readable.
        """
        try:
            handle = ectx.tr_from_tpmpublic(index)
            public, _ = ectx.nv_read_public(handle)
            total = int(public.nvPublic.dataSize)
        except Exception as exc:  # noqa: BLE001
            logger.debug("NV index 0x%X not defined: %s", index, exc)
            return None

        chunk = _NV_READ_CHUNK_BYTES
        try:
            caps = ectx.get_capability(_TPM2_CAP_TPM_PROPERTIES, _TPM2_PT_NV_BUFFER_MAX, 1)
            for prop in caps[1].data.tpmProperties:
                if int(prop.property) == _TPM2_PT_NV_BUFFER_MAX:
                    chunk = min(chunk, int(prop.value))
                    break
        except Exception as exc:  # noqa: BLE001
            logger.debug("NV buffer max unavailable, using %d: %s", chunk, exc)

        out = bytearray()
        try:
            while len(out) < total:
                want = min(chunk, total - len(out))
                out += bytes(ectx.nv_read(handle, want, len(out)))
        except Exception as exc:  # noqa: BLE001
            logger.debug("NV index 0x%X read failed at offset %d: %s", index, len(out), exc)
            return None
        return bytes(out)

    @staticmethod
    def _certifies(chain_pem: bytes, tpm_public: Any) -> bool:
        """True when the chain's leaf certificate carries the TPM key's public key."""
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        leaf = x509.load_pem_x509_certificates(chain_pem)[0]
        return leaf.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ) == tpm_public.to_pem()

    @staticmethod
    def _chain_from_leaf(leaf_der: bytes) -> bytes:
        """
        Build a leaf-first PEM chain by following each certificate's AIA extension.

        The chain is assembled at collection time on purpose: shipping it with the
        evidence is what keeps verification offline later. A self-signed certificate
        or a missing AIA ends the walk, and whatever was gathered is returned so a
        partial chain still travels rather than being discarded.
        """
        import urllib.request

        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import pkcs7

        def load_any(data: bytes) -> list[x509.Certificate]:
            for loader in (x509.load_der_x509_certificate, x509.load_pem_x509_certificate):
                try:
                    return [loader(data)]
                except Exception as exc:  # noqa: BLE001
                    logger.debug("not an X.509 certificate via %s: %s", loader.__name__, exc)
            for bundle_loader in (
                pkcs7.load_der_pkcs7_certificates,
                pkcs7.load_pem_pkcs7_certificates,
            ):
                found: list[x509.Certificate] = []
                try:
                    found = list(bundle_loader(data))
                except Exception as exc:  # noqa: BLE001
                    logger.debug(
                        "not a PKCS#7 bundle via %s: %s", bundle_loader.__name__, exc
                    )
                if found:
                    return found
            return []

        chain = load_any(leaf_der)
        if not chain:
            logger.warning(
                "The attestation key certificate could not be parsed as X.509 or PKCS#7; "
                "no chain will be shipped."
            )
            return b""

        while len(chain) < _AIA_MAX_DEPTH:
            current = chain[-1]
            if current.subject == current.issuer:
                break
            try:
                aia = current.extensions.get_extension_for_class(
                    x509.AuthorityInformationAccess
                ).value
            except x509.ExtensionNotFound:
                break
            urls = [
                d.access_location.value
                for d in aia
                if d.access_method.dotted_string == "1.3.6.1.5.5.7.48.2"
            ]
            issuer = None
            for url in urls:
                if not url.startswith(("http://", "https://")):
                    continue
                try:
                    with urllib.request.urlopen(  # noqa: S310  # nosec B310 - http(s) only, checked above
                        url, timeout=_AIA_FETCH_TIMEOUT_SECONDS
                    ) as response:
                        found = load_any(response.read())
                    if found:
                        issuer = found[0]
                        break
                except Exception as exc:  # noqa: BLE001
                    logger.debug("AIA fetch failed for %s: %s", url, exc)
            if issuer is None:
                break
            chain.append(issuer)

        from cryptography.hazmat.primitives.serialization import Encoding

        return b"".join(c.public_bytes(Encoding.PEM) for c in chain)

    @staticmethod
    def _create_attestation_key(ectx: Any) -> tuple[Any, Any]:
        """
        Create a restricted signing key under the owner hierarchy and return
        (handle, public).

        Restricted signing is what makes the key usable for TPM2_Quote: the TPM will
        only sign TPM-generated structures with it, so a quote cannot be forged by
        asking the key to sign arbitrary bytes. The key is transient and flushed
        after use. Binding it to the platform EK is separate work (issue #431).
        """
        from tpm2_pytss.constants import ESYS_TR
        from tpm2_pytss.types import TPM2B_PUBLIC, TPM2B_SENSITIVE_CREATE

        template = TPM2B_PUBLIC.parse(
            "rsa2048:rsassa:null",
            objectAttributes=(
                "restricted|sign|fixedtpm|fixedparent|"
                "sensitivedataorigin|userwithauth|noda"
            ),
        )
        handle, public, _, _, _ = ectx.create_primary(
            TPM2B_SENSITIVE_CREATE(), template, ESYS_TR.OWNER
        )
        return handle, public

    @staticmethod
    def _downgrade_note(measurement_note: str | None, raw_evidence: bytes | None) -> str | None:
        """
        Return the note that decides whether this report may present as hardware-attested.

        A PCR read on its own carries no signature and nothing binds it to a TPM, so a
        report without quote evidence is reported as software-only. This mirrors the
        existing SHA-1 bank downgrade rather than inventing a second policy.
        """
        if measurement_note is not None:
            return measurement_note
        if raw_evidence is None:
            logger.warning(
                "TPM PCR read produced no quote evidence. Downgrading attestation to "
                "software-only. TRACE Claim will not present as hardware-attested."
            )
            return "tpm-pcr-read-unsigned"
        return None

    # ── subprocess fallback ───────────────────────────────────────────────────

    def _report_via_subprocess(self, nonce: bytes) -> AttestationReport:
        """Read PCRs 0-7 using tpm2_pcrread subprocess."""
        try:
            result = subprocess.run(  # noqa: S603  # nosec B603, B607
                ["tpm2_pcrread", "sha256:0,1,2,3,4,5,6,7"],  # noqa: S607
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"TPM device found but could not read PCRs: {exc}") from exc

        if result.returncode != 0:
            # Try SHA-1
            result = subprocess.run(  # noqa: S603  # nosec B603, B607
                ["tpm2_pcrread", "sha1:0,1,2,3,4,5,6,7"],  # noqa: S607
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"TPM device found but could not read PCRs: tpm2_pcrread exited "
                    f"{result.returncode}: {result.stderr.strip()}"
                )
            measurement_note: str | None = "sha1-bank-fallback"
            logger.warning(
                "TPM SHA-1 fallback: SHA-256 PCR bank unavailable. "
                "Downgrading attestation to software-only. "
                "TRACE Claim will not present as hardware-attested."
            )
        else:
            measurement_note = None

        pcr_values = _parse_tpm2_pcrread_output(result.stdout)
        if len(pcr_values) < 8:
            raise RuntimeError(
                f"TPM device found but could not read PCRs: parsed {len(pcr_values)} PCRs"
            )

        concatenated = b"".join(pcr_values[:8])
        measurement = "sha256:" + hashlib.sha256(concatenated).hexdigest()

        measurement_note = self._downgrade_note(measurement_note, None)
        effective_provider = (
            self.provider_name() if measurement_note is None else "software-only"
        )
        return AttestationReport(
            provider=effective_provider,
            measurement=measurement,
            report_data=nonce.hex(),
            raw_evidence=None,
            attestation_generated_at=datetime.now(tz=UTC),
            attestation_validity_seconds=3600,
            measurement_note=measurement_note,
        )


def _parse_tpm2_pcrread_output(output: str) -> list[bytes]:
    """
    Parse tpm2_pcrread YAML-ish output into a list of raw PCR bytes.

    Expected format (per PCR):
      sha256:
        0 : 0xABCD...

    ``lstrip("0x")`` cannot be used to drop the prefix: it strips a character set,
    so a value whose digits begin with 0 loses those digits as well.
    """
    pcr_values: list[bytes] = []
    for line in output.splitlines():
        line = line.strip()
        if ":" in line and line.split(":")[0].strip().isdigit():
            _, _, hex_val = line.partition(":")
            hex_val = hex_val.strip()
            if hex_val[:2].lower() == "0x":
                hex_val = hex_val[2:]
            if not hex_val:
                raise RuntimeError(f"TPM PCR read returned an empty value: {line!r}")
            try:
                pcr_values.append(bytes.fromhex(hex_val))
            except ValueError as exc:
                raise RuntimeError(
                    f"TPM PCR read returned an unparseable value: {line!r}"
                ) from exc
    return pcr_values
