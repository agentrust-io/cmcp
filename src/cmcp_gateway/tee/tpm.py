"""TPM 2.0 TEE provider — implements issue #83."""

from __future__ import annotations

import hashlib
import subprocess  # nosec B404
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from cmcp_gateway.tee.base import AttestationReport, TEEProvider

if TYPE_CHECKING:
    pass

try:
    import tpm2_pytss  # type: ignore[import-not-found]

    _TSS2_AVAILABLE = True
except ImportError:
    tpm2_pytss = None
    _TSS2_AVAILABLE = False

_TPM_DEVICES = [Path("/dev/tpm0"), Path("/dev/tpmrm0")]


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
        from tpm2_pytss.ESAPI import ESAPI  # type: ignore[import-not-found]
        from tpm2_pytss.types import (  # type: ignore[import-not-found]
            TPM2_ALG,
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
                for bank in digests.digests:
                    for digest in bank.digests:
                        raw_pcrs.append(bytes(digest.buffer))
            except Exception:  # noqa: BLE001
                # Fall back to SHA-1
                measurement_note = "sha1-bank-fallback"
                pcr_sel = TPML_PCR_SELECTION.parse("sha1:0,1,2,3,4,5,6,7")
                _, _, digests = ectx.pcr_read(pcr_sel)
                raw_pcrs = []
                for bank in digests.digests:
                    for digest in bank.digests:
                        raw_pcrs.append(bytes(digest.buffer))

            # Ensure we got 8 PCRs
            if len(raw_pcrs) < 8:
                raise RuntimeError(
                    f"TPM device found but could not read PCRs: got {len(raw_pcrs)}, expected 8"
                )

            concatenated = b"".join(raw_pcrs[:8])
            measurement = "sha256:" + hashlib.sha256(concatenated).hexdigest()

            # Attempt TPM2_Quote for raw_evidence
            raw_evidence: bytes | None = None
            try:
                qualifying_data = TPM2B_DATA(nonce[:32])
                pcr_sel_quote = TPML_PCR_SELECTION.parse("sha256:0,1,2,3,4,5,6,7")
                quoted, _signature = ectx.quote(
                    object_handle=ectx.get_capability(TPM2_ALG.NULL),
                    qualifying_data=qualifying_data,
                    in_scheme=TPM2_ALG.NULL,
                    pcrselect=pcr_sel_quote,
                )
                raw_evidence = bytes(quoted.attestationData)
            except Exception:  # noqa: BLE001
                raw_evidence = None

        return AttestationReport(
            provider=self.provider_name(),
            measurement=measurement,
            report_data=nonce.hex(),
            raw_evidence=raw_evidence,
            attestation_generated_at=datetime.now(tz=UTC),
            attestation_validity_seconds=3600,
            measurement_note=measurement_note,
        )

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
        else:
            measurement_note = None

        pcr_values = _parse_tpm2_pcrread_output(result.stdout)
        if len(pcr_values) < 8:
            raise RuntimeError(
                f"TPM device found but could not read PCRs: parsed {len(pcr_values)} PCRs"
            )

        concatenated = b"".join(pcr_values[:8])
        measurement = "sha256:" + hashlib.sha256(concatenated).hexdigest()

        return AttestationReport(
            provider=self.provider_name(),
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
    """
    pcr_values: list[bytes] = []
    for line in output.splitlines():
        line = line.strip()
        if ":" in line and line.split(":")[0].strip().isdigit():
            _, _, hex_val = line.partition(":")
            hex_val = hex_val.strip().lstrip("0x").lstrip("0X")
            try:
                pcr_values.append(bytes.fromhex(hex_val or "00"))
            except ValueError:
                continue
    return pcr_values
