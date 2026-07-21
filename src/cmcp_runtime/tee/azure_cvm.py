"""Azure confidential-VM (vTPM-rooted SEV-SNP) TEE provider.

Azure runs AMD SEV-SNP behind a Hyper-V paravisor, so there is no
``/dev/sev-guest`` and the guest cannot control the SNP ``REPORT_DATA`` field:
the paravisor sets ``REPORT_DATA = sha256(runtime_data)`` to bind the vTPM
attestation key (HCLAkPub) to the silicon. The SNP/HCL report is read from the
vTPM NV index ``0x01400001`` ("HCLA" wrapper, SNP report embedded at 0x20).

cMCP's attestation nonce (``jwk_thumbprint(gateway_key) || sha256(audit_root)``)
therefore cannot be committed into the SNP report directly. This provider
commits it into a TPM2_Quote's qualifying data, signed by the vTPM AK, and
roots that AK in silicon via the SNP report. A verifier chains:

    nonce -> AK-signed quote (extraData) -> AK == HCLAkPub bound in SNP
    REPORT_DATA -> SNP report signed by VCEK -> VCEK <- ASK <- ARK.

Validated on live Azure SEV-SNP hardware. See cmcp_verify/azure_cvm.py.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import struct
import subprocess  # nosec B404
import sys
import tempfile
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from cmcp_runtime.tee.base import AttestationReport, TEEProvider

# Azure vTPM NV index that holds the "HCLA" report (SNP report + runtime data).
_HCL_NV_INDEX = "0x01400001"
# SNP attestation report is embedded at this offset inside the HCL wrapper.
_HCL_SNP_OFFSET = 0x20
_SNP_REPORT_LEN = 0x4A0
# SNP report field offsets (AMD SEV-SNP ABI, Table "ATTESTATION_REPORT").
_RD_OFFSET = 0x50
_MEAS_OFFSET = 0x90
_REPORTED_TCB_OFFSET = 0x180
_CHIP_ID_OFFSET = 0x1A0
# Resettable, application-scope PCR used only to satisfy tpm2_quote's PCR
# selection; the manifest binding lives in the quote's qualifying data (nonce).
_QUOTE_PCR = 16
_KDS_BASE = "https://kdsintf.amd.com/vcek/v1"


class AzureCVMProvider(TEEProvider):
    """Azure confidential VM attestation (vTPM-rooted SEV-SNP)."""

    def __init__(self, product: str = "Milan") -> None:
        self._product = product

    def provider_name(self) -> str:
        return "azure-cvm-sev-snp"

    def detect(self) -> bool:
        """True on Linux when the Azure vTPM HCL NV index is readable."""
        try:
            if sys.platform != "linux":
                return False
            if shutil.which("tpm2_nvreadpublic") is None:
                return False
            proc = subprocess.run(  # noqa: S603  # nosec B603, B607
                ["tpm2_nvreadpublic", _HCL_NV_INDEX],  # noqa: S607
                capture_output=True,
                timeout=15,
                check=False,
            )
            return proc.returncode == 0
        except Exception:  # noqa: BLE001
            return False

    # ── helpers ───────────────────────────────────────────────────────────────

    def _tpm(self, args: list[str]) -> bytes:
        exe = shutil.which(args[0])
        if exe is None:
            raise RuntimeError(f"Azure CVM attestation failed: {args[0]} not found")
        proc = subprocess.run(  # noqa: S603  # nosec B603
            [exe, *args[1:]], capture_output=True, timeout=30, check=False
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"Azure CVM attestation failed: {' '.join(args)}: "
                f"{proc.stderr.decode('utf-8', 'replace').strip()}"
            )
        return proc.stdout

    def _read_hcl_report(self) -> bytes:
        fd, path = tempfile.mkstemp(suffix=".hcl")
        Path(path).unlink(missing_ok=True)
        try:
            self._tpm(["tpm2_nvread", _HCL_NV_INDEX, "-C", "o", "-o", path])
            return Path(path).read_bytes()
        finally:
            Path(path).unlink(missing_ok=True)

    @staticmethod
    def _split_hcl(hcl: bytes) -> tuple[bytes, bytes]:
        if hcl[:4] != b"HCLA":
            raise RuntimeError(f"not an HCL report: magic {hcl[:4]!r}")
        snp = hcl[_HCL_SNP_OFFSET : _HCL_SNP_OFFSET + _SNP_REPORT_LEN]
        tail = hcl[_HCL_SNP_OFFSET + _SNP_REPORT_LEN :]
        runtime = b""
        if len(tail) >= 4:
            (declared,) = struct.unpack_from("<I", tail, 0)
            if 0 < declared <= len(tail) - 4:
                runtime = tail[4 : 4 + declared]
        if not (runtime[:1] == b"{" and runtime.rstrip()[-1:] == b"}"):
            start, end = tail.find(b"{"), tail.rfind(b"}")
            runtime = tail[start : end + 1] if start >= 0 and end > start else b""
        return snp, runtime

    @staticmethod
    def _ak_modulus_hex(runtime_data: bytes) -> str:
        keys = json.loads(runtime_data).get("keys", [])
        ak = next((k for k in keys if k.get("kid") == "HCLAkPub"), None)
        if ak is None:
            raise RuntimeError("runtime data does not carry the HCLAkPub attestation key")
        n_b64 = ak["n"] + "=" * ((4 - len(ak["n"]) % 4) % 4)
        return base64.urlsafe_b64decode(n_b64).hex()

    def _find_ak_handle(self, modulus_hex: str) -> str:
        out = self._tpm(["tpm2_getcap", "handles-persistent"]).decode()
        handles = [line.split()[-1] for line in out.splitlines() if "0x" in line]
        for handle in handles:
            pub = self._tpm(["tpm2_readpublic", "-c", handle]).decode()
            for line in pub.splitlines():
                stripped = line.strip()
                if stripped.startswith("rsa:") and stripped.split(":", 1)[1].strip().lower() == modulus_hex.lower():
                    return handle
        raise RuntimeError("vTPM AK (HCLAkPub) persistent handle not found")

    def _fetch_vcek_chain(self, snp: bytes) -> bytes:
        """Fetch VCEK + ASK/ARK from the AMD KDS; return a PEM bundle or b"" on failure."""
        try:
            tcb = snp[_REPORTED_TCB_OFFSET : _REPORTED_TCB_OFFSET + 8]
            chip = snp[_CHIP_ID_OFFSET : _CHIP_ID_OFFSET + 64].hex()
            url = (
                f"{_KDS_BASE}/{self._product}/{chip}"
                f"?blSPL={tcb[0]}&teeSPL={tcb[1]}&snpSPL={tcb[6]}&ucodeSPL={tcb[7]}"
            )

            def _get(u: str) -> bytes:
                # URL is always the fixed https AMD KDS host; scheme is not user-controlled.
                req = urllib.request.Request(u, headers={"User-Agent": "cmcp"})  # noqa: S310  # nosec B310
                with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310  # nosec B310
                    return resp.read()

            from cryptography import x509

            vcek = x509.load_der_x509_certificate(_get(url))
            chain = _get(f"{_KDS_BASE}/{self._product}/cert_chain")
            from cryptography.hazmat.primitives.serialization import Encoding

            return vcek.public_bytes(Encoding.PEM) + chain
        except Exception:  # noqa: BLE001
            return b""

    # ── main entry ──────────────────────────────────────────────────────────────

    def get_attestation_report(self, nonce: bytes) -> AttestationReport:
        hcl = self._read_hcl_report()
        snp, runtime = self._split_hcl(hcl)
        if len(snp) < _SNP_REPORT_LEN or not runtime:
            raise RuntimeError("Azure CVM attestation failed: malformed HCL report")

        report_data = snp[_RD_OFFSET : _RD_OFFSET + 64]
        if report_data[:32] != hashlib.sha256(runtime).digest():
            raise RuntimeError(
                "Azure SNP REPORT_DATA does not bind the runtime data; the vTPM AK "
                "cannot be trusted as silicon-rooted"
            )

        ak_handle = self._find_ak_handle(self._ak_modulus_hex(runtime))

        tmp = tempfile.mkdtemp()
        try:
            msg = f"{tmp}/q.msg"
            sig = f"{tmp}/q.sig"
            pcrs = f"{tmp}/q.pcrs"
            akpub = f"{tmp}/ak.pem"
            # PCR content is irrelevant here; the binding is the quote's qualifying
            # data (the cMCP nonce). Reset then quote for a deterministic PCR value.
            self._tpm(["tpm2_pcrreset", str(_QUOTE_PCR)])
            # The quote commits sha256(nonce), not the raw 64-byte nonce: a vTPM's
            # qualifyingData (TPM2B_DATA) is capped below 64 bytes on some platforms
            # (Azure returns TPM_RC_SIZE). sha256(nonce) is an equivalent binding and
            # always fits. The verifier re-derives sha256(report_data) and compares.
            self._tpm([
                "tpm2_quote", "-c", ak_handle, "-l", f"sha256:{_QUOTE_PCR}",
                "-q", hashlib.sha256(nonce).hexdigest(),
                "-m", msg, "-s", sig, "-o", pcrs, "-g", "sha256",
            ])
            self._tpm(["tpm2_readpublic", "-c", ak_handle, "-f", "pem", "-o", akpub])
            quote_msg = Path(msg).read_bytes()
            quote_sig = Path(sig).read_bytes()
            ak_pub_pem = Path(akpub).read_text()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

        measurement = "sha384:" + hashlib.sha384(snp[_MEAS_OFFSET : _MEAS_OFFSET + 48]).hexdigest()
        envelope = json.dumps({
            "v": 1,
            "snp_report": base64.b64encode(snp).decode(),
            "runtime_data": base64.b64encode(runtime).decode(),
            "quote_msg": base64.b64encode(quote_msg).decode(),
            "quote_sig": base64.b64encode(quote_sig).decode(),
            "ak_pub_pem": ak_pub_pem,
            "vcek_chain_pem": base64.b64encode(self._fetch_vcek_chain(snp)).decode(),
        }).encode()

        return AttestationReport(
            provider=self.provider_name(),
            measurement=measurement,
            report_data=nonce.hex(),
            raw_evidence=envelope,
            attestation_generated_at=datetime.now(tz=UTC),
            attestation_validity_seconds=86400,
        )
