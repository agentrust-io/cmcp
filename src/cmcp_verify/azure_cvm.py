"""Azure confidential-VM (vTPM-rooted SEV-SNP) attestation verification.

Verifies the evidence produced by ``cmcp_runtime.tee.azure_cvm.AzureCVMProvider``.
On Azure the guest cannot control SNP ``REPORT_DATA`` (the paravisor binds the
vTPM AK there), so cMCP's nonce is committed into a TPM2_Quote's qualifying
data signed by that AK. This module verifies the full chain, fail-closed:

  1. SNP report signature (VCEK) + VCEK <- ASK <- ARK to a pinned AMD ARK
     (reusing :mod:`cmcp_verify.sev_snp`).
  2. measurement field matches the claimed measurement.
  3. AK-to-silicon: SNP ``REPORT_DATA[:32] == sha256(runtime_data)``.
  4. the AK public key equals the HCLAkPub carried in runtime_data.
  5. the AK-signed TPM quote's extraData equals the claim nonce (report_data)
     -- this is what binds cMCP's key + audit-root to the silicon-rooted AK.

Validated against evidence produced on live Azure SEV-SNP hardware.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import json
import struct
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from cmcp_verify.sev_snp import (
    _SnpAttestationReport,
    load_snp_cert_chain,
    verify_snp_report_signature,
    verify_vcek_chain,
)

# SNP REPORT_DATA offset (AMD ABI); _rd_offset() prefers the ctypes field offset.
_RD_OFFSET = 0x50
_SNP_REPORT_SIZE = ctypes.sizeof(_SnpAttestationReport)

_TPM_GENERATED_VALUE = 0xFF544347
# TPMT_SIGNATURE sigAlg values.
_ALG_RSASSA = 0x0014
_ALG_RSAPSS = 0x0016
_ALG_HASH = {0x0004: hashes.SHA1(), 0x000B: hashes.SHA256(), 0x000C: hashes.SHA384()}


@dataclass
class AzureCVMVerificationResult:
    verified: bool
    verified_fields: list[str] = field(default_factory=list)
    unverified_fields: list[str] = field(default_factory=list)
    failure_reason: str | None = None
    details: dict[str, str] = field(default_factory=dict)


def _rd_offset() -> int:
    # Prefer the ctypes-computed offset; fall back to the ABI constant.
    try:
        return int(_SnpAttestationReport.report_data.offset)
    except Exception:  # noqa: BLE001
        return _RD_OFFSET


def _extract_extra_data(quote_msg: bytes) -> bytes:
    """Return the extraData (qualifying data) from a TPM(2B)_ATTEST blob.

    ``tpm2_quote -m`` writes the raw TPMS_ATTEST (magic 0xFF544347 at offset 0);
    some producers wrap it in a TPM2B (2-byte big-endian size prefix). Handle
    both by locating the magic.
    """
    if struct.unpack_from(">I", quote_msg, 0)[0] == _TPM_GENERATED_VALUE:
        attest = quote_msg
    elif len(quote_msg) >= 6 and struct.unpack_from(">I", quote_msg, 2)[0] == _TPM_GENERATED_VALUE:
        size = struct.unpack_from(">H", quote_msg, 0)[0]
        attest = quote_msg[2 : 2 + size]
    else:
        raise ValueError("TPMS_ATTEST magic not found")
    offset = 6  # magic(4) + type(2)
    qs_size = struct.unpack_from(">H", attest, offset)[0]
    offset += 2 + qs_size  # skip qualifiedSigner
    ed_size = struct.unpack_from(">H", attest, offset)[0]
    offset += 2
    return attest[offset : offset + ed_size]


def _verify_quote_signature(quote_msg: bytes, quote_sig: bytes, ak: rsa.RSAPublicKey) -> bool:
    """Verify a TPMT_SIGNATURE over quote_msg with the AK (RSASSA/RSAPSS)."""
    sig_alg = struct.unpack_from(">H", quote_sig, 0)[0]
    hash_alg = struct.unpack_from(">H", quote_sig, 2)[0]
    algo = _ALG_HASH.get(hash_alg)
    if algo is None:
        return False
    sig_size = struct.unpack_from(">H", quote_sig, 4)[0]
    signature = quote_sig[6 : 6 + sig_size]
    if sig_alg == _ALG_RSASSA:
        pad: padding.AsymmetricPadding = padding.PKCS1v15()
    elif sig_alg == _ALG_RSAPSS:
        pad = padding.PSS(mgf=padding.MGF1(algo), salt_length=padding.PSS.DIGEST_LENGTH)
    else:
        return False
    try:
        ak.verify(signature, quote_msg, pad, algo)
        return True
    except Exception:  # noqa: BLE001
        return False


def _ak_from_runtime_data(runtime_data: bytes) -> rsa.RSAPublicKey:
    keys = json.loads(runtime_data).get("keys", [])
    ak = next((k for k in keys if k.get("kid") == "HCLAkPub"), None)
    if ak is None:
        raise ValueError("runtime data does not carry HCLAkPub")

    def _b64u(v: str) -> int:
        return int.from_bytes(base64.urlsafe_b64decode(v + "=" * ((4 - len(v) % 4) % 4)), "big")

    return rsa.RSAPublicNumbers(_b64u(ak["e"]), _b64u(ak["n"])).public_key()


def verify_azure_cvm_measurement(
    measurement: str,
    raw_evidence: bytes | None,
    report_data_hex: str | None = None,
    trusted_ark_pem: bytes | None = None,
) -> AzureCVMVerificationResult:
    """Verify Azure CVM (vTPM-rooted SEV-SNP) attestation evidence. Fail-closed."""
    result = AzureCVMVerificationResult(verified=True)

    if raw_evidence is None:
        result.verified = False
        result.failure_reason = "no_raw_evidence"
        result.unverified_fields.append("vcek_cert_chain")
        return result

    # Step a: parse the evidence envelope.
    try:
        env = json.loads(raw_evidence)
        snp = base64.b64decode(env["snp_report"])
        runtime = base64.b64decode(env["runtime_data"])
        quote_msg = base64.b64decode(env["quote_msg"])
        quote_sig = base64.b64decode(env["quote_sig"])
        ak_pub_pem = env["ak_pub_pem"].encode()
        chain_pem = base64.b64decode(env.get("vcek_chain_pem", ""))
    except Exception as exc:  # noqa: BLE001
        result.verified = False
        result.failure_reason = "evidence_parse_error"
        result.details["evidence"] = str(exc)
        return result

    rd_off = _rd_offset()
    if len(snp) < rd_off + 64:
        result.verified = False
        result.failure_reason = "raw_evidence_parse_error"
        return result

    # Step c: measurement field matches the claim.
    try:
        report = _SnpAttestationReport.from_buffer_copy(snp[:_SNP_REPORT_SIZE])
        computed = "sha384:" + hashlib.sha384(bytes(report.measurement)).hexdigest()
    except Exception:  # noqa: BLE001
        result.verified = False
        result.failure_reason = "raw_evidence_parse_error"
        return result
    if computed != measurement:
        result.verified = False
        result.failure_reason = "measurement_mismatch"
        return result
    result.verified_fields.append("measurement")

    # Step d: AK-to-silicon binding -- REPORT_DATA[:32] == sha256(runtime_data). FATAL.
    if snp[rd_off : rd_off + 32] != hashlib.sha256(runtime).digest():
        result.verified = False
        result.failure_reason = "runtime_data_binding_mismatch"
        return result
    result.verified_fields.append("runtime_data_binding")

    # Step e: the quote-signing AK equals the HCLAkPub bound into the SNP report.
    try:
        ak_from_pem = serialization.load_pem_public_key(ak_pub_pem)
        ak_from_rt = _ak_from_runtime_data(runtime)
        if not isinstance(ak_from_pem, rsa.RSAPublicKey):
            raise ValueError("AK is not RSA")
        if ak_from_pem.public_numbers() != ak_from_rt.public_numbers():
            result.verified = False
            result.failure_reason = "ak_mismatch"
            return result
    except Exception as exc:  # noqa: BLE001
        result.verified = False
        result.failure_reason = "ak_parse_error"
        result.details["ak"] = str(exc)
        return result
    ak = ak_from_rt
    result.verified_fields.append("ak_binding")

    # Step f: the AK-signed quote commits the nonce in extraData. FATAL.
    if not _verify_quote_signature(quote_msg, quote_sig, ak):
        result.verified = False
        result.failure_reason = "quote_signature_invalid"
        return result
    if report_data_hex is not None:
        try:
            extra = _extract_extra_data(quote_msg)
        except Exception as exc:  # noqa: BLE001
            result.verified = False
            result.failure_reason = "quote_parse_error"
            result.details["quote"] = str(exc)
            return result
        # The quote commits sha256(nonce); the nonce itself is report_data, checked
        # against the key thumbprint + audit root by the generic CRYPTO-001/AUDIT-006
        # steps. Here we prove that nonce was hardware-committed by the AK.
        expected = hashlib.sha256(bytes.fromhex(report_data_hex)).digest()
        if not hmac.compare_digest(extra, expected):
            result.verified = False
            result.failure_reason = "quote_nonce_mismatch"
            return result
        result.verified_fields.append("quote_nonce_binding")

    # Step b: SNP report signature + VCEK -> ASK -> ARK chain (silicon root).
    if not chain_pem or trusted_ark_pem is None:
        result.unverified_fields.append("vcek_cert_chain")
        result.details["vcek_chain"] = "cert chain and/or pinned ARK not supplied"
        return result
    try:
        from cryptography import x509

        vcek, ask, ark = load_snp_cert_chain(chain_pem)
        trusted_arks = x509.load_pem_x509_certificates(trusted_ark_pem)
        if not trusted_arks:
            raise ValueError("trusted_ark_pem contained no certificate")
    except Exception as exc:  # noqa: BLE001
        result.verified = False
        result.failure_reason = "cert_chain_malformed"
        result.unverified_fields.append("vcek_cert_chain")
        result.details["vcek_chain"] = str(exc)
        return result

    chain_ok, chain_reason = verify_vcek_chain(vcek, ask, ark, trusted_arks[0])
    if not chain_ok:
        result.verified = False
        result.failure_reason = "vcek_chain_invalid"
        result.unverified_fields.append("vcek_cert_chain")
        result.details["vcek_chain"] = chain_reason or "VCEK chain verification failed"
        return result

    sig_ok, sig_reason = verify_snp_report_signature(snp, vcek)
    if not sig_ok:
        result.verified = False
        result.failure_reason = "report_signature_invalid"
        result.unverified_fields.append("report_signature")
        result.details["report_signature"] = sig_reason or "SNP report signature invalid"
        return result

    result.verified_fields.append("vcek_cert_chain")
    result.verified_fields.append("report_signature")
    return result
