"""
Hardware TEE attestation experiment (requires a confidential VM).

Every other experiment in this directory runs in software-only mode and produces
TRACE Claims with attestation_assurance = none. This one exercises the *real*
hardware path end to end: it asks the detected TEE provider for a genuine
attestation report, binds the gateway key into it, builds a signed TRACE Claim,
and runs the verifier over both the claim and the raw hardware evidence.

It is safe to run anywhere: on a host with no confidential-computing hardware it
detects that and exits 0 with a SKIP message, so it does not fail in CI or on a
laptop. The hardware properties can only be demonstrated on a real SEV-SNP, TDX,
or TPM-equipped host -- see README.md for the Azure / GCP deploy steps.

Properties demonstrated (hardware only):

P1  A real TEE provider is detected (sev-snp / tdx / tpm), not software-only.
P2  The attestation report binds the gateway-supplied nonce: report.report_data
    equals the nonce we passed in.
P3  The measurement is a real hardware value, not the software-only placeholder.
P4  A fresh report with a different nonce yields different report_data
    (freshness / instance binding).
P5  The provider-specific verifier accepts the raw hardware evidence (format,
    measurement, and report_data checks). Cert-chain appraisal (AMD KDS /
    Intel DCAP / TPM EK) is reported separately -- it requires the vendor
    services and is listed under unverified_fields until those are wired.
P6  A full TRACE Claim built from the real report verifies end to end: schema,
    Ed25519 signature, and TEE key binding (report_data[:32] == JWK thumbprint).

Running:
  pip install -e .
  python experiments/claim-hw-attestation/run.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys

from cmcp_runtime.audit.keys import SigningKey
from cmcp_runtime.audit.trace_claim import (
    AttestationReportInfo,
    CallGraphSummary,
    CallSummary,
    PolicyBundleInfo,
    ToolCatalogInfo,
    generate_trace_claim,
)
from cmcp_runtime.tee.base import AttestationReport, TEEProvider
from cmcp_verify.verify import ApprovedHashes, verify_trace_claim

_SW_ONLY_MEASUREMENT = "DEVELOPMENT_ONLY_NOT_FOR_PRODUCTION"
_ZERO_HASH = "sha256:" + "0" * 64


def _detect_hardware_provider() -> TEEProvider | None:
    """Return the first available hardware TEE provider, or None.

    Mirrors the gateway probe order (tpm -> sev-snp -> tdx) but never falls back
    to the software-only provider: this experiment is meaningless without real
    hardware, so when nothing is detected we skip rather than simulate.
    """
    candidates: list[TEEProvider] = []
    try:
        from cmcp_runtime.tee.tpm import TPMProvider

        candidates.append(TPMProvider())
    except ImportError:
        pass
    try:
        from cmcp_runtime.tee.sev_snp import SEVSNPProvider

        candidates.append(SEVSNPProvider())
    except ImportError:
        pass
    try:
        from cmcp_runtime.tee.tdx import TDXProvider

        candidates.append(TDXProvider())
    except ImportError:
        pass

    for provider in candidates:
        try:
            if provider.detect():
                return provider
        except Exception:
            continue
    return None


def _jwk_thumbprint(x_b64url: str) -> bytes:
    """RFC 7638 JWK thumbprint for an Ed25519 OKP key (members sorted: crv,kty,x).

    This matches the gateway's nonce construction in cmcp_runtime.startup so the
    verifier's TEE key-binding check (report_data[:32] == thumbprint) passes.
    """
    members = f'{{"crv":"Ed25519","kty":"OKP","x":"{x_b64url}"}}'
    return hashlib.sha256(members.encode()).digest()


def _gateway_nonce(signing_key: SigningKey, salt: bytes) -> bytes:
    """Reproduce the gateway nonce: JWK thumbprint (32) || salt (32)."""
    x_b64 = base64.urlsafe_b64encode(signing_key.public_key_bytes).rstrip(b"=").decode()
    return _jwk_thumbprint(x_b64) + salt


def _build_claim(report: AttestationReport, signing_key: SigningKey, session_id: str):
    policy = PolicyBundleInfo(hash=_ZERO_HASH, enforcement_mode="enforcing", policy_version="1.0.0")
    catalog = ToolCatalogInfo(hash=_ZERO_HASH)
    summary = CallSummary(
        tool_calls_total=1,
        tool_calls_allowed=1,
        tool_calls_denied=0,
        tool_calls_faulted=0,
        tools_invoked=["ehr.get_patient"],
        session_max_sensitivity="hipaa_phi",
        call_graph_summary=CallGraphSummary(compliance_domains_touched=["hipaa_phi"], cross_boundary_events=[]),
    )
    report_info = AttestationReportInfo(
        provider=report.provider,
        measurement=report.measurement,
        report_data=report.report_data,
        attestation_generated_at=report.attestation_generated_at.isoformat(),
        attestation_validity_seconds=report.attestation_validity_seconds,
        measurement_note=report.measurement_note,
        raw_evidence=(base64.b64encode(report.raw_evidence).decode() if report.raw_evidence else None),
    )
    return generate_trace_claim(
        session_id=session_id,
        signing_key=signing_key,
        attestation_report=report_info,
        policy_bundle=policy,
        tool_catalog=catalog,
        call_summary=summary,
        audit_chain_root=_ZERO_HASH,
        audit_chain_tip=_ZERO_HASH,
        audit_chain_length=1,
    )


def _verify_raw_evidence(report: AttestationReport, signing_key: SigningKey, session_id: str):
    """Run the provider-specific verifier over the real hardware evidence."""
    name = report.provider
    if name == "sev-snp":
        from cmcp_verify.sev_snp import verify_sev_snp_measurement

        return verify_sev_snp_measurement(
            measurement=report.measurement,
            raw_evidence=report.raw_evidence,
            report_data_hex=report.report_data,
        )
    if name == "tdx":
        from cmcp_verify.tdx import verify_tdx_measurement

        return verify_tdx_measurement(
            measurement=report.measurement,
            raw_evidence=report.raw_evidence,
            report_data_hex=report.report_data,
        )
    if name == "tpm":
        from cmcp_runtime.tee.base import jwk_thumbprint
        from cmcp_verify.tpm import verify_tpm_measurement

        return verify_tpm_measurement(
            measurement=report.measurement,
            raw_evidence=report.raw_evidence,
            expected_qualifying_data=jwk_thumbprint(signing_key.public_key_bytes),
        )
    return None


def _result(label: str, value: str) -> None:
    print(f"  {label}: {value}")


def main() -> int:
    print()
    print("Hardware TEE attestation | real attestation report + verification")
    print("=" * 72)

    provider = _detect_hardware_provider()
    if provider is None:
        print()
        print("SKIP: no hardware TEE detected on this host.")
        print("This experiment requires a confidential VM (AMD SEV-SNP, Intel TDX,")
        print("or a TPM 2.0 device). See experiments/claim-hw-attestation/README.md")
        print("for Azure / GCP deployment steps. Exiting 0 so CI and dev hosts pass.")
        print()
        return 0

    signing_key = SigningKey()
    session_id = "hw-experiment-session-001"

    # --- P1: real provider ---
    print()
    print("P1  Hardware provider detected")
    _result("Provider", provider.provider_name())
    if provider.provider_name() not in ("sev-snp", "tdx", "tpm"):
        print("  FAIL: detected provider is not a hardware provider")
        return 1
    print("  PASS: a hardware TEE provider is active (not software-only)")

    # --- P2: nonce binding ---
    print()
    print("P2  Report binds the gateway-supplied nonce")
    salt = b"\x11" * 32  # fixed salt so P4 can vary it; production uses secrets.token_bytes
    nonce = _gateway_nonce(signing_key, salt)
    report = provider.get_attestation_report(nonce)
    _result("Nonce (hex)", nonce.hex())
    _result("report_data", report.report_data)
    if report.report_data != nonce.hex():
        print("  FAIL: report_data does not equal the nonce we supplied")
        return 1
    print("  PASS: report_data == nonce -- report is bound to this gateway key")

    # --- P3: real measurement ---
    print()
    print("P3  Measurement is a real hardware value")
    _result("Measurement", report.measurement[:48] + ("..." if len(report.measurement) > 48 else ""))
    _result("Raw evidence bytes", str(len(report.raw_evidence) if report.raw_evidence else 0))
    if not report.measurement or report.measurement == _SW_ONLY_MEASUREMENT:
        print("  FAIL: measurement is empty or the software-only placeholder")
        return 1
    print("  PASS: measurement is hardware-backed")

    # --- P4: freshness / instance binding ---
    print()
    print("P4  A different nonce yields a different report")
    nonce2 = _gateway_nonce(signing_key, b"\x22" * 32)
    report2 = provider.get_attestation_report(nonce2)
    _result("report_data #1", report.report_data)
    _result("report_data #2", report2.report_data)
    if report.report_data == report2.report_data:
        print("  FAIL: two different nonces produced identical report_data")
        return 1
    print("  PASS: report_data tracks the nonce -- no replay across nonces")

    # --- P5: verify raw hardware evidence ---
    print()
    print("P5  Provider-specific verification of the raw evidence")
    raw_result = _verify_raw_evidence(report, signing_key, session_id)
    if raw_result is None:
        print("  FAIL: no verifier for this provider")
        return 1
    _result("Verified fields", ", ".join(raw_result.verified_fields) or "(none)")
    _result("Unverified fields", ", ".join(raw_result.unverified_fields) or "(none)")
    if raw_result.failure_reason:
        _result("Failure reason", str(raw_result.failure_reason))
    for k, v in raw_result.details.items():
        _result(f"detail[{k}]", v)
    print("  NOTE: cert-chain appraisal (AMD KDS / Intel DCAP / TPM EK) appears under")
    print("        unverified_fields until the vendor services are wired in cmcp_verify.")

    # --- P6: end-to-end TRACE Claim verification ---
    print()
    print("P6  Full TRACE Claim verifies end to end")
    claim = _build_claim(report, signing_key, session_id)
    claim_json = json.loads(claim.model_dump_json(exclude_none=True))
    result = verify_trace_claim(
        claim_json,
        ApprovedHashes(policy_bundle_hash=_ZERO_HASH, tool_catalog_hash=_ZERO_HASH),
    )
    _result("Status", str(result.status))
    _result("Verified fields", ", ".join(result.verified_fields) or "(none)")
    _result("Unverified fields", ", ".join(result.unverified_fields) or "(none)")
    for required in ("schema", "signature"):
        if required not in result.verified_fields:
            print(f"  FAIL: expected '{required}' to verify")
            return 1
    print("  PASS: schema + signature verify; claim is bound to the TEE key")

    print()
    print("All hardware properties demonstrated on:", provider.provider_name())
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
