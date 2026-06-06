"""Tests for TPM 2.0 attestation verification (issue #62)."""

from __future__ import annotations

import base64
import hashlib
import struct
from datetime import UTC, datetime

from cmcp_gateway.audit.chain import AuditChain
from cmcp_gateway.audit.keys import SigningKey
from cmcp_gateway.audit.trace_claim import (
    AttestationReportInfo,
    CallGraphSummary,
    CallSummary,
    PolicyBundleInfo,
    ToolCatalogInfo,
    _to_dict,
    generate_trace_claim,
)
from cmcp_verify.tpm import verify_tpm_measurement
from cmcp_verify.verify import ApprovedHashes, verify_trace_claim

POLICY_HASH = "sha256:" + "a" * 64
CATALOG_HASH = "sha256:" + "b" * 64
VALID_MEASUREMENT = "sha256:" + "c" * 64


# ── Helper to build a minimal valid TPM2B_ATTEST blob ────────────────────────


def _make_tpm2b_attest(
    qualifying_data: bytes = b"\x00" * 32,
    magic: int = 0xFF544347,
    qualified_signer: bytes = b"",
) -> bytes:
    """Build a minimal TPM2B_ATTEST with the given qualifying_data."""
    # TPMS_ATTEST body
    magic_bytes = struct.pack(">I", magic)
    type_bytes = struct.pack(">H", 0x8018)  # TPM_ST_ATTEST_QUOTE
    qs = struct.pack(">H", len(qualified_signer)) + qualified_signer
    ed = struct.pack(">H", len(qualifying_data)) + qualifying_data
    # clockInfo (8 bytes) + firmwareVersion (8 bytes) + minimal attested
    tail = b"\x00" * 16 + struct.pack(">H", 0) + b"\x00" * 4  # minimal pcrSelect
    attest_body = magic_bytes + type_bytes + qs + ed + tail

    # Outer TPM2B size
    return struct.pack(">H", len(attest_body)) + attest_body


# ── Unit tests for verify_tpm_measurement ────────────────────────────────────


def test_valid_measurement_format_passes() -> None:
    result = verify_tpm_measurement(
        measurement=VALID_MEASUREMENT,
        raw_evidence=None,
    )
    assert "measurement_format" in result.verified_fields
    assert result.failure_reason is None


def test_invalid_measurement_no_prefix_fails() -> None:
    result = verify_tpm_measurement(
        measurement="deadbeef" * 8,
        raw_evidence=None,
    )
    assert result.verified is False
    assert result.failure_reason == "invalid_measurement_format"
    assert "measurement_format" not in result.verified_fields


def test_invalid_measurement_short_hex_fails() -> None:
    result = verify_tpm_measurement(
        measurement="sha256:" + "ab" * 31,  # 62 chars, not 64
        raw_evidence=None,
    )
    assert result.verified is False
    assert result.failure_reason == "invalid_measurement_format"


def test_invalid_measurement_non_hex_fails() -> None:
    result = verify_tpm_measurement(
        measurement="sha256:" + "z" * 64,
        raw_evidence=None,
    )
    assert result.verified is False
    assert result.failure_reason == "invalid_measurement_format"


def test_no_raw_evidence_pcr_digest_unverified() -> None:
    result = verify_tpm_measurement(
        measurement=VALID_MEASUREMENT,
        raw_evidence=None,
    )
    assert "pcr_digest" in result.unverified_fields
    assert "qualifying_data" in result.unverified_fields
    assert "ek_cert_chain" in result.unverified_fields


def test_no_raw_evidence_ek_cert_always_unverified() -> None:
    result = verify_tpm_measurement(
        measurement=VALID_MEASUREMENT,
        raw_evidence=None,
    )
    assert "ek_cert_chain" in result.unverified_fields
    assert result.details.get("ek_cert_chain_validation") == "ek_cert_chain_validation_requires_ca_lookup"


def test_raw_evidence_valid_magic_parsed() -> None:
    blob = _make_tpm2b_attest()
    result = verify_tpm_measurement(
        measurement=VALID_MEASUREMENT,
        raw_evidence=blob,
    )
    assert "pcr_format" in result.verified_fields
    assert result.failure_reason is None


def test_raw_evidence_wrong_magic_fails_gracefully() -> None:
    blob = _make_tpm2b_attest(magic=0xDEADBEEF)
    result = verify_tpm_measurement(
        measurement=VALID_MEASUREMENT,
        raw_evidence=blob,
    )
    # Must not raise — verified should be False or pcr_format unverified
    assert "pcr_format" in result.unverified_fields
    assert "tpm_parse_error" in result.details


def test_raw_evidence_truncated_fails_gracefully() -> None:
    result = verify_tpm_measurement(
        measurement=VALID_MEASUREMENT,
        raw_evidence=b"\x00\x10",  # claims 16 bytes but body is empty
    )
    assert "pcr_format" in result.unverified_fields


def test_raw_evidence_empty_fails_gracefully() -> None:
    result = verify_tpm_measurement(
        measurement=VALID_MEASUREMENT,
        raw_evidence=b"",
    )
    assert "pcr_format" in result.unverified_fields


def test_qualifying_data_verified_when_correct() -> None:
    pub_key_hex = "aa" * 32
    session = "test-session-123"
    expected_qd = hashlib.sha256(bytes.fromhex(pub_key_hex) + session.encode()).digest()
    blob = _make_tpm2b_attest(qualifying_data=expected_qd)

    result = verify_tpm_measurement(
        measurement=VALID_MEASUREMENT,
        raw_evidence=blob,
        tee_public_key_hex=pub_key_hex,
        session_id=session,
    )
    assert "qualifying_data" in result.verified_fields
    assert "qualifying_data" not in result.unverified_fields


def test_qualifying_data_mismatch_is_unverified() -> None:
    pub_key_hex = "aa" * 32
    session = "test-session-123"
    blob = _make_tpm2b_attest(qualifying_data=b"\xff" * 32)

    result = verify_tpm_measurement(
        measurement=VALID_MEASUREMENT,
        raw_evidence=blob,
        tee_public_key_hex=pub_key_hex,
        session_id=session,
    )
    assert "qualifying_data" in result.unverified_fields
    assert "qualifying_data" not in result.verified_fields


def test_no_keys_qualifying_data_unverified() -> None:
    blob = _make_tpm2b_attest()
    result = verify_tpm_measurement(
        measurement=VALID_MEASUREMENT,
        raw_evidence=blob,
        tee_public_key_hex=None,
        session_id=None,
    )
    assert "qualifying_data" in result.unverified_fields


# ── Integration: verify_trace_claim with tpm2 platform ───────────────────────


def _make_tpm2_claim(
    measurement: str = VALID_MEASUREMENT,
    firmware_version: str = "2.0-production",
    raw_evidence_b64: str | None = None,
) -> dict:
    """Build a signed claim with tpm2 platform.

    firmware_version and raw_evidence are injected directly into the serialized dict
    after signing, since AttestationReportInfo does not carry those fields and
    verify_trace_claim reads them from the raw dict.
    """
    key = SigningKey()
    chain = AuditChain("tpm-session")

    # Use a valid sha256 measurement for claim generation so Pydantic accepts it
    gen_measurement = VALID_MEASUREMENT

    claim = generate_trace_claim(
        session_id="tpm-session",
        signing_key=key,
        attestation_report=AttestationReportInfo(
            provider="tpm",
            measurement=gen_measurement,
            report_data="00" * 32,
            attestation_generated_at=datetime.now(tz=UTC).isoformat(),
            attestation_validity_seconds=86400,
        ),
        policy_bundle=PolicyBundleInfo(
            hash=POLICY_HASH,
            enforcement_mode="enforcing",
            policy_version="1.0.0",
        ),
        tool_catalog=ToolCatalogInfo(hash=CATALOG_HASH),
        call_summary=CallSummary(
            tool_calls_total=1,
            tool_calls_allowed=1,
            tool_calls_denied=0,
            tool_calls_faulted=0,
            tools_invoked=["test.tool"],
            session_max_sensitivity="public",
            call_graph_summary=CallGraphSummary(
                compliance_domains_touched=[],
                cross_boundary_events=[],
            ),
        ),
        audit_chain_root=chain.chain_root,
        audit_chain_tip=chain.chain_tip,
        audit_chain_length=chain.length,
        do_sign=True,
    )

    claim_dict = _to_dict(claim)

    # Inject fields that verify_trace_claim reads from the raw dict
    claim_dict["trace"]["runtime"]["firmware_version"] = firmware_version
    if measurement != gen_measurement:
        claim_dict["trace"]["runtime"]["measurement"] = measurement
    if raw_evidence_b64 is not None:
        claim_dict["trace"]["runtime"]["raw_evidence"] = raw_evidence_b64

    return claim_dict


def _approved() -> ApprovedHashes:
    return ApprovedHashes(policy_bundle_hash=POLICY_HASH, tool_catalog_hash=CATALOG_HASH)


def test_tpm2_valid_measurement_triggers_tpm_path() -> None:
    claim_dict = _make_tpm2_claim()
    result = verify_trace_claim(claim_dict, _approved())
    # hardware_attestation should not be in the "not implemented" stub path
    assert "hardware_attestation" in result.verified_fields or "hardware_attestation" in result.unverified_fields
    assert "Platform 'tpm2' attestation verification not yet implemented" not in str(result.details)


def test_tpm2_invalid_measurement_format_fails() -> None:
    claim_dict = _make_tpm2_claim(measurement="bad-measurement")
    result = verify_trace_claim(claim_dict, _approved())
    assert "tpm_failure" in result.details
    assert result.details["tpm_failure"] == "invalid_measurement_format"


def test_software_only_stays_in_sw_path() -> None:
    """firmware_version == software-only-dev-mode must not enter the TPM verification path."""
    key = SigningKey()
    chain = AuditChain("sw-session")
    claim = generate_trace_claim(
        session_id="sw-session",
        signing_key=key,
        attestation_report=AttestationReportInfo(
            provider="software-only",
            measurement="DEVELOPMENT_ONLY",
            report_data="00" * 32,
            attestation_generated_at=datetime.now(tz=UTC).isoformat(),
            attestation_validity_seconds=86400,
        ),
        policy_bundle=PolicyBundleInfo(
            hash=POLICY_HASH,
            enforcement_mode="enforcing",
            policy_version="1.0.0",
        ),
        tool_catalog=ToolCatalogInfo(hash=CATALOG_HASH),
        call_summary=CallSummary(
            tool_calls_total=1,
            tool_calls_allowed=1,
            tool_calls_denied=0,
            tool_calls_faulted=0,
            tools_invoked=["test.tool"],
            session_max_sensitivity="public",
            call_graph_summary=CallGraphSummary(
                compliance_domains_touched=[],
                cross_boundary_events=[],
            ),
        ),
        audit_chain_root=chain.chain_root,
        audit_chain_tip=chain.chain_tip,
        audit_chain_length=chain.length,
        do_sign=True,
    )
    claim_dict = _to_dict(claim)
    result = verify_trace_claim(claim_dict, _approved())
    assert "hardware_attestation" in result.unverified_fields
    assert result.details.get("hardware_attestation") == "software-only mode — not hardware-backed"


def test_tpm2_with_valid_raw_evidence_parses() -> None:
    blob = _make_tpm2b_attest()
    raw_b64 = base64.b64encode(blob).decode()
    claim_dict = _make_tpm2_claim(raw_evidence_b64=raw_b64)
    result = verify_trace_claim(claim_dict, _approved())
    # pcr_format should be verified since magic is correct
    assert "pcr_format" in result.verified_fields
