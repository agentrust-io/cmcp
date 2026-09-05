"""Regression matrix for Opaque managed-attestation fail-closed semantics (#594)."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from cmcp_verify.opaque import (
    OpaqueVerificationResult,
    _redact_auth_headers,
    verify_opaque_measurement,
)
from cmcp_verify.verify import VerificationError, verify_trace_claim
from tests.unit.test_verify import _approved, _make_signed_claim

_MEASUREMENT = "sha384:" + "a" * 96
_ENDPOINT = "https://attest.example.com/v1/verify"
_EVIDENCE = bytes(64)


def _response_bytes(payload: bytes) -> MagicMock:
    response = MagicMock()
    response.__enter__ = lambda s: s
    response.__exit__ = MagicMock(return_value=False)
    response.read.return_value = payload
    return response


def _response_json(payload: object) -> MagicMock:
    return _response_bytes(json.dumps(payload).encode())


def _verify_payload(payload: object) -> OpaqueVerificationResult:
    with patch("cmcp_verify.opaque.urllib.request.urlopen") as mock_open:
        mock_open.return_value = _response_json(payload)
        return verify_opaque_measurement(
            _MEASUREMENT,
            _EVIDENCE,
            opaque_endpoint=_ENDPOINT,
        )


def test_opaque_requires_both_affirmative_success_predicates() -> None:
    result = _verify_payload({"verified": True, "measurement_matched": True})

    assert result.verified is True
    assert result.failure_reason is None
    assert "opaque_managed_attestation" in result.verified_fields
    assert "opaque_managed_attestation" not in result.unverified_fields


@pytest.mark.parametrize(
    "payload",
    [
        {"verified": True, "measurement_matched": False},
        {"verified": True},
        {"measurement_matched": True},
        {"verified": False, "measurement_matched": True},
        {"verified": "true", "measurement_matched": True},
        {"verified": 1, "measurement_matched": True},
        {"verified": None, "measurement_matched": True},
        {"verified": True, "measurement_matched": "true"},
        {"verified": True, "measurement_matched": 1},
        {"verified": True, "measurement_matched": None},
    ],
)
def test_opaque_refuses_missing_false_or_non_boolean_success_members(payload: object) -> None:
    result = _verify_payload(payload)

    assert result.verified is False
    assert result.failure_reason is not None
    assert "opaque_managed_attestation" in result.unverified_fields
    assert "opaque_managed_attestation" not in result.verified_fields


def test_opaque_preserves_endpoint_failure_reason() -> None:
    result = _verify_payload(
        {
            "verified": False,
            "measurement_matched": False,
            "failure_reason": "measurement_unknown",
        }
    )

    assert result.verified is False
    assert result.failure_reason == "measurement_unknown"


def test_opaque_requires_parsed_response_to_be_an_object() -> None:
    result = _verify_payload([])

    assert result.verified is False
    assert result.failure_reason == "opaque_invalid_response"
    assert result.details.get("opaque_response_type") == "list"
    assert "opaque_managed_attestation" in result.unverified_fields


def test_opaque_parse_failure_is_unverified_and_observable() -> None:
    with patch("cmcp_verify.opaque.urllib.request.urlopen") as mock_open:
        mock_open.return_value = _response_bytes(b"not-json")
        result = verify_opaque_measurement(
            _MEASUREMENT,
            _EVIDENCE,
            opaque_endpoint=_ENDPOINT,
        )

    assert result.verified is False
    assert result.failure_reason == "opaque_verification_error"
    assert result.details.get("opaque_error") == "JSONDecodeError"
    assert "opaque_managed_attestation" in result.unverified_fields


def test_opaque_transport_failure_is_unverified_and_redacted_to_error_type() -> None:
    with patch(
        "cmcp_verify.opaque.urllib.request.urlopen",
        side_effect=OSError("secret-bearing transport detail"),
    ):
        result = verify_opaque_measurement(
            _MEASUREMENT,
            _EVIDENCE,
            opaque_endpoint=_ENDPOINT,
        )

    assert result.verified is False
    assert result.failure_reason == "opaque_verification_error"
    assert result.details.get("opaque_error") == "OSError"
    assert "secret-bearing transport detail" not in str(result.details)


def test_failed_opaque_appraisal_cannot_credit_hardware_attestation(monkeypatch) -> None:
    claim, _ = _make_signed_claim(provider="opaque")
    failed = OpaqueVerificationResult(
        verified=False,
        unverified_fields=["opaque_managed_attestation"],
        failure_reason="opaque_verification_failed",
    )
    monkeypatch.setattr(
        "cmcp_verify.opaque.verify_opaque_measurement",
        lambda *args, **kwargs: failed,
    )

    result = verify_trace_claim(claim, _approved())

    assert "hardware_attestation" not in result.verified_fields
    assert "hardware_attestation" in result.unverified_fields
    assert result.failure_reason == VerificationError.HARDWARE_ATTESTATION_FAILED


@pytest.mark.parametrize(
    "header",
    [
        "Authorization",
        "authorization",
        "Proxy-Authorization",
        "X-API-Key",
        "x-apikey",
        "Cookie",
        "Set-Cookie",
        "X-Auth-Token",
        "X-Opaque-Secret",
        "X-Client-Password",
        "X-Signed-Credential",
        "X-Request-Signature",
    ],
)
def test_credential_bearing_headers_are_never_logged_in_clear(header: str) -> None:
    """HW-008: redaction is deny-by-default, not an Authorization special case.

    Redacting only Authorization left OPAQUE_API_KEY in clear for any deployment
    that carries it under a vendor header spelling or a cookie.
    """
    redacted = _redact_auth_headers({header: "super-secret-value"})

    assert redacted[header] == "[REDACTED]"
    assert "super-secret-value" not in str(redacted)


def test_redaction_leaves_non_credential_headers_readable() -> None:
    """Redaction must not blind the debug log to the fields that explain a failure."""
    redacted = _redact_auth_headers(
        {"Content-Type": "application/json", "User-Agent": "cmcp/1.0", "Accept": "*/*"}
    )

    assert redacted == {
        "Content-Type": "application/json",
        "User-Agent": "cmcp/1.0",
        "Accept": "*/*",
    }
