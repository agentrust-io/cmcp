"""Opaque Systems managed attestation verification -- implements issue #70."""
from __future__ import annotations

import base64
import json
import logging
import os
import urllib.request
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_OPAQUE_ENDPOINT_ENV = "CMCP_OPAQUE_ATTESTATION_ENDPOINT"
_OPAQUE_API_KEY_ENV = "OPAQUE_API_KEY"
_OPAQUE_TIMEOUT_SECONDS = 10


def _redact_auth_headers(headers: dict[str, str]) -> dict[str, str]:
    """HW-008: return a copy of headers with Authorization value replaced by [REDACTED]."""
    return {
        k: "[REDACTED]" if k.lower() == "authorization" else v
        for k, v in headers.items()
    }


@dataclass
class OpaqueVerificationResult:
    verified: bool
    verified_fields: list[str] = field(default_factory=list)
    unverified_fields: list[str] = field(default_factory=list)
    failure_reason: str | None = None
    details: dict[str, str] = field(default_factory=dict)


def verify_opaque_measurement(
    measurement: str,
    raw_evidence: bytes | None,
    opaque_endpoint: str | None = None,
) -> OpaqueVerificationResult:
    """
    Verify an Opaque Systems managed attestation.

    Sends raw_evidence to the Opaque attestation endpoint and parses the
    response. Returns PARTIALLY_VERIFIED if the endpoint is not configured.

    The endpoint URL is read from the CMCP_OPAQUE_ATTESTATION_ENDPOINT
    environment variable if not passed explicitly.

    If OPAQUE_API_KEY is set, it is sent as a Bearer token in the Authorization
    header. The header value is never logged -- _redact_auth_headers() strips it
    before any debug output (HW-008).
    """
    result = OpaqueVerificationResult(verified=True)

    endpoint = opaque_endpoint or os.environ.get(_OPAQUE_ENDPOINT_ENV)
    if not endpoint:
        result.verified = False
        result.failure_reason = "opaque_endpoint_not_configured"
        result.unverified_fields.append("opaque_managed_attestation")
        result.details["hint"] = (
            f"Set {_OPAQUE_ENDPOINT_ENV} to enable Opaque attestation verification"
        )
        return result

    if raw_evidence is None:
        # Fail closed: an attestation claim with no evidence cannot verify.
        result.verified = False
        result.failure_reason = "no_raw_evidence"
        result.unverified_fields.append("opaque_managed_attestation")
        result.details["opaque_endpoint"] = endpoint
        result.details["hint"] = "raw_evidence not provided; cannot verify with Opaque"
        return result

    if not endpoint or not endpoint.startswith("https://"):
        raise ValueError(
            f"Opaque attestation endpoint must use https://. Got: {endpoint!r}. "
            "Set CMCP_OPAQUE_ATTESTATION_ENDPOINT to a valid https:// URL."
        )

    # POST raw_evidence (base64-encoded) to the Opaque attestation endpoint
    payload = json.dumps({
        "measurement": measurement,
        "raw_evidence": base64.b64encode(raw_evidence).decode(),
    }).encode()

    request_headers: dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    api_key = os.environ.get(_OPAQUE_API_KEY_ENV)
    if api_key:
        request_headers["Authorization"] = f"Bearer {api_key}"

    try:
        req = urllib.request.Request(
            endpoint,
            data=payload,
            method="POST",
            headers=request_headers,
        )
        with urllib.request.urlopen(req, timeout=_OPAQUE_TIMEOUT_SECONDS) as resp:  # nosec B310 - req is a Request object with explicit HTTPS endpoint
            body = json.loads(resp.read().decode())

        if body.get("verified") is True:
            result.verified_fields.append("opaque_managed_attestation")
            result.details["opaque_endpoint"] = endpoint
        else:
            result.verified = False
            result.failure_reason = body.get("failure_reason", "opaque_verification_failed")
            result.unverified_fields.append("opaque_managed_attestation")
            result.details["opaque_response"] = str(body.get("details", ""))

    except Exception as exc:  # noqa: BLE001
        # HW-008: log type and endpoint only -- never include request headers
        # (which may contain the Authorization / OPAQUE_API_KEY value).
        logger.debug(
            "opaque_verify_failed: endpoint=%s error_type=%s safe_headers=%s",
            endpoint,
            type(exc).__name__,
            _redact_auth_headers(request_headers),
        )
        result.unverified_fields.append("opaque_managed_attestation")
        result.details["opaque_endpoint"] = endpoint
        result.details["opaque_error"] = type(exc).__name__

    return result
