"""Opaque Systems managed attestation verification — implements issue #70."""
from __future__ import annotations

import base64
import json
import os
import urllib.request
from dataclasses import dataclass, field

_OPAQUE_ENDPOINT_ENV = "CMCP_OPAQUE_ATTESTATION_ENDPOINT"
_OPAQUE_TIMEOUT_SECONDS = 10


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
        result.unverified_fields.append("opaque_managed_attestation")
        result.details["opaque_endpoint"] = endpoint
        result.details["hint"] = "raw_evidence not provided; cannot verify with Opaque"
        return result

    # POST raw_evidence (base64-encoded) to the Opaque attestation endpoint
    payload = json.dumps({
        "measurement": measurement,
        "raw_evidence": base64.b64encode(raw_evidence).decode(),
    }).encode()

    try:
        req = urllib.request.Request(
            endpoint,
            data=payload,
            method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=_OPAQUE_TIMEOUT_SECONDS) as resp:
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
        result.unverified_fields.append("opaque_managed_attestation")
        result.details["opaque_endpoint"] = endpoint
        result.details["opaque_error"] = type(exc).__name__

    return result
