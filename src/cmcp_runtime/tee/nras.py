"""NVIDIA Remote Attestation Service (NRAS) client -- Phase 2 / v0.2.

Implements issue #125: post-attestation appraisal via the NRAS REST API.
After get_attestation_report() completes, callers may optionally submit
the raw evidence to NRAS for hardware-level appraisal. The result is stored
in RuntimeContext.nras_appraisal and written into the TRACE Trust Record
appraisal field.

Integration is opt-in: if CMCP_NRAS_API_KEY is absent the step is skipped
with a WARNING log and RuntimeContext.nras_appraisal is None.

Phase 2 / v0.2 -- target: Q3 2026 (Berlin demo).
"""

from __future__ import annotations

import base64
import json
import logging
import math
import os
import urllib.parse
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

from cmcp_runtime.tee.base import AttestationReport

logger = logging.getLogger(__name__)

NRAS_ENDPOINT: str = "https://nras.nvidia.com/v1/attestation/gpu"
_DEFAULT_TIMEOUT_SECONDS: float = 10.0
_ENV_API_KEY: str = "CMCP_NRAS_API_KEY"
_VALID_STATUSES: frozenset[str] = frozenset({"affirming", "warning", "contraindicated"})


@dataclass
class AppraisalResult:
    """EAR (Evidence Appraisal Result) returned by NRAS.

    Attributes:
        status:     EAR appraisal status -- one of affirming, warning, contraindicated.
        verifier:   NRAS verifier identifier string from verifier-identifier.
        timestamp:  ISO 8601 UTC timestamp of when the appraisal was received.
        ear_raw:    Full EAR JSON payload, preserved verbatim for audit.
    """

    status: str
    verifier: str
    timestamp: str
    ear_raw: dict[str, Any]


class NRASError(Exception):
    """Base class for all NRAS client errors."""


class NRASAuthError(NRASError):
    """NRAS returned HTTP 401 -- API key invalid or missing."""


class NRASAppraisalError(NRASError):
    """NRAS rejected the attestation evidence (4xx other than 401)."""

    def __init__(self, status_code: int, body: str) -> None:
        self.status_code = status_code
        super().__init__(f"NRAS appraisal failed: HTTP {status_code} -- {body[:200]}")


class NRASClient:
    """Client for the NVIDIA Remote Attestation Service.

    Phase 2 / v0.2 -- implements issue #125.

    Args:
        api_key:     NVIDIA developer API key (CMCP_NRAS_API_KEY).
        endpoint:    NRAS appraisal endpoint URL. Override for testing only.
        timeout:     HTTP request timeout in seconds.
        http_client: Optional pre-built httpx.Client; injected in tests.
    """

    def __init__(
        self,
        api_key: str,
        *,
        endpoint: str = NRAS_ENDPOINT,
        timeout: float = _DEFAULT_TIMEOUT_SECONDS,
        http_client: httpx.Client | None = None,
    ) -> None:
        if not isinstance(api_key, str) or not api_key.strip():
            raise ValueError("api_key must be a non-empty string")
        parsed = urllib.parse.urlsplit(endpoint) if isinstance(endpoint, str) else None
        if parsed is None or parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("endpoint must be a valid HTTPS URL with a hostname")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("timeout must be a positive finite number")
        self._api_key = api_key
        self._endpoint = endpoint
        self._timeout = timeout
        self._http_client = http_client

    def appraise(self, report: AttestationReport) -> AppraisalResult:
        """Submit attestation evidence to NRAS and return the EAR result.

        The nonce field is taken from report.report_data (hex-encoded SHA-256 nonce).
        attestation_report is the base64-encoded raw_evidence blob; if raw_evidence
        is None (software-only dev mode) the measurement bytes are encoded instead.

        Raises:
            NRASAuthError:      HTTP 401 from NRAS.
            NRASAppraisalError: Any other 4xx response.
            NRASError:          Network / timeout errors or unexpected response.
        """
        rd = getattr(report, "report_data", None)
        if (
            not isinstance(rd, str)
            or len(rd) not in (64, 128)
            or any(c not in "0123456789abcdefABCDEF" for c in rd)
        ):
            raise NRASError("report.report_data must be a 64- or 128-character hex string")
        nonce_b64 = base64.b64encode(bytes.fromhex(rd)).decode()

        if report.raw_evidence is not None:
            evidence_b64 = base64.b64encode(report.raw_evidence).decode()
        else:
            evidence_b64 = base64.b64encode(report.measurement.encode()).decode()

        payload: dict[str, Any] = {
            "nonce": nonce_b64,
            "attestation_report": evidence_b64,
        }
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        try:
            ear = self._post(payload, headers)
        except (NRASAuthError, NRASAppraisalError, NRASError):
            raise
        except httpx.TimeoutException as exc:
            raise NRASError(f"NRAS request timed out after {self._timeout}s") from exc
        except httpx.HTTPError as exc:
            raise NRASError(f"NRAS HTTP transport error: {exc}") from exc

        return self._parse_ear(ear)

    def _post(self, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
        """POST to the NRAS endpoint and return the parsed JSON body."""
        client = self._http_client
        if client is not None:
            response = client.post(self._endpoint, json=payload, headers=headers)
        else:
            with httpx.Client(timeout=self._timeout) as c:
                response = c.post(self._endpoint, json=payload, headers=headers)

        if response.status_code == 401:
            raise NRASAuthError("NRAS rejected the API key (HTTP 401)")
        if response.status_code >= 400:
            raise NRASAppraisalError(response.status_code, response.text)

        def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            out: dict[str, Any] = {}
            for key, value in pairs:
                if key in out:
                    raise ValueError(f"duplicate JSON object key: {key!r}")
                out[key] = value
            return out

        def _no_nonfinite(token: str) -> Any:
            raise ValueError(f"non-finite JSON constant: {token}")

        try:
            parsed = json.loads(
                response.text,
                object_pairs_hook=_no_duplicate_keys,
                parse_constant=_no_nonfinite,
            )
        except Exception as exc:
            raise NRASError(f"NRAS response is not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise NRASError("NRAS response must be a JSON object")
        return parsed

    @staticmethod
    def _parse_ear(ear: dict[str, Any]) -> AppraisalResult:
        """Validate and extract fields from a raw EAR JSON payload."""
        if not isinstance(ear, dict):
            raise NRASError("EAR payload must be a JSON object")
        status = ear.get("status", "")
        if not isinstance(status, str) or status not in _VALID_STATUSES:
            raise NRASError(
                f"NRAS returned unrecognised EAR status {status!r}. Expected one of {sorted(_VALID_STATUSES)}."
            )

        verifier = ear.get("verifier-identifier", "")
        if not isinstance(verifier, str) or not verifier:
            verifier = "nras.nvidia.com"

        timestamp = datetime.now(tz=UTC).isoformat()

        return AppraisalResult(
            status=status,
            verifier=verifier,
            timestamp=timestamp,
            ear_raw=ear,
        )


def try_appraise(report: AttestationReport) -> AppraisalResult | None:
    """Attempt NRAS appraisal using the CMCP_NRAS_API_KEY env var.

    Returns None (and logs a WARNING) when:
    - CMCP_NRAS_API_KEY is not set.
    - The NRAS call fails for any reason.

    This is the integration point called from startup.run_startup() after
    get_attestation_report() succeeds. It must never raise -- a missing or
    failed appraisal is non-fatal per issue #125.

    Layering: this in-tree appraisal is the standalone fallback for deployments
    with no attested-TLS (aTLS) peer. When cMCP is composed with a platform that
    performs attestation in the aTLS handshake, the platform verdict is
    authoritative and this path stands down -- it is a fallback, not the primary
    gate. Do not wire it up as the enforcing check.

    Phase 2 / v0.2 -- implements issue #125.
    """
    api_key = os.environ.get(_ENV_API_KEY)
    if not api_key or not api_key.strip():
        logger.warning(
            "CMCP_NRAS_API_KEY is not set -- skipping NRAS post-attestation appraisal. "
            "The TRACE Trust Record appraisal field will be empty. "
            "Set CMCP_NRAS_API_KEY to enable hardware appraisal (Phase 2 / v0.2)."
        )
        return None

    try:
        client = NRASClient(api_key=api_key)
        result = client.appraise(report)
        logger.info(
            "NRAS appraisal complete: status=%s verifier=%s",
            result.status,
            result.verifier,
        )
        return result
    except NRASAuthError:
        logger.warning(
            "NRAS appraisal skipped: API key was rejected (HTTP 401). Check CMCP_NRAS_API_KEY."
        )
    except NRASAppraisalError as exc:
        logger.warning("NRAS appraisal rejected evidence: %s", exc)
    except (NRASError, ValueError) as exc:
        logger.warning("NRAS appraisal failed (network/timeout): %s", exc)
    return None
