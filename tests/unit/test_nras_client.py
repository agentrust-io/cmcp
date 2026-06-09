from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import patch

import httpx
import pytest

from cmcp_runtime.tee.base import AttestationReport
from cmcp_runtime.tee.nras import (
    NRAS_ENDPOINT,
    AppraisalResult,
    NRASAppraisalError,
    NRASAuthError,
    NRASClient,
    NRASError,
    try_appraise,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sw_report() -> AttestationReport:
    return AttestationReport(
        provider="software-only",
        measurement="DEVELOPMENT_ONLY_NOT_FOR_PRODUCTION",
        report_data="aa" * 32,
        raw_evidence=None,
        attestation_generated_at=datetime.now(tz=UTC),
        attestation_validity_seconds=86400,
    )


@pytest.fixture()
def hw_report() -> AttestationReport:
    return AttestationReport(
        provider="software-only",
        measurement="sha256:" + "ab" * 32,
        report_data="cd" * 32,
        raw_evidence=bytes.fromhex("deadbeef") * 64,
        attestation_generated_at=datetime.now(tz=UTC),
        attestation_validity_seconds=86400,
    )


def _make_ear(status: str = "affirming") -> dict:
    return {
        "eat_profile": "tag:nvidia.com,2024:nras-v1",
        "status": status,
        "verifier-identifier": "nras.nvidia.com",
    }


def _mock_client(status_code: int, body: object) -> httpx.Client:
    content = json.dumps(body).encode()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, content=content)

    return httpx.Client(transport=httpx.MockTransport(handler))


def _mock_text_client(status_code: int, text: str) -> httpx.Client:
    content = text.encode()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, content=content)

    return httpx.Client(transport=httpx.MockTransport(handler))


# ---------------------------------------------------------------------------
# NRASClient.appraise -- happy paths
# ---------------------------------------------------------------------------


def test_appraise_affirming_status(sw_report):
    ear = _make_ear("affirming")
    client = NRASClient(api_key="test-key", http_client=_mock_client(200, ear))
    result = client.appraise(sw_report)
    assert isinstance(result, AppraisalResult)
    assert result.status == "affirming"
    assert result.verifier == "nras.nvidia.com"
    assert result.ear_raw == ear
    assert result.timestamp


def test_appraise_warning_status(sw_report):
    ear = _make_ear("warning")
    client = NRASClient(api_key="test-key", http_client=_mock_client(200, ear))
    result = client.appraise(sw_report)
    assert result.status == "warning"


def test_appraise_contraindicated_status(sw_report):
    ear = _make_ear("contraindicated")
    client = NRASClient(api_key="test-key", http_client=_mock_client(200, ear))
    result = client.appraise(sw_report)
    assert result.status == "contraindicated"


def test_appraise_uses_raw_evidence_when_present(hw_report):
    import base64

    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, content=json.dumps(_make_ear()).encode())

    http = httpx.Client(transport=httpx.MockTransport(handler))
    client = NRASClient(api_key="test-key", http_client=http)
    client.appraise(hw_report)

    body = json.loads(captured[0].content)
    expected = base64.b64encode(hw_report.raw_evidence).decode()
    assert body["attestation_report"] == expected


def test_appraise_uses_measurement_when_no_raw_evidence(sw_report):
    import base64

    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, content=json.dumps(_make_ear()).encode())

    http = httpx.Client(transport=httpx.MockTransport(handler))
    client = NRASClient(api_key="k", http_client=http)
    client.appraise(sw_report)

    body = json.loads(captured[0].content)
    expected = base64.b64encode(sw_report.measurement.encode()).decode()
    assert body["attestation_report"] == expected


def test_appraise_sends_bearer_auth(sw_report):
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, content=json.dumps(_make_ear()).encode())

    http = httpx.Client(transport=httpx.MockTransport(handler))
    client = NRASClient(api_key="my-secret-key", http_client=http)
    client.appraise(sw_report)
    assert captured[0].headers["authorization"] == "Bearer my-secret-key"


def test_appraise_posts_to_nras_endpoint(sw_report):
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, content=json.dumps(_make_ear()).encode())

    http = httpx.Client(transport=httpx.MockTransport(handler))
    client = NRASClient(api_key="k", http_client=http)
    client.appraise(sw_report)
    assert str(captured[0].url) == NRAS_ENDPOINT
    assert captured[0].method == "POST"


def test_verifier_defaults_when_missing_from_ear(sw_report):
    ear = {"status": "affirming"}
    client = NRASClient(api_key="k", http_client=_mock_client(200, ear))
    result = client.appraise(sw_report)
    assert result.verifier == "nras.nvidia.com"


# ---------------------------------------------------------------------------
# NRASClient.appraise -- error paths
# ---------------------------------------------------------------------------


def test_appraise_raises_auth_error_on_401(sw_report):
    client = NRASClient(api_key="bad", http_client=_mock_text_client(401, "Unauthorized"))
    with pytest.raises(NRASAuthError):
        client.appraise(sw_report)


def test_appraise_raises_appraisal_error_on_422(sw_report):
    client = NRASClient(api_key="k", http_client=_mock_text_client(422, "invalid evidence"))
    with pytest.raises(NRASAppraisalError) as exc_info:
        client.appraise(sw_report)
    assert exc_info.value.status_code == 422


def test_appraise_raises_appraisal_error_on_400(sw_report):
    client = NRASClient(api_key="k", http_client=_mock_text_client(400, "bad request"))
    with pytest.raises(NRASAppraisalError) as exc_info:
        client.appraise(sw_report)
    assert exc_info.value.status_code == 400


def test_appraise_raises_nras_error_on_unknown_ear_status(sw_report):
    ear = {"status": "unknown-future-status", "verifier-identifier": "nras.nvidia.com"}
    client = NRASClient(api_key="k", http_client=_mock_client(200, ear))
    with pytest.raises(NRASError, match="unrecognised EAR status"):
        client.appraise(sw_report)


def test_appraise_raises_nras_error_on_timeout(sw_report):
    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out", request=request)

    http = httpx.Client(transport=httpx.MockTransport(timeout_handler))
    client = NRASClient(api_key="k", http_client=http)
    with pytest.raises(NRASError, match="timed out"):
        client.appraise(sw_report)


def test_appraise_raises_nras_error_on_non_json_response(sw_report):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not json at all")

    http = httpx.Client(transport=httpx.MockTransport(handler))
    client = NRASClient(api_key="k", http_client=http)
    with pytest.raises(NRASError, match="not valid JSON"):
        client.appraise(sw_report)


# ---------------------------------------------------------------------------
# try_appraise -- non-fatal wrapper
# ---------------------------------------------------------------------------


def test_try_appraise_returns_none_when_no_api_key(sw_report, monkeypatch):
    monkeypatch.delenv("CMCP_NRAS_API_KEY", raising=False)
    result = try_appraise(sw_report)
    assert result is None


def test_try_appraise_returns_result_on_success(sw_report, monkeypatch):
    monkeypatch.setenv("CMCP_NRAS_API_KEY", "valid-key")
    ear = _make_ear("affirming")
    mock_instance = NRASClient(api_key="valid-key", http_client=_mock_client(200, ear))

    with patch("cmcp_runtime.tee.nras.NRASClient", return_value=mock_instance):
        result = try_appraise(sw_report)

    assert result is not None
    assert result.status == "affirming"


def test_try_appraise_returns_none_on_auth_failure(sw_report, monkeypatch):
    monkeypatch.setenv("CMCP_NRAS_API_KEY", "bad-key")
    mock_instance = NRASClient(
        api_key="bad-key",
        http_client=_mock_text_client(401, "Unauthorized"),
    )

    with patch("cmcp_runtime.tee.nras.NRASClient", return_value=mock_instance):
        result = try_appraise(sw_report)

    assert result is None


def test_try_appraise_returns_none_on_appraisal_rejection(sw_report, monkeypatch):
    monkeypatch.setenv("CMCP_NRAS_API_KEY", "k")
    mock_instance = NRASClient(
        api_key="k",
        http_client=_mock_text_client(422, "bad evidence"),
    )

    with patch("cmcp_runtime.tee.nras.NRASClient", return_value=mock_instance):
        result = try_appraise(sw_report)

    assert result is None


def test_try_appraise_returns_none_on_timeout(sw_report, monkeypatch):
    monkeypatch.setenv("CMCP_NRAS_API_KEY", "k")

    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out", request=request)

    http = httpx.Client(transport=httpx.MockTransport(timeout_handler))
    mock_instance = NRASClient(api_key="k", http_client=http)

    with patch("cmcp_runtime.tee.nras.NRASClient", return_value=mock_instance):
        result = try_appraise(sw_report)

    assert result is None


def test_try_appraise_logs_warning_when_no_key(sw_report, monkeypatch, caplog):
    import logging
    monkeypatch.delenv("CMCP_NRAS_API_KEY", raising=False)
    with caplog.at_level(logging.WARNING, logger="cmcp_runtime.tee.nras"):
        try_appraise(sw_report)
    assert any("CMCP_NRAS_API_KEY" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# RuntimeContext: nras_appraisal field
# ---------------------------------------------------------------------------


def test_gateway_context_nras_appraisal_defaults_none():
    from cmcp_runtime.startup import RuntimeContext
    assert RuntimeContext.__dataclass_fields__["nras_appraisal"].default is None
