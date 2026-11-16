"""Claim format 1.1: signed over RFC 8785 (JCS), and only observed TRACE fields."""

from __future__ import annotations

import base64
import json
import pathlib
from typing import Any

import jsonschema
import pytest
import rfc8785
from agentrust_trace import iter_errors
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import ValidationError

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.audit.keys import SigningKey
from cmcp_runtime.audit.trace_claim import (
    AttestationReportInfo,
    CallGraphSummary,
    CallSummary,
    KillSwitchState,
    PolicyBundleInfo,
    RuntimeClaim,
    ToolCatalogInfo,
    ToolTranscriptEntry,
    _to_dict,
    canonical_json,
    generate_trace_claim,
)
from cmcp_runtime.session.manager import SessionManager
from cmcp_runtime.tee.measurement import measurement_from_components
from cmcp_verify.verify import _verify_signature

SCHEMA = json.loads(
    (pathlib.Path(__file__).parents[2] / "schemas" / "trace-claim.schema.json").read_text()
)
CODE = "ab" * 32
# A non-ASCII tool name and a whole-number float: the two places the 1.0
# serialization and JCS produce different bytes.
TOOL = "café.lookup"


def _claim(key: SigningKey, code: str | None = None) -> RuntimeClaim:
    chain = AuditChain("sess-1")
    return generate_trace_claim(
        session_id="sess-1",
        signing_key=key,
        attestation_report=AttestationReportInfo(
            provider="software-only",
            measurement="DEVELOPMENT_ONLY_NOT_FOR_PRODUCTION",
            report_data="aa" * 32,
            attestation_generated_at="2026-06-04T00:00:00+00:00",
            attestation_validity_seconds=86400,
        ),
        policy_bundle=PolicyBundleInfo(
            hash="sha256:" + "0" * 64, enforcement_mode="enforcing", policy_version="1"
        ),
        tool_catalog=ToolCatalogInfo(hash="sha256:" + "1" * 64),
        call_summary=CallSummary(
            tool_calls_total=1,
            tool_calls_allowed=1,
            tool_calls_denied=0,
            tool_calls_faulted=0,
            tools_invoked=[TOOL],
            session_max_sensitivity="pii",
            call_graph_summary=CallGraphSummary(
                compliance_domains_touched=["pii"], cross_boundary_events=[]
            ),
        ),
        audit_chain_root=chain.chain_root,
        audit_chain_tip=chain.chain_tip,
        audit_chain_length=chain.length,
        transcript_entries=[
            ToolTranscriptEntry(tool_name=TOOL, data_class="pii", decision="allow")
        ],
        kill_switch=KillSwitchState(
            enabled=True, window_seconds=60, deny_rate_threshold=1.0, min_calls=1
        ),
        gateway_code_digest=code,
    )


def _sign(claim: dict[str, Any], key: SigningKey, body: bytes) -> dict[str, Any]:
    claim["signature"] = base64.urlsafe_b64encode(key.sign(body)).rstrip(b"=").decode()
    return claim


def _as_1_0(claim: dict[str, Any], key: SigningKey) -> dict[str, Any]:
    """The same session in the 1.0 shape, signed the 1.0 way."""
    legacy = json.loads(json.dumps(claim))
    legacy["cmcp_version"] = "1.0"
    for name in ("model", "build_provenance", "appraisal"):
        legacy["trace"].pop(name, None)
    legacy["gateway"].pop("trace_omitted")
    legacy["trace"]["tool_transcript"]["entries"] = legacy["gateway"].pop("transcript_entries")
    body = {k: v for k, v in legacy.items() if k != "signature"}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return _sign(legacy, key, raw)


def test_claim_is_signed_over_jcs():
    key = SigningKey()
    claim = _to_dict(_claim(key))
    assert claim["cmcp_version"] == "1.1"
    body = rfc8785.dumps({k: v for k, v in claim.items() if k != "signature"})
    legacy = json.dumps(
        {k: v for k, v in claim.items() if k != "signature"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    assert body != legacy  # the case 1.0 got wrong
    assert canonical_json(claim) == body
    # Any RFC 8785 verifier accepts it, using only the key in trace.cnf.
    x = claim["trace"]["cnf"]["jwk"]["x"]
    public = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(x + "=" * (-len(x) % 4)))
    public.verify(
        base64.urlsafe_b64decode(claim["signature"] + "=" * (-len(claim["signature"]) % 4)), body
    )
    with pytest.raises(InvalidSignature):
        public.verify(
            base64.urlsafe_b64decode(claim["signature"] + "=" * (-len(claim["signature"]) % 4)),
            legacy,
        )
    assert _verify_signature(claim) == (True, None)


def test_1_0_claims_still_verify():
    key = SigningKey()
    legacy = _as_1_0(_to_dict(_claim(key)), key)
    RuntimeClaim.model_validate(legacy)
    jsonschema.validate(legacy, SCHEMA)
    assert _verify_signature(legacy) == (True, None)


def test_version_cannot_be_swapped_after_signing():
    key = SigningKey()
    claim = _to_dict(_claim(key))
    claim["cmcp_version"] = "1.0"
    assert _verify_signature(claim)[0] is False
    legacy = _as_1_0(_to_dict(_claim(key)), key)
    legacy["cmcp_version"] = "1.1"
    assert _verify_signature(legacy)[0] is False


def test_unmeasured_gateway_omits_model_and_build_provenance():
    key = SigningKey()
    claim = _to_dict(_claim(key))
    trace = claim["trace"]
    assert "model" not in trace and "build_provenance" not in trace
    assert claim["gateway"]["trace_omitted"] == ["model", "build_provenance"]
    assert trace["appraisal"] == {"status": "none", "verifier": trace["subject"]}
    assert "entries" not in trace["tool_transcript"]
    assert claim["gateway"]["transcript_entries"][0]["tool_name"] == TOOL
    jsonschema.validate(claim, SCHEMA)


def test_measured_code_becomes_build_provenance():
    key = SigningKey()
    claim = _to_dict(_claim(key, CODE))
    assert claim["trace"]["build_provenance"] == {"slsa_level": 0, "digest": "sha256:" + CODE}
    assert claim["gateway"]["trace_omitted"] == ["model"]
    jsonschema.validate(claim, SCHEMA)
    # The TRACE block is a TRACE v0.2 record except for what the claim says it omits.
    errors = iter_errors(claim["trace"])
    assert [(e.validator, e.message) for e in errors] == [
        ("required", "'model' is a required property")
    ]


def _shape(edit) -> dict[str, Any]:
    claim = _to_dict(_claim(SigningKey(), CODE))
    edit(claim)
    return claim


@pytest.mark.parametrize(
    "edit",
    [
        pytest.param(
            lambda c: c["trace"]["tool_transcript"].update(entries=[]), id="1.1-entries-in-trace"
        ),
        pytest.param(lambda c: c["trace"].pop("appraisal"), id="1.1-no-appraisal"),
        pytest.param(lambda c: c["gateway"].pop("trace_omitted"), id="1.1-no-omitted-list"),
        pytest.param(
            lambda c: c["gateway"].update(trace_omitted=[]), id="1.1-omission-not-declared"
        ),
        pytest.param(
            lambda c: c["gateway"].update(trace_omitted=["model", "build_provenance"]),
            id="1.1-present-field-declared-omitted",
        ),
        pytest.param(lambda c: c.update(cmcp_version="1.0"), id="1.0-with-1.1-fields"),
        pytest.param(lambda c: c.update(cmcp_version="1.2"), id="unknown-version"),
    ],
)
def test_shape_must_match_version(edit):
    with pytest.raises(ValidationError):
        RuntimeClaim.model_validate(_shape(edit))


@pytest.mark.parametrize(
    "edit",
    [
        lambda c: c["trace"]["tool_transcript"].update(entries=[]),
        lambda c: c["trace"].pop("appraisal"),
        lambda c: c["gateway"].pop("trace_omitted"),
        lambda c: c.update(cmcp_version="1.0"),
    ],
)
def test_json_schema_checks_the_same_shape(edit):
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(_shape(edit), SCHEMA)


def test_manager_reads_code_digest_from_the_measurement():
    manager = SessionManager.__new__(SessionManager)
    manager._ctx = type("Ctx", (), {"gateway_measurement": None})()
    assert manager._gateway_code_digest() is None
    manager._ctx.gateway_measurement = measurement_from_components(
        {"code": CODE, "policy": "cd" * 32, "config": "ef" * 32}
    )
    assert manager._gateway_code_digest() == CODE
