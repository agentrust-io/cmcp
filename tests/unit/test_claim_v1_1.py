"""Claim format 1.1: signed over RFC 8785 (JCS), and only observed TRACE fields."""

from __future__ import annotations

import base64
import copy
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
    _PROVIDER_MAP,
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


# ── Review round: version, JCS domain, schema parity, full verifier ─────────

MAX_SAFE = 2**53 - 1


def _full(claim: dict[str, Any]) -> Any:
    from cmcp_verify import ApprovedHashes, verify_trace_claim

    return verify_trace_claim(
        claim,
        ApprovedHashes(
            policy_bundle_hash=claim["trace"]["policy"]["bundle_hash"],
            tool_catalog_hash=claim["gateway"]["catalog"]["hash"],
        ),
    )


def _resigned(claim: dict[str, Any], key: SigningKey) -> dict[str, Any]:
    return _sign(claim, key, canonical_json(claim))


def test_a_claim_without_a_version_is_malformed():
    """The version picks the signed bytes, so it is never assumed."""
    claim = _to_dict(_claim(SigningKey()))
    del claim["cmcp_version"]
    with pytest.raises(ValidationError):
        RuntimeClaim.model_validate(claim)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(claim, SCHEMA)
    assert _full(claim).failure_reason.value == "CLAIM_MALFORMED"


@pytest.mark.parametrize("wire", ["1", True, 1.5])
def test_a_signed_slsa_level_the_schema_refuses_fails_the_schema_check(wire: Any):
    """The original wire value stays what was signed: a string "1" was turned
    into 1 by agentrust-trace 0.11.0's model, and the schema check reported
    verified on a claim the published schema rejects."""
    key = SigningKey()
    claim = _to_dict(_claim(key, CODE))
    claim["trace"]["build_provenance"]["slsa_level"] = wire
    claim = _resigned(claim, key)
    assert _verify_signature(claim)[0] is True  # signed as it stands
    assert not jsonschema.Draft202012Validator(SCHEMA).is_valid(claim)
    result = _full(claim)
    assert "schema" not in result.verified_fields
    assert result.failure_reason.value == "CLAIM_MALFORMED"


@pytest.mark.parametrize(
    "place, safe",
    [
        ("sequence_number", MAX_SAFE),
        ("cross_boundary", MAX_SAFE),
        ("cross_boundary", -MAX_SAFE),
    ],
)
def test_safe_integers_are_accepted(place: str, safe: int):
    key = SigningKey()
    claim = _to_dict(_claim(key))
    if place == "sequence_number":
        claim["gateway"]["sequence_number"] = safe
    else:
        claim["gateway"]["call_summary"]["call_graph_summary"]["cross_boundary_events"] = [
            {"n": safe}
        ]
    claim = _resigned(claim, key)
    RuntimeClaim.model_validate(claim)
    assert _verify_signature(claim) == (True, None)


@pytest.mark.parametrize(
    "place, unsafe",
    [
        ("sequence_number", MAX_SAFE + 1),
        ("cross_boundary", MAX_SAFE + 1),
        ("cross_boundary", -MAX_SAFE - 1),
        ("cross_boundary", float("inf")),
        ("cross_boundary", 1e20),  # rfc8785 serializes it; the schema refuses it
        ("cross_boundary", "\ud800"),
    ],
)
def test_a_claim_with_no_canonical_form_is_malformed_not_raised(place: str, unsafe: Any):
    claim = _to_dict(_claim(SigningKey()))
    if place == "sequence_number":
        claim["gateway"]["sequence_number"] = unsafe
    else:
        claim["gateway"]["call_summary"]["call_graph_summary"]["cross_boundary_events"] = [
            {"n": unsafe}
        ]
    with pytest.raises(ValidationError, match="canonical form|safe range"):
        RuntimeClaim.model_validate(claim)
    result = _full(claim)
    assert result.failure_reason.value == "CLAIM_MALFORMED"
    ok, err = _verify_signature(claim)  # a direct caller gets a result too
    assert ok is False
    if unsafe != 1e20:  # 1e20 has an RFC 8785 form; only the integer range refuses it
        assert "canonical form" in (err or "")


def test_schema_bounds_integers_to_the_jcs_range():
    claim = _to_dict(_claim(SigningKey()))
    claim["gateway"]["sequence_number"] = MAX_SAFE + 1
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(claim, SCHEMA)


def _with_model(claim: dict[str, Any]) -> dict[str, Any]:
    claim["trace"]["model"] = {"provider": "p", "model_id": "m"}
    claim["gateway"]["trace_omitted"] = [
        n for n in claim["gateway"]["trace_omitted"] if n != "model"
    ]
    return claim


@pytest.mark.parametrize(
    "edit",
    [
        pytest.param(lambda c: c, id="as-emitted"),
        pytest.param(
            lambda c: c["gateway"].update(trace_omitted=["build_provenance", "model"]),
            id="reversed-order",
        ),
        pytest.param(_with_model, id="model-observed"),
    ],
)
def test_omissions_both_validators_accept(edit):
    claim = _to_dict(_claim(SigningKey()))
    edit(claim)
    RuntimeClaim.model_validate(claim)
    jsonschema.validate(claim, SCHEMA)


@pytest.mark.parametrize(
    "edit",
    [
        pytest.param(
            lambda c: c["gateway"].update(trace_omitted=["model"]), id="absent-not-listed"
        ),
        pytest.param(
            lambda c: c["gateway"].update(trace_omitted=["model", "model", "build_provenance"]),
            id="repeat",
        ),
        pytest.param(
            lambda c: _with_model(c)["gateway"]["trace_omitted"].append("model"),
            id="present-but-listed",
        ),
        pytest.param(lambda c: c["trace"].update(model=None), id="null-model"),
        pytest.param(
            lambda c: c["trace"].update(build_provenance=None), id="null-build-provenance"
        ),
        pytest.param(lambda c: c["trace"].update(appraisal=None), id="null-appraisal"),
        pytest.param(lambda c: c["gateway"].update(transcript_entries=None), id="null-entries"),
        pytest.param(lambda c: c["gateway"].update(trace_omitted=None), id="null-omitted"),
    ],
)
def test_omissions_both_validators_refuse(edit):
    claim = _to_dict(_claim(SigningKey()))
    edit(claim)
    with pytest.raises(ValidationError):
        RuntimeClaim.model_validate(claim)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(claim, SCHEMA)


@pytest.mark.parametrize("provider", sorted(_PROVIDER_MAP))
def test_every_provider_emits_a_schema_valid_claim(provider: str):
    key = SigningKey()
    report = AttestationReportInfo(
        provider=provider,
        measurement="ab" * 32,
        report_data="cd" * 64,
        attestation_generated_at="2026-06-04T00:00:00+00:00",
        attestation_validity_seconds=86400,
    )
    chain = AuditChain("s")
    claim = generate_trace_claim(
        session_id="s",
        signing_key=key,
        attestation_report=report,
        policy_bundle=PolicyBundleInfo(
            hash="sha256:" + "0" * 64, enforcement_mode="enforcing", policy_version="1"
        ),
        tool_catalog=ToolCatalogInfo(hash="sha256:" + "1" * 64),
        call_summary=CallSummary(
            tool_calls_total=0,
            tool_calls_allowed=0,
            tool_calls_denied=0,
            tool_calls_faulted=0,
            tools_invoked=[],
            session_max_sensitivity="public",
            call_graph_summary=CallGraphSummary(
                compliance_domains_touched=[], cross_boundary_events=[]
            ),
        ),
        audit_chain_root=chain.chain_root,
        audit_chain_tip=chain.chain_tip,
        audit_chain_length=chain.length,
    )
    jsonschema.validate(_to_dict(claim), SCHEMA)


def test_full_verifier_on_a_1_1_claim_reports_what_it_left_out():
    claim = _to_dict(_claim(SigningKey(), CODE))
    result = _full(claim)
    assert result.failure_reason is None or result.failure_reason.value != "CLAIM_MALFORMED"
    assert "signature" in result.verified_fields
    assert result.trace_omitted == ["model"]


def test_full_verifier_still_verifies_a_1_0_claim():
    key = SigningKey()
    legacy = _as_1_0(_to_dict(_claim(key)), key)
    result = _full(legacy)
    assert "signature" in result.verified_fields
    assert result.trace_omitted == []


def test_prev_claim_hash_is_the_jcs_hash_of_the_previous_signed_claim():
    import hashlib

    from tests.unit.test_session_manager import _make_ctx

    manager = SessionManager(_make_ctx())
    first_state, first_chain = manager.create_session()
    first = manager.close_session(first_state.session_id, first_state, first_chain)
    second_state, second_chain = manager.create_session()
    second = manager.close_session(second_state.session_id, second_state, second_chain)
    expected = "sha256:" + hashlib.sha256(rfc8785.dumps(first)).hexdigest()
    assert second["gateway"]["prev_claim_hash"] == expected


# ── Review round 2: one contract for the model, the schema and the verifier ──


_VALUES = [None, True, False, "1", 1, 1.0, 1.5, 0, -1, MAX_SAFE + 1, -MAX_SAFE - 1, 1e20, [], {}]


def _bases() -> dict[str, dict[str, Any]]:
    key = SigningKey()
    return {
        "1.1-measured": _to_dict(_claim(key, CODE)),
        "1.1-unmeasured": _to_dict(_claim(key)),
        "1.1-model-observed": _with_model(_to_dict(_claim(key, CODE))),
        "1.0": _as_1_0(_to_dict(_claim(key)), key),
    }


def _members(node: Any, prefix: tuple = ()):
    items = (
        node.items()
        if isinstance(node, dict)
        else enumerate(node)
        if isinstance(node, list)
        else ()
    )
    for key, child in items:
        yield prefix + (key,), child
        yield from _members(child, prefix + (key,))


def _mutations(base: dict[str, Any]):
    yield ("root", "extra"), {**copy.deepcopy(base), "zz_unknown": 1}
    for path, value in list(_members(base)):
        edits = [("delete", ...)] if not isinstance(path[-1], int) else []
        edits += [("set", v) for v in _VALUES]
        if isinstance(value, dict):
            edits.append(("extra", ...))
        for kind, new in edits:
            claim = copy.deepcopy(base)
            node = claim
            for key in path[:-1]:
                node = node[key]
            if kind == "delete":
                del node[path[-1]]
            elif kind == "extra":
                node[path[-1]]["zz_unknown"] = 1
            else:
                node[path[-1]] = new
            yield (path, kind if kind != "set" else repr(new)), claim


def _model_accepts(claim: dict[str, Any]) -> bool:
    try:
        RuntimeClaim.model_validate(claim)
    except (ValidationError, ValueError):
        return False
    return True


@pytest.mark.parametrize("name", ["1.1-measured", "1.1-unmeasured", "1.1-model-observed", "1.0"])
def test_model_and_json_schema_agree_on_every_mutation(name: str):
    """Every member deleted, nulled, retyped, pushed out of range or given an
    unknown sibling: the model and the published schema give the same answer."""
    validator = jsonschema.Draft202012Validator(SCHEMA)
    base = _bases()[name]
    assert _model_accepts(base) and validator.is_valid(base)
    disagreements = [
        mutation
        for mutation, claim in _mutations(base)
        if _model_accepts(claim) != validator.is_valid(claim)
    ]
    assert disagreements == []


INTEGER_FIELDS = [
    ("gateway", "sequence_number"),
    ("gateway", "attestation_validity_seconds"),
    ("gateway", "audit_chain", "length"),
    ("gateway", "call_summary", "tool_calls_total"),
    ("gateway", "call_summary", "tool_calls_allowed"),
    ("gateway", "call_summary", "tool_calls_denied"),
    ("gateway", "call_summary", "tool_calls_faulted"),
    ("gateway", "kill_switch", "window_seconds"),
    ("gateway", "kill_switch", "min_calls"),
    ("trace", "tool_transcript", "call_count"),
    ("trace", "iat"),
]


@pytest.mark.parametrize("path", INTEGER_FIELDS, ids=[".".join(p) for p in INTEGER_FIELDS])
@pytest.mark.parametrize("value", [True, False])
def test_a_bool_is_never_an_integer(path: tuple, value: bool):
    claim = _to_dict(_claim(SigningKey()))
    node = claim
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    assert not _model_accepts(claim)
    assert not jsonschema.Draft202012Validator(SCHEMA).is_valid(claim)


@pytest.mark.parametrize("name", ["1.1-measured", "1.0"])
def test_the_public_verifier_never_raises_on_a_malformed_claim(name: str):
    """Every mutation above, through verify_trace_claim: a result, never an exception."""
    from cmcp_verify import ApprovedHashes, VerificationResult, verify_trace_claim

    base = _bases()[name]
    approved = ApprovedHashes(
        policy_bundle_hash=base["trace"]["policy"]["bundle_hash"],
        tool_catalog_hash=base["gateway"]["catalog"]["hash"],
    )
    for mutation, claim in _mutations(base):
        result = verify_trace_claim(claim, approved)
        assert isinstance(result, VerificationResult), mutation
        assert result.failure_reason is not None or claim == base, mutation


@pytest.mark.parametrize(
    "value", [object(), b"bytes", float("nan"), float("inf"), {1, 2}, (1, 2), "\ud800"]
)
def test_python_only_values_get_a_structured_failure(value: Any):
    """Values JSON cannot carry: a result, never an exception. A tuple is the one
    with an exact JSON meaning (an array), so only the signature fails."""
    claim = _to_dict(_claim(SigningKey()))
    claim["gateway"]["call_summary"]["call_graph_summary"]["cross_boundary_events"] = [{"v": value}]
    result = _full(claim)
    expected = "SIGNATURE_INVALID" if isinstance(value, tuple) else "CLAIM_MALFORMED"
    assert result.failure_reason is not None and result.failure_reason.value == expected


@pytest.mark.parametrize("version", ["9.9", "", 1.1, 2])
def test_the_canonicalizers_refuse_an_unsupported_version(version: Any):
    from cmcp_verify.verify import _canonical_json as verifier_form

    claim = _to_dict(_claim(SigningKey()))
    claim["cmcp_version"] = version
    with pytest.raises(ValueError, match="unsupported cmcp_version"):
        canonical_json(claim)
    with pytest.raises(ValueError, match="unsupported cmcp_version"):
        verifier_form(claim)
    assert _verify_signature(claim)[0] is False
    assert _full(claim).failure_reason.value == "CLAIM_MALFORMED"


def test_a_document_without_a_version_keeps_the_1_0_form():
    """Refusal receipts carry no cmcp_version and are signed in the 1.0 form."""
    receipt = {"type": "x", "n": 1.0, "s": "é"}
    assert (
        canonical_json(receipt)
        == json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    )


@pytest.mark.parametrize("code", ["AB" * 32, "ab" * 31, "zz" * 32, 7, None])
def test_a_malformed_code_digest_is_left_out_not_fatal(code: Any):
    from cmcp_runtime.tee.measurement import GatewayMeasurement
    from tests.unit.test_session_manager import _make_ctx

    ctx = _make_ctx()
    ctx.gateway_measurement = GatewayMeasurement(
        digest=b"\x00" * 32, components={"code": code, "policy": "cd" * 32, "config": "ef" * 32}
    )
    manager = SessionManager(ctx)
    state, chain = manager.create_session()
    claim = manager.close_session(state.session_id, state, chain)
    assert "build_provenance" not in claim["trace"]
    assert claim["gateway"]["trace_omitted"] == ["model", "build_provenance"]


def test_the_stored_claim_is_the_signed_claim():
    from tests.unit.test_session_manager import _make_ctx

    manager = SessionManager(_make_ctx())
    state, chain = manager.create_session()
    closed = manager.close_session(state.session_id, state, chain)
    stored = manager.get_trace_claim(state.session_id)
    assert stored == closed
    assert stored["cmcp_version"] == "1.1"
    assert _verify_signature(stored) == (True, None)


def test_each_manager_starts_its_own_claim_chain():
    """prev_claim_hash links the claims one SessionManager signs; a new manager
    (a new gateway process) starts a new chain."""
    from tests.unit.test_session_manager import _make_ctx

    for _ in range(2):
        manager = SessionManager(_make_ctx())
        state, chain = manager.create_session()
        first = manager.close_session(state.session_id, state, chain)
        assert "prev_claim_hash" not in first["gateway"]


# ── Object graphs that are not JSON trees ────────────────────────────────────
#
# verify_trace_claim takes native Python objects, so a caller can hand it a
# container that contains itself, or one nested past any stack. JSON text
# cannot express either; each must be refused as malformed, never raised.


def _events(claim: dict[str, Any]) -> list[Any]:
    return claim["gateway"]["call_summary"]["call_graph_summary"]["cross_boundary_events"]


def _nested(depth: int) -> list[Any]:
    value: list[Any] = []
    for _ in range(depth - 1):
        value = [value]
    return value


def _self_list() -> list[Any]:
    loop: list[Any] = []
    loop.append(loop)
    return loop


def _self_dict() -> dict[str, Any]:
    loop: dict[str, Any] = {}
    loop["again"] = loop
    return loop


def _mixed_cycle() -> dict[str, Any]:
    outer: dict[str, Any] = {"items": [{"back": None}]}
    outer["items"][0]["back"] = outer  # dict -> list -> dict -> the first dict
    return outer


def _root_cycle(claim: dict[str, Any]) -> dict[str, Any]:
    claim["self"] = claim
    return claim


def _policy_cycle(claim: dict[str, Any]) -> dict[str, Any]:
    claim["trace"]["policy"]["again"] = claim["trace"]["policy"]
    return claim


def _in_events(make):
    def edit(claim: dict[str, Any]) -> dict[str, Any]:
        _events(claim).append({"evidence": make()})
        return claim
    return edit


@pytest.mark.parametrize(
    "edit",
    [
        pytest.param(_root_cycle, id="claim-contains-itself"),
        pytest.param(_policy_cycle, id="cycle-outside-free-form"),
        pytest.param(_in_events(_self_list), id="cyclic-list-in-events"),
        pytest.param(_in_events(_self_dict), id="cyclic-dict-in-events"),
        pytest.param(_in_events(_mixed_cycle), id="dict-list-dict-cycle-in-events"),
        pytest.param(_in_events(lambda: _nested(100_000)), id="nested-past-any-stack"),
    ],
)
def test_a_claim_that_is_not_a_json_tree_is_malformed_not_raised(edit):
    from cmcp_verify import VerificationError

    claim = edit(_to_dict(_claim(SigningKey())))
    result = _full(claim)
    assert result.failure_reason == VerificationError.CLAIM_MALFORMED
    assert "schema" in result.unverified_fields


def test_a_bare_container_that_contains_itself_is_malformed_not_raised():
    from cmcp_verify import ApprovedHashes, VerificationError, verify_trace_claim

    root: dict[str, Any] = {}
    root["self"] = root
    result = verify_trace_claim(root, ApprovedHashes("sha256:" + "0" * 64, "sha256:" + "1" * 64))
    assert result.failure_reason == VerificationError.CLAIM_MALFORMED


def test_nesting_is_bounded_at_the_documented_depth():
    from cmcp_runtime.audit.trace_claim import _MAX_DEPTH, ClaimShapeError, check_json_tree

    # A container's depth is the length of its path: the evidence list below is
    # at gateway.call_summary.call_graph_summary.cross_boundary_events.<n>.evidence, 6.
    claim = _to_dict(_claim(SigningKey()))
    _events(claim).append({"evidence": _nested(_MAX_DEPTH - 6)})
    check_json_tree(claim)  # its innermost list is at depth _MAX_DEPTH - 1
    _events(claim)[-1]["evidence"] = _nested(_MAX_DEPTH - 5)
    with pytest.raises(ClaimShapeError, match=f"deeper than {_MAX_DEPTH}"):
        check_json_tree(claim)


def test_a_value_shared_by_two_members_is_not_a_cycle():
    """The same object in two places is a tree to JSON: it serializes twice."""
    key = SigningKey()
    claim = _to_dict(_claim(key))
    shared = {"from_domain": "pii", "to_domain": "internal", "tool_name": TOOL}
    _events(claim).extend([shared, shared])
    claim = _resigned(claim, key)
    result = _full(claim)
    assert result.failure_reason is None or result.failure_reason.value != "CLAIM_MALFORMED"
    assert {"schema", "signature"} <= set(result.verified_fields)


def test_a_receipt_check_against_a_cyclic_claim_is_an_error_not_an_exception():
    from cmcp_verify import verify_kill_switch_refusal
    from tests.unit.test_kill_switch_evidence import _receipt_pair

    claim, receipt = _receipt_pair("1.1")
    _events(claim).append({"evidence": _self_list()})
    result = verify_kill_switch_refusal(receipt, claim)
    assert result.valid is False
    assert any("contains itself" in error for error in result.errors)


def test_the_unsafe_integer_walk_ends_on_a_cycle():
    from cmcp_runtime.audit.trace_claim import _has_unsafe_integer

    loop = _self_list()
    assert _has_unsafe_integer(loop) is False
    loop.append({"n": 2**53})
    assert _has_unsafe_integer(loop) is True


def test_null_stays_allowed_anywhere_inside_free_form_evidence():
    key = SigningKey()
    claim = _to_dict(_claim(key))
    _events(claim).append({"from_domain": None, "detail": {"reason": None, "seen": [None]}})
    claim = _resigned(claim, key)
    assert {"schema", "signature"} <= set(_full(claim).verified_fields)


def test_the_tree_check_looks_past_a_null():
    """A null is not a shape error: the walk goes on and still finds a cycle."""
    from cmcp_runtime.audit.trace_claim import ClaimShapeError, check_json_tree

    with pytest.raises(ClaimShapeError, match="contains itself"):
        check_json_tree({"a": None, "b": _self_list()})


# ── Values JSON cannot hold, and shared containers ───────────────────────────
#
# Free-form evidence is typed Any, so only a check of the whole document keeps
# a native value JSON cannot hold from reaching the signed bytes or the
# serializer. A container shared by several members is repeated in the JSON
# form, so [x, x] nested n deep is 2**(n + 1) values from n + 1 objects.

_NOT_JSON = {
    "object": object(),
    "bytes": b"x",
    "set": {1},
    "nan": float("nan"),
    "infinity": float("inf"),
    "minus-infinity": float("-inf"),
    "integer-member-name": {1: "a"},
}


def _signed_any_way(claim: dict[str, Any], key: SigningKey) -> dict[str, Any]:
    """Signed over what a lenient serializer would emit, as a producer might have."""
    body = {k: v for k, v in claim.items() if k != "signature"}
    try:
        raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    except TypeError:
        raw = b"{}"  # no JSON form at all; the signature cannot matter
    return _sign(claim, key, raw)


@pytest.mark.parametrize("version", ["1.0", "1.1"])
@pytest.mark.parametrize("name", list(_NOT_JSON))
def test_a_value_json_cannot_hold_is_malformed_never_raised_nor_credited(version, name):
    from cmcp_verify import VerificationError

    key = SigningKey()
    claim = _to_dict(_claim(key))
    if version == "1.0":
        claim = _as_1_0(claim, key)
    _events(claim).append({"evidence": _NOT_JSON[name]})
    result = _full(_signed_any_way(claim, key))
    assert result.failure_reason == VerificationError.CLAIM_MALFORMED
    assert not {"schema", "signature"} & set(result.verified_fields)


@pytest.mark.parametrize("value", [float("nan"), float("inf")])
def test_both_1_0_serializers_refuse_a_non_finite_number(value):
    """The backstop: neither writes NaN or Infinity, which are not JSON."""
    from cmcp_verify.verify import _canonical_json as verifier_form

    key = SigningKey()
    claim = _as_1_0(_to_dict(_claim(key)), key)
    _events(claim).append({"evidence": value})
    claim.pop("signature")
    with pytest.raises(ValueError):
        canonical_json(claim)
    with pytest.raises(ValueError):
        verifier_form(claim)


def _shared(depth: int) -> list[Any]:
    node: list[Any] = []
    for _ in range(depth):
        node = [node, node]
    return node


def test_a_shared_container_bomb_is_refused_quickly():
    import time

    from cmcp_verify import VerificationError, verify_kill_switch_refusal
    from tests.unit.test_kill_switch_evidence import _receipt_pair

    # 41 objects, 2**41 values, within the depth limit so the repeats are what stop it.
    claim = _to_dict(_claim(SigningKey()))
    _events(claim).append({"evidence": _shared(40)})
    started = time.perf_counter()
    assert _full(claim).failure_reason == VerificationError.CLAIM_MALFORMED
    claim, receipt = _receipt_pair("1.1")
    _events(claim).append({"evidence": _shared(40)})
    result = verify_kill_switch_refusal(receipt, claim)
    assert result.valid is False
    assert any("repeated values" in error for error in result.errors)
    assert time.perf_counter() - started < 2


def test_repeats_are_bounded_and_unshared_values_are_not():
    from cmcp_runtime.audit.trace_claim import (
        _MAX_REPEATED_VALUES,
        ClaimShapeError,
        check_json_tree,
    )

    # A list walked a second time repeats itself and each of its items.
    check_json_tree({"a": (shared := [0] * (_MAX_REPEATED_VALUES - 1)), "b": shared})
    with pytest.raises(ClaimShapeError, match="repeated values"):
        check_json_tree({"a": (shared := [0] * _MAX_REPEATED_VALUES), "b": shared})
    # Values that are not shared are never limited, however many.
    check_json_tree({"a": [{"n": i} for i in range(5 * _MAX_REPEATED_VALUES)]})


def test_a_tuple_is_walked_as_the_array_it_serializes_to():
    from cmcp_runtime.audit.trace_claim import ClaimShapeError, check_json_tree

    check_json_tree({"a": (1, [2], {"b": None})})
    loop: list[Any] = []
    loop.append((loop,))
    with pytest.raises(ClaimShapeError, match="contains itself"):
        check_json_tree({"a": loop})
    with pytest.raises(ClaimShapeError, match="not a JSON value"):
        check_json_tree({"a": (object(),)})


def test_shared_tuples_count_as_repeats_too():
    from cmcp_runtime.audit.trace_claim import ClaimShapeError, check_json_tree

    node: tuple[Any, ...] = ()
    for _ in range(40):
        node = (node, node)
    with pytest.raises(ClaimShapeError, match="repeated values"):
        check_json_tree({"a": node})
