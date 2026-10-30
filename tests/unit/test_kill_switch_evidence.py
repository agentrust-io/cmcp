"""Evidence a verifier can check: the claim says the switch was armed, and refusals are signed."""

from __future__ import annotations

import copy
import json
import pathlib

import jsonschema
import pytest

from cmcp_runtime.audit.trace_claim import REFUSAL_RECEIPT_TYPE
from cmcp_runtime.cli import build_server
from cmcp_runtime.config import KillSwitchConfig
from cmcp_runtime.kill_switch import KillSwitchBlockStore
from cmcp_runtime.startup import run_startup
from cmcp_verify import verify_kill_switch_refusal
from tests.unit.test_kill_switch_durable import (
    _AGENT_ID,
    _bearer,
    _client,
    _ctx,
    _operator,
    _tool_call_body,
)
from tests.unit.test_kill_switch_mid_session import _deny_every_call
from tests.unit.test_startup import _minimal_setup

_SCHEMA = json.loads(
    (pathlib.Path(__file__).parents[2] / "schemas" / "trace-claim.schema.json").read_text()
)
# The kill_switch object's own schema. Whole-claim validation is covered in
# test_trace_claim.py; here the subject is only the block this change adds.
_KILL_SWITCH_SCHEMA = _SCHEMA["properties"]["gateway"]["properties"]["kill_switch"]


def _validate_kill_switch(claim: dict) -> None:
    jsonschema.validate(instance=claim["gateway"]["kill_switch"], schema=_KILL_SWITCH_SCHEMA)


def _trip_body() -> dict[str, str]:
    return {"reason": "exfiltration attempt reported by SOC", "authorized_by": "oncall"}


async def _operator_trip(server, client) -> dict:
    resp = await client.post("/kill-switch/trip", json=_trip_body(), headers=_operator())
    assert resp.status_code == 200, resp.text
    return resp.json()["claim"]


async def _refusal(client) -> dict:
    resp = await client.post("/mcp", json=_tool_call_body("refused"), headers=_bearer())
    assert resp.status_code == 403
    return resp.json()["error"]["data"]["receipt"]


# ── The claim records the armed switch ──────────────────────────────────────


@pytest.mark.asyncio
async def test_claim_records_armed_settings_when_not_tripped(tmp_path):
    server = build_server(_ctx(KillSwitchBlockStore(tmp_path / "audit.db")))
    sid = server._session.session_id
    async with _client(server) as client:
        claim = (await client.post(f"/sessions/{sid}/close", headers=_bearer())).json()
    ks = claim["gateway"]["kill_switch"]
    assert ks == {"enabled": True, "window_seconds": 300, "deny_rate_threshold": 0.9, "min_calls": 5}
    _validate_kill_switch(claim)


@pytest.mark.asyncio
async def test_claim_names_the_operator_as_the_trigger(tmp_path):
    server = build_server(_ctx(KillSwitchBlockStore(tmp_path / "audit.db")))
    async with _client(server) as client:
        claim = await _operator_trip(server, client)
    assert claim["gateway"]["kill_switch"]["trigger"] == "operator"
    _validate_kill_switch(claim)


@pytest.mark.asyncio
async def test_claim_names_the_deny_rate_as_the_trigger(tmp_path):
    server = build_server(_ctx(KillSwitchBlockStore(tmp_path / "audit.db")))
    _deny_every_call(server)
    sid = server._session.session_id
    async with _client(server) as client:
        for i in range(server._session_manager._kill_switch._config.min_calls):
            await client.post("/mcp", json=_tool_call_body(str(i)), headers=_bearer())
    claim = server._session_manager.get_trace_claim(sid)
    assert claim["gateway"]["kill_switch"]["trigger"] == "deny_rate"
    _validate_kill_switch(claim)


@pytest.mark.asyncio
async def test_claim_has_no_kill_switch_block_when_the_switch_is_disabled(tmp_path):
    ctx = _ctx(KillSwitchBlockStore(tmp_path / "audit.db"))
    ctx.config.kill_switch = KillSwitchConfig(enabled=False)
    server = build_server(ctx)
    sid = server._session.session_id
    async with _client(server) as client:
        claim = (await client.post(f"/sessions/{sid}/close", headers=_bearer())).json()
    assert "kill_switch" not in claim["gateway"]


# ── Signed refusals ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_refusal_receipt_verifies_against_the_tripped_sessions_claim(tmp_path):
    server = build_server(_ctx(KillSwitchBlockStore(tmp_path / "audit.db")))
    async with _client(server) as client:
        claim = await _operator_trip(server, client)
        receipt = await _refusal(client)

    assert receipt["type"] == REFUSAL_RECEIPT_TYPE
    assert receipt["agent_id"] == _AGENT_ID
    result = verify_kill_switch_refusal(receipt, claim)
    assert result.valid, result.errors
    assert result.session_id == claim["gateway"]["session_id"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("agent_id", "spiffe://example.com/agent/someone-else", "signature verification failed"),
        ("refused_at", "2020-01-01T00:00:00+00:00", "signature verification failed"),
        ("claim_digest", "sha256:" + "0" * 64, "does not match the claim"),
        ("type", "something/else", "receipt type"),
    ],
)
async def test_an_altered_receipt_fails(tmp_path, field, value, expected):
    server = build_server(_ctx(KillSwitchBlockStore(tmp_path / "audit.db")))
    async with _client(server) as client:
        claim = await _operator_trip(server, client)
        receipt = await _refusal(client)
    receipt[field] = value
    result = verify_kill_switch_refusal(receipt, claim)
    assert not result.valid
    assert any(expected in e for e in result.errors), result.errors


@pytest.mark.asyncio
async def test_a_receipt_does_not_verify_against_another_gateways_claim(tmp_path):
    first = build_server(_ctx(KillSwitchBlockStore(tmp_path / "a.db")))
    second = build_server(_ctx(KillSwitchBlockStore(tmp_path / "b.db")))
    async with _client(first) as client:
        await _operator_trip(first, client)
        receipt = await _refusal(client)
    async with _client(second) as client:
        other_claim = await _operator_trip(second, client)
    result = verify_kill_switch_refusal(receipt, other_claim)
    assert not result.valid
    assert any("key that signed the claim" in e for e in result.errors)


@pytest.mark.asyncio
async def test_a_tampered_claim_fails_even_with_a_genuine_receipt(tmp_path):
    server = build_server(_ctx(KillSwitchBlockStore(tmp_path / "audit.db")))
    async with _client(server) as client:
        claim = await _operator_trip(server, client)
        receipt = await _refusal(client)
    forged = copy.deepcopy(claim)
    # Say the switch was set far more strictly than it was.
    forged["gateway"]["kill_switch"]["min_calls"] = 1
    assert forged != claim
    result = verify_kill_switch_refusal(receipt, forged)
    assert not result.valid
    assert any("claim signature" in e for e in result.errors)


@pytest.mark.asyncio
async def test_a_receipt_from_a_gateway_blocked_at_start_says_it_has_no_claim(tmp_path):
    store = KillSwitchBlockStore(tmp_path / "audit.db")
    store.block(_AGENT_ID, reason="deny_rate_threshold")
    server = build_server(_ctx(store))
    async with _client(server) as client:
        receipt = await _refusal(client)
    assert "claim_digest" not in receipt
    assert receipt["session_id"] == server._session.session_id


# ── Startup ──────────────────────────────────────────────────────────────────


def test_enabled_kill_switch_without_an_identity_refuses_to_start(tmp_path, monkeypatch):
    """Enabled with no Agent Manifest, the switch would look armed and stop nothing."""
    import cmcp_runtime.config as _cfg

    monkeypatch.setattr(_cfg, "DEV_MODE", True)
    config_path = _minimal_setup(tmp_path, "kill_switch:\n  enabled: true\n")
    monkeypatch.setenv("CMCP_DEV_MODE", "1")
    with pytest.raises(SystemExit) as exc_info:
        run_startup(str(config_path))
    assert exc_info.value.code == 1


def test_kill_switch_and_claim_verify_reject_non_canonical_b64url_and_private_jwk():
    import base64
    import hashlib
    from datetime import UTC, datetime

    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    from cmcp_runtime.audit.chain import AuditChain
    from cmcp_runtime.audit.keys import SigningKey
    from cmcp_runtime.audit.trace_claim import (
        AttestationReportInfo,
        CallGraphSummary,
        CallSummary,
        PolicyBundleInfo,
        ToolCatalogInfo,
        _to_dict,
        generate_trace_claim,
    )
    from cmcp_verify.kill_switch import _b64url_decode
    from cmcp_verify.verify import (
        ApprovedHashes,
        VerificationError,
        VerificationStatus,
        _canonical_json,
        _verify_key_binding,
        _verify_signature,
        verify_trace_claim,
    )

    with pytest.raises(ValueError):
        _b64url_decode("A" * 85 + "B")
    with pytest.raises(ValueError):
        _b64url_decode("A" * 42 + "B")

    key = SigningKey()
    chain = AuditChain("ks-test-session")
    x_b64 = base64.urlsafe_b64encode(key.public_key_bytes).rstrip(b"=").decode("ascii")
    jwk_fp = hashlib.sha256(
        json.dumps(
            {"crv": "Ed25519", "kty": "OKP", "x": x_b64},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).digest()
    report_data = (jwk_fp + hashlib.sha256(bytes.fromhex(chain.chain_root)).digest()).hex()

    claim_obj = generate_trace_claim(
        session_id="ks-test-session",
        signing_key=key,
        attestation_report=AttestationReportInfo(
            provider="sev-snp",
            measurement="ab" * 32,
            report_data=report_data,
            attestation_generated_at=datetime.now(tz=UTC).isoformat(),
            attestation_validity_seconds=86400,
        ),
        policy_bundle=PolicyBundleInfo(
            hash="sha256:" + "a" * 64,
            enforcement_mode="enforcing",
            policy_version="1.0.0",
        ),
        tool_catalog=ToolCatalogInfo(hash="sha256:" + "b" * 64),
        call_summary=CallSummary(
            tool_calls_total=0,
            tool_calls_allowed=0,
            tool_calls_denied=0,
            tool_calls_faulted=0,
            tools_invoked=[],
            session_max_sensitivity="public",
            call_graph_summary=CallGraphSummary(
                compliance_domains_touched=[],
                cross_boundary_events=[],
            ),
        ),
        audit_chain_root=chain.chain_root,
        audit_chain_tip=chain.chain_tip,
        audit_chain_length=chain.length,
        kill_switch_triggered=True,
        do_sign=True,
    )
    claim = _to_dict(claim_obj)
    approved = ApprovedHashes(
        policy_bundle_hash="sha256:" + "a" * 64,
        tool_catalog_hash="sha256:" + "b" * 64,
    )

    receipt = {
        "type": REFUSAL_RECEIPT_TYPE,
        "agent_id": _AGENT_ID,
        "session_id": claim["gateway"]["session_id"],
        "refused_at": datetime.now(tz=UTC).isoformat(),
        "gateway_key": x_b64,
        "claim_digest": "sha256:" + hashlib.sha256(_canonical_json(claim)).hexdigest(),
    }
    receipt["signature"] = (
        base64.urlsafe_b64encode(key.sign(_canonical_json(receipt)))
        .rstrip(b"=")
        .decode("ascii")
    )

    # Intact signed control passes both public verifiers
    control_res = verify_trace_claim(
        claim, approved, trusted_public_key_hex=key.public_key_hex
    )
    assert "signature" in control_res.verified_fields
    assert "public_key_binding" in control_res.verified_fields
    assert verify_kill_switch_refusal(receipt, claim).valid is True

    def _flip_pad_bit(b64_str: str) -> str:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        idx = alphabet.index(b64_str[-1])
        return b64_str[:-1] + alphabet[idx ^ 1]

    # Non-canonical signature alias (same decoded bytes, non-zero pad bit) fails verify_trace_claim
    sig_alias_claim = copy.deepcopy(claim)
    sig_alias_claim["signature"] = _flip_pad_bit(claim["signature"])
    sig_res = verify_trace_claim(
        sig_alias_claim, approved, trusted_public_key_hex=key.public_key_hex
    )
    assert "signature" in sig_res.unverified_fields
    assert sig_res.failure_reason == VerificationError.SIGNATURE_INVALID

    # Non-canonical key x alias fails verify_trace_claim and _verify_key_binding
    key_alias_claim = copy.deepcopy(claim)
    alias = _flip_pad_bit(x_b64)
    assert base64.urlsafe_b64decode(alias + "=") == key.public_key_bytes
    key_alias_claim["trace"]["cnf"]["jwk"]["x"] = alias
    # Bind the altered textual JWK too, so a stale thumbprint cannot mask the guard.
    alias_fp = hashlib.sha256(json.dumps(
        {"crv": "Ed25519", "kty": "OKP", "x": alias},
        separators=(",", ":"), sort_keys=True,
    ).encode()).digest()
    key_alias_claim["trace"]["runtime"]["nonce"] = base64.urlsafe_b64encode(
        alias_fp + hashlib.sha256(bytes.fromhex(chain.chain_root)).digest()
    ).rstrip(b"=").decode("ascii")
    key_alias_claim["signature"] = base64.urlsafe_b64encode(
        key.sign(_canonical_json(key_alias_claim))
    ).rstrip(b"=").decode("ascii")
    key_res = verify_trace_claim(
        key_alias_claim, approved, trusted_public_key_hex=key.public_key_hex
    )
    assert "signature" in key_res.unverified_fields
    assert _verify_key_binding(key_alias_claim, is_sw_only=False)[0] is False

    # Freshly re-signed claim carrying private JWK member 'd' is rejected
    priv_claim = copy.deepcopy(claim)
    priv_raw = key._private.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    priv_claim["trace"]["cnf"]["jwk"]["d"] = (
        base64.urlsafe_b64encode(priv_raw).rstrip(b"=").decode("ascii")
    )
    priv_claim["signature"] = (
        base64.urlsafe_b64encode(key.sign(_canonical_json(priv_claim)))
        .rstrip(b"=")
        .decode("ascii")
    )
    priv_res = verify_trace_claim(
        priv_claim, approved, trusted_public_key_hex=key.public_key_hex
    )
    assert priv_res.status != VerificationStatus.VERIFIED
    assert "signature" not in priv_res.verified_fields
    priv_receipt = copy.deepcopy(receipt)
    priv_receipt["claim_digest"] = (
        "sha256:" + hashlib.sha256(_canonical_json(priv_claim)).hexdigest()
    )
    priv_receipt["signature"] = (
        base64.urlsafe_b64encode(key.sign(_canonical_json(priv_receipt)))
        .rstrip(b"=")
        .decode("ascii")
    )
    priv_ks_res = verify_kill_switch_refusal(priv_receipt, priv_claim)
    assert priv_ks_res.valid is False
    assert any("private" in e for e in priv_ks_res.errors)
    ok, err = _verify_signature(priv_claim)
    assert ok is False and err is not None and "private" in err
    kb_ok, kb_err = _verify_key_binding(priv_claim, is_sw_only=False)
    assert kb_ok is False and kb_err is not None and "private" in kb_err

    # Empty or non-string required receipt fields and non-canonical receipt signature fail
    for field in ("agent_id", "session_id", "refused_at"):
        for bad_val in ("", None, 123):
            bad_receipt = copy.deepcopy(receipt)
            bad_receipt[field] = bad_val
            bad_receipt["signature"] = (
                base64.urlsafe_b64encode(key.sign(_canonical_json(bad_receipt)))
                .rstrip(b"=")
                .decode("ascii")
            )
            res = verify_kill_switch_refusal(bad_receipt, claim)
            assert res.valid is False
            assert any(f"receipt.{field}" in e for e in res.errors)

    alias_receipt = copy.deepcopy(receipt)
    alias_receipt["signature"] = _flip_pad_bit(receipt["signature"])
    assert verify_kill_switch_refusal(alias_receipt, claim).valid is False
