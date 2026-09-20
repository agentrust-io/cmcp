"""Revoking a policy signing key on a running gateway, without a restart.

Before this, the only answer to a compromised CMCP_POLICY_SIGNING_KEY was new
config plus a restart, and until each gateway restarted the holder of the stolen
key could keep pushing signed bundles to it. The model tested here:

- ``CMCP_POLICY_SUCCESSOR_SIGNING_KEY`` pins a second key next to the current one.
  It signs no bundle until promoted.
- A revocation statement in ``signing-key-revocations.json``, signed by the
  successor (or by the current key itself), revokes the current key on the next
  reload and promotes the successor.
- The policy in force was signed by the revoked key, so it stops being trusted:
  every tool call is refused, in every enforcement mode, until a bundle signed by
  the successor is installed.
- Nothing un-revokes. Removing the statement, replaying it, or presenting a
  statement signed by the revoked key against the successor changes nothing.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from pathlib import Path
from unittest.mock import AsyncMock, patch

import jsonschema
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.config import AttestationConfig, Config, EnforcementMode
from cmcp_runtime.errors import (
    ConfigError,
    PolicyKeyRevocationInvalid,
    PolicySigningKeyRevoked,
)
from cmcp_runtime.policy import bundle as bundle_module
from cmcp_runtime.policy.bundle import (
    REVOCATION_FILE,
    PolicySigningKeys,
    PolicyStore,
    load_policy_bundle,
    policy_key_id,
    revocation_pre_image,
)
from cmcp_runtime.policy.evaluator import PolicyEvaluator

# A catalog entry with a correct definition_hash, so startup gets past step 5.
from tests.unit.test_startup import CATALOG_ENTRY

MANIFEST = {
    "version": "1.0.0",
    "authored_at": "2026-09-18T00:00:00Z",
    "author_identity": "test@example.com",
    "commit_sha": "abc123",
}
PERMIT = "permit(principal, action, resource);"
FORBID = "forbid(principal, action, resource);"
SCHEMA = '{"cMCP": {"entityTypes": {}, "actions": {}}}'
CONTEXT = {"tool_name": "crm.query", "session_max_sensitivity": "public", "workflow_id": "default"}


class Key:
    def __init__(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        self.id = policy_key_id(self.public)


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@pytest.fixture
def bundle_dir(tmp_path: Path) -> Path:
    (tmp_path / "manifest.json").write_text(json.dumps(MANIFEST))
    (tmp_path / "policy.cedar").write_text(PERMIT)
    (tmp_path / "schema.cedarschema").write_text(SCHEMA)
    return tmp_path


def _publish(bundle_dir: Path, key: Key, *, version: str, policy: str = PERMIT) -> None:
    """Write a bundle at ``version`` and sign it with ``key``."""
    manifest = dict(MANIFEST, version=version)
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest))
    (bundle_dir / "policy.cedar").write_text(policy)
    unsigned = load_policy_bundle(str(bundle_dir))
    manifest["signature"] = _b64(
        key.private.sign(bundle_module.signing_pre_image(unsigned.bundle_hash))
    )
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest))


def _statement(revoked: Key, signer: Key) -> dict[str, str]:
    return {
        "revoked_key_id": revoked.id,
        "signature": _b64(signer.private.sign(revocation_pre_image(revoked.id))),
    }


def _write_revocations(bundle_dir: Path, *statements: object) -> None:
    (bundle_dir / REVOCATION_FILE).write_text(json.dumps(list(statements)))


def _store(bundle_dir: Path, current: Key, successor: Key | None) -> PolicyStore:
    keys = PolicySigningKeys(current.public, successor.public if successor else None)
    return PolicyStore(
        bundle=load_policy_bundle(str(bundle_dir), None, current.public),
        bundle_path=str(bundle_dir),
        reload_interval_seconds=1,
        signing_keys=keys,
    )


def _reload_now(store: PolicyStore) -> bool:
    start = store._last_reload_at
    with patch("cmcp_runtime.policy.bundle.time") as mock_time:
        mock_time.monotonic.return_value = start + 2
        return store.reload_if_stale()


# --------------------------------------------------------------------------
# Rotation to the successor, without a restart
# --------------------------------------------------------------------------


def test_successor_revocation_then_successor_bundle_installs(bundle_dir: Path) -> None:
    current, successor = Key(), Key()
    _publish(bundle_dir, current, version="1.0.0")
    store = _store(bundle_dir, current, successor)

    _write_revocations(bundle_dir, _statement(current, successor))
    _publish(bundle_dir, successor, version="1.0.1", policy=FORBID)

    assert _reload_now(store) is True
    assert store.bundle.manifest.version == "1.0.1"
    assert store.bundle.signing_key_id == successor.id
    assert store.revoked_key_ids == [current.id]
    store.require_trusted()  # the policy in force has a trusted signer again


def test_the_current_key_may_revoke_itself(bundle_dir: Path) -> None:
    """Gives a thief nothing: it hands policy to the successor and cannot be undone."""
    current, successor = Key(), Key()
    _publish(bundle_dir, current, version="1.0.0")
    keys = PolicySigningKeys(current.public, successor.public)
    assert keys.apply(_statement(current, current)) == current.id
    assert keys.current == successor.public


def test_a_revocation_signed_by_an_unrelated_key_is_refused(bundle_dir: Path) -> None:
    current, successor, stranger = Key(), Key(), Key()
    keys = PolicySigningKeys(current.public, successor.public)
    with pytest.raises(PolicyKeyRevocationInvalid, match="neither"):
        keys.apply(_statement(current, stranger))
    assert keys.current == current.public
    assert keys.revoked == ()


def test_a_bundle_signature_cannot_be_replayed_as_a_revocation() -> None:
    """Domain separation: the two signatures cover different pre-images."""
    current, successor = Key(), Key()
    keys = PolicySigningKeys(current.public, successor.public)
    bundle_sig = successor.private.sign(bundle_module.signing_pre_image(current.id))
    with pytest.raises(PolicyKeyRevocationInvalid):
        keys.apply({"revoked_key_id": current.id, "signature": _b64(bundle_sig)})


def test_the_successor_must_differ_from_the_current_key() -> None:
    key = Key()
    with pytest.raises(ConfigError, match="differ"):
        PolicySigningKeys(key.public, key.public)


# --------------------------------------------------------------------------
# A revoked key is refused
# --------------------------------------------------------------------------


def test_a_newer_bundle_signed_by_the_revoked_key_is_refused(bundle_dir: Path) -> None:
    """The attack revocation exists for: the thief signs a newer bundle."""
    current, successor = Key(), Key()
    _publish(bundle_dir, current, version="1.0.0")
    store = _store(bundle_dir, current, successor)
    _write_revocations(bundle_dir, _statement(current, successor))
    _publish(bundle_dir, current, version="9.0.0")

    assert _reload_now(store) is False
    assert store.bundle.manifest.version == "1.0.0"

    with pytest.raises(PolicySigningKeyRevoked, match="revoked policy signing key"):
        load_policy_bundle(str(bundle_dir), None, successor.public, [current.public])


def test_refusal_carries_its_own_error_code() -> None:
    assert PolicySigningKeyRevoked.code == "POLICY_SIGNING_KEY_REVOKED"
    assert PolicyKeyRevocationInvalid.code == "POLICY_KEY_REVOCATION_INVALID"


# --------------------------------------------------------------------------
# Fail closed while the policy in force has a revoked signer
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mode", [EnforcementMode.ENFORCING, EnforcementMode.ADVISORY, EnforcementMode.SILENT]
)
def test_evaluation_fails_closed_until_a_trusted_bundle_is_installed(
    bundle_dir: Path, mode: EnforcementMode
) -> None:
    """Through the real reload path and a real Cedar backend. The permit-all
    policy in force stops being honoured the moment its key is revoked, in every
    mode, and comes back only when the successor signs a replacement."""
    current, successor = Key(), Key()
    _publish(bundle_dir, current, version="1.0.0")
    store = _store(bundle_dir, current, successor)
    evaluator = PolicyEvaluator(store, Config(attestation=AttestationConfig(enforcement_mode=mode)))
    assert evaluator.evaluate(CONTEXT).allowed is True

    _write_revocations(bundle_dir, _statement(current, successor))
    with patch("cmcp_runtime.policy.bundle.time") as mock_time:
        mock_time.monotonic.return_value = store._last_reload_at + 2
        with pytest.raises(PolicySigningKeyRevoked):
            evaluator.evaluate(CONTEXT)

    # Still refused on later calls, with no reload due.
    with pytest.raises(PolicySigningKeyRevoked):
        evaluator.evaluate(CONTEXT)

    _publish(bundle_dir, successor, version="1.0.1")
    with patch("cmcp_runtime.policy.bundle.time") as mock_time:
        mock_time.monotonic.return_value = store._last_reload_at + 2
        assert evaluator.evaluate(CONTEXT).allowed is True


def test_revoking_with_no_successor_leaves_nothing_trusted(bundle_dir: Path) -> None:
    """Self-revocation with no successor pinned: fail closed until restart. The
    reload must not fall back to loading with no key, which would skip the
    signature check altogether."""
    current = Key()
    _publish(bundle_dir, current, version="1.0.0")
    store = _store(bundle_dir, current, None)
    _write_revocations(bundle_dir, _statement(current, current))
    # An unsigned newer bundle appears. With no key it would load.
    (bundle_dir / "manifest.json").write_text(json.dumps(dict(MANIFEST, version="2.0.0")))

    assert _reload_now(store) is False
    assert store.bundle.manifest.version == "1.0.0"
    with pytest.raises(PolicySigningKeyRevoked):
        store.require_trusted()


@pytest.mark.asyncio
async def test_a_refused_call_is_recorded_as_a_deny_in_the_audit_chain(bundle_dir: Path) -> None:
    """End to end through the proxy: the refusal is a deny terminal naming the
    revoked key, not a fault and not a silent allow."""
    from cmcp_runtime.catalog.loader import (
        ApprovedDefinition,
        CatalogEntry,
        ServerIdentity,
        ToolCatalog,
    )
    from cmcp_runtime.mcp.proxy import CMCPProxy
    from cmcp_runtime.session.state import SessionState

    current, successor = Key(), Key()
    _publish(bundle_dir, current, version="1.0.0")
    store = _store(bundle_dir, current, successor)
    config = Config(attestation=AttestationConfig(enforcement_mode=EnforcementMode.ENFORCING))
    evaluator = PolicyEvaluator(store, config)
    entry = CatalogEntry(
        tool_name="test.echo",
        server=ServerIdentity(
            display_name="Local",
            url="https://local.invalid/mcp",
            tls_fingerprint="SHA256:" + "A" * 43 + "=",
            spiffe_id=None,
            transport="http-sse",
            rotation_mode="key-pinned",
        ),
        approved_definition=ApprovedDefinition(description="echo", input_schema={}, output_schema=None),
        definition_hash="sha256:" + "0" * 64,
        compliance_domain="public",
        requires_baa=False,
        sensitivity_level="public",
        added_at="2026-09-18T00:00:00Z",
        approved_by="key-revocation-test",
    )
    catalog = ToolCatalog(entries={"test.echo": entry}, catalog_hash="sha256:" + "1" * 64)
    chain = AuditChain("key-revocation")
    with (
        patch("cmcp_runtime.mcp.proxy.MCPGateway") as gateway,
        patch("cmcp_runtime.mcp.proxy.MCPResponseScanner"),
    ):
        gateway.return_value.intercept_tool_call.return_value = (True, None)
        proxy = CMCPProxy(catalog, evaluator, SessionState(session_id="kr"), chain, config)
    proxy._check_upstream_drift = AsyncMock(return_value=False)
    proxy._forward_to_upstream = AsyncMock(return_value="{}")

    _write_revocations(bundle_dir, _statement(current, successor))
    with patch("cmcp_runtime.policy.bundle.time") as mock_time:
        mock_time.monotonic.return_value = store._last_reload_at + 2
        result = await proxy.call_tool("call-1", "test.echo", {})

    assert result.allowed is False
    assert "revoked" in (result.deny_reason or "")
    proxy._forward_to_upstream.assert_not_awaited()
    terminal = [e for e in chain.entries if e.entry_type == "tool_call"][-1]
    assert terminal.policy_decision == "deny"
    assert "revoked policy signing key" in (terminal.policy_rule_matched or "")


# --------------------------------------------------------------------------
# No un-revoke
# --------------------------------------------------------------------------


def test_removing_the_statement_does_not_un_revoke(bundle_dir: Path) -> None:
    current, successor = Key(), Key()
    _publish(bundle_dir, current, version="1.0.0")
    store = _store(bundle_dir, current, successor)
    _write_revocations(bundle_dir, _statement(current, successor))
    _reload_now(store)

    (bundle_dir / REVOCATION_FILE).unlink()
    _publish(bundle_dir, current, version="2.0.0")
    assert _reload_now(store) is False
    assert store.revoked_key_ids == [current.id]
    with pytest.raises(PolicySigningKeyRevoked):
        store.require_trusted()


def test_the_revoked_key_cannot_revoke_the_successor() -> None:
    """The thief's counter-move: after losing, try to take the successor down too."""
    current, successor = Key(), Key()
    keys = PolicySigningKeys(current.public, successor.public)
    keys.apply(_statement(current, successor))
    with pytest.raises(PolicyKeyRevocationInvalid):
        keys.apply(_statement(successor, current))
    assert keys.current == successor.public
    assert keys.revoked_key_ids == [current.id]


def test_the_current_key_cannot_revoke_its_successor_before_rotation() -> None:
    """Otherwise a stolen current key could destroy the recovery path first."""
    current, successor = Key(), Key()
    keys = PolicySigningKeys(current.public, successor.public)
    with pytest.raises(PolicyKeyRevocationInvalid, match="currently trusted"):
        keys.apply(_statement(successor, current))
    assert keys.successor == successor.public


def test_replaying_an_applied_statement_is_a_no_op() -> None:
    current, successor = Key(), Key()
    keys = PolicySigningKeys(current.public, successor.public)
    statement = _statement(current, successor)
    assert keys.apply(statement) == current.id
    assert keys.apply(statement) is None
    assert keys.current == successor.public
    assert keys.revoked_key_ids == [current.id]


def test_a_bad_statement_does_not_block_a_good_one_or_the_reload(
    bundle_dir: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Anyone who can write the bundle directory can write garbage. It must not
    stop a genuine revocation or the successor's bundle from landing."""
    current, successor, stranger = Key(), Key(), Key()
    _publish(bundle_dir, current, version="1.0.0")
    store = _store(bundle_dir, current, successor)
    _write_revocations(
        bundle_dir,
        "not an object",
        _statement(current, stranger),
        _statement(current, successor),
    )
    _publish(bundle_dir, successor, version="1.0.1")
    with caplog.at_level(logging.WARNING, logger="cmcp_runtime.policy.bundle"):
        assert _reload_now(store) is True
    assert store.bundle.signing_key_id == successor.id
    assert "POLICY_KEY_REVOCATION_INVALID" in caplog.text
    assert "POLICY_SIGNING_KEY_REVOKED" in caplog.text


def test_an_unreadable_revocation_file_does_not_block_reload(bundle_dir: Path) -> None:
    current = Key()
    _publish(bundle_dir, current, version="1.0.0")
    store = _store(bundle_dir, current, None)
    (bundle_dir / REVOCATION_FILE).write_text("{not json")
    _publish(bundle_dir, current, version="1.0.1")
    assert _reload_now(store) is True
    assert store.bundle.manifest.version == "1.0.1"


def test_the_revocation_file_is_not_part_of_the_bundle_hash(bundle_dir: Path) -> None:
    before = load_policy_bundle(str(bundle_dir)).bundle_hash
    current = Key()
    _write_revocations(bundle_dir, _statement(current, current))
    assert load_policy_bundle(str(bundle_dir)).bundle_hash == before


# --------------------------------------------------------------------------
# Startup
# --------------------------------------------------------------------------



def _startup(tmp_path: Path, bundle_dir: Path, env: dict[str, str], monkeypatch: pytest.MonkeyPatch):
    import cmcp_runtime.config as _cfg
    from cmcp_runtime.startup import run_startup

    monkeypatch.setattr(_cfg, "DEV_MODE", True)
    catalog_path = tmp_path / "catalog.json"
    catalog_path.write_text(json.dumps([CATALOG_ENTRY]))
    config_path = tmp_path / "cmcp-config.yaml"
    config_path.write_text(
        f"policy_bundle_path: {bundle_dir.as_posix()}\ncatalog_path: {catalog_path.as_posix()}\n"
        "policy_reload_interval_seconds: 60\n"
    )
    with patch.dict(os.environ, {"CMCP_DEV_MODE": "1", **env}, clear=True):
        return run_startup(str(config_path))


@pytest.fixture
def startup_dirs(tmp_path: Path) -> tuple[Path, Path]:
    bundle_dir = tmp_path / "policy"
    bundle_dir.mkdir()
    (bundle_dir / "schema.cedarschema").write_text(SCHEMA)
    return tmp_path, bundle_dir


def test_startup_applies_a_revocation_already_on_disk(startup_dirs, monkeypatch) -> None:
    """A restart must not quietly re-trust a key while its revocation is still there."""
    tmp_path, bundle_dir = startup_dirs
    current, successor = Key(), Key()
    _publish(bundle_dir, successor, version="2.0.0")
    _write_revocations(bundle_dir, _statement(current, successor))
    ctx = _startup(
        tmp_path,
        bundle_dir,
        {
            "CMCP_POLICY_SIGNING_KEY": current.public.hex(),
            "CMCP_POLICY_SUCCESSOR_SIGNING_KEY": successor.public.hex(),
        },
        monkeypatch,
    )
    assert ctx.policy_bundle.bundle.signing_key_id == successor.id
    assert ctx.policy_bundle.revoked_key_ids == [current.id]


def test_startup_refuses_a_bundle_signed_by_a_revoked_key(
    startup_dirs, monkeypatch, caplog
) -> None:
    tmp_path, bundle_dir = startup_dirs
    current, successor = Key(), Key()
    _publish(bundle_dir, current, version="2.0.0")
    _write_revocations(bundle_dir, _statement(current, successor))
    with pytest.raises(SystemExit) as exc_info:
        _startup(
            tmp_path,
            bundle_dir,
            {
                "CMCP_POLICY_SIGNING_KEY": current.public.hex(),
                "CMCP_POLICY_SUCCESSOR_SIGNING_KEY": successor.public.hex(),
            },
            monkeypatch,
        )
    assert exc_info.value.code == 1
    assert "POLICY_SIGNING_KEY_REVOKED" in caplog.text


def test_startup_refuses_a_successor_without_a_current_key(
    startup_dirs, monkeypatch, caplog
) -> None:
    tmp_path, bundle_dir = startup_dirs
    _publish(bundle_dir, Key(), version="1.0.0")
    with pytest.raises(SystemExit) as exc_info:
        _startup(
            tmp_path,
            bundle_dir,
            {"CMCP_POLICY_SUCCESSOR_SIGNING_KEY": Key().public.hex()},
            monkeypatch,
        )
    assert exc_info.value.code == 1
    assert "CMCP_POLICY_SUCCESSOR_SIGNING_KEY is set without" in caplog.text


# --------------------------------------------------------------------------
# Evidence: which key signed the policy in force
# --------------------------------------------------------------------------


def _claim(signing_key_id: str | None, revoked: list[str]) -> dict:
    from cmcp_runtime.audit.keys import SigningKey
    from cmcp_runtime.audit.trace_claim import (
        AttestationReportInfo,
        CallGraphSummary,
        CallSummary,
        PolicyBundleInfo,
        ToolCatalogInfo,
        generate_trace_claim,
    )

    claim = generate_trace_claim(
        session_id="kr",
        signing_key=SigningKey(),
        attestation_report=AttestationReportInfo(
            provider="software-only",
            measurement="DEVELOPMENT_ONLY_NOT_FOR_PRODUCTION",
            report_data="aa" * 32,
            attestation_generated_at="2026-09-18T00:00:00+00:00",
            attestation_validity_seconds=86400,
        ),
        policy_bundle=PolicyBundleInfo(
            hash="sha256:" + "a" * 64,
            enforcement_mode="enforcing",
            policy_version="1.0.1",
            signing_key_id=signing_key_id,
            revoked_signing_key_ids=revoked,
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
                compliance_domains_touched=[], cross_boundary_events=[]
            ),
        ),
        audit_chain_root="sha256:" + "c" * 64,
        audit_chain_tip="sha256:" + "d" * 64,
        audit_chain_length=1,
    )
    return claim.model_dump(exclude_none=True)


def _schema() -> dict:
    path = Path(__file__).parents[2] / "schemas" / "trace-claim.schema.json"
    return json.loads(path.read_text())


def test_claim_records_the_signer_and_the_revoked_keys() -> None:
    current, successor = Key(), Key()
    claim = _claim(successor.id, [current.id])
    assert claim["gateway"]["policy_signing"] == {
        "key_id": successor.id,
        "revoked_key_ids": [current.id],
    }
    jsonschema.validate(claim, _schema())


def test_claim_without_a_pinned_key_is_unchanged() -> None:
    """Additive and optional: no key pinned, no field, same bytes as before."""
    claim = _claim(None, [])
    assert "policy_signing" not in claim["gateway"]
    jsonschema.validate(claim, _schema())
