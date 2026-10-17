"""run_startup with attestation.seal_signing_key on, against swtpm (#462).

Every ESAPI context startup opens is routed to this test's swtpm, and the TPM
device check is pointed at a file in tmp_path, so nothing here can reach a host
TPM. Each run_startup is one gateway process; releasing the held key between
runs stands in for the process exiting.
"""

from __future__ import annotations

import json
import logging
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest
from swtpm_lab import Swtpm, swtpm_available

from cmcp_runtime.startup import RuntimeContext, run_startup
from cmcp_runtime.tee.base import jwk_thumbprint
from cmcp_runtime.tee.seal import SealedKeyStore, reseal_after_reload

pytestmark = pytest.mark.skipif(not swtpm_available(), reason="needs swtpm and tpm2-pytss")

_MANIFEST = {
    "version": "1.0.0",
    "authored_at": "2026-06-04T00:00:00Z",
    "author_identity": "test@example.com",
    "commit_sha": "abc123",
}
_CATALOG_ENTRY = {
    "tool_name": "test.tool",
    "server": {
        "display_name": "Test",
        "url": "https://test.example.com/mcp",
        "tls_fingerprint": "SHA256:AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
        "transport": "http-sse",
    },
    "approved_definition": {"description": "test", "input_schema": {}},
    "definition_hash": "sha256:17e2f3382a5c3582d0ed6ba64511ce791a242051319529d810ff2b4fe499821a",
    "compliance_domain": "external",
    "requires_baa": False,
    "sensitivity_level": "public",
    "added_at": "2026-06-01T00:00:00Z",
    "approved_by": "test",
}


@pytest.fixture
def tpm(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Swtpm]:
    import importlib

    import cmcp_runtime.config as config_module
    import cmcp_runtime.tee.tpm as tpm_module

    # The package re-exports the class under the submodule's name, so the module
    # that `from tpm2_pytss.ESAPI import ESAPI` reads has to be fetched this way.
    esapi_module = importlib.import_module("tpm2_pytss.ESAPI")
    instance = Swtpm(tmp_path / "tpm-state").start()

    class _Routed(esapi_module.ESAPI):  # type: ignore[misc]
        def __init__(self, tcti: object = None) -> None:
            super().__init__(instance.tcti if tcti is None else tcti)

    monkeypatch.setattr(esapi_module, "ESAPI", _Routed)
    device = tmp_path / "tpm0"
    device.touch()
    monkeypatch.setattr(tpm_module, "_TPM_DEVICES", [device])
    monkeypatch.setattr("cmcp_runtime.tee.measurement.code_digest", lambda: "c" * 64)
    monkeypatch.setattr(config_module, "DEV_MODE", True)
    monkeypatch.setenv("CMCP_DEV_MODE", "1")
    monkeypatch.chdir(tmp_path)
    try:
        yield instance
    finally:
        instance.stop()


def _gateway(tmp_path: Path, *, seal: bool = True) -> Path:
    policy_dir = tmp_path / "policy"
    policy_dir.mkdir(exist_ok=True)
    (policy_dir / "manifest.json").write_text(json.dumps(_MANIFEST))
    (policy_dir / "allow.cedar").write_text("permit(principal, action, resource) when { true };")
    (policy_dir / "schema.cedarschema").write_text('{"cMCP": {}}')
    catalog_path = tmp_path / "catalog.json"
    catalog_path.write_text(json.dumps([_CATALOG_ENTRY]))
    config_path = tmp_path / "cmcp-config.yaml"
    config_path.write_text(
        f"policy_bundle_path: {policy_dir}\n"
        f"catalog_path: {catalog_path}\n"
        "attestation:\n"
        "  provider: tpm\n"
        f"  seal_signing_key: {'true' if seal else 'false'}\n"
        f"  sealed_key_dir: {tmp_path / 'sealed'}\n"
    )
    return config_path


def _start(config_path: Path) -> RuntimeContext:
    ctx = run_startup(str(config_path))
    if ctx.audit_store is not None:
        ctx.audit_store.close()
    return ctx


def _stop(ctx: RuntimeContext) -> None:
    if ctx.sealed_key is not None:
        ctx.sealed_key.release()


def test_the_key_is_provisioned_once_and_unsealed_on_every_restart(
    tpm: Swtpm, tmp_path: Path
) -> None:
    config_path = _gateway(tmp_path)
    first = _start(config_path)
    assert first.sealed_key is not None and first.sealed_key.provisioned
    public_key = first.signing_key.public_key_bytes
    assert first.sealed_key.public_key == public_key
    _stop(first)

    for _ in range(2):
        tpm.restart()
        again = _start(config_path)
        assert again.sealed_key is not None and not again.sealed_key.provisioned
        assert again.signing_key.public_key_bytes == public_key
        # CRYPTO-001 is unchanged: report_data[:32] commits the key that signs.
        report_data = bytes.fromhex(again.attestation_report.report_data)
        assert report_data[:32] == jwk_thumbprint(public_key)
        _stop(again)


def test_without_sealing_every_start_gets_a_new_key(tpm: Swtpm, tmp_path: Path) -> None:
    """ATTEST-004 still holds on the tpm provider when sealing is off."""
    config_path = _gateway(tmp_path, seal=False)
    first = _start(config_path)
    second = _start(config_path)
    assert first.sealed_key is None and second.sealed_key is None
    assert first.signing_key.public_key_bytes != second.signing_key.public_key_bytes
    assert not SealedKeyStore(tmp_path / "sealed").path.exists()


def test_a_changed_policy_refuses_to_start(
    tpm: Swtpm, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    config_path = _gateway(tmp_path)
    _stop(_start(config_path))
    (tmp_path / "policy" / "allow.cedar").write_text(
        "permit(principal, action, resource) when { 1 == 1 };"
    )
    with caplog.at_level(logging.CRITICAL), pytest.raises(SystemExit) as exc:
        run_startup(str(config_path))
    assert exc.value.code == 1
    assert "SEALED_KEY_DIGEST_MISMATCH" in caplog.text


def test_a_verified_reload_reseals_so_the_next_start_keeps_the_key(
    tpm: Swtpm, tmp_path: Path
) -> None:
    config_path = _gateway(tmp_path)
    ctx = _start(config_path)
    public_key = ctx.signing_key.public_key_bytes
    (tmp_path / "policy" / "allow.cedar").write_text(
        "permit(principal, action, resource) when { 1 == 1 };"
    )
    assert reseal_after_reload(ctx) is True
    assert reseal_after_reload(ctx) is False  # already sealed to this digest
    _stop(ctx)

    tpm.restart()
    after = _start(config_path)
    assert after.signing_key.public_key_bytes == public_key
    _stop(after)


def test_a_second_gateway_on_the_same_store_refuses_to_start(
    tpm: Swtpm, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    config_path = _gateway(tmp_path)
    running = _start(config_path)
    with caplog.at_level(logging.CRITICAL), pytest.raises(SystemExit):
        run_startup(str(config_path))
    assert "SEALED_KEY_LOCKED" in caplog.text
    _stop(running)


def test_sealing_needs_the_tpm_provider_named_explicitly(tmp_path: Path) -> None:
    from cmcp_runtime.config import ConfigError, load_config

    config_path = tmp_path / "cmcp-config.yaml"
    config_path.write_text("attestation:\n  seal_signing_key: true\n")
    with pytest.raises(ConfigError, match="provider: tpm"):
        load_config(str(config_path))


# The operator commands, through click, against the same routed swtpm.


def _cli(*args: str) -> object:
    from click.testing import CliRunner

    from cmcp_runtime.cli import main

    return CliRunner().invoke(main, list(args), catch_exceptions=False)


def test_resealing_before_an_upgrade_keeps_the_key_and_rollback_works(
    tpm: Swtpm, tmp_path: Path
) -> None:
    config_path = _gateway(tmp_path)
    first = _start(config_path)
    public_key = first.signing_key.public_key_bytes
    _stop(first)

    allow = tmp_path / "policy" / "allow.cedar"
    original = allow.read_text()
    allow.write_text("permit(principal, action, resource) when { 1 == 1 };")
    result = _cli("key", "reseal", "--config", str(config_path))
    assert result.exit_code == 0, result.output
    assert _cli("key", "public", "--config", str(config_path)).output.strip() == public_key.hex()

    upgraded = _start(config_path)
    assert upgraded.signing_key.public_key_bytes == public_key
    _stop(upgraded)

    allow.write_text(original)
    rolled_back = _start(config_path)
    assert rolled_back.signing_key.public_key_bytes == public_key
    _stop(rolled_back)


def test_rotating_replaces_the_key_on_purpose(tpm: Swtpm, tmp_path: Path) -> None:
    config_path = _gateway(tmp_path)
    first = _start(config_path)
    _stop(first)

    result = _cli("key", "rotate", "--config", str(config_path), "--yes")
    assert result.exit_code == 0, result.output
    rotated = _cli("key", "public", "--config", str(config_path)).output.strip()
    assert rotated != first.signing_key.public_key_bytes.hex()

    after = _start(config_path)
    assert after.signing_key.public_key_bytes.hex() == rotated
    _stop(after)


def test_the_commands_refuse_while_a_gateway_holds_the_key(tpm: Swtpm, tmp_path: Path) -> None:
    config_path = _gateway(tmp_path)
    running = _start(config_path)
    result = _cli("key", "reseal", "--config", str(config_path))
    assert result.exit_code == 1
    assert "SEALED_KEY_LOCKED" in result.output
    _stop(running)


# Startup's own refusals. Each is fatal, with the sealed-key code, before any traffic.


def _refused(caplog: pytest.LogCaptureFixture, config_path: Path) -> str:
    with caplog.at_level(logging.CRITICAL), pytest.raises(SystemExit) as exc:
        run_startup(str(config_path))
    assert exc.value.code == 1
    return caplog.text


def test_an_unmeasurable_gateway_gets_no_key(
    tpm: Swtpm, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Dev mode lets an unmeasurable gateway start, but there is no digest to unseal under."""
    config_path = _gateway(tmp_path)
    shutil.rmtree(tmp_path / "policy")
    text = _refused(caplog, config_path)
    assert "SEALED_KEY_UNAVAILABLE" in text and "could not be measured" in text


def test_a_tpm_that_has_gone_away_is_reported_not_raised(
    tpm: Swtpm, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    config_path = _gateway(tmp_path)
    _stop(_start(config_path))
    tpm.stop()
    text = _refused(caplog, config_path)
    assert "SEALED_KEY_UNAVAILABLE" in text and "could not be opened" in text


def test_a_store_rewritten_behind_the_lock_is_refused(
    tpm: Swtpm, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The key the nonce committed is checked against the key the TPM unsealed.

    Something that ignores the lock provisions another key between the nonce and
    the unseal; the gateway must not sign with a key its attestation does not name.
    """
    from cmcp_runtime.config import load_config
    from cmcp_runtime.startup import _begin_sealed_start, _finish_sealed_start
    from cmcp_runtime.tee.measurement import GatewayMeasurement
    from cmcp_runtime.tee.seal import open_sealed_key

    config = load_config(str(_gateway(tmp_path)))
    start = _begin_sealed_start(config)
    digest = b"\x0d" * 32
    with tpm.context() as ectx:
        open_sealed_key(ectx, SealedKeyStore(tmp_path / "sealed"), digest)
    try:
        with caplog.at_level(logging.CRITICAL), pytest.raises(SystemExit):
            _finish_sealed_start(start, GatewayMeasurement(digest, {}))
    finally:
        start.lock.release()
    assert "SEALED_KEY_PUBLIC_KEY_MISMATCH" in caplog.text


def test_a_reload_while_the_tpm_is_away_keeps_serving_and_the_next_start_refuses(
    tpm: Swtpm, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    config_path = _gateway(tmp_path)
    ctx = _start(config_path)
    (tmp_path / "policy" / "allow.cedar").write_text(
        "permit(principal, action, resource) when { 1 == 1 };"
    )
    tpm.stop()
    with caplog.at_level(logging.WARNING):
        assert reseal_after_reload(ctx) is False
    assert "could not be resealed" in caplog.text
    _stop(ctx)

    tpm.start()
    assert "SEALED_KEY_DIGEST_MISMATCH" in _refused(caplog, config_path)
