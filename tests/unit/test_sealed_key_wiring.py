"""Config, measurement and reload wiring for the sealed signing key (#462)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from cmcp_runtime.config import ConfigError, load_config
from cmcp_runtime.tee import measurement


def _config(tmp_path: Path, attestation: str) -> Path:
    path = tmp_path / "cmcp-config.yaml"
    path.write_text("attestation:\n" + attestation)
    return path


def test_sealing_is_off_by_default(tmp_path: Path) -> None:
    config = load_config(str(_config(tmp_path, "  provider: tpm\n")))
    assert config.attestation.seal_signing_key is False
    assert config.attestation.sealed_key_dir == "sealed-key"


@pytest.mark.parametrize(
    ("attestation", "message"),
    [
        ("  provider: auto\n  seal_signing_key: true\n", "provider: tpm"),
        ("  provider: sev-snp\n  seal_signing_key: true\n", "provider: tpm"),
        ("  provider: tpm\n  seal_signing_key: yes-please\n", "must be a boolean"),
        ("  provider: tpm\n  sealed_key_dir: ''\n", "non-empty"),
        ("  provider: tpm\n  sealed_key_dir: ../elsewhere\n", r"\.\."),
    ],
)
def test_invalid_sealing_settings_are_refused(
    tmp_path: Path, attestation: str, message: str
) -> None:
    with pytest.raises(ConfigError, match=message):
        load_config(str(_config(tmp_path, attestation)))


def test_the_sealing_settings_are_measured(tmp_path: Path) -> None:
    """Turning sealing on is a configuration change like any other."""
    off = load_config(str(_config(tmp_path, "  provider: tpm\n")))
    on = load_config(str(_config(tmp_path, "  provider: tpm\n  seal_signing_key: true\n")))
    assert measurement.config_digest(off) != measurement.config_digest(on)


def test_the_digest_from_components_is_the_gateway_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(measurement, "code_digest", lambda: "c" * 64)
    (tmp_path / "policies").mkdir()
    (tmp_path / "policies" / "a.cedar").write_text("permit(principal, action, resource);")
    config = load_config(str(_config(tmp_path, "  provider: tpm\n")))
    config.policy_bundle_path = str(tmp_path / "policies")

    full = measurement.gateway_measurement(config)
    assert measurement.measurement_from_components(dict(full.components)) == full


def test_components_must_be_exactly_code_policy_and_config() -> None:
    with pytest.raises(ValueError):
        measurement.measurement_from_components({"code": "c", "policy": "p"})


def test_reload_reseals_even_when_the_re_attestation_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cmcp_runtime import cli

    calls: list[str] = []

    def failing_refresh(ctx: object) -> bool:
        calls.append("refresh")
        raise RuntimeError("TEE unavailable")

    def reseal(ctx: object) -> bool:
        calls.append("reseal")
        return True

    monkeypatch.setattr("cmcp_runtime.tee.report_binding.refresh_measurement_binding", failing_refresh)
    monkeypatch.setattr("cmcp_runtime.tee.seal.reseal_after_reload", reseal)
    with pytest.raises(RuntimeError):
        cli._after_policy_reload(SimpleNamespace())  # type: ignore[arg-type]
    assert calls == ["refresh", "reseal"]


def test_reseal_after_reload_is_a_no_op_without_a_sealed_key() -> None:
    from cmcp_runtime.tee.seal import reseal_after_reload

    assert reseal_after_reload(SimpleNamespace(sealed_key=None, gateway_measurement=None)) is False


def _cli(*args: str) -> object:
    from click.testing import CliRunner

    from cmcp_runtime.cli import main

    return CliRunner().invoke(main, list(args))


def test_measure_prints_the_gateway_digest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import json

    monkeypatch.setattr(measurement, "code_digest", lambda: "c" * 64)
    (tmp_path / "policies").mkdir()
    (tmp_path / "policies" / "a.cedar").write_text("permit(principal, action, resource);")
    config_path = tmp_path / "cmcp-config.yaml"
    config_path.write_text(f"policy_bundle_path: {tmp_path / 'policies'}\n")
    expected = measurement.gateway_measurement(load_config(str(config_path)))

    plain = _cli("measure", "--config", str(config_path))
    assert plain.exit_code == 0, plain.output
    assert plain.output.splitlines()[0] == expected.digest_hex
    as_json = json.loads(_cli("measure", "--config", str(config_path), "--json").output)
    assert as_json == {"digest": expected.digest_hex, "components": expected.components}


def test_key_commands_refuse_when_sealing_is_off(tmp_path: Path) -> None:
    config_path = _config(tmp_path, "  provider: tpm\n")
    result = _cli("key", "public", "--config", str(config_path))
    assert result.exit_code == 1
    assert "seal_signing_key is off" in result.output


def test_key_public_before_the_first_start(tmp_path: Path) -> None:
    config_path = _config(
        tmp_path,
        f"  provider: tpm\n  seal_signing_key: true\n  sealed_key_dir: {tmp_path / 's'}\n",
    )
    result = _cli("key", "public", "--config", str(config_path))
    assert result.exit_code == 1
    assert "first start provisions" in result.output


@pytest.mark.parametrize("value", ["zz", "sha256:" + "ab" * 16])
def test_a_malformed_digest_is_a_usage_error(tmp_path: Path, value: str) -> None:
    config_path = _config(
        tmp_path,
        f"  provider: tpm\n  seal_signing_key: true\n  sealed_key_dir: {tmp_path / 's'}\n",
    )
    result = _cli("key", "reseal", "--config", str(config_path), "--to-digest", value)
    assert result.exit_code == 2


class _Refusal(Exception):
    def __init__(self, error: int) -> None:
        super().__init__(f"rc {error:#x}")
        self.error = error


@pytest.mark.parametrize(
    ("error", "is_mismatch"),
    [(0x126, True), (0x09D, True), (0x922, False), (0x101, False)],
)
def test_only_a_policy_refusal_counts_as_a_digest_mismatch(error: int, is_mismatch: bool) -> None:
    from cmcp_runtime.tee.seal import _is_policy_refusal

    assert _is_policy_refusal(_Refusal(error)) is is_mismatch
    assert _is_policy_refusal(RuntimeError("no rc")) is False


def test_key_commands_report_an_unusable_tpm_without_a_traceback(tmp_path: Path) -> None:
    """No tpm2-pytss, no TPM, or the suite's own refusal: an error line and exit 1."""
    config_path = _config(
        tmp_path,
        f"  provider: tpm\n  seal_signing_key: true\n  sealed_key_dir: {tmp_path / 's'}\n",
    )
    result = _cli("key", "reseal", "--config", str(config_path), "--to-digest", "ab" * 32)
    assert result.exit_code == 1
    assert isinstance(result.exception, SystemExit)
    assert "Traceback" not in result.output


def test_key_reseal_reports_an_unmeasurable_gateway_without_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)  # the default policy_bundle_path does not exist here
    config_path = _config(
        tmp_path,
        f"  provider: tpm\n  seal_signing_key: true\n  sealed_key_dir: {tmp_path / 's'}\n",
    )
    result = _cli("key", "reseal", "--config", str(config_path))
    assert result.exit_code == 1
    assert "Cannot measure" in result.output
