"""
Regression tests for CLI status markers on a legacy console.

`cmcp validate-config` printed "✓ Config valid: ..." from inside the same
try block that ran the validation. On a Windows console, whose default code
page cannot encode that character, the echo raised UnicodeEncodeError, the
`except Exception` caught it, and the command reported

    ✗ Config invalid: 'charmap' codec can't encode character '✓' ...

then exited 1. The config was valid. A user following the published quickstart
was told their config was broken because the tool could not draw a tick.
"""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from cmcp_runtime.cli import _bad, _marker, _ok, main


class _Stream:
    """Minimal stand-in for sys.stdout with a fixed encoding."""

    def __init__(self, encoding: str | None) -> None:
        self.encoding = encoding


@pytest.mark.parametrize(
    ("encoding", "expected"),
    [
        ("utf-8", "✓"),
        ("UTF-8", "✓"),
        ("cp1252", "OK"),
        ("ascii", "OK"),
        ("cp437", "OK"),
        (None, "OK"),
        ("not-a-real-codec", "OK"),
    ],
)
def test_marker_falls_back_when_the_stream_cannot_encode_it(encoding, expected):
    assert _marker("✓", "OK", _Stream(encoding)) == expected


def test_marker_never_raises_on_an_object_without_encoding():
    assert _marker("✓", "OK", object()) == "OK"


def test_ok_and_bad_return_something_printable():
    assert _ok() in ("✓", "OK")
    assert _bad() in ("✗", "ERROR")


def _write_valid_config(tmp_path):
    config = tmp_path / "cmcp-config.yaml"
    config.write_text(
        "attestation:\n"
        "  provider: auto\n"
        "  enforcement_mode: enforcing\n"
        "policy_bundle_path: ./policies/\n"
        "catalog_path: ./catalog.json\n"
        'listen_addr: "127.0.0.1:8443"\n',
        encoding="utf-8",
    )
    return config


def test_validate_config_succeeds_on_a_legacy_code_page(tmp_path):
    """A valid config must validate where the tick cannot be drawn."""
    config = _write_valid_config(tmp_path)
    result = CliRunner(charset="cp1252").invoke(
        main, ["validate-config", "--config", str(config)]
    )
    assert result.exit_code == 0, result.output
    assert "Config valid" in result.output
    assert "Config invalid" not in result.output


def test_validate_config_keeps_the_tick_where_utf8_is_available(tmp_path):
    config = _write_valid_config(tmp_path)
    result = CliRunner(charset="utf-8").invoke(
        main, ["validate-config", "--config", str(config)]
    )
    assert result.exit_code == 0, result.output
    assert "✓ Config valid" in result.output


def test_an_actually_invalid_config_still_fails(tmp_path):
    """The fallback must not turn a real validation failure into a pass."""
    config = tmp_path / "cmcp-config.yaml"
    config.write_text("attestation: [this is not a mapping" + chr(10), encoding="utf-8")
    result = CliRunner(charset="cp1252").invoke(
        main, ["validate-config", "--config", str(config)]
    )
    assert result.exit_code == 1
    assert "Config invalid" in result.output


def test_a_failed_success_message_is_never_relabelled_as_invalid(tmp_path, monkeypatch):
    """The success echo must sit outside the try that runs the validation.

    A real Windows console raises UnicodeEncodeError from the write itself.
    When the success echo lived inside the try, `except Exception` caught that
    and printed "Config invalid: 'charmap' codec can't encode ...", so a valid
    config was reported broken. Here the first echo raises and the test asserts
    the command never claims the config is invalid.
    """
    import cmcp_runtime.cli as cli

    config = _write_valid_config(tmp_path)
    seen: list[str] = []
    calls = {"n": 0}

    def flaky_echo(message="", *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise UnicodeEncodeError("charmap", "✓", 0, 1, "unmapped")
        seen.append(str(message))

    monkeypatch.setattr(cli.click, "echo", flaky_echo)

    with pytest.raises(UnicodeEncodeError):
        cli.validate_config.callback(config=str(config))

    assert not any("Config invalid" in m for m in seen), (
        "a printing failure was relabelled as a validation failure: %r" % seen
    )
