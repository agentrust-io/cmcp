"""TEE-002: CMCP_DEV_MODE must be frozen at process startup, not re-read at runtime."""

from __future__ import annotations

import importlib
import sys


def _reload_config_with_env(monkeypatch, value: str | None) -> object:
    """
    Reload cmcp_runtime.config with CMCP_DEV_MODE set to *value* (or absent if None),
    and return the fresh module so we can inspect its DEV_MODE constant.
    """
    if value is None:
        monkeypatch.delenv("CMCP_DEV_MODE", raising=False)
    else:
        monkeypatch.setenv("CMCP_DEV_MODE", value)

    # Force a clean reimport so the module-level constant is re-evaluated.
    sys.modules.pop("cmcp_runtime.config", None)
    return importlib.import_module("cmcp_runtime.config")


def test_dev_mode_constant_true_when_env_set_before_import(monkeypatch):
    """TEE-002: DEV_MODE is True when CMCP_DEV_MODE=1 is present at import time."""
    mod = _reload_config_with_env(monkeypatch, "1")
    assert mod.DEV_MODE is True


def test_dev_mode_constant_false_when_env_absent_at_import(monkeypatch):
    """TEE-002: DEV_MODE is False when CMCP_DEV_MODE is absent at import time."""
    mod = _reload_config_with_env(monkeypatch, None)
    assert mod.DEV_MODE is False


def test_dev_mode_constant_false_when_env_zero_at_import(monkeypatch):
    """TEE-002: DEV_MODE is False when CMCP_DEV_MODE=0 at import time."""
    mod = _reload_config_with_env(monkeypatch, "0")
    assert mod.DEV_MODE is False


def test_dev_mode_constant_not_changed_by_later_env_mutation(monkeypatch):
    """TEE-002: mutating os.environ AFTER import must not change DEV_MODE."""
    # Import with dev mode off.
    mod = _reload_config_with_env(monkeypatch, "0")
    assert mod.DEV_MODE is False

    # Now set the env var — simulates an attacker injecting it at runtime.
    monkeypatch.setenv("CMCP_DEV_MODE", "1")

    # The constant on the already-imported module must remain False.
    assert mod.DEV_MODE is False


def test_dev_mode_constant_not_cleared_by_later_env_removal(monkeypatch):
    """TEE-002: removing CMCP_DEV_MODE from os.environ after import must not clear DEV_MODE."""
    # Import with dev mode on.
    mod = _reload_config_with_env(monkeypatch, "1")
    assert mod.DEV_MODE is True

    # Remove the env var — the constant must stay True.
    monkeypatch.delenv("CMCP_DEV_MODE", raising=False)
    assert mod.DEV_MODE is True


def test_load_config_uses_frozen_constant(monkeypatch, tmp_path):
    """TEE-002: load_config reflects DEV_MODE constant, not a live env read."""
    import textwrap

    cfg_file = tmp_path / "cmcp-config.yaml"
    cfg_file.write_text(textwrap.dedent("""
        attestation:
          provider: auto
    """))

    # Import with dev mode OFF, then enable env var afterward.
    mod = _reload_config_with_env(monkeypatch, "0")
    assert mod.DEV_MODE is False

    monkeypatch.setenv("CMCP_DEV_MODE", "1")

    cfg = mod.load_config(str(cfg_file))
    # Config must reflect the frozen False, not the live env var.
    assert cfg.dev_mode is False
