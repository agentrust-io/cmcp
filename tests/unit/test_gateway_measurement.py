"""Tests for measuring the gateway into a TPM NV extend index (#432).

The TPM-facing calls are driven with a fake ESAPI context that enforces the
``TPM_NT_EXTEND`` semantics that make this design work: a write is
``H(old || data)``, never a replacement. That is what a real TPM does, and it is
the property the whole approach rests on, so a test that let a write replace the
value would pass while the design was broken.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from cmcp_runtime.tee.measurement import (
    DEFAULT_MEASUREMENT_NV_INDEX,
    ExtendResult,
    GatewayMeasurement,
    MeasurementUnavailable,
    code_digest,
    config_digest,
    extend_gateway_measurement,
    gateway_measurement,
    policy_digest,
)

# ── config stand-ins ──────────────────────────────────────────────────────────


@dataclass
class _Nested:
    mode: str = "enforcing"
    validity_seconds: int = 86400


@dataclass
class _Config:
    policy_bundle_path: str = "policies/"
    listen_addr: str = "0.0.0.0:8443"
    dev_mode: bool = False
    bearer_token: str | None = None
    attestation: _Nested = field(default_factory=_Nested)


# ── policy digest ─────────────────────────────────────────────────────────────


def _bundle(tmp_path: Path, files: dict[str, str]) -> str:
    root = tmp_path / "policies"
    root.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    return str(root)


def test_policy_digest_is_stable(tmp_path: Path) -> None:
    path = _bundle(tmp_path, {"a.cedar": "permit(...);", "manifest.json": "{}"})
    assert policy_digest(path) == policy_digest(path)


def test_policy_digest_changes_when_a_policy_changes(tmp_path: Path) -> None:
    """The point of #432: a swapped policy bundle must not measure identically."""
    path = _bundle(tmp_path, {"a.cedar": "permit(...);"})
    before = policy_digest(path)
    (Path(path) / "a.cedar").write_text("forbid(...);")
    assert policy_digest(path) != before


def test_policy_digest_changes_when_a_file_is_added(tmp_path: Path) -> None:
    path = _bundle(tmp_path, {"a.cedar": "permit(...);"})
    before = policy_digest(path)
    (Path(path) / "b.cedar").write_text("permit(...);")
    assert policy_digest(path) != before


def test_policy_digest_covers_the_path_not_only_the_bytes(tmp_path: Path) -> None:
    """Renaming a policy file must change the digest even if bytes are identical."""
    one = _bundle(tmp_path / "one", {"a.cedar": "permit(...);"})
    two = _bundle(tmp_path / "two", {"b.cedar": "permit(...);"})
    assert policy_digest(one) != policy_digest(two)


def test_policy_digest_fails_loudly_on_a_missing_path(tmp_path: Path) -> None:
    with pytest.raises(MeasurementUnavailable, match="does not exist"):
        policy_digest(str(tmp_path / "absent"))


def test_policy_digest_fails_loudly_on_an_empty_bundle(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(MeasurementUnavailable, match="empty"):
        policy_digest(str(empty))


# ── config digest ─────────────────────────────────────────────────────────────


def test_config_digest_is_stable() -> None:
    assert config_digest(_Config()) == config_digest(_Config())


def test_config_digest_changes_with_a_config_change() -> None:
    assert config_digest(_Config()) != config_digest(_Config(listen_addr="127.0.0.1:9000"))


def test_config_digest_covers_nested_config() -> None:
    changed = _Config(attestation=_Nested(mode="advisory"))
    assert config_digest(_Config()) != config_digest(changed)


def test_config_digest_excludes_the_bearer_token() -> None:
    """A secret must not be measured: the index is read back in evidence.

    Extending a digest over the token would publish an offline guessing oracle for
    it, and the token authenticates callers rather than describing what is running.
    """
    with_token = _Config(bearer_token="s3cret")
    assert config_digest(_Config()) == config_digest(with_token)


# ── code digest ───────────────────────────────────────────────────────────────


def test_code_digest_covers_recorded_file_hashes(monkeypatch: pytest.MonkeyPatch) -> None:
    """The digest is over RECORD hashes, so a changed dependency file changes it."""

    class _Dist:
        def __init__(self, name: str, version: str, record: str | None) -> None:
            self.metadata = {"Name": name}
            self.version = version
            self._record = record

        def read_text(self, name: str) -> str | None:
            return self._record if name == "RECORD" else None

    clean = [
        _Dist("cmcp", "1.0.0", "cmcp/__init__.py,sha256=AAA,10\n"),
        _Dist("requests", "2.0.0", "requests/api.py,sha256=BBB,20\n"),
    ]
    tampered = [
        _Dist("cmcp", "1.0.0", "cmcp/__init__.py,sha256=AAA,10\n"),
        _Dist("requests", "2.0.0", "requests/api.py,sha256=EVIL,20\n"),
    ]

    monkeypatch.setattr("cmcp_runtime.tee.measurement.distributions", lambda: clean)
    baseline = code_digest()
    monkeypatch.setattr("cmcp_runtime.tee.measurement.distributions", lambda: tampered)
    assert code_digest() != baseline


def test_code_digest_is_independent_of_scan_order(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Dist:
        def __init__(self, name: str) -> None:
            self.metadata = {"Name": name}
            self.version = "1.0.0"

        def read_text(self, name: str) -> str | None:
            return f"{self.metadata['Name']}/m.py,sha256=X,1\n" if name == "RECORD" else None

    forward = [_Dist("aaa"), _Dist("bbb"), _Dist("ccc")]
    monkeypatch.setattr("cmcp_runtime.tee.measurement.distributions", lambda: forward)
    baseline = code_digest()
    monkeypatch.setattr(
        "cmcp_runtime.tee.measurement.distributions", lambda: list(reversed(forward))
    )
    assert code_digest() == baseline


def test_code_digest_fails_loudly_without_record(monkeypatch: pytest.MonkeyPatch) -> None:
    """An editable install has no RECORD, and a partial measurement must not pass.

    Silently skipping unmeasurable distributions would report a confident digest
    over an unknown amount of code, which is worse than refusing.
    """

    class _Editable:
        metadata = {"Name": "cmcp"}
        version = "1.0.0"

        def read_text(self, name: str) -> None:
            return None

    monkeypatch.setattr("cmcp_runtime.tee.measurement.distributions", lambda: [_Editable()])
    with pytest.raises(MeasurementUnavailable, match="RECORD"):
        code_digest()


# ── the combined measurement ──────────────────────────────────────────────────


def _stub_code(monkeypatch: pytest.MonkeyPatch, digest: str = "c" * 64) -> None:
    monkeypatch.setattr("cmcp_runtime.tee.measurement.code_digest", lambda: digest)


def test_gateway_measurement_reports_its_components(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_code(monkeypatch)
    config = _Config(policy_bundle_path=_bundle(tmp_path, {"a.cedar": "permit(...);"}))
    measured = gateway_measurement(config)
    assert set(measured.components) == {"code", "policy", "config"}
    assert len(measured.digest) == 32
    assert measured.digest_hex.startswith("sha256:")


def test_gateway_measurement_changes_with_any_component(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _bundle(tmp_path, {"a.cedar": "permit(...);"})
    _stub_code(monkeypatch)
    baseline = gateway_measurement(_Config(policy_bundle_path=path)).digest

    # config differs
    assert gateway_measurement(
        _Config(policy_bundle_path=path, listen_addr="127.0.0.1:1")
    ).digest != baseline

    # policy differs
    (Path(path) / "a.cedar").write_text("forbid(...);")
    assert gateway_measurement(_Config(policy_bundle_path=path)).digest != baseline

    # code differs
    _stub_code(monkeypatch, "d" * 64)
    assert gateway_measurement(_Config(policy_bundle_path=path)).digest != baseline


def test_gateway_measurement_is_domain_separated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bare hash of the components must not equal the measurement."""
    _stub_code(monkeypatch)
    config = _Config(policy_bundle_path=_bundle(tmp_path, {"a.cedar": "x"}))
    measured = gateway_measurement(config)
    naive = hashlib.sha256(
        json.dumps(measured.components, separators=(",", ":"), sort_keys=True).encode()
    ).digest()
    assert measured.digest != naive


# ── NV extend index ───────────────────────────────────────────────────────────


class _FakeNvTpm:
    """An ESAPI stand-in enforcing real TPM_NT_EXTEND semantics."""

    def __init__(self, *, defined: bool = False, replace_on_write: bool = False) -> None:
        self.value = bytes(32) if defined else None
        self.defined = defined
        self.defines: list[int] = []
        self.extends: list[bytes] = []
        # Set to model a broken TPM (or a plain ordinary index) that replaces
        # instead of extending, which the collector must catch.
        self.replace_on_write = replace_on_write

    def tr_from_tpmpublic(self, index: int) -> str:
        if not self.defined:
            raise RuntimeError("TPM_RC_HANDLE: NV index is not defined")
        return f"handle-{index:#x}"

    def nv_define_space(self, _auth: Any, nv_public: Any, **_kw: Any) -> None:
        self.defines.append(int(nv_public.nvPublic.nvIndex))
        self.defined = True
        self.value = bytes(32)

    def nv_read_public(self, _handle: str) -> tuple[Any, None]:
        from types import SimpleNamespace

        return SimpleNamespace(nvPublic=SimpleNamespace(dataSize=32)), None

    def nv_read(self, _handle: str, size: int, offset: int) -> bytes:
        if self.value is None:
            raise RuntimeError("TPM_RC_NV_UNINITIALIZED")
        return self.value[offset : offset + size]

    def nv_extend(self, _handle: str, data: bytes, **_kw: Any) -> None:
        self.extends.append(bytes(data))
        if self.replace_on_write:
            self.value = bytes(data)
        else:
            self.value = hashlib.sha256((self.value or bytes(32)) + bytes(data)).digest()


@pytest.fixture
def _pytss(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stand in for tpm2_pytss.constants.ESYS_TR and the NV public types."""
    import sys
    import types
    from types import SimpleNamespace

    if "tpm2_pytss" in sys.modules:  # pragma: no cover - real bindings present
        return

    pkg = types.ModuleType("tpm2_pytss")
    constants = types.ModuleType("tpm2_pytss.constants")
    constants.ESYS_TR = SimpleNamespace(OWNER="owner")
    constants.TPM2_ALG = SimpleNamespace(SHA256=0x000B)
    constants.TPM2_NT = SimpleNamespace(EXTEND=0x4)
    constants.TPMA_NV = SimpleNamespace(parse=lambda _spec: 0x2000000)
    types_mod = types.ModuleType("tpm2_pytss.types")
    types_mod.TPMS_NV_PUBLIC = lambda **kw: SimpleNamespace(**kw)
    types_mod.TPM2B_NV_PUBLIC = lambda **kw: SimpleNamespace(**kw)

    monkeypatch.setitem(sys.modules, "tpm2_pytss", pkg)
    monkeypatch.setitem(sys.modules, "tpm2_pytss.constants", constants)
    monkeypatch.setitem(sys.modules, "tpm2_pytss.types", types_mod)


def _measurement(digest: bytes = b"\xab" * 32) -> GatewayMeasurement:
    return GatewayMeasurement(digest=digest, components={"code": "x"})


@pytest.mark.usefixtures("_pytss")
def test_extend_provisions_the_index_when_absent() -> None:
    tpm = _FakeNvTpm(defined=False)
    result = extend_gateway_measurement(tpm, _measurement())
    assert result.provisioned is True
    assert tpm.defines == [DEFAULT_MEASUREMENT_NV_INDEX]


@pytest.mark.usefixtures("_pytss")
def test_extend_reuses_an_existing_index() -> None:
    """Re-provisioning each boot would hand the adversary the reset they want."""
    tpm = _FakeNvTpm(defined=True)
    result = extend_gateway_measurement(tpm, _measurement())
    assert result.provisioned is False
    assert tpm.defines == []


@pytest.mark.usefixtures("_pytss")
def test_extend_returns_a_chaining_before_and_after() -> None:
    tpm = _FakeNvTpm(defined=True)
    measurement = _measurement()
    result = extend_gateway_measurement(tpm, measurement)
    assert result.before == bytes(32)
    assert result.after == hashlib.sha256(bytes(32) + measurement.digest).digest()
    assert result.chains_from(measurement.digest)


@pytest.mark.usefixtures("_pytss")
def test_extends_accumulate_across_starts() -> None:
    """Extends are one-way, so the value is a chain over every boot, not a reset.

    This is why a verifier cannot predict an absolute value from the current
    gateway digest, and why before/after are both reported.
    """
    tpm = _FakeNvTpm(defined=True)
    measurement = _measurement()
    first = extend_gateway_measurement(tpm, measurement)
    second = extend_gateway_measurement(tpm, measurement)
    assert second.before == first.after
    assert second.after != first.after
    assert second.chains_from(measurement.digest)


@pytest.mark.usefixtures("_pytss")
def test_extend_rejects_an_index_that_replaces_instead_of_extending() -> None:
    """A non-extend index would let an adversary write a chosen clean value.

    If the index were defined without TPM_NT_EXTEND, a write would replace the
    value and the tamper-evidence argument collapses, so the mismatch is fatal.
    """
    tpm = _FakeNvTpm(defined=True, replace_on_write=True)
    with pytest.raises(MeasurementUnavailable, match="does not chain"):
        extend_gateway_measurement(tpm, _measurement())


@pytest.mark.usefixtures("_pytss")
def test_extend_fails_loudly_when_the_tpm_rejects_the_write() -> None:
    class _Refusing(_FakeNvTpm):
        def nv_extend(self, _handle: str, data: bytes, **_kw: Any) -> None:
            raise RuntimeError("TPM_RC_NV_AUTHORIZATION")

    with pytest.raises(MeasurementUnavailable, match="TPM2_NV_Extend failed"):
        extend_gateway_measurement(_Refusing(defined=True), _measurement())


@pytest.mark.usefixtures("_pytss")
def test_extend_fails_loudly_when_the_index_cannot_be_defined() -> None:
    class _Undefinable(_FakeNvTpm):
        def nv_define_space(self, _auth: Any, nv_public: Any, **_kw: Any) -> None:
            raise RuntimeError("TPM_RC_NV_SPACE")

    with pytest.raises(MeasurementUnavailable, match="could not be defined"):
        extend_gateway_measurement(_Undefinable(defined=False), _measurement())


def test_chains_from_rejects_a_foreign_digest() -> None:
    before = bytes(32)
    result = ExtendResult(
        index=DEFAULT_MEASUREMENT_NV_INDEX,
        before=before,
        after=hashlib.sha256(before + b"\x01" * 32).digest(),
        provisioned=False,
    )
    assert result.chains_from(b"\x01" * 32)
    assert not result.chains_from(b"\x02" * 32)
