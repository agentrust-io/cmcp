"""Bind the gateway measurement into SEV-SNP / TDX / Azure-CVM report_data (#552).

These are the properties #552 prototyped, kept as tests so the contract cannot
regress silently. They are software-only by design: SoftwareOnlyProvider echoes the
nonce into report_data, which is exactly the collector-side shape SEV-SNP and TDX
give, so the round trip proves the *contract*. Whether real silicon signs those 64
bytes is a hardware question and #552 leaves it out of scope on purpose.

The verifier stand-in below recomputes both halves from scratch, the way a relying
party would: the thumbprint from the public key, the digest from code, policy and
config. Nothing it checks is taken from the report itself.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from cmcp_runtime.config import Config
from cmcp_runtime.policy.bundle import PolicyBundle, PolicyManifest
from cmcp_runtime.policy.evaluator import PolicyEvaluator
from cmcp_runtime.tee.base import (
    SoftwareOnlyProvider,
    jwk_thumbprint,
    make_measurement_bound_nonce,
)
from cmcp_runtime.tee.measurement import GatewayMeasurement, gateway_measurement
from cmcp_runtime.tee.report_binding import (
    MEASUREMENT_BOUND_PROVIDERS,
    binds_measurement_into_report_data,
    measurement_bound_nonce_for,
    refresh_measurement_binding,
)

_KEY = bytes(range(32))
_DIGEST = b"\xab" * 32


# ── config and context stand-ins ──────────────────────────────────────────────


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


@dataclass
class _SigningKey:
    public_key_bytes: bytes = _KEY


@dataclass
class _Ctx:
    """The slice of RuntimeContext refresh_measurement_binding actually touches."""

    config: _Config
    tee_provider: object
    signing_key: _SigningKey = field(default_factory=_SigningKey)
    gateway_measurement: GatewayMeasurement | None = None
    attestation_report: object | None = None


def _bundle(tmp_path: Path, content: str) -> str:
    root = tmp_path / "policies"
    root.mkdir(parents=True, exist_ok=True)
    (root / "a.cedar").write_text(content)
    return str(root)


@pytest.fixture
def stub_code(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin code_digest: an editable test install has no RECORD to measure."""
    monkeypatch.setattr("cmcp_runtime.tee.measurement.code_digest", lambda: "c" * 64)


# ── nonce layout ──────────────────────────────────────────────────────────────


def test_nonce_is_thumbprint_then_measurement() -> None:
    """The 64-byte layout #552 specifies, with the digest unreshaped."""
    nonce = make_measurement_bound_nonce(_KEY, _DIGEST)

    assert len(nonce) == 64
    assert nonce[:32] == jwk_thumbprint(_KEY)
    assert nonce[32:64] == _DIGEST


def test_nonce_keeps_the_key_binding_intact() -> None:
    """CRYPTO-001 still holds: report_data[:32] is re-derivable from cnf.jwk.x."""
    other = bytes(range(1, 33))
    assert make_measurement_bound_nonce(_KEY, _DIGEST)[:32] != (
        make_measurement_bound_nonce(other, _DIGEST)[:32]
    )


def test_nonce_rejects_a_wrong_sized_digest() -> None:
    """A short digest would leave the second half partly zero, committing nothing."""
    with pytest.raises(ValueError, match="32 bytes"):
        make_measurement_bound_nonce(_KEY, b"\xab" * 31)


def test_nonce_is_fresh_per_start_despite_being_deterministic() -> None:
    """Replacing the random salt does not cost freshness: the key is per-start.

    make_nonce got its freshness from 32 random bytes. This layout has none, so the
    property has to come from the first half instead, and it does: run_startup
    generates a new signing key on every start, so two starts of byte-identical
    code, policy and config still produce different report_data.
    """
    start_a = make_measurement_bound_nonce(_KEY, _DIGEST)
    start_b = make_measurement_bound_nonce(bytes(range(32, 64)), _DIGEST)
    assert start_a != start_b


# ── which providers use it ────────────────────────────────────────────────────


def test_tpm_does_not_use_report_data_binding() -> None:
    """The TPM tier has the NV extend index, which keeps history report_data cannot."""
    assert not binds_measurement_into_report_data("tpm")


@pytest.mark.parametrize("provider", sorted(MEASUREMENT_BOUND_PROVIDERS))
def test_launch_measurement_platforms_use_report_data_binding(provider: str) -> None:
    assert binds_measurement_into_report_data(provider)


def test_the_three_platforms_from_the_issue_are_covered() -> None:
    assert {"sev-snp", "azure-cvm-sev-snp", "tdx"} == MEASUREMENT_BOUND_PROVIDERS


# ── the measurement itself ────────────────────────────────────────────────────


def test_measurement_is_deterministic_across_repeat_calls(
    tmp_path: Path, stub_code: None
) -> None:
    config = _Config(policy_bundle_path=_bundle(tmp_path, "permit(...);"))
    assert gateway_measurement(config).digest == gateway_measurement(config).digest


def test_one_character_of_cedar_moves_only_the_policy_component(
    tmp_path: Path, stub_code: None
) -> None:
    """Component isolation is what makes a mismatch diagnosable rather than opaque."""
    path = _bundle(tmp_path, "permit(...);")
    config = _Config(policy_bundle_path=path)
    before = gateway_measurement(config)

    (Path(path) / "a.cedar").write_text("permit(...) ;")
    after = gateway_measurement(config)

    assert after.components["policy"] != before.components["policy"]
    assert after.components["code"] == before.components["code"]
    assert after.components["config"] == before.components["config"]
    assert after.digest != before.digest


# ── full round trip through a provider ────────────────────────────────────────


def _verifier_recompute(public_key: bytes, config: _Config) -> bytes:
    """What a relying party derives independently: neither half read off the report."""
    return jwk_thumbprint(public_key) + gateway_measurement(config).digest


def test_round_trip_matches_both_halves_of_report_data(
    tmp_path: Path, stub_code: None
) -> None:
    config = _Config(policy_bundle_path=_bundle(tmp_path, "permit(...);"))
    measurement = gateway_measurement(config)

    nonce = measurement_bound_nonce_for(_KEY, measurement)
    report = SoftwareOnlyProvider().get_attestation_report(nonce)
    report_data = bytes.fromhex(report.report_data)

    expected = _verifier_recompute(_KEY, config)
    assert report_data[:32] == expected[:32]
    assert report_data[32:64] == expected[32:64]


def test_a_swapped_policy_bundle_no_longer_matches_the_report(
    tmp_path: Path, stub_code: None
) -> None:
    """The gap #552 closes: on these platforms this comparison used to pass anyway.

    The launch measurement is boot-time, so before this change nothing in the signed
    report moved when the Cedar bundle did.
    """
    path = _bundle(tmp_path, "permit(...);")
    config = _Config(policy_bundle_path=path)

    nonce = measurement_bound_nonce_for(_KEY, gateway_measurement(config))
    report_data = bytes.fromhex(
        SoftwareOnlyProvider().get_attestation_report(nonce).report_data
    )

    (Path(path) / "a.cedar").write_text("forbid(...);")
    assert report_data[32:64] != _verifier_recompute(_KEY, config)[32:64]


# ── refresh on policy reload ──────────────────────────────────────────────────


class _CountingProvider(SoftwareOnlyProvider):
    """SoftwareOnlyProvider that records the nonces it was asked to commit."""

    def __init__(self, provider: str = "sev-snp") -> None:
        self._provider = provider
        self.nonces: list[bytes] = []

    def provider_name(self) -> str:
        return self._provider

    def get_attestation_report(self, nonce: bytes):  # type: ignore[no-untyped-def]
        self.nonces.append(nonce)
        report = super().get_attestation_report(nonce)
        report.provider = self._provider
        return report


def test_reload_produces_a_report_reflecting_the_new_measurement(
    tmp_path: Path, stub_code: None
) -> None:
    path = _bundle(tmp_path, "permit(...);")
    config = _Config(policy_bundle_path=path)
    provider = _CountingProvider()
    ctx = _Ctx(config=config, tee_provider=provider)

    assert refresh_measurement_binding(ctx) is True
    first = bytes.fromhex(ctx.attestation_report.report_data)

    (Path(path) / "a.cedar").write_text("forbid(...);")
    assert refresh_measurement_binding(ctx) is True
    second = bytes.fromhex(ctx.attestation_report.report_data)

    assert second != first
    assert second[32:64] == gateway_measurement(config).digest
    assert len(provider.nonces) == 2


def test_a_stale_pre_reload_report_is_rejected_on_recompute(
    tmp_path: Path, stub_code: None
) -> None:
    """The freshness property: report_data has no history, so staleness must show."""
    path = _bundle(tmp_path, "permit(...);")
    config = _Config(policy_bundle_path=path)
    ctx = _Ctx(config=config, tee_provider=_CountingProvider())

    refresh_measurement_binding(ctx)
    stale = bytes.fromhex(ctx.attestation_report.report_data)

    (Path(path) / "a.cedar").write_text("forbid(...);")
    assert stale[32:64] != _verifier_recompute(_KEY, config)[32:64]


def test_every_reload_re_attests_even_when_the_measurement_is_unchanged(
    tmp_path: Path, stub_code: None
) -> None:
    """#552 asks for a refresh on every reload, not only on the ones that changed.

    report_data carries no history, so the same digest re-signed now and that digest
    signed an hour ago are different assertions, and only the latest one reaches a
    verifier. Skipping the unchanged case would leave the stale one standing.
    """
    config = _Config(policy_bundle_path=_bundle(tmp_path, "permit(...);"))
    provider = _CountingProvider()
    ctx = _Ctx(config=config, tee_provider=provider)

    assert refresh_measurement_binding(ctx) is True
    assert refresh_measurement_binding(ctx) is True
    assert refresh_measurement_binding(ctx) is True

    assert len(provider.nonces) == 3
    assert provider.nonces[0] == provider.nonces[1] == provider.nonces[2]
    assert bytes.fromhex(ctx.attestation_report.report_data)[32:64] == (
        gateway_measurement(config).digest
    )


def test_the_cost_is_bounded_by_the_reload_interval_not_the_request_rate(
    tmp_path: Path, stub_code: None
) -> None:
    """Evaluating tool calls between reloads must not each spend a TEE call.

    The bound comes from PolicyStore.reload_if_stale, which stamps its clock before
    the attempt and returns False until the interval elapses, so the hook fires once
    per interval however many calls arrive in it.
    """
    from cmcp_runtime.policy.bundle import PolicyStore

    calls: list[int] = []
    store = PolicyStore(
        bundle=_policy_bundle("permit(principal, action, resource);"),
        bundle_path=str(tmp_path / "nonexistent"),
        reload_interval_seconds=3600,
    )
    evaluator = PolicyEvaluator(bundle=store, config=Config(), on_reload=lambda: calls.append(1))

    for _ in range(5):
        evaluator._maybe_reload()

    assert calls == []  # interval has not elapsed since the store was built


def test_refresh_is_a_no_op_on_the_tpm_provider(tmp_path: Path, stub_code: None) -> None:
    """The TPM tier commits through the NV index; report_data is not its mechanism."""
    config = _Config(policy_bundle_path=_bundle(tmp_path, "permit(...);"))
    provider = _CountingProvider(provider="tpm")
    ctx = _Ctx(config=config, tee_provider=provider)

    assert refresh_measurement_binding(ctx) is False
    assert provider.nonces == []
    assert ctx.attestation_report is None


def test_a_failed_re_attestation_leaves_the_previous_report_in_place(
    tmp_path: Path, stub_code: None
) -> None:
    """Availability over fail-closed, because the stale binding is detectable.

    The context must not end up advertising a measurement its report_data does not
    commit, so the pair is replaced together or not at all.
    """
    path = _bundle(tmp_path, "permit(...);")
    config = _Config(policy_bundle_path=path)
    provider = _CountingProvider()
    ctx = _Ctx(config=config, tee_provider=provider)
    refresh_measurement_binding(ctx)
    good_report = ctx.attestation_report
    good_measurement = ctx.gateway_measurement

    def _boom(nonce: bytes):  # type: ignore[no-untyped-def]
        raise RuntimeError("TEE unavailable")

    provider.get_attestation_report = _boom  # type: ignore[method-assign]
    (Path(path) / "a.cedar").write_text("forbid(...);")

    assert refresh_measurement_binding(ctx) is False
    assert ctx.attestation_report is good_report
    assert ctx.gateway_measurement is good_measurement


def test_an_unmeasurable_gateway_leaves_the_previous_report_in_place(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stub_code: None
) -> None:
    config = _Config(policy_bundle_path=_bundle(tmp_path, "permit(...);"))
    ctx = _Ctx(config=config, tee_provider=_CountingProvider())
    refresh_measurement_binding(ctx)
    good_report = ctx.attestation_report

    monkeypatch.setattr(config, "policy_bundle_path", str(tmp_path / "gone"))
    assert refresh_measurement_binding(ctx) is False
    assert ctx.attestation_report is good_report


# ── the evaluator hook ────────────────────────────────────────────────────────


def _policy_bundle(content: str) -> PolicyBundle:
    return PolicyBundle(
        manifest=PolicyManifest(
            version="1.0.0",
            authored_at="2026-08-23T00:00:00Z",
            author_identity="test",
            commit_sha="abc",
        ),
        policy_files={"a.cedar": content},
        schema_content='{"cMCP": {}}',
        bundle_hash="sha256:" + hashlib.sha256(content.encode()).hexdigest(),
    )


def _evaluator_with_hook(
    hook: Callable[[], object], *, reloads: bool = True
) -> PolicyEvaluator:
    """Build an evaluator whose store reports ``reloads`` from reload_if_stale."""
    evaluator = PolicyEvaluator(
        bundle=_policy_bundle("permit(principal, action, resource);"),
        config=Config(),
        on_reload=hook,
    )
    evaluator._store.reload_if_stale = lambda: reloads  # type: ignore[method-assign]
    return evaluator


def _swap_bundle(evaluator: PolicyEvaluator) -> None:
    """Force the hash-changed branch without needing a real on-disk reload."""
    evaluator._store._bundle = _policy_bundle("forbid(principal, action, resource);")


def test_evaluator_calls_the_hook_on_every_reload() -> None:
    """The literal reading of #552: every reload, not only the ones that changed.

    A PolicyStore whose reload_if_stale reports a reload fires the hook whether or
    not the bundle hash moved, which is the whole point of the second bullet.
    """
    calls: list[int] = []
    evaluator = _evaluator_with_hook(lambda: calls.append(1), reloads=True)

    evaluator._maybe_reload()
    assert calls == [1]  # unchanged bundle, still re-committed

    _swap_bundle(evaluator)
    evaluator._maybe_reload()
    assert calls == [1, 1]


def test_a_reload_that_did_not_happen_does_not_call_the_hook() -> None:
    """No reload, no re-attestation: the hook tracks reloads, not evaluations."""
    calls: list[int] = []
    evaluator = _evaluator_with_hook(lambda: calls.append(1), reloads=False)

    evaluator._maybe_reload()
    evaluator._maybe_reload()
    assert calls == []


def test_a_failed_reload_does_not_call_the_hook() -> None:
    """reload_if_stale returns False when the read failed, and there is nothing new
    to commit: the bundle in force is the one already bound."""
    calls: list[int] = []
    evaluator = _evaluator_with_hook(lambda: calls.append(1), reloads=False)
    evaluator._store.reload_if_stale = lambda: False  # type: ignore[method-assign]

    _swap_bundle(evaluator)
    evaluator._maybe_reload()
    assert calls == []


def test_a_failing_hook_does_not_break_enforcement() -> None:
    """A TEE fault must not take the gateway down; the verifier catches it instead."""

    def _boom() -> None:
        raise RuntimeError("TEE unavailable")

    evaluator = _evaluator_with_hook(_boom)
    _swap_bundle(evaluator)
    evaluator._maybe_reload()  # must not raise


def test_no_hook_is_the_default() -> None:
    """Every other caller of PolicyEvaluator keeps working untouched."""
    evaluator = PolicyEvaluator(
        bundle=_policy_bundle("permit(principal, action, resource);"),
        config=Config(),
    )
    evaluator._store.reload_if_stale = lambda: True  # type: ignore[method-assign]
    _swap_bundle(evaluator)
    evaluator._maybe_reload()  # must not raise


# ── startup wiring ────────────────────────────────────────────────────────────


def test_startup_binds_the_measurement_into_the_nonce_on_sev_snp(
    tmp_path: Path, stub_code: None
) -> None:
    from cmcp_runtime.startup import _attestation_nonce, _measure_gateway

    config = _Config(policy_bundle_path=_bundle(tmp_path, "permit(...);"))
    provider = _CountingProvider()

    measurement = _measure_gateway(config, provider)
    assert measurement is not None

    nonce = _attestation_nonce(
        jwk_thumbprint(_KEY), _SigningKey(), provider, measurement
    )
    assert nonce == jwk_thumbprint(_KEY) + gateway_measurement(config).digest


def test_startup_keeps_the_random_salt_on_the_tpm_tier(
    tmp_path: Path, stub_code: None
) -> None:
    """The TPM commits via the NV extend index, so its nonce is unchanged (#432)."""
    from cmcp_runtime.startup import _attestation_nonce, _measure_gateway

    config = _Config(policy_bundle_path=_bundle(tmp_path, "permit(...);"))
    provider = _CountingProvider(provider="tpm")

    measurement = _measure_gateway(config, provider)
    assert measurement is not None  # still measured, just committed elsewhere

    fingerprint = jwk_thumbprint(_KEY)
    first = _attestation_nonce(fingerprint, _SigningKey(), provider, measurement)
    second = _attestation_nonce(fingerprint, _SigningKey(), provider, measurement)

    assert first[:32] == fingerprint
    assert first != second  # the salt is random per call
    assert first[32:64] != measurement.digest


def test_startup_skips_the_measurement_where_nothing_commits_it(
    tmp_path: Path, stub_code: None
) -> None:
    from cmcp_runtime.startup import _measure_gateway

    config = _Config(policy_bundle_path=_bundle(tmp_path, "permit(...);"))
    assert _measure_gateway(config, SoftwareOnlyProvider()) is None


def test_an_unmeasurable_gateway_aborts_startup_on_sev_snp(tmp_path: Path) -> None:
    """Fail-closed, for the same reason the TPM tier does: unmeasured is unattested.

    #552 extends the measurement to these platforms, so it extends the consequence
    of not having one. Dev mode keeps the escape hatch an editable install needs.
    """
    from cmcp_runtime.startup import _measure_gateway

    config = _Config(policy_bundle_path=str(tmp_path / "gone"), dev_mode=False)
    with pytest.raises(SystemExit):
        _measure_gateway(config, _CountingProvider())


def test_dev_mode_downgrades_that_abort_to_a_warning(tmp_path: Path) -> None:
    from cmcp_runtime.startup import _measure_gateway

    config = _Config(policy_bundle_path=str(tmp_path / "gone"), dev_mode=True)
    assert _measure_gateway(config, _CountingProvider()) is None


# ── verifier-side recompute-and-compare ───────────────────────────────────────
#
# The second bullet of #552 ends "Verifier-side recompute-and-compare has to do
# that job". report_data carries no history, so nothing in a single report says
# whether it is current. These are the checks that do that job.


def _claim_with_nonce(nonce: bytes) -> dict:
    return {"trace": {"runtime": {"nonce": _b64url(nonce)}}}


def _b64url(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def test_verifier_accepts_a_report_committing_the_expected_measurement(
    tmp_path: Path, stub_code: None
) -> None:
    from cmcp_verify.verify import _check_measurement_binding

    config = _Config(policy_bundle_path=_bundle(tmp_path, "permit(...);"))
    digest = gateway_measurement(config).digest
    claim = _claim_with_nonce(make_measurement_bound_nonce(_KEY, digest))

    assert _check_measurement_binding(claim, digest, is_sw_only=False) == (True, None)


def test_verifier_rejects_a_stale_report_after_a_policy_change(
    tmp_path: Path, stub_code: None
) -> None:
    """The freshness property, from the other side: recompute catches the staleness."""
    from cmcp_verify.verify import _check_measurement_binding

    path = _bundle(tmp_path, "permit(...);")
    config = _Config(policy_bundle_path=path)
    claim = _claim_with_nonce(
        make_measurement_bound_nonce(_KEY, gateway_measurement(config).digest)
    )

    (Path(path) / "a.cedar").write_text("forbid(...);")
    ok, reason = _check_measurement_binding(
        claim, gateway_measurement(config).digest, is_sw_only=False
    )

    assert ok is False
    assert "does not match report_data[32:64]" in (reason or "")


def test_verifier_compares_the_digest_without_re_hashing_it() -> None:
    """AUDIT-006 commits SHA-256(chain_root); this commits the digest itself."""
    from cmcp_verify.verify import _check_measurement_binding

    claim = _claim_with_nonce(make_measurement_bound_nonce(_KEY, _DIGEST))

    assert _check_measurement_binding(claim, _DIGEST, is_sw_only=False)[0] is True
    rehashed = hashlib.sha256(_DIGEST).digest()
    assert _check_measurement_binding(claim, rehashed, is_sw_only=False)[0] is False


def test_verifier_fails_closed_without_a_nonce() -> None:
    from cmcp_verify.verify import _check_measurement_binding

    ok, reason = _check_measurement_binding({}, _DIGEST, is_sw_only=False)
    assert ok is False
    assert "does not" in (reason or "")


def test_verifier_rejects_an_expected_digest_that_is_not_a_sha256() -> None:
    """A caller passing the wrong shape must not silently compare 31 bytes."""
    from cmcp_verify.verify import _check_measurement_binding

    claim = _claim_with_nonce(make_measurement_bound_nonce(_KEY, _DIGEST))
    ok, reason = _check_measurement_binding(claim, _DIGEST[:31], is_sw_only=False)
    assert ok is False
    assert "not 32" in (reason or "")


def test_a_mismatch_is_fatal_in_software_only_mode_too() -> None:
    """Software-only costs provenance, not correctness: the digest is computed the
    same way, so a mismatch is a real disagreement about what is running."""
    from cmcp_verify.verify import _check_measurement_binding

    claim = _claim_with_nonce(make_measurement_bound_nonce(_KEY, _DIGEST))
    assert _check_measurement_binding(claim, b"\xcd" * 32, is_sw_only=True)[0] is False
    assert _check_measurement_binding(claim, _DIGEST, is_sw_only=True)[0] is None


def test_the_expected_digest_accepts_hex_and_the_sha256_prefix() -> None:
    from cmcp_verify.verify import _coerce_measurement_digest

    assert _coerce_measurement_digest(_DIGEST) == _DIGEST
    assert _coerce_measurement_digest(_DIGEST.hex()) == _DIGEST
    assert _coerce_measurement_digest("sha256:" + _DIGEST.hex()) == _DIGEST
    assert _coerce_measurement_digest("not-hex") is None


# ── the two seams the rest of the suite stubs or assumes ──────────────────────


def test_a_real_unchanged_bundle_reload_fires_the_hook(tmp_path: Path) -> None:
    """Bullet 2 end to end, with nothing stubbed on the reload seam.

    Every other hook test replaces reload_if_stale to control what it reports. This
    one uses a real PolicyStore over a real bundle on disk, lets the interval elapse,
    and reloads a bundle that did not change. The hook must still fire: that is the
    whole difference between "every reload" and "every reload that changed the hash".
    """
    import json

    from cmcp_runtime.policy.bundle import PolicyStore, load_policy_bundle

    root = tmp_path / "bundle"
    root.mkdir()
    (root / "manifest.json").write_text(
        json.dumps(
            {
                "version": "1.0.0",
                "authored_at": "2026-08-23T00:00:00Z",
                "author_identity": "test@example.com",
                "commit_sha": "abc123",
            }
        )
    )
    (root / "allow.cedar").write_text("permit(principal, action, resource);")
    (root / "schema.cedarschema").write_text('{"cMCP": {"entityTypes": {}, "actions": {}}}')

    bundle = load_policy_bundle(str(root))
    store = PolicyStore(bundle=bundle, bundle_path=str(root), reload_interval_seconds=1)

    calls: list[int] = []
    evaluator = PolicyEvaluator(bundle=store, config=Config(), on_reload=lambda: calls.append(1))

    # Age the store past its interval rather than sleeping for it.
    store._last_reload_at -= 3600
    evaluator._maybe_reload()

    assert calls == [1]
    assert store.bundle.bundle_hash == bundle.bundle_hash  # genuinely unchanged


def test_the_two_jwk_thumbprint_implementations_agree() -> None:
    """startup and tee.base each derive the thumbprint; a divergence would split
    report_data[:32] between the measurement-bound path and every other path.

    startup._jwk_thumbprint_sha256 builds the first 32 bytes for the salt nonce;
    tee.base.jwk_thumbprint builds them for the measurement-bound one. Nothing else
    in the tree forces them to agree, so this is the guard that does.
    """
    import base64

    from cmcp_runtime.startup import _jwk_thumbprint_sha256

    x_b64 = base64.urlsafe_b64encode(_KEY).rstrip(b"=").decode()
    assert _jwk_thumbprint_sha256(x_b64) == jwk_thumbprint(_KEY)


def test_all_three_providers_put_the_whole_nonce_into_report_data() -> None:
    """The binding is only real if the 64 bytes reach the hardware-signed field.

    SEV-SNP and TDX write the nonce into REPORT_DATA / REPORTDATA directly. Azure
    CVM cannot (the paravisor owns SNP REPORT_DATA) and commits sha256(nonce) into
    the AK-signed quote instead, but still surfaces the nonce as report_data, which
    is what cmcp_verify.azure_cvm re-derives against. All three therefore carry the
    measurement in report_data[32:64] where the verifier check looks.
    """
    import inspect

    from cmcp_runtime.tee.azure_cvm import AzureCVMProvider
    from cmcp_runtime.tee.sev_snp import SEVSNPProvider
    from cmcp_runtime.tee.tdx import TDXProvider

    providers = (SEVSNPProvider, TDXProvider, AzureCVMProvider)

    # Named explicitly rather than discovered, so this cannot quietly start
    # inspecting the abstract base and passing for the wrong reason.
    assert {p.__name__ for p in providers} == {
        "SEVSNPProvider",
        "TDXProvider",
        "AzureCVMProvider",
    }
    for provider in providers:
        source = inspect.getsource(provider.get_attestation_report)
        assert "report_data=nonce.hex()" in source, provider.__name__

    # And every one of them is in the set that gets the measurement-bound nonce.
    assert {p().provider_name() for p in providers} == MEASUREMENT_BOUND_PROVIDERS
