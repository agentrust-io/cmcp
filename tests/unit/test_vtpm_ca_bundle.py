"""Unit tests for vendored vTPM CA resolution on hosts that publish no AIA.

None of these need a TPM or a network. The chain-assembly tests run against a
synthetic PKI so a leaf can actually be signed; the real Microsoft certificates
are exercised for the links that do not need a private key, plus the properties
that would silently rot -- expiry, and drift against the pinned root.
"""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from cmcp_runtime.tee import vtpm_ca_bundle
from cmcp_runtime.tee.tpm import TPMProvider
from cmcp_runtime.tee.vtpm_ca_bundle import (
    AZURE_VTPM_ROOT_2023_PEM,
    GLOBAL_VIRTUAL_TPM_CA_03_PEM,
    vendored_issuer_for,
)

_DAY = datetime.timedelta(days=1)


def _issue(
    subject: str,
    *,
    issuer_cert: x509.Certificate | None = None,
    issuer_key: rsa.RSAPrivateKey | None = None,
    ca: bool = False,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Issue a certificate, self-signed unless an issuer is supplied."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    now = datetime.datetime.now(datetime.UTC)
    signing_key = issuer_key or key
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_cert.subject if issuer_cert else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _DAY)
        .not_valid_after(now + 365 * _DAY)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    return builder.sign(signing_key, hashes.SHA256()), key


@pytest.fixture
def synthetic_pki(monkeypatch: pytest.MonkeyPatch) -> tuple[x509.Certificate, ...]:
    """A root -> intermediate -> leaf PKI installed as the vendored bundle."""
    root, root_key = _issue("Test Root", ca=True)
    inter, inter_key = _issue("Test Intermediate", issuer_cert=root, issuer_key=root_key, ca=True)
    leaf, _ = _issue("test-vm.example", issuer_cert=inter, issuer_key=inter_key)
    monkeypatch.setattr(
        vtpm_ca_bundle,
        "_BUNDLE_PEMS",
        (
            inter.public_bytes(serialization.Encoding.PEM),
            root.public_bytes(serialization.Encoding.PEM),
        ),
    )
    return leaf, inter, root


def test_leaf_without_aia_reaches_the_root_via_the_vendored_bundle(
    synthetic_pki: tuple[x509.Certificate, ...],
) -> None:
    """The CA-03 case: no AIA to walk, so the chain must come from the bundle."""
    leaf, inter, root = synthetic_pki

    chain_pem = TPMProvider._chain_from_leaf(leaf.public_bytes(serialization.Encoding.DER))
    chain = x509.load_pem_x509_certificates(chain_pem)

    assert [c.subject for c in chain] == [leaf.subject, inter.subject, root.subject]
    assert chain[-1].subject == chain[-1].issuer, "chain must terminate at a self-signed root"


def test_unresolvable_leaf_still_ships_a_partial_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unknown issuer is the present behaviour: short chain, not a crash."""
    monkeypatch.setattr(vtpm_ca_bundle, "_BUNDLE_PEMS", ())
    root, root_key = _issue("Unknown CA", ca=True)
    leaf, _ = _issue("test-vm.example", issuer_cert=root, issuer_key=root_key)

    chain_pem = TPMProvider._chain_from_leaf(leaf.public_bytes(serialization.Encoding.DER))

    assert chain_pem.count(b"BEGIN CERTIFICATE") == 1


def test_same_name_different_key_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """A subject name is not an identity, so a name match alone must not resolve.

    This is the property that makes vendoring safe: were Microsoft to re-key a CA
    while keeping its name, the impostor cannot enter the chain.
    """
    real_ca, real_key = _issue("Global Virtual TPM CA - 03", ca=True)
    impostor, _ = _issue("Global Virtual TPM CA - 03", ca=True)
    leaf, _ = _issue("test-vm.example", issuer_cert=real_ca, issuer_key=real_key)

    monkeypatch.setattr(
        vtpm_ca_bundle, "_BUNDLE_PEMS", (impostor.public_bytes(serialization.Encoding.PEM),)
    )

    assert impostor.subject == leaf.issuer, "precondition: the names do collide"
    assert vendored_issuer_for(leaf) is None


def test_self_signed_certificate_does_not_resolve_to_itself() -> None:
    """Otherwise the walk would append the root forever."""
    root = x509.load_pem_x509_certificate(AZURE_VTPM_ROOT_2023_PEM)

    assert vendored_issuer_for(root) is None


def test_real_ca_03_resolves_to_the_real_root() -> None:
    """The link that can be checked without hardware, against the shipped bytes."""
    ica = x509.load_pem_x509_certificate(GLOBAL_VIRTUAL_TPM_CA_03_PEM)

    issuer = vendored_issuer_for(ica)

    assert issuer is not None
    assert issuer.subject.rfc4514_string().startswith("CN=Azure Virtual TPM Root Certificate")


def test_bundled_root_matches_the_pinned_root() -> None:
    """Two copies of a trust anchor must not drift apart."""
    from cmcp_verify.tpm_roots import AZURE_VTPM_ROOT_2023_PEM as pinned

    bundled = x509.load_pem_x509_certificate(AZURE_VTPM_ROOT_2023_PEM)
    pinned_cert = x509.load_pem_x509_certificate(pinned)

    assert bundled.public_bytes(serialization.Encoding.DER) == pinned_cert.public_bytes(
        serialization.Encoding.DER
    )


def test_bundled_intermediate_is_not_close_to_expiry() -> None:
    """Fail deliberately, ahead of time, rather than as an outage on a CA-03 host.

    Intermediates rotate on a far shorter cycle than roots and Microsoft publishes
    no URL to poll, so nothing will notice this for us.
    """
    ica = x509.load_pem_x509_certificate(GLOBAL_VIRTUAL_TPM_CA_03_PEM)
    remaining = ica.not_valid_after_utc - datetime.datetime.now(datetime.UTC)

    assert remaining > datetime.timedelta(days=90), (
        f"Global Virtual TPM CA - 03 expires {ica.not_valid_after_utc:%Y-%m-%d} "
        f"({remaining.days} days). Refresh it from the Trusted Launch FAQ "
        "(vTPM AK certificate section) and update this bundle."
    )
