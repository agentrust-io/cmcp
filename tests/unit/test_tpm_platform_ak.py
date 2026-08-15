"""Unit tests for the platform attestation key path: NV reads and chain assembly.

None of these need a TPM. The chunked NV read is exercised against a fake ESAPI that
enforces the same buffer limit real hardware does, which is the constraint that made
the first implementation fail on a 1596-byte certificate.
"""

from __future__ import annotations

import datetime
import logging
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

from cmcp_runtime.tee.tpm import TPMProvider


class _FakeNvPublic:
    def __init__(self, size: int) -> None:
        self.nvPublic = type("_P", (), {"dataSize": size})()


class _FakeESAPI:
    """Minimal ESAPI stand-in that enforces a maximum NV read size, as a TPM does."""

    def __init__(self, data: bytes, buffer_max: int | None = 512, *, defined: bool = True) -> None:
        self._data = data
        self._buffer_max = buffer_max
        self._defined = defined
        self.read_sizes: list[int] = []

    def tr_from_tpmpublic(self, handle: int) -> int:
        if not self._defined:
            raise RuntimeError("NV index not defined")
        return handle

    def nv_read_public(self, handle: int) -> tuple[_FakeNvPublic, None]:
        return _FakeNvPublic(len(self._data)), None

    def get_capability(self, cap: int, prop: int, count: int) -> tuple[bool, object]:
        if self._buffer_max is None:
            raise RuntimeError("capability unavailable")
        entry = type("_E", (), {"property": prop, "value": self._buffer_max})()
        data = type("_D", (), {"tpmProperties": [entry]})()
        return True, type("_C", (), {"data": data})()

    def nv_read(self, handle: int, size: int, offset: int = 0) -> bytes:
        if self._buffer_max is not None and size > self._buffer_max:
            raise RuntimeError("tpm:parameter(1):value is out of range")
        self.read_sizes.append(size)
        return self._data[offset : offset + size]


def _self_signed(cn: str = "unit-test-ak") -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )


def _build_chain(depth: int) -> list[x509.Certificate]:
    """Build a synthetic chain of `depth` certificates, leaf first, each signed by
    the next and carrying an AIA extension pointing at the next by URL, terminating
    in a self signed root (#514)."""
    keys = [rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(depth)]
    names = [
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"unit-test-{i}")])
        for i in range(depth)
    ]
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    certs: list[x509.Certificate] = []
    for i in range(depth):
        is_root = i == depth - 1
        issuer = names[i] if is_root else names[i + 1]
        signing_key = keys[i] if is_root else keys[i + 1]
        builder = (
            x509.CertificateBuilder()
            .subject_name(names[i])
            .issuer_name(issuer)
            .public_key(keys[i].public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
        )
        if not is_root:
            url = f"https://example.test/cert{i + 1}.der"
            builder = builder.add_extension(
                x509.AuthorityInformationAccess([
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.CA_ISSUERS,
                        x509.UniformResourceIdentifier(url),
                    )
                ]),
                critical=False,
            )
        certs.append(builder.sign(signing_key, hashes.SHA256()))
    return certs


class _FakeAiaResponse:
    """Minimal urlopen() context manager stand-in serving one certificate's DER."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def __enter__(self) -> _FakeAiaResponse:
        return self

    def __exit__(self, *args: object) -> bool:
        return False

    def read(self) -> bytes:
        return self._data


def _fake_urlopen_for(certs: list[x509.Certificate]):
    """Serve certs[i] DER bytes for the URL _build_chain() gave cert i-1's AIA."""
    der_by_url = {
        f"https://example.test/cert{i + 1}.der": certs[i + 1].public_bytes(
            serialization.Encoding.DER
        )
        for i in range(len(certs) - 1)
    }

    def _urlopen(url: str, timeout: float | None = None) -> _FakeAiaResponse:
        return _FakeAiaResponse(der_by_url[url])

    return _urlopen


def test_nv_read_chunks_within_the_buffer_limit() -> None:
    """A 1596-byte certificate cannot be read in one call: TPM2_NV_Read is bounded by
    TPM2_PT_NV_BUFFER_MAX. Reading it whole is what failed on real hardware."""
    payload = bytes(range(256)) * 7  # 1792 bytes, larger than the limit
    ectx = _FakeESAPI(payload, buffer_max=512)

    result = TPMProvider._read_nv(ectx, 0x01C101D0)

    assert result == payload
    assert max(ectx.read_sizes) <= 512
    assert len(ectx.read_sizes) == 4  # 512 + 512 + 512 + 256


def test_nv_read_honours_a_smaller_reported_buffer_max() -> None:
    payload = b"\xab" * 300
    ectx = _FakeESAPI(payload, buffer_max=128)

    assert TPMProvider._read_nv(ectx, 0x01C101D0) == payload
    assert max(ectx.read_sizes) <= 128


def test_nv_read_falls_back_to_the_default_chunk_when_capability_is_unavailable() -> None:
    payload = b"\xcd" * 400
    ectx = _FakeESAPI(payload, buffer_max=None)

    # buffer_max None means get_capability raises and nv_read enforces nothing.
    assert TPMProvider._read_nv(ectx, 0x01C101D0) == payload


def test_nv_read_returns_none_when_the_index_is_undefined() -> None:
    """Most platforms define no attestation key certificate; that is not an error."""
    ectx = _FakeESAPI(b"", defined=False)

    assert TPMProvider._read_nv(ectx, 0x01C101D0) is None


def test_chain_from_a_self_signed_leaf_stops_immediately() -> None:
    """A self-signed certificate ends the walk, so no network access is attempted."""
    cert = _self_signed()

    chain = TPMProvider._chain_from_leaf(cert.public_bytes(serialization.Encoding.DER))

    assert chain.count(b"BEGIN CERTIFICATE") == 1
    assert x509.load_pem_x509_certificates(chain)[0].subject == cert.subject


def test_chain_from_unrecognised_bytes_is_empty_rather_than_raising() -> None:
    assert TPMProvider._chain_from_leaf(b"not a certificate") == b""


def test_certifies_matches_only_the_key_in_the_leaf() -> None:
    cert = _self_signed()
    chain = cert.public_bytes(serialization.Encoding.PEM)
    leaf_pem = cert.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    class _Pub:
        def __init__(self, pem: bytes) -> None:
            self._pem = pem

        def to_pem(self) -> bytes:
            return self._pem

    other = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    other_pem = other.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    assert TPMProvider._certifies(chain, _Pub(leaf_pem)) is True
    assert TPMProvider._certifies(chain, _Pub(other_pem)) is False


@pytest.mark.parametrize("blob", [b"", b"\x30\x82", b"\xff" * 64])
def test_chain_from_malformed_input_never_raises(blob: bytes) -> None:
    assert TPMProvider._chain_from_leaf(blob) == b""


def test_chain_walk_reaches_root_deeper_than_previously_known_azure_depth() -> None:
    """#514: the two Azure hierarchies measured on real hardware are 4 and 3
    certificates deep. A chain one hop deeper than the deeper of the two must not
    be truncated by the widened depth cap."""
    certs = _build_chain(5)

    with patch("urllib.request.urlopen", side_effect=_fake_urlopen_for(certs)):
        chain = TPMProvider._chain_from_leaf(certs[0].public_bytes(serialization.Encoding.DER))

    loaded = x509.load_pem_x509_certificates(chain)
    assert len(loaded) == 5
    assert loaded[-1].subject == loaded[-1].issuer  # reached the real, self signed root


def test_chain_walk_past_the_depth_cap_logs_a_truncation_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """#514: when a chain needs more hops than the cap allows, the walk stops
    without reaching the root, and that must be visible in the logs rather than
    only surfacing later as a chain-verification failure that looks identical to
    a chain that legitimately reaches an untrusted root."""
    monkeypatch.setattr("cmcp_runtime.tee.tpm._AIA_MAX_DEPTH", 2)
    certs = _build_chain(3)

    with (
        patch("urllib.request.urlopen", side_effect=_fake_urlopen_for(certs)),
        caplog.at_level(logging.WARNING, logger="cmcp_runtime.tee.tpm"),
    ):
        chain = TPMProvider._chain_from_leaf(certs[0].public_bytes(serialization.Encoding.DER))

    loaded = x509.load_pem_x509_certificates(chain)
    assert len(loaded) == 2
    assert loaded[-1].subject != loaded[-1].issuer  # truncated, not the real root
    assert any("depth cap" in record.message for record in caplog.records)
