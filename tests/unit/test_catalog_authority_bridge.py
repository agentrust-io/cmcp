"""Negative and positive cases for the independent catalog bridge receipt."""
from __future__ import annotations

import copy
import hashlib
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from cmcp_runtime.catalog.authority_bridge import sign_bridge, verify_bridge
from cmcp_runtime.errors import ConfigError


@pytest.fixture
def case():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key_id = hashlib.sha256(public).hexdigest()
    payload = dict(version=1, manifest_id='manifest-1', manifest_digest='sha256:'+'a'*64,
                   agent_id='spiffe://example/agent', policy_hash='sha256:'+'b'*64,
                   runtime_catalog_hash='sha256:'+'c'*64, manifest_catalog_root='sha256:'+'d'*64,
                   not_before='2026-01-01T00:00:00Z', expires_at='2027-01-01T00:00:00Z', key_id=key_id)
    expected = {k:payload[k] for k in ('manifest_id','manifest_digest','agent_id','policy_hash','runtime_catalog_hash','manifest_catalog_root')}
    return private, {key_id:public}, payload, expected


def check(case, receipt, **overrides):
    _, keys, _, expected = case
    verify_bridge(receipt, keys, now=datetime(2026,10,10,tzinfo=UTC), **(expected|overrides))


def test_valid_receipt(case):
    private, _, payload, _ = case
    check(case, sign_bridge(payload, private))


@pytest.mark.parametrize('field', ['manifest_id','manifest_digest','agent_id','policy_hash','runtime_catalog_hash','manifest_catalog_root'])
def test_substituted_context_fails(case, field):
    private, _, payload, expected = case
    with pytest.raises(ConfigError):
        check(case, sign_bridge(payload, private), **{field:expected[field]+'-changed'})


@pytest.mark.parametrize('field', ['manifest_id','manifest_digest','agent_id','policy_hash','runtime_catalog_hash','manifest_catalog_root','not_before','expires_at','key_id'])
def test_modified_signed_payload_fails(case, field):
    private, _, payload, _ = case
    receipt = sign_bridge(payload, private)
    receipt['payload'][field] = 'changed'
    with pytest.raises(ConfigError):
        check(case, receipt)


def test_untrusted_signer_fails(case):
    private, keys, payload, expected = case
    with pytest.raises(ConfigError):
        verify_bridge(sign_bridge(payload, private), {}, now=datetime(2026,10,10,tzinfo=UTC), **expected)


def test_expired_fails(case):
    private, _, payload, expected = case
    with pytest.raises(ConfigError):
        verify_bridge(sign_bridge(payload, private), case[1], now=datetime(2028,1,1,tzinfo=UTC), **expected)


def test_extra_fields_fail(case):
    private, _, payload, _ = case
    with pytest.raises(ConfigError):
        sign_bridge(payload|{'unauthorized':True}, private)


def test_signature_corruption_fails(case):
    private, _, payload, _ = case
    receipt = sign_bridge(payload, private)
    receipt['signature'] = 'A' * 86
    with pytest.raises(ConfigError):
        check(case, receipt)


@pytest.mark.parametrize('field,value', [
    ('version', True), ('version', '1'), ('key_id', 'wrong'),
    ('manifest_digest', 'sha256:invalid'), ('policy_hash', 'sha256:invalid'),
    ('runtime_catalog_hash', 'sha256:invalid'), ('manifest_catalog_root', 'sha256:invalid'),
    ('not_before', 'not-a-time'), ('expires_at', '2025-01-01T00:00:00Z'),
    ('agent_id', None), ('manifest_id', []),
])
def test_malformed_signed_payload_rejected(case, field, value):
    private, _, payload, _ = case
    with pytest.raises(ConfigError):
        sign_bridge(payload | {field: value}, private)


def test_receipt_cannot_be_replayed_across_signers(case):
    private, _, payload, _ = case
    receipt = sign_bridge(payload, private)
    different = Ed25519PrivateKey.generate()
    wrong_public = different.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    with pytest.raises(ConfigError):
        verify_bridge(receipt, {payload['key_id']: wrong_public},
                      now=datetime(2026,10,10,tzinfo=UTC), **case[3])


def test_not_yet_valid_receipt_rejected(case):
    private, _, payload, _ = case
    receipt = sign_bridge(payload, private)
    with pytest.raises(ConfigError):
        verify_bridge(receipt, case[1], now=datetime(2025,10,10,tzinfo=UTC), **case[3])
