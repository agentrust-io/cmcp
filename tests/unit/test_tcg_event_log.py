"""Unit tests for TCG event log parsing and PCR replay."""

from __future__ import annotations

import hashlib
import struct

import pytest

from cmcp_verify.tcg_event_log import (
    ALG_SHA1,
    ALG_SHA256,
    EV_NO_ACTION,
    EventLogError,
    parse_event_log,
    replay_pcrs,
    verify_event_log,
)

EV_SEPARATOR = 0x00000004
EV_EFI_BOOT_SERVICES_APPLICATION = 0x80000003


def _header_event() -> bytes:
    """A legacy header event carrying a Spec ID Event03 declaring SHA-1 and SHA-256."""
    spec = b"Spec ID Event03\x00"
    spec += struct.pack("<I", 0)  # platformClass
    spec += bytes([0, 2, 0, 8])  # minor, major, errata, uintnSize
    spec += struct.pack("<I", 2)  # two algorithms
    spec += struct.pack("<HH", ALG_SHA1, 20)
    spec += struct.pack("<HH", ALG_SHA256, 32)
    spec += bytes([0])  # vendorInfoSize
    return struct.pack("<II20sI", 0, EV_NO_ACTION, b"\x00" * 20, len(spec)) + spec


def _event(pcr: int, event_type: int, payload: bytes) -> bytes:
    sha1 = hashlib.sha1(payload).digest()
    sha256 = hashlib.sha256(payload).digest()
    out = struct.pack("<III", pcr, event_type, 2)
    out += struct.pack("<H", ALG_SHA1) + sha1
    out += struct.pack("<H", ALG_SHA256) + sha256
    out += struct.pack("<I", len(payload)) + payload
    return out


def _expected_pcr(payloads: list[bytes], start: bytes = b"\x00" * 32) -> bytes:
    """Independently compute the extend chain, so the test does not reuse the code."""
    value = start
    for payload in payloads:
        value = hashlib.sha256(value + hashlib.sha256(payload).digest()).digest()
    return value


@pytest.fixture
def log() -> bytes:
    return (
        _header_event()
        + _event(0, EV_EFI_BOOT_SERVICES_APPLICATION, b"firmware-blob")
        + _event(0, EV_SEPARATOR, b"\x00\x00\x00\x00")
        + _event(4, EV_EFI_BOOT_SERVICES_APPLICATION, b"bootloader")
    )


def test_parse_returns_every_entry_and_the_declared_algorithms(log: bytes) -> None:
    entries, sizes = parse_event_log(log)

    assert len(entries) == 3
    assert sizes == {ALG_SHA1: 20, ALG_SHA256: 32}
    assert [e.pcr_index for e in entries] == [0, 0, 4]


def test_replay_matches_an_independently_computed_extend_chain(log: bytes) -> None:
    entries, _ = parse_event_log(log)

    pcrs = replay_pcrs(entries, ALG_SHA256)

    assert pcrs[0] == _expected_pcr([b"firmware-blob", b"\x00\x00\x00\x00"])
    assert pcrs[4] == _expected_pcr([b"bootloader"])


def test_no_action_events_do_not_extend() -> None:
    payloads = [b"real-measurement"]
    log = (
        _header_event()
        + _event(0, EV_NO_ACTION, b"informational")
        + _event(0, EV_EFI_BOOT_SERVICES_APPLICATION, payloads[0])
    )
    entries, _ = parse_event_log(log)

    assert replay_pcrs(entries, ALG_SHA256)[0] == _expected_pcr(payloads)


def test_drtm_pcrs_start_at_ff_not_zero() -> None:
    log = _header_event() + _event(17, EV_EFI_BOOT_SERVICES_APPLICATION, b"drtm")
    entries, _ = parse_event_log(log)

    expected = _expected_pcr([b"drtm"], start=b"\xff" * 32)
    assert replay_pcrs(entries, ALG_SHA256)[17] == expected


def test_verify_reports_matched_and_mismatched_pcrs(log: bytes) -> None:
    entries, _ = parse_event_log(log)
    computed = replay_pcrs(entries, ALG_SHA256)

    result = verify_event_log(log, {0: computed[0], 4: b"\x99" * 32})

    assert result.matched == [0]
    assert result.mismatched == [4]
    assert result.verified is False


def test_verify_flags_a_reported_pcr_the_log_never_extends(log: bytes) -> None:
    """A PCR value with no corresponding measurement must not silently pass."""
    entries, _ = parse_event_log(log)

    result = verify_event_log(log, {0: replay_pcrs(entries, ALG_SHA256)[0], 7: b"\x00" * 32})

    assert result.matched == [0]
    assert result.absent_from_log == [7]
    assert result.verified is False


def test_verify_passes_when_every_reported_pcr_replays(log: bytes) -> None:
    entries, _ = parse_event_log(log)
    computed = replay_pcrs(entries, ALG_SHA256)

    result = verify_event_log(log, computed)

    assert result.verified is True
    assert result.mismatched == []


def test_truncated_log_raises_instead_of_replaying_a_partial_chain(log: bytes) -> None:
    with pytest.raises(EventLogError):
        parse_event_log(log[:-7])


def test_undeclared_algorithm_is_rejected() -> None:
    body = struct.pack("<III", 0, EV_SEPARATOR, 1)
    body += struct.pack("<H", 0x000C) + b"\x00" * 48  # SHA-384, never declared
    body += struct.pack("<I", 0)
    with pytest.raises(EventLogError, match="did not declare"):
        parse_event_log(_header_event() + body)


def test_missing_header_is_rejected() -> None:
    with pytest.raises(EventLogError):
        parse_event_log(b"\x00" * 64)
