"""TCG event log parsing and PCR replay.

A PCR digest on its own is opaque: a verifier can tell that platform state differs
from a known-good value but not what changed. The TCG event log is the record of
every measurement that produced those PCRs, so replaying it turns an opaque digest
into an auditable list of components.

Format reference: TCG PC Client Platform Firmware Profile, the crypto-agile log.
The first entry is a legacy ``TCG_PCClientPCREvent`` carrying a Spec ID event that
declares which digest algorithms the rest of the log uses. Every later entry is a
``TCG_PCR_EVENT2`` with one digest per declared algorithm.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

# Event types that record information without extending a PCR.
EV_NO_ACTION = 0x00000003

# TPM2_ALG_ID values we can replay.
ALG_SHA1 = 0x0004
ALG_SHA256 = 0x000B
ALG_SHA384 = 0x000C
ALG_SHA512 = 0x000D

_HASHES = {
    ALG_SHA1: hashlib.sha1,
    ALG_SHA256: hashlib.sha256,
    ALG_SHA384: hashlib.sha384,
    ALG_SHA512: hashlib.sha512,
}

_ALG_NAMES = {
    ALG_SHA1: "sha1",
    ALG_SHA256: "sha256",
    ALG_SHA384: "sha384",
    ALG_SHA512: "sha512",
}

_SPEC_ID_SIGNATURE = b"Spec ID Event03\x00"

# SRTM PCRs start at zero. DRTM PCRs 17 through 22 start at 0xFF and are only
# reset by a measured launch, so a replay that starts them at zero is wrong.
_DRTM_PCRS = range(17, 23)


class EventLogError(ValueError):
    """The event log could not be parsed."""


@dataclass(frozen=True)
class EventLogEntry:
    """One measurement record."""

    pcr_index: int
    event_type: int
    digests: dict[int, bytes]
    event_data: bytes

    @property
    def extends(self) -> bool:
        """EV_NO_ACTION entries are informational and never extend a PCR."""
        return self.event_type != EV_NO_ACTION


@dataclass(frozen=True)
class ReplayResult:
    """Outcome of replaying a log against reported PCR values."""

    algorithm: str
    computed: dict[int, bytes]
    matched: list[int] = field(default_factory=list)
    mismatched: list[int] = field(default_factory=list)
    absent_from_log: list[int] = field(default_factory=list)

    @property
    def verified(self) -> bool:
        return not self.mismatched and not self.absent_from_log


def _starting_value(pcr_index: int, digest_size: int) -> bytes:
    if pcr_index in _DRTM_PCRS:
        return b"\xff" * digest_size
    return b"\x00" * digest_size


def _parse_spec_id(event_data: bytes) -> dict[int, int]:
    """Return {algorithm_id: digest_size} declared by the Spec ID event."""
    if not event_data.startswith(_SPEC_ID_SIGNATURE):
        raise EventLogError("first event is not a Spec ID Event03 header")
    # signature(16) platformClass(4) minor(1) major(1) errata(1) uintnSize(1)
    offset = 16 + 4 + 1 + 1 + 1 + 1
    if len(event_data) < offset + 4:
        raise EventLogError("Spec ID event truncated before algorithm count")
    (count,) = struct.unpack_from("<I", event_data, offset)
    offset += 4
    if count == 0:
        raise EventLogError("Spec ID event declares no digest algorithms")
    sizes: dict[int, int] = {}
    for _ in range(count):
        if len(event_data) < offset + 4:
            raise EventLogError("Spec ID event truncated inside the algorithm list")
        alg_id, digest_size = struct.unpack_from("<HH", event_data, offset)
        offset += 4
        sizes[alg_id] = digest_size
    return sizes


def parse_event_log(data: bytes) -> tuple[list[EventLogEntry], dict[int, int]]:
    """
    Parse a crypto-agile TCG event log.

    Returns the entries and the {algorithm_id: digest_size} map from the header.
    Raises EventLogError on any truncation rather than returning a partial log: a
    silently truncated log replays to the wrong PCR values.
    """
    if len(data) < 32:
        raise EventLogError("event log too short to contain a header event")

    # Legacy header event: pcrIndex(4) eventType(4) digest(20) eventDataSize(4)
    pcr_index, event_type, _sha1_digest, event_size = struct.unpack_from("<II20sI", data, 0)
    offset = 32
    if len(data) < offset + event_size:
        raise EventLogError("header event data truncated")
    header_data = data[offset : offset + event_size]
    offset += event_size

    if pcr_index != 0 or event_type != EV_NO_ACTION:
        raise EventLogError(
            f"unexpected header event (pcr={pcr_index}, type=0x{event_type:08x})"
        )
    digest_sizes = _parse_spec_id(header_data)

    entries: list[EventLogEntry] = []
    while offset < len(data):
        if len(data) < offset + 12:
            raise EventLogError("event truncated before its digest count")
        pcr_index, event_type, digest_count = struct.unpack_from("<III", data, offset)
        offset += 12

        digests: dict[int, bytes] = {}
        for _ in range(digest_count):
            if len(data) < offset + 2:
                raise EventLogError("event truncated before a digest algorithm id")
            (alg_id,) = struct.unpack_from("<H", data, offset)
            offset += 2
            size = digest_sizes.get(alg_id)
            if size is None:
                raise EventLogError(
                    f"event uses algorithm 0x{alg_id:04x}, which the header did not declare"
                )
            if len(data) < offset + size:
                raise EventLogError("event truncated inside a digest")
            digests[alg_id] = data[offset : offset + size]
            offset += size

        if len(data) < offset + 4:
            raise EventLogError("event truncated before its data size")
        (event_size,) = struct.unpack_from("<I", data, offset)
        offset += 4
        if len(data) < offset + event_size:
            raise EventLogError("event data truncated")
        event_data = data[offset : offset + event_size]
        offset += event_size

        entries.append(EventLogEntry(pcr_index, event_type, digests, event_data))

    return entries, digest_sizes


def replay_pcrs(
    entries: list[EventLogEntry], algorithm: int = ALG_SHA256
) -> dict[int, bytes]:
    """Replay the log and return the PCR values it implies for one algorithm."""
    hasher = _HASHES.get(algorithm)
    if hasher is None:
        raise EventLogError(f"unsupported digest algorithm 0x{algorithm:04x}")
    digest_size = hasher().digest_size

    pcrs: dict[int, bytes] = {}
    for entry in entries:
        if not entry.extends:
            continue
        digest = entry.digests.get(algorithm)
        if digest is None:
            raise EventLogError(
                f"event for PCR {entry.pcr_index} carries no "
                f"{_ALG_NAMES.get(algorithm, algorithm)} digest"
            )
        current = pcrs.get(entry.pcr_index, _starting_value(entry.pcr_index, digest_size))
        pcrs[entry.pcr_index] = hasher(current + digest).digest()
    return pcrs


def verify_event_log(
    log: bytes, reported_pcrs: dict[int, bytes], algorithm: int = ALG_SHA256
) -> ReplayResult:
    """
    Replay ``log`` and compare the result against the PCR values reported by the TPM.

    ``reported_pcrs`` maps PCR index to raw digest bytes. A PCR that the log never
    extends is listed in ``absent_from_log`` rather than silently passing, because a
    reported value with no corresponding measurement is exactly the case a verifier
    must not accept.
    """
    entries, _sizes = parse_event_log(log)
    computed = replay_pcrs(entries, algorithm)

    matched: list[int] = []
    mismatched: list[int] = []
    absent: list[int] = []
    for index, value in sorted(reported_pcrs.items()):
        if index not in computed:
            absent.append(index)
        elif computed[index] == value:
            matched.append(index)
        else:
            mismatched.append(index)

    return ReplayResult(
        algorithm=_ALG_NAMES.get(algorithm, f"0x{algorithm:04x}"),
        computed=computed,
        matched=matched,
        mismatched=mismatched,
        absent_from_log=absent,
    )
