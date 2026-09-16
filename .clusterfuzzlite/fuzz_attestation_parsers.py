#!/usr/bin/python3
"""Fuzz the attestation blob parsers in cmcp_verify.

parse_event_log walks a TCG event log: a Spec ID header that declares which
digest algorithms are present and how long each one is, then a run of events
each carrying its own declared digest count and data length. Every one of those
numbers comes from the blob being parsed, and the log arrives from the platform
before anything about it has been verified.

parse_nv_certify reads a bare or size-prefixed TPM NV certification, where a
length prefix decides how much of the rest is structure.

The property is that each parser fails closed: it returns, or raises the
ValueError its module documents (EventLogError is a ValueError). A struct.error,
IndexError, MemoryError or OverflowError reaching the caller means a declared
length was believed, and callers written against the documented exception will
not catch it.
"""
import sys

import atheris

with atheris.instrument_imports():
    from cmcp_verify.nv_certify import parse_nv_certify
    from cmcp_verify.tcg_event_log import parse_event_log

_TARGETS = [parse_event_log, parse_nv_certify]


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    fdp = atheris.FuzzedDataProvider(data)
    parser = _TARGETS[fdp.ConsumeIntInRange(0, len(_TARGETS) - 1)]
    blob = fdp.ConsumeBytes(fdp.remaining_bytes())
    try:
        parser(blob)
    except ValueError:
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
