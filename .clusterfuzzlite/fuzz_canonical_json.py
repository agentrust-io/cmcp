#!/usr/bin/python3
"""Fuzz the canonicalizer that catalog approvals are signed over.

canonical_json() produces the bytes an approval signature covers, so those bytes
have to be a faithful, lossless encoding of the input. The property asserted
here is a round trip: parsing the canonical output must reproduce the input.

That is stronger than checking for a crash, deliberately. The three RFC 8785
bugs found in the sibling agent-manifest canonicalizer in September 2026 were
all silent. The sharpest was NFC normalization of object keys: two distinct keys
normalized to one, the output carried that key twice, json.loads kept one of the
pair, and a field disappeared from a document whose signature claimed to cover
it. Nothing raised. cmcp's implementation does not have that bug, and this is
what keeps it that way.

Structure is built from the fuzz data rather than by mutating JSON text, so the
budget goes on key and value shapes (combining marks, surrogate pairs, control
characters, integer boundaries) instead of on producing syntactically valid JSON.
"""
import json
import math
import sys

import atheris

with atheris.instrument_imports():
    from cmcp_runtime.catalog.approval import canonical_json

_MAX_DEPTH = 4
_MAX_ITEMS = 6


def _build(fdp: atheris.FuzzedDataProvider, depth: int = 0):
    if depth >= _MAX_DEPTH or fdp.remaining_bytes() == 0:
        return fdp.ConsumeUnicodeNoSurrogates(16)
    kind = fdp.ConsumeIntInRange(0, 7)
    if kind == 0:
        return None
    if kind == 1:
        return fdp.ConsumeBool()
    if kind == 2:
        # Straddle the safe-integer boundary on purpose: past it, RFC 8785 maps
        # two distinct integers to the same digits, so the canonicalizer has to
        # refuse rather than emit them.
        return fdp.ConsumeIntInRange(-(2**54), 2**54)
    if kind == 3:
        return fdp.ConsumeFloat()
    if kind == 4:
        return fdp.ConsumeUnicodeNoSurrogates(64)
    if kind == 5:
        return [_build(fdp, depth + 1) for _ in range(fdp.ConsumeIntInRange(0, _MAX_ITEMS))]
    return {
        fdp.ConsumeUnicodeNoSurrogates(24): _build(fdp, depth + 1)
        for _ in range(fdp.ConsumeIntInRange(0, _MAX_ITEMS))
    }


def _json_equal(a, b) -> bool:
    """Equality up to JSON's number model.

    JSON has one number type, so a float whose shortest form has no fractional
    part re-parses as a Python int and will not compare equal to the float it
    came from. That is correct output, not a defect, so the round trip is
    asserted up to numeric type.
    """
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return float(a) == float(b)
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_json_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_json_equal(x, y) for x, y in zip(a, b))
    return type(a) is type(b) and a == b


def _has_nonfinite(value) -> bool:
    """NaN and Infinity have no JSON form; the canonicalizer rejects them."""
    if isinstance(value, float):
        return not math.isfinite(value)
    if isinstance(value, dict):
        return any(_has_nonfinite(v) for v in value.values())
    if isinstance(value, list):
        return any(_has_nonfinite(v) for v in value)
    return False


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    value = _build(fdp)
    if _has_nonfinite(value):
        return
    try:
        out = canonical_json(value)
    except ValueError:
        # Declared: CatalogApprovalError is a ValueError, and covers floats,
        # integers outside the RFC 8785 safe domain, and unsupported types.
        return

    assert _json_equal(json.loads(out), value), f"canonical bytes did not round-trip: {out!r}"
    assert canonical_json(value) == out, "canonicalization is not deterministic"


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
