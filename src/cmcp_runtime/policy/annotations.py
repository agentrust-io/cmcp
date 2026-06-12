"""
Cedar policy annotation extraction.

Cedar has no first-class "advice" construct: annotations (``@key("value")``)
attached to a policy are the supported way to carry structured metadata such
as HITL escalation instructions. cedarpy reports which policies determined a
decision (``diagnostics.reasons`` as implicit ids ``policy0``, ``policy1``,
... in source order) but only surfaces the ``@id`` annotation value, so the
full annotation set must be recovered from the policy source.

This module parses annotations from a combined Cedar policy string, keyed by
the same implicit ids cedarpy assigns, so a deny decision can be mapped back
to the matched policies' annotations.
"""

from __future__ import annotations

import re

# @key("value") - value may contain escaped quotes/backslashes.
_ANNOTATION_RE = re.compile(
    r'@([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*"((?:[^"\\]|\\.)*)"\s*\)'
)

# A policy statement: zero or more annotations followed by permit/forbid.
# Matched against comment-stripped source, in order, so the Nth match is
# cedarpy's implicit id "policyN".
_POLICY_RE = re.compile(
    r'((?:@[A-Za-z_][A-Za-z0-9_]*\s*\(\s*"(?:[^"\\]|\\.)*"\s*\)\s*)*)'
    r"\b(permit|forbid)\s*\("
)


def _strip_line_comments(text: str) -> str:
    """Remove ``// ...`` comments, ignoring ``//`` inside string literals."""
    out_lines: list[str] = []
    for line in text.splitlines():
        in_string = False
        escaped = False
        cut = len(line)
        for i, ch in enumerate(line):
            if escaped:
                escaped = False
                continue
            if ch == "\\" and in_string:
                escaped = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if ch == "/" and not in_string and line[i : i + 2] == "//":
                cut = i
                break
        out_lines.append(line[:cut])
    return "\n".join(out_lines)


def _unescape(value: str) -> str:
    return value.replace('\\"', '"').replace("\\\\", "\\")


def parse_policy_annotations(policy_text: str) -> dict[str, dict[str, str]]:
    """
    Map implicit Cedar policy ids to their annotations.

    Returns ``{"policy0": {"reason": "...", ...}, "policy2": {...}}``; policies
    without annotations are omitted. Ordering follows statement order in the
    source, matching the ids cedarpy assigns when parsing the same string.
    """
    stripped = _strip_line_comments(policy_text)
    annotations: dict[str, dict[str, str]] = {}
    for index, match in enumerate(_POLICY_RE.finditer(stripped)):
        block = match.group(1)
        if not block:
            continue
        parsed = {
            key: _unescape(value)
            for key, value in _ANNOTATION_RE.findall(block)
        }
        if parsed:
            annotations[f"policy{index}"] = parsed
    return annotations
