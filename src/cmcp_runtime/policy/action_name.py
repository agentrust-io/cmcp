"""The Cedar action a tool name maps to, in one place.

The Cedar backend names a call's action by joining the underscore-separated
parts of the tool name, each capitalised: ``read_file`` becomes ``ReadFile``.
That mapping is not injective. ``read_file``, ``read__file``, ``_read_file``
and ``read_file_`` all become ``ReadFile``, so two catalog entries can share
one policy identity and a permit or forbid written for one applies to the
other (#655). The catalog loader refuses such a pair using this same function,
so the check cannot drift from what the backend actually evaluates.
"""

from __future__ import annotations


def cedar_action_name(tool_name: str) -> str:
    """Return the Cedar action name the policy backend uses for ``tool_name``."""
    return "".join(part.capitalize() for part in tool_name.split("_"))
