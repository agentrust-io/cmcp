"""
Provisional action-binding construction for execution correlation (issue #565).

This is a stub. `ExecutionRegistry` takes the action binding as an opaque digest
and never computes it; a running gateway still needs *something* to produce that
digest, and this stands in until the real construction lands.

The preimage shape is an open question on issue #588 and is not settled. The
canonical byte/admissibility contract (JCS member ordering, UTF-8 output, the
refusal set) is #588's; whether the action field set is also #588's or #565's is
unanswered. altrudev has proposed a profiled envelope on #588:

    {"profile": "tag:agentrust-io.com,2026:cmcp-execution-action-v1",
     "method": "tools/call",
     "name": "<ingress-normalized tool name>",
     "arguments": {...validated caller arguments...}}

and noted the profile string and exact field set are a normative decision not
yet written down. This stub does not adopt that shape and does not decide the
question: it hashes the smallest thing ingress already has, `{"tool_name",
"arguments"}`, only so the state machine can be exercised end to end. Because the
binding reaches the proxy through an injected `action_binding_fn`, adopting the
settled shape changes nothing in the execution package.

The one property a stub here must not get wrong is refusal: an argument set that
cannot be pinned down deterministically must raise rather than hash to something
ambiguous, so a mutated operation can never masquerade as a retry. It reuses the
RFC 8785 / JCS canonicalizer already in the tree
(`cmcp_runtime.catalog.approval`).
"""

from __future__ import annotations

from typing import Any

from cmcp_runtime.catalog.approval import CatalogApprovalError, digest_json


class ActionBindingError(ValueError):
    """The action could not be canonicalized into a stable binding."""


def provisional_action_binding(tool_name: str, arguments: dict[str, Any]) -> str:
    """
    Return an opaque digest binding this tool call's action.

    Stub with an undecided preimage: see the module docstring. Raises
    ActionBindingError when the arguments contain a value the canonicalizer
    refuses.
    """
    try:
        return digest_json({"tool_name": tool_name, "arguments": arguments})
    except CatalogApprovalError as exc:
        raise ActionBindingError(str(exc)) from exc
