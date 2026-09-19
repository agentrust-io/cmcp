"""Reference operator gate for live restriction of an existing cMCP session."""

import asyncio

from examples.confinement.adapter import Refused


class PolicyGate:
    """Serialize cutover with dispatch; never replace the underlying cMCP state.

    This overlay can restrict or re-enable originally configured tools. It
    cannot expand catalog/sink ceilings or lower the session classification.
    The operator method is not exposed on the agent's stdio protocol.
    """

    def __init__(self, dispatch, approved_tools):
        self._dispatch = dispatch
        self._approved = frozenset(approved_tools)
        self._allowed = self._approved
        self._revision = 0
        self._closed = False
        self._lock = asyncio.Lock()

    async def replace(self, revision, allowed_tools):
        async with self._lock:
            # A failed update leaves future calls denied until a valid newer
            # update arrives. Never silently keep an unexpectedly broad policy.
            self._closed = True
            if (type(revision) is not int or revision <= self._revision
                    or not isinstance(allowed_tools, (set, frozenset))
                    or not all(isinstance(t, str) for t in allowed_tools)
                    or not allowed_tools <= self._approved):
                raise Refused("invalid operator policy revision")
            self._allowed = frozenset(allowed_tools)
            self._revision = revision
            self._closed = False
            return self._revision

    async def __call__(self, tool, arguments):
        async with self._lock:
            if self._closed or tool not in self._allowed:
                return {"allowed": False, "response": None}
            return await self._dispatch(tool, arguments)
