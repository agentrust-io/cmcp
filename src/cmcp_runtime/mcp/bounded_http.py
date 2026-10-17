"""Bound HTTP response input before JSON/SSE parsing or content decoding."""

from __future__ import annotations

import httpx

from cmcp_runtime.errors import ResponseSizeExceeded

# Unlike HTTPX's per-operation timeout, this bounds a continuously active SSE
# response too. Keep the existing 30-second upstream budget as an absolute one.
UPSTREAM_HTTP_RESPONSE_TIMEOUT_SECONDS = 30.0


async def read_bounded_response(response: httpx.Response, max_bytes: int) -> httpx.Response:
    """Read an identity-encoded body up to the limit, then expose it for parsing.

    The caller owns the streaming response context and must close it on every
    exit. Count actual bytes even when Content-Length is absent or misleading.
    Never invoke HTTPX's decoder on an untrusted compressed response: decoding
    one input chunk can allocate far beyond the limit before yielding output.
    """
    encoding = response.headers.get("content-encoding", "identity").strip().lower()
    if encoding not in ("", "identity"):
        raise ValueError("upstream response must use identity content encoding")
    declared = response.headers.get("content-length")
    if declared is not None:
        if not declared.isascii() or not declared.isdecimal():
            raise ValueError("invalid upstream Content-Length")
        # Compare decimal strings before conversion: even an arbitrarily long
        # header must not require parsing an arbitrarily large Python integer.
        length = declared.lstrip("0") or "0"
        limit = str(max_bytes)
        if len(length) > len(limit) or (len(length) == len(limit) and length > limit):
            raise ResponseSizeExceeded("upstream HTTP body exceeds response size limit")
    content = bytearray()
    async for chunk in response.aiter_bytes():
        if len(chunk) > max_bytes - len(content):
            raise ResponseSizeExceeded("upstream HTTP body exceeds response size limit")
        content.extend(chunk)
    return httpx.Response(
        response.status_code,
        headers=response.headers,
        content=bytes(content),
        request=response.request,
        extensions=response.extensions,
    )
