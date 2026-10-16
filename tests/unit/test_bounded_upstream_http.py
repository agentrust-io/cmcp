"""Bound transport input before parsing, even with a small tool-text result."""

from __future__ import annotations

import asyncio
import gzip
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from cmcp_runtime.audit.chain import AuditChain
from cmcp_runtime.errors import ResponseSizeExceeded
from cmcp_runtime.mcp.bounded_http import read_bounded_response
from tests.unit.test_issue_571_finalization import _make_proxy, _provenance, _terminals


class TrackedBody(httpx.AsyncByteStream):
    def __init__(self, content: bytes, *, stall: bool = False):
        self.content = content
        self.stall = stall
        self.bytes_read = 0
        self.closed = False
        self.started = asyncio.Event()

    async def __aiter__(self):
        self.started.set()
        if self.stall:
            await asyncio.Event().wait()
        for offset in range(0, len(self.content), 32):
            chunk = self.content[offset:offset + 32]
            self.bytes_read += len(chunk)
            yield chunk

    async def aclose(self):
        self.closed = True


class KeepaliveBody(TrackedBody):
    async def __aiter__(self):
        while True:
            self.bytes_read += 3
            yield b":\n\n"
            await asyncio.sleep(0.001)


@pytest.mark.asyncio
@pytest.mark.parametrize("length", [None, "0", "4096"])
@pytest.mark.parametrize("media_type", ["application/json", "text/event-stream"])
async def test_oversized_body_is_closed_before_parsing(length, media_type):
    raw = json.dumps({"jsonrpc": "2.0", "id": "current", "padding": "x" * 4096,
                      "result": {"content": [{"type": "text", "text": "ok"}]}}).encode()
    if media_type == "text/event-stream":
        raw = b"data: " + raw + b"\n\n"
    stream = TrackedBody(raw)
    headers = {"content-type": media_type}
    if length is not None:
        headers["content-length"] = length
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, headers=headers, stream=stream)

    chain = AuditChain("issue-571")
    proxy = _make_proxy(chain)
    proxy._config.max_response_size_bytes = 256
    proxy._check_provenance = AsyncMock(return_value=_provenance(meets_requirement=True))
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler), trust_env=False) as client:
        proxy._client_for_upstream = MagicMock(return_value=client)
        with patch("cmcp_runtime.mcp.proxy.parse_response") as parser:
            result = await proxy.call_tool("current", "test.echo", {})
        parser.assert_not_called()
    assert len(requests) == 1
    assert requests[0].headers["accept-encoding"] == "identity"
    assert stream.closed
    assert stream.bytes_read == (0 if length == "4096" else 288)
    assert result.allowed is False
    assert result.response is None
    assert result.deny_reason == "response_size_exceeded"
    terminal, = _terminals(chain)
    assert terminal.response_inspection_result == "size_exceeded"
    assert terminal.response_payload_hash is None
    assert terminal.detail["effect_boundary_state"] == "transport_response_received"
    assert terminal.detail["terminal_disposition"] == "outcome_unknown"


@pytest.mark.asyncio
@pytest.mark.parametrize("media_type", ["application/json", "text/event-stream"])
async def test_discovery_body_is_bounded_without_parsing_or_partial_acceptance(media_type):
    stream = TrackedBody(b"x" * 4096)
    chain = AuditChain("issue-571")
    proxy = _make_proxy(chain)
    proxy._config.max_response_size_bytes = 256
    entry = proxy._catalog.lookup("test.echo")
    async with httpx.AsyncClient(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, headers={"content-type": media_type}, stream=stream)
    ), trust_env=False) as client:
        proxy._client_for_upstream = MagicMock(return_value=client)
        with patch("cmcp_runtime.mcp.proxy.parse_response") as parser:
            assert await proxy._discover_tools(entry) is None
        parser.assert_not_called()
    assert stream.closed
    assert stream.bytes_read == 288


@pytest.mark.asyncio
async def test_body_cancellation_closes_stream_and_retains_unknown_outcome():
    stream = TrackedBody(b"", stall=True)
    chain = AuditChain("issue-571")
    proxy = _make_proxy(chain)
    proxy._check_provenance = AsyncMock(return_value=_provenance(meets_requirement=True))
    async with httpx.AsyncClient(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=stream)
    ), trust_env=False) as client:
        proxy._client_for_upstream = MagicMock(return_value=client)
        task = asyncio.create_task(proxy.call_tool("current", "test.echo", {}))
        try:
            await asyncio.wait_for(stream.started.wait(), 1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            if not task.done():
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
    assert stream.closed
    terminal, = _terminals(chain)
    assert terminal.response_payload_hash is None
    assert terminal.detail["terminal_disposition"] == "outcome_unknown"


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [255, 256, 257])
async def test_measured_body_limit_includes_exact_boundary(size):
    stream = TrackedBody(b"x" * size)
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda req: httpx.Response(200, stream=stream)),
        trust_env=False,
    ) as client, client.stream("POST", "https://local.invalid/mcp") as response:
        if size > 256:
            with pytest.raises(ResponseSizeExceeded):
                await read_bounded_response(response, 256)
        else:
            bounded = await read_bounded_response(response, 256)
            assert bounded.content == b"x" * size
    assert stream.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("length", ["-1", "+1", "1, 1", "no", "١", "9" * 5000])
async def test_invalid_or_extreme_declared_length_is_refused_without_reading(length):
    stream = TrackedBody(b"unused")
    # Unicode cannot be an HTTP header value, so validate the public helper with
    # UTF-8 bytes as an adversarial header spelling instead of a Python string.
    headers = [(b"content-length", length.encode("utf-8"))]
    response = httpx.Response(200, headers=headers, stream=stream,
                              request=httpx.Request("POST", "https://local.invalid/mcp"))
    try:
        with pytest.raises((ValueError, ResponseSizeExceeded)):
            await read_bounded_response(response, 256)
        assert stream.bytes_read == 0
    finally:
        await response.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("encoding", ["gzip", "deflate", "br", "zstd", "gzip, identity"])
async def test_compressed_response_is_refused_before_decoding(encoding):
    stream = TrackedBody(gzip.compress(b"x" * (1024 * 1024)))
    response = httpx.Response(200, headers={"content-encoding": encoding}, stream=stream,
                              request=httpx.Request("POST", "https://local.invalid/mcp"))
    try:
        with pytest.raises(ValueError, match="identity content encoding"):
            await read_bounded_response(response, 256)
        assert stream.bytes_read == 0
    finally:
        await response.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("media_type", ["application/json", "text/event-stream"])
async def test_valid_small_reply_is_returned(media_type):
    body = {"jsonrpc": "2.0", "id": "current",
            "result": {"content": [{"type": "text", "text": "ok"}]}}
    raw = json.dumps(body).encode()
    if media_type == "text/event-stream":
        raw = b"data: " + raw + b"\n\n"
    stream = TrackedBody(raw)
    chain = AuditChain("issue-571")
    proxy = _make_proxy(chain)
    proxy._config.max_response_size_bytes = 256
    proxy._check_provenance = AsyncMock(return_value=_provenance(meets_requirement=True))
    async with httpx.AsyncClient(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, headers={"content-type": media_type}, stream=stream)
    ), trust_env=False) as client:
        proxy._client_for_upstream = MagicMock(return_value=client)
        result = await proxy.call_tool("current", "test.echo", {})
    assert result.allowed is True
    assert result.response == "ok"
    assert len(_terminals(chain)) == 1
    assert stream.closed


@pytest.mark.asyncio
@pytest.mark.parametrize("active", [False, True])
async def test_body_deadline_closes_stream_and_records_unknown(monkeypatch, active):
    monkeypatch.setattr("cmcp_runtime.mcp.proxy.UPSTREAM_HTTP_RESPONSE_TIMEOUT_SECONDS", 0.02)
    stream = KeepaliveBody(b"") if active else TrackedBody(b"", stall=True)
    chain = AuditChain("issue-571")
    proxy = _make_proxy(chain)
    proxy._check_provenance = AsyncMock(return_value=_provenance(meets_requirement=True))
    async with httpx.AsyncClient(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=stream)
    ), trust_env=False) as client:
        proxy._client_for_upstream = MagicMock(return_value=client)
        result = await proxy.call_tool("current", "test.echo", {})
    assert result.allowed is False
    assert stream.closed
    if active:
        assert stream.bytes_read > 0
    terminal, = _terminals(chain)
    assert terminal.detail["effect_boundary_state"] == "transport_response_received"
    assert terminal.detail["terminal_disposition"] == "outcome_unknown"
