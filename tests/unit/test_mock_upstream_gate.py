"""Tests for scripts/mock_upstream.py's JSON-RPC request gate (#518).

Spins up the real MockMCPHandler in-process against a random local port and
issues raw HTTP requests, so these exercise the actual handler class rather
than a reimplementation of it.
"""

from __future__ import annotations

import contextlib
import http.client
import json
import socket
import sys
import threading
from http.server import HTTPServer
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from mock_upstream import (  # noqa: E402
    _MAX_ARG_STRING_LENGTH,
    MAX_REQUEST_BYTES,
    MockMCPHandler,
)


@pytest.fixture(scope="module")
def upstream():
    server = HTTPServer(("127.0.0.1", 0), MockMCPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_port
    server.shutdown()


def _post(port: int, body: bytes, *, headers: dict[str, str] | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    conn.request("POST", "/mcp", body=body, headers=hdrs)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    return resp.status, json.loads(raw)


VALID_REQUEST = json.dumps(
    {
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "tools/call",
        "params": {"name": "echo", "arguments": {"message": "hi"}},
    }
).encode()


# ---------------------------------------------------------------------------
# Existing valid-request behavior must be unchanged
# ---------------------------------------------------------------------------


def test_valid_request_returns_200_with_expected_shape(upstream):
    status, body = _post(upstream, VALID_REQUEST)
    assert status == 200
    assert body["jsonrpc"] == "2.0"
    assert body["id"] == "req-1"
    text = body["result"]["content"][0]["text"]
    assert text == 'mock upstream: echo called with {"message": "hi"}'


def test_valid_request_without_arguments_defaults_to_empty_dict(upstream):
    req = json.dumps(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "echo"}}
    ).encode()
    status, body = _post(upstream, req)
    assert status == 200
    assert body["result"]["content"][0]["text"] == "mock upstream: echo called with {}"


# ---------------------------------------------------------------------------
# -32700 Parse error: malformed JSON
# ---------------------------------------------------------------------------


def test_malformed_json_returns_parse_error(upstream):
    status, body = _post(upstream, b"{not valid json")
    assert status == 400
    assert body["jsonrpc"] == "2.0"
    assert body["error"]["code"] == -32700
    assert body["id"] is None


def test_empty_body_returns_parse_error(upstream):
    status, body = _post(upstream, b"")
    assert status == 400
    assert body["error"]["code"] == -32700


# ---------------------------------------------------------------------------
# -32600 Invalid Request: structurally wrong
# ---------------------------------------------------------------------------


def test_non_object_json_returns_invalid_request(upstream):
    status, body = _post(upstream, b"[1, 2, 3]")
    assert status == 400
    assert body["error"]["code"] == -32600
    assert body["id"] is None


def test_missing_method_returns_invalid_request(upstream):
    req = json.dumps({"jsonrpc": "2.0", "id": 3, "params": {"name": "echo"}}).encode()
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32600
    assert body["id"] == 3


def test_non_string_method_returns_invalid_request(upstream):
    req = json.dumps(
        {"jsonrpc": "2.0", "id": 4, "method": 7, "params": {"name": "echo"}}
    ).encode()
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32600
    assert body["id"] == 4


def test_non_object_params_returns_invalid_request(upstream):
    req = json.dumps(
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": "nope"}
    ).encode()
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32600
    assert body["id"] == 5


# ---------------------------------------------------------------------------
# -32602 Invalid params
# ---------------------------------------------------------------------------


def test_missing_tool_name_returns_invalid_params(upstream):
    req = json.dumps(
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {}}
    ).encode()
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32602
    assert body["id"] == 6


def test_non_string_tool_name_returns_invalid_params(upstream):
    req = json.dumps(
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": 42}}
    ).encode()
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32602
    assert body["id"] == 7


def test_non_object_arguments_returns_invalid_params(upstream):
    req = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": "nope"},
        }
    ).encode()
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32602
    assert body["id"] == 8


# ---------------------------------------------------------------------------
# Bounded request size
# ---------------------------------------------------------------------------


def test_oversized_request_rejected_before_parsing(upstream):
    huge_args = "x" * 2_000_000
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"message": huge_args}},
        }
    ).encode()
    status, resp = _post(upstream, body)
    assert status == 413
    assert resp["error"]["code"] == -32600
    assert resp["id"] is None


def test_far_oversized_request_beyond_the_drain_ceiling_still_gets_a_clean_response(upstream):
    # Above DRAIN_CEILING_BYTES the server stops draining and closes instead,
    # so this is allowed to surface as a connection-level failure on the
    # client side rather than a parsed response -- covered separately so the
    # two size regimes (bounded-drain vs. give-up-and-close) are both tested.
    huge_args = "x" * 15_000_000
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"message": huge_args}},
        }
    ).encode()
    with socket.create_connection(("127.0.0.1", upstream), timeout=5) as sock:
        header = (
            f"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n"
        ).encode()
        sock.sendall(header)
        # Acceptable above the drain ceiling: the header alone already
        # triggers rejection, so a broken pipe while writing the body is not
        # a defect.
        with contextlib.suppress(BrokenPipeError, ConnectionResetError):
            sock.sendall(body)
        # The same applies to the read. Once the server has stopped draining
        # and closed, the reset can arrive before the buffered 413 is read,
        # and on Windows that surfaces as ConnectionAbortedError (WinError
        # 10053) rather than an empty read. The comment above always said a
        # connection-level failure was acceptable here; only sendall was
        # actually allowed one, which made this test fail about one run in
        # four on an unmodified tree.
        raw_response = b""
        with contextlib.suppress(
            ConnectionResetError, ConnectionAbortedError, TimeoutError, OSError
        ):
            raw_response = sock.recv(65536)

    # If a response did come back it must be the rejection, never an
    # acceptance. If the connection was torn down first, that is the
    # give-up-and-close path this test exists to cover.
    if raw_response:
        assert b"413" in raw_response.split(b"\r\n", 1)[0]

    # The contract that holds either way: a 15 MB body must not wedge the
    # server. Whichever path the request above took, the next one is served
    # normally. This is what makes the test meaningful when the connection is
    # reset before any bytes are read.
    status, resp = _post(upstream, VALID_REQUEST)
    assert status == 200
    assert resp["id"] == "req-1"


def test_request_at_the_limit_is_accepted(upstream):
    # Build a request whose total serialized size sits just under the whole
    # body cap. Split across two string fields, each under the separate
    # per-string length cap (#562), so this test stays targeted at the
    # DOS-001 whole-body boundary rather than also tripping the string cap.
    field_len = _MAX_ARG_STRING_LENGTH - 100
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "echo",
                "arguments": {"a": "x" * field_len, "b": "x" * field_len},
            },
        }
    ).encode()
    assert len(body) < MAX_REQUEST_BYTES
    status, resp = _post(upstream, body)
    assert status == 200
    assert resp["id"] == 10


# ---------------------------------------------------------------------------
# Security visibility: rejections are logged (#518)
# ---------------------------------------------------------------------------


def test_malformed_json_is_logged(upstream, caplog):
    with caplog.at_level("WARNING", logger="mock_upstream"):
        _post(upstream, b"{not valid json")
    assert any("event=parse_error" in r.message for r in caplog.records)


def test_invalid_request_is_logged(upstream, caplog):
    with caplog.at_level("WARNING", logger="mock_upstream"):
        _post(upstream, b"[1, 2, 3]")
    assert any("event=invalid_request" in r.message for r in caplog.records)


def test_invalid_params_is_logged(upstream, caplog):
    req = json.dumps(
        {"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": {}}
    ).encode()
    with caplog.at_level("WARNING", logger="mock_upstream"):
        _post(upstream, req)
    assert any("event=invalid_params" in r.message for r in caplog.records)


def test_oversized_request_is_logged(upstream, caplog):
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"message": "x" * 2_000_000}},
        }
    ).encode()
    with caplog.at_level("WARNING", logger="mock_upstream"):
        _post(upstream, body)
    assert any("event=oversized_request" in r.message for r in caplog.records)


def test_valid_request_is_not_logged(upstream, caplog):
    with caplog.at_level("WARNING", logger="mock_upstream"):
        _post(upstream, VALID_REQUEST)
    assert caplog.records == []


# ---------------------------------------------------------------------------
# Strict jsonrpc/id validation (#518)
# ---------------------------------------------------------------------------


def test_wrong_jsonrpc_version_returns_invalid_request(upstream):
    req = json.dumps(
        {"jsonrpc": "1.0", "id": 20, "method": "tools/call", "params": {"name": "echo"}}
    ).encode()
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32600
    assert body["id"] == 20


def test_missing_jsonrpc_returns_invalid_request(upstream):
    req = json.dumps({"id": 21, "method": "tools/call", "params": {"name": "echo"}}).encode()
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32600


def test_object_id_returns_invalid_request_with_null_id(upstream):
    req = json.dumps(
        {"jsonrpc": "2.0", "id": {"nope": True}, "method": "tools/call", "params": {}}
    ).encode()
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32600
    assert body["id"] is None


def test_bool_id_returns_invalid_request_with_null_id(upstream):
    req = json.dumps({"jsonrpc": "2.0", "id": True, "method": "tools/call", "params": {}}).encode()
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32600
    assert body["id"] is None


def test_null_id_is_valid(upstream):
    req = json.dumps(
        {"jsonrpc": "2.0", "id": None, "method": "tools/call", "params": {"name": "echo"}}
    ).encode()
    status, body = _post(upstream, req)
    assert status == 200
    assert body["id"] is None


def test_absent_id_is_valid(upstream):
    req = json.dumps(
        {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "echo"}}
    ).encode()
    status, body = _post(upstream, req)
    assert status == 200
    assert body["id"] is None


# ---------------------------------------------------------------------------
# Argument depth/key-count caps (#518)
# ---------------------------------------------------------------------------


def _nested(depth: int) -> dict:
    value: Any = "leaf"
    for _ in range(depth):
        value = {"child": value}
    return value


def test_arguments_within_depth_cap_are_accepted(upstream):
    req = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 30,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": _nested(3)},
        }
    ).encode()
    status, body = _post(upstream, req)
    assert status == 200


def test_arguments_past_depth_cap_returns_invalid_params(upstream):
    req = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": _nested(25)},
        }
    ).encode()
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32602
    assert body["id"] == 31


def test_arguments_past_key_count_cap_returns_invalid_params(upstream):
    huge_flat = {f"k{i}": i for i in range(300)}
    req = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 32,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": huge_flat},
        }
    ).encode()
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32602
    assert body["id"] == 32


def test_arguments_within_key_count_cap_are_accepted(upstream):
    small_flat = {f"k{i}": i for i in range(10)}
    req = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 33,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": small_flat},
        }
    ).encode()
    status, body = _post(upstream, req)
    assert status == 200


# ---------------------------------------------------------------------------
# Argument string-length cap (#562, docs/spec/proxy-security.md MAX_STRING_LENGTH)
# ---------------------------------------------------------------------------


def test_string_within_length_cap_is_accepted(upstream):
    req = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 34,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"text": "a" * 1000}},
        }
    ).encode()
    status, body = _post(upstream, req)
    assert status == 200


def test_string_past_length_cap_returns_invalid_params(upstream):
    # Past the string cap but comfortably under MAX_REQUEST_BYTES, so this
    # exercises the string-length check itself, not the whole-body size gate.
    assert _MAX_ARG_STRING_LENGTH + 1 < MAX_REQUEST_BYTES
    req = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 35,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"text": "a" * (_MAX_ARG_STRING_LENGTH + 1)}},
        }
    ).encode()
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32602
    assert body["id"] == 35


def test_oversized_object_key_returns_invalid_params(upstream):
    """A huge key is as expensive as a huge value and is not bounded by the
    key *count* cap, so it must be rejected on its own."""
    key = "a" * (_MAX_ARG_STRING_LENGTH + 1)
    req = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 38,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {key: 1}},
        }
    ).encode()
    # Reachable: over the string cap but still under the whole-body cap, so
    # this exercises the key check rather than DOS-001's size rejection.
    assert len(req) < MAX_REQUEST_BYTES
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32602
    assert body["id"] == 38


def test_well_formed_list_in_arguments_is_accepted(upstream):
    """The list walk must fall through cleanly when nothing inside it violates a
    cap, mirroring the same case in tests/unit/test_mcp_server_auth.py."""
    req = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 40,
            "method": "tools/call",
            "params": {
                "name": "echo",
                "arguments": {"items": [1, "ok", {"nested": ["fine"]}, None]},
            },
        }
    ).encode()
    status, _ = _post(upstream, req)
    assert status == 200


def test_oversized_string_nested_inside_arguments_is_caught(upstream):
    """The cap applies at any depth, not only to top-level string values."""
    req = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 36,
            "method": "tools/call",
            "params": {
                "name": "echo",
                "arguments": {"child": {"text": "a" * (_MAX_ARG_STRING_LENGTH + 1)}},
            },
        }
    ).encode()
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32602


def test_multibyte_string_length_measured_in_bytes_not_characters(upstream):
    """A 4-byte-per-char string well under the byte cap in character count
    but over it in UTF-8 bytes must still be rejected."""
    # U+1F600 (😀) is 4 bytes in UTF-8, 1 codepoint in Python's len(). Choose
    # a character count that clears the string cap in bytes while staying
    # well under MAX_REQUEST_BYTES once JSON-encoded.
    char_count = (_MAX_ARG_STRING_LENGTH // 4) + 1
    oversized_by_bytes = "\U0001F600" * char_count
    assert len(oversized_by_bytes.encode("utf-8")) > _MAX_ARG_STRING_LENGTH
    # ensure_ascii=False: the default True would escape each emoji to a
    # 12-byte \uXXXX\uXXXX surrogate pair, inflating the wire size far past
    # the string's actual UTF-8 length and tripping MAX_REQUEST_BYTES
    # instead of the check this test targets.
    req = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 37,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"text": oversized_by_bytes}},
        },
        ensure_ascii=False,
    ).encode()
    assert len(req) < MAX_REQUEST_BYTES
    status, body = _post(upstream, req)
    assert status == 400
    assert body["error"]["code"] == -32602


# ---------------------------------------------------------------------------
# Non-standard JSON values (NaN, Infinity, -Infinity) (#518)
# ---------------------------------------------------------------------------


def test_nan_in_arguments_is_rejected(upstream):
    body = (
        b'{"jsonrpc": "2.0", "id": 40, "method": "tools/call", '
        b'"params": {"name": "echo", "arguments": {"x": NaN}}}'
    )
    status, resp = _post(upstream, body)
    assert status == 400
    assert resp["error"]["code"] == -32700


def test_infinity_in_arguments_is_rejected(upstream):
    body = (
        b'{"jsonrpc": "2.0", "id": 41, "method": "tools/call", '
        b'"params": {"name": "echo", "arguments": {"x": Infinity}}}'
    )
    status, resp = _post(upstream, body)
    assert status == 400
    assert resp["error"]["code"] == -32700


def test_negative_infinity_in_arguments_is_rejected(upstream):
    body = (
        b'{"jsonrpc": "2.0", "id": 42, "method": "tools/call", '
        b'"params": {"name": "echo", "arguments": {"x": -Infinity}}}'
    )
    status, resp = _post(upstream, body)
    assert status == 400
    assert resp["error"]["code"] == -32700
