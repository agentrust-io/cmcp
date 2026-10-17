# Upstream HTTP input bounds

The HTTP proxy enforces `max_response_size_bytes` on each complete response body
before JSON/SSE parsing, as well as on extracted tool text before scanning. It
counts actual bytes even when Content-Length is absent or understated; an
excessive declared length is refused before reading. Tool calls and each
tools/list page use the same bound. Streaming response contexts close on
success, refusal, cancellation or error.

The proxy requests `Accept-Encoding: identity` and refuses other Content-Encoding
values before decoding. **Compressed upstream replies are not supported by this
path.** Decompression can allocate beyond the limit before yielding a chunk;
upstreams must honor identity encoding. Each HTTP request has a 30-second absolute
deadline, including continuously active SSE data, rather than only a per-read
timeout. This can refuse a previously accepted long-lived upstream stream.

An over-limit tool reply returns `response_size_exceeded` without parsing,
scanning or hashing partial content as a complete result. The audit outcome
remains unknown because upstream transport has already started. No automatic
retry is implied. A failed discovery page remains an unavailable/unchecked
acquisition, subject to the configured provenance requirement.

This is a per-response input bound, not a bound on total process memory,
discovery-page accumulation or parser nesting depth. SSE is still buffered within
the byte/deadline bounds before its final response is parsed. Parser depth limits
remain separate work discussed in #571.
