# Phase 2 Proxy Security: Parser Fuzzing

---
Status: Draft v0.1
Last updated: 2026-06-04
Stability: Unstable , expect breaking changes before v1.0
---

This document defines the fuzzing definition of done (DoD) for the Phase 2 proxy parser. No Phase 2 release ships without satisfying every item below.

## Fuzz Targets

Four fuzz targets are required:

1. **JSON-RPC parser.** Input: arbitrary bytes. Output: valid or invalid parse result. Must not crash or hang under any input.

2. **MCP message schema validator.** Input: valid JSON-RPC with arbitrary MCP message content. Output: valid or invalid schema result. Must not crash.

3. **Tool call argument deserializer.** Input: arbitrary JSON as tool arguments. Output: deserialized result or parse error. Must not crash and must not produce unbounded memory allocation.

4. **Tool response processor.** Input: arbitrary JSON as tool response. Output: processed response or error. Must not crash.

## Fuzzing Definition of Done

All items must be satisfied before Phase 2 ships. Items are non-negotiable; a partial pass does not qualify.

- [ ] 1 billion fuzz iterations on each target with no crashes
- [ ] 0 timeout-inducing inputs (max 100ms per fuzz case)
- [ ] Resource limits enforced in code (see constants below)
- [ ] All inputs resulting in a parse error return a structured error response (no null returns, no uncaught exceptions)
- [ ] Regression corpus of 50+ MCP edge cases committed to `test/corpus/`

## Resource Limits

These constants are hard-coded in the proxy implementation. They are not configurable at runtime or via operator-supplied configuration. Making them configurable would allow an operator to raise limits and defeat the protection.

```python
MAX_REQUEST_BYTES = 10 * 1024 * 1024  # 10MB
MAX_JSON_NESTING_DEPTH = 64
MAX_PARSE_TIME_MS = 100
MAX_STRING_LENGTH = 1 * 1024 * 1024   # 1MB per string field
```

## Malformed Input Handling

Every parse path has an explicit error handler. No input reaches undefined behavior. The error handler contract:

1. Log the input hash (SHA-256 of the raw bytes), not the input content. This prevents log-injection and limits PII exposure.
2. Return a structured error response to the caller.
3. Do not pass partial parse results downstream. A partial result is treated as a failed parse.

This contract applies to all four fuzz targets. Any code path that returns a null, panics, or passes a partial result downstream is a bug, not an acceptable error mode.

