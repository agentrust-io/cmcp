# Execution Action Binding v1

Status: proposed normative contract for [#588](https://github.com/agentrust-io/cmcp/issues/588).

This document defines the canonical action binding consumed by session-independent execution correlation. It does not activate the execution registry by itself; activation remains subject to the admission, terminal-state, audit-transaction, crash/recovery, and replay requirements in [execution-correlation.md](execution-correlation.md).

## Normative contract

An execution action binding MUST be computed from the RFC 8785 / JSON Canonicalization Scheme (JCS) UTF-8 encoding of exactly this object:

```json
{
  "domain": "cmcp.execution-action-binding",
  "version": 1,
  "agent_id": "<authenticated agent identity>",
  "action_type": "<canonical action type>",
  "action_scope": "<canonical action scope>",
  "action_timestamp": "<canonical action timestamp>"
}
```

The six members above are the complete v1 preimage. A producer MUST NOT add, remove, rename, or reinterpret a member while continuing to call the result a v1 execution action binding.

### 1. Canonicalization

The preimage MUST be serialized with RFC 8785/JCS and encoded as UTF-8. Implementations MUST NOT substitute host-language key ordering, ASCII escaping, implementation-defined float rendering, or another serializer that merely agrees on ordinary ASCII examples.

The canonicalizer used by the current cMCP embodied-action verifier is the existing RFC 8785 implementation exposed through `cmcp_verify.embodied_action.canonical_json_bytes()`. A shared canonicalization primitive does not make two bindings equivalent unless they also share the same domain, version, and preimage definition.

### 2. Digest representation

The binding MUST be rendered as:

```text
<algorithm>:<lowercase hexadecimal digest>
```

`sha256` and `sha384` are accepted algorithms. Any other algorithm identifier MUST be refused. A `sha256` digest therefore carries 64 lowercase hexadecimal characters and a `sha384` digest carries 96.

The complete rendered digest string is the value stored and compared by execution correlation. Changing the algorithm under an already-reserved `(authenticated agent identity, execution_id)` changes the binding and MUST NOT be treated as the same reservation.

### 3. Action preimage field set

The action-specific members are exactly:

- `agent_id`
- `action_type`
- `action_scope`
- `action_timestamp`

These are the field set already used by the embodied-action `action_ref` construction. The execution binding adds the domain and version members below so the bytes answer one unambiguous question and remain distinguishable across contract revisions.

`agent_id` MUST identify the authenticated agent identity under which `execution_id` is reserved. An adapter that derives `action_type`, `action_scope`, or `action_timestamp` from a richer request MUST preserve every distinction that the governing action semantics require for logical-operation identity, or refuse the request before producing a binding.

### 4. Domain separation

`domain` MUST be the exact string:

```text
cmcp.execution-action-binding
```

The domain member is inside the JCS preimage and therefore inside the digest. It MUST NOT be carried only beside the digest or inferred from the call site.

This prevents the same canonical JSON object, hashed for a different cMCP purpose, from acquiring execution-action semantics merely because its digest bytes happen to match.

### 5. Version discrimination

`version` MUST be the JSON integer `1` for this contract. The version member is inside the JCS preimage and therefore inside the digest.

A later version that changes the field set or interpretation MUST use a different version value. An implementation MUST NOT reinterpret a v1 digest using a later contract or accept a later-version binding as v1 merely because the remaining action fields happen to match.

## Correlation, replay, and comparison semantics

The authoritative reservation key is `(authenticated agent identity, execution_id)`. The registry consumes the action binding as an opaque rendered digest and compares it exactly.

For an existing reservation:

- the same binding may enter the correlation/retry classification path, subject to the terminal-state rules;
- a different binding is a conflicting or mutated logical operation and MUST be refused before upstream invocation;
- a matching binding is not permission to replay an action after a terminal or `outcome_unknown` state;
- the binding does not establish that an external effect occurred.

The three identities remain distinct:

```text
attempt identity != logical operation identity != external outcome identity
```

`call_id` identifies an attempt, the execution action binding contributes to logical-operation identity, and independently verifiable external evidence is required for claims about external outcome.

## Semantic adequacy of the binding

Byte-level interoperability and semantic adequacy are separate requirements.

Two implementations can correctly produce the same JCS bytes while a downstream authorization, admission, gating, or invocation-input consumer still treats the originating requests differently. Such a differential is an adjudication witness, not automatic proof that JCS or the binding is wrong.

The governing semantics of that consumer determine the correction:

- if the governing schema or policy requires the values to remain distinct, the adapter constructing the v1 preimage MUST preserve or exclude the distinction so one binding equivalence class cannot span materially different operations;
- if the governing semantics define the values as equivalent, the downstream consumer MUST NOT over-discriminate based only on host-language representation.

The reproduced `{"x":1}` versus `{"x":1.0}` cases are retained as this kind of witness. RFC 8785 canonicalizes them to the same JSON number representation, while current cMCP paths have demonstrated different downstream treatment. The expected outcome therefore comes from the governing schema/policy semantics, not from Python's representation and not from canonicalization alone.

## Conformance evidence

The companion [execution-action-binding-v1-vectors.json](execution-action-binding-v1-vectors.json) fixes exact JCS bytes and digests for ASCII, non-ASCII, domain, version, and digest-algorithm controls.

A conforming implementation MUST reproduce the canonical bytes and expected digest for each vector using an RFC 8785 implementation independent of the vector file. Tests that compute expected output with the same helper under test do not establish interoperability.

The semantic-adjudication witness in the vector file is deliberately not assigned an automatic `same_operation` or `different_operation` verdict. Its purpose is to require the implementation or integrating profile to name the governing semantics before admission.

## Non-claims

This contract does not by itself provide exactly-once execution, external-effect proof, crash-safe audit consistency, or replay permission. It also does not authorize activation of the non-operational execution registry foundation from #606. Those remain the integration and durability requirements owned by #565.
