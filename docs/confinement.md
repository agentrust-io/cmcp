# Reference agent confinement

Tracking: [#659](https://github.com/agentrust-io/cmcp/issues/659).
The executable reference is `examples/confinement/adapter.py`; its adversarial
fixture and independent observers are in `tests/confinement/`.

## Contract and scope

An agent that already holds plaintext must not be able to select an alternate
route around the gateway's release decision. This adapter creates a native-Linux
Docker container with no network, a read-only root filesystem, no host volumes,
no extra capabilities, a non-root user, no Docker log driver, no automatic
restart, and hard core-dump, process and memory limits. It inspects the effective
container configuration before starting the agent and again before admitting
data. Unknown image tags, inherited image volumes and weakened profiles fail
admission. Only an immutable local image ID is accepted.

The host bridge is the agent's only application channel. Newline-delimited JSON
requests contain exactly `operation` and `arguments`. Operator-owned aliases map
operations to catalog tools. Agent-provided tool names, call IDs, classification,
sink policies and other top-level metadata are not accepted. Each request passes
through real `CMCPProxy.call_tool`; the bridge never forwards raw stdout. Stderr
is drained without logging its contents. Frames, aggregate output, call count
and session duration are bounded. Parser failures, excess output, gateway
exceptions and timeouts terminate the container. The attach client exiting does
not exempt the container from cleanup.

This is an experimental adapter and test harness, not a new default for `cmcp
start`. The trusted integration in `tests/confinement/gateway.py` shows the
required composition: classify the initial payload **before** giving it to the
agent, create a fresh session, install immutable sink ceilings, and expose only
the approved dispatch callback. The generic adapter cannot establish these
properties for an arbitrary callback supplied by an operator. The fixture uses
`confidential` session state, a `confidential` permitted sink and a `public`
denied sink. Its permissive Cedar policy deliberately leaves the sink ceiling
as the decision being tested. The upstream is a real measured stdio process.

## Plaintext routes and mediators

| Source / destination | Mediator and failure behavior |
| --- | --- |
| Initial input and returned tool results | Trusted bridge stdin; preflight and container inspection precede initial input. Operator classifies input; cMCP evaluates tool responses. |
| Approved tool arguments | Bounded stdio frames, fixed aliases, cMCP policy and sink ceilings before transport. A denied sink gets no invocation. |
| Alternate tools or endpoints | Unknown aliases fail parsing. Direct IPv4, IPv6 and UDP/DNS have no interface beyond private loopback. There is no proxy socket or gateway credential inside the agent. |
| Spawned agent children | Inherit namespaces, filesystem restrictions and hard resource limits; no capabilities to create a less restricted child. |
| Files and subprocess inheritance | No host mounts, shared PID namespace or inherited gateway descriptors. Root filesystem is read-only. Docker-managed `/dev`, shared-memory tmpfs and hosts/resolver files remain container-private; they are not claimed unwritable. |
| Stdout, stderr and container logs | Stdout is a private protocol stream; malformed frames stop the session. Stderr content is discarded. Docker logging is disabled before execution. Neither stream is a user-facing response channel. |
| Audit and telemetry | Only trusted catalog names and generated call IDs enter gateway metadata. The adapter emits fixed errors and numeric counters, no raw frames. Existing cMCP audit/export code remains inside the trusted boundary; arbitrary exporters and error paths are not proven payload-free by this harness. |
| Crash artifacts | Host core policy gate plus hard/soft `RLIMIT_CORE=0` on bridge and agent. The bridge's stdio tools inherit the host limit. Unsupported piped handlers refuse startup. |
| Shutdown and restart | No automatic container restart. Each run gets a fresh container and trusted session configuration; cleanup stops the container even if its attach process failed. Gateway unavailability has no direct-network fallback. |

## Crash-dump policy

The host's `/proc/sys/kernel/core_pattern` is checked before plaintext admission.
Piped handlers are refused: Linux ignores `RLIMIT_CORE` when piping a core dump
to a handler, and that handler executes in the initial namespaces. A container
setting alone therefore cannot make this route safe. See
[Linux core(5)](https://man7.org/linux/man-pages/man5/core.5.html) and the
[issue feedback](https://github.com/agentrust-io/cmcp/issues/659#issuecomment-5726031481).

The adapter never changes host policy. The CI job temporarily selects a file
core pattern on its disposable runner and restores it afterward. A trusted
operator must prevent host policy changes during a session. Checking a path
cannot prevent a privileged host from changing the kernel setting later.

## Reproduce and assess the evidence

On a disposable native-Linux host with a local Docker Engine, IPv6 loopback and
a non-piped core pattern:

```sh
python -m pip install --require-hashes -r requirements/dev.txt
python -m pip install --no-deps -e .
docker build --iidfile /tmp/cmcp-confinement-image examples/confinement
export CMCP_CONFINEMENT_IMAGE="$(cat /tmp/cmcp-confinement-image)"
python -m pytest tests/confinement -v --tb=short
```

Without that environment variable, the OS-independent parser/profile tests and
real gateway delivery tests still run; Docker tests are explicitly skipped.
`.github/workflows/confinement.yml` runs the Docker suite and retains test results,
numeric sink observations, kernel version and Docker version as
`confinement-evidence`. No canary payloads enter that observation artifact.

Observers live outside the agent. TCP listeners count direct IPv4, IPv6 and
child-process delivery; a local UDP listener receives a DNS question without
forwarding it. The trusted upstream records actual tool calls. After exit,
Docker copies the target file from the container and reads container logs.
Assertions use those sink observations rather than the agent's exception text.

Synthetic mutations remove network isolation, filesystem read-only protection,
Docker log suppression or the public sink ceiling. For Docker mutations, the
test first requires admission inspection to reject the changed configuration,
then bypasses inspection **in the test only** to exercise the OS restriction.
Each mutant must deliver the canary at its corresponding sink and fail the same
confinement oracle used for the protected run. The permitted tool must still
work. Restart, malformed stdout, attempted policy replacement, unavailable
gateway, oversized stdout, stderr flood, crash and timeout cases test bounded
failure and termination. No real secrets or external recipients are used.

## Bridge failure and live policy restrictions

Before plaintext admission, the running container gets a separate host watchdog.
The bridge sends a payload-free heartbeat every 250 ms over a private inherited
pipe. EOF or a two-second missed-heartbeat lease makes the watchdog stop the
container. The watchdog runs in a separate process session, so a killed or paused
bridge cannot prevent that cleanup. A watchdog failure also terminates the
bridge exchange. The bound is the lease plus Docker stop latency; a responsive
trusted host/daemon is required. The watcher retries a failed stop up to three
times with a five-second timeout per attempt.

The watcher is armed after attaching to the container and before supplying its
initial frame. A bridge crash before that point can leave an empty container;
the adapter does not provide a host-wide orphan collector. Simultaneous loss of
the bridge and watchdog, a dead Docker daemon or a host crash requires external
supervision. Container isolation remains in place independently of either
process. The watcher contains the container identifier, not the agent payload.

`examples/confinement/lifecycle.py` adds a trusted operator `PolicyGate` around
the cMCP dispatch callback. It can revoke or restore originally approved tools
without replacing the gateway, resetting sensitivity or expanding its original
sink ceilings. A monotonically increasing revision and an async lock serialize
the cutover with actual dispatch. An update is acknowledged only after earlier
admitted calls finish. Calls queued behind that update see the new restriction.
An invalid or rolled-back update closes future admission until a valid newer
revision arrives. This operator API is not exposed to agent frames.

Cutover cannot undo an earlier tool side effect. The reference supports this
restrictive overlay, not arbitrary hot replacement of catalogs, classifiers,
Cedar bundles or sink ceilings. A new deployment configuration still requires
a new session. Revision state is process-local and is not rollback-resistant
storage.

Hosted lifecycle tests kill and pause a real bridge after an independent tool
sink observes its canary, kill the watchdog separately, and inspect Docker from
another process. A synthetic mutation disables the watcher and requires the
adversarial container to survive bridge death, demonstrating why the watcher is
needed. Live policy tests include an in-flight call, a queued call, revocation,
restoration and invalid/stale revisions; the Docker fixture also exercises
revocation/restoration without a session reset.

## Audit and telemetry probes

The confinement job installs the hash-pinned optional SDK from
`requirements/confinement.txt`. Its tests send synthetic payloads through the
real gateway and stdio upstream, then inspect persisted SQLite audit entries,
in-memory chain entries, real SDK-exported spans and Python logs. Success,
payload-bearing upstream errors, malformed stdout and stderr echoing all have
positive tool-delivery controls. Payload hashes and fixed decision metadata
remain present; literal canary payloads must be absent from these observed sinks.

Two regression tests cover audit-observer and OTel export exceptions containing
private data. Failure diagnostics now omit observer representations and
tracebacks. The tests reproduced both leaks before that change. An arbitrary
plugin can still write its own logs, and metadata/hashes may themselves be
sensitive; these probes do not certify all collectors, exporters or encodings.

## Limits and remaining issue work

The trusted boundary includes the host kernel, Docker daemon and local socket,
bridge, cMCP process, interpreter, dependencies, approved tool and operator
configuration. A forwarded socket or VM-backed daemon is unsupported: the
adapter's explicit local socket and Docker Desktop rejection do not prove that
an administrator has not substituted the endpoint. Image IDs provide content
identity, not publisher authorization or TEE measurement.

Docker isolates the agent from these components; it does not protect plaintext
from the host, kernel vulnerabilities, swap, hibernation, a privileged debugger,
host tracing, a compromised approved tool, or a malicious gateway. No hardware
attestation or GPU inference is exercised. An allowed tool receives the data;
downstream custody requires its own independently enforced policy. Responses
cannot undo tool side effects.

Canary observations cover these probes, not all encodings, kernel interfaces or
covert channels. Timing, traffic shape, resource contention, shared hardware and
other side channels remain untested. Crash tests verify termination and configured
hard limits; they do not scan host crash services or prove memory erasure.
The watchdog covers loss of the bridge while the watcher and daemon survive;
it is not a host-wide supervisor/recovery protocol. Live restrictions preserve
the existing gateway state, but arbitrary policy replacement remains unsupported.
Broader exporter/plugin adversarial coverage, host-wide recovery and
deployment-specific custody evidence remain outside this reference claim.

Docker behavior references:
[container execution](https://docs.docker.com/engine/containers/run/) and
[none network driver](https://docs.docker.com/engine/network/drivers/none/).
