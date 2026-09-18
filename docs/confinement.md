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
kernel version and Docker version as `confinement-evidence`.

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
Abrupt loss of the host bridge is not a full supervisor/recovery protocol: the
container retains its isolation and limits, but needs external reaping if the
bridge cannot execute cleanup. Live operator-policy replacement is unsupported;
stop the old session and construct a new one. Broader audit/export adversarial
coverage, host lifecycle supervision and deployment-specific custody evidence
remain tracked in #659 rather than implied by a passing reference run.

Docker behavior references:
[container execution](https://docs.docker.com/engine/containers/run/) and
[none network driver](https://docs.docker.com/engine/network/drivers/none/).
