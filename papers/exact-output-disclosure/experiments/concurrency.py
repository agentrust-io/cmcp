"""Thread race, lost acknowledgment and storage rollback for the disclosure gate.

Hypothesis: for one intact replay database, 16 concurrent release attempts with
the same approval produce one delivery and 15 replay refusals, in each of 20
rounds; an attempt whose adapter records delivery and then times out leaves the
request consumed. The third observation is a limit, recorded on purpose: copying
back a database taken before consumption lets the approval be used again.

Uses the real DisclosureGate and ReplayStore with a synthetic payload and a
generated Ed25519 key. Each gate opens its own connection to the shared file.

Usage: concurrency.py run SCRATCH   (prints JSON, exit 0 when every assertion holds)
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import shutil
import sys


def run(scratch: Path) -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cmcp_runtime.disclosure import (DisclosureGate, ReleaseAuthority, ReleaseRecipient, ReleaseRequest,
                                         ReplayStore, approve_exact_output)
    scratch.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    path = scratch / "attempts.db"
    ReplayStore(path)
    backup = scratch / "empty.db"
    shutil.copyfile(path, backup)
    deliveries = []

    def gate(store=path, sink=deliveries.append):
        return DisclosureGate(
            policy_version="p1", source_scopes=frozenset({"s"}), sensitivity_order={"public": 0, "secret": 1},
            recipients={"r": ReleaseRecipient("public", "external", sink)},
            authorities={"owner": ReleaseAuthority(key.public_key(), frozenset({"s"}), frozenset({"r"}),
                                                   frozenset({"review"}))},
            replay_store=ReplayStore(store), now=lambda: 100)

    def request():
        r = ReleaseRequest(b"synthetic output", "w", "s", ("secret",), "r", "review", "p1")
        return r, approve_exact_output(r, principal="owner", key=key, not_before=90, expires_at=110)

    result = {"experiment": "exact-output-concurrency"}
    try:
        rounds = []
        for _ in range(20):
            r, a = request()
            with ThreadPoolExecutor(max_workers=8) as pool:
                obs = list(pool.map(lambda _: gate().release(r, a), range(16)))
            counts = {"acknowledged": sum(o.delivery == "acknowledged" for o in obs),
                      "replays": sum(o.reason == "replay" for o in obs)}
            rounds.append(counts)
            assert counts == {"acknowledged": 1, "replays": 15}, counts
        result.update(race_rounds=rounds, attempts=320, race_deliveries=sum(x["acknowledged"] for x in rounds))

        r, a = request()

        def lost_ack(payload):
            deliveries.append(payload)
            raise TimeoutError("synthetic lost acknowledgment")
        first = gate(sink=lost_ack).release(r, a)
        retry = gate().release(r, a)
        result["lost_acknowledgment"] = {"first": first.delivery, "retry": retry.reason}
        assert first.delivery == "unknown" and retry.reason == "replay"

        rollback = scratch / "rolled-back.db"
        shutil.copyfile(backup, rollback)
        restored = gate(store=rollback).release(r, a)
        result["database_rollback_replay"] = restored.delivery
        assert restored.delivery == "acknowledged"  # the stated storage-trust limit
        result["criterion_met"] = True
    except AssertionError as exc:
        result.update(criterion_met=False, assertion=str(exc))
    return result


if __name__ == "__main__":
    res = run(Path(sys.argv[2]))
    print(json.dumps(res, indent=2))
    raise SystemExit(0 if res["criterion_met"] else 1)
