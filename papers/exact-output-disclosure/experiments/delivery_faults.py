"""Process kills, storage errors and a recording receiver for the disclosure gate.

Hypothesis: with one intact shared SQLite ledger, the pinned disclosure gate lets
at most one delivery attempt reach a separate recording receiver per request
identifier, even when sender processes are killed on either side of the ledger
commit, the receiver drops its acknowledgment, or storage fails.

Every sender is a separate OS process. The receiver is a separate process that
records each received body (fsync) before it decides whether to acknowledge,
so receipt and acknowledgment are observed separately. Kill points inside the
ledger transaction are injected by wrapping the sqlite3 connection that the
unmodified ReplayStore opens; the gate code itself is not edited.

Usage: exp10_delivery_faults.py run SCRATCH   (prints JSON, exit 0 when the
criterion holds). Subcommands receiver/sender/locker are internal.
"""
from __future__ import annotations

import http.client
import http.server
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

HERE = Path(__file__).resolve()
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)  # no console window on Windows


# ---------------------------------------------------------------- receiver
def receiver(log: str, port_file: str) -> None:
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            return

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            mode = self.headers.get("X-Mode", "ack")
            with open(log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"request_id": self.headers.get("X-Request-Id"),
                                     "bytes": len(body), "mode": mode, "t": time.time()}) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            if mode == "drop":
                self.close_connection = True
                return  # recorded, never acknowledged
            if mode == "hang":
                time.sleep(60)
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    Path(port_file).write_text(str(server.server_address[1]), encoding="utf-8")
    server.serve_forever()


# ------------------------------------------------------------------ sender
class _Conn:
    """Delegate to a real sqlite3 connection; optionally die around COMMIT."""

    def __init__(self, real, kill_at):
        self._real, self._kill_at = real, kill_at

    def execute(self, *a):
        return self._real.execute(*a)

    def commit(self):
        if self._kill_at == "before_commit":
            os._exit(71)
        self._real.commit()
        if self._kill_at == "after_commit":
            os._exit(72)
        if self._kill_at == "error_after_commit":
            raise sqlite3.OperationalError("synthetic error reported after commit")

    def rollback(self):
        self._real.rollback()

    def close(self):
        self._real.close()


def sender(spec_file: str, db: str, port: str, mode: str, kill_at: str, go_file: str) -> None:
    """Open the ledger first, signal readiness, wait for go, then release once."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    import cmcp_runtime.disclosure as disclosure
    store = disclosure.ReplayStore(db)  # unwrapped: the table exists before any lock or kill
    if go_file != "-":
        Path(f"{go_file}.ready-{os.getpid()}").write_text("ready", encoding="utf-8")
        while not os.path.exists(go_file):
            time.sleep(0.005)
    if kill_at in ("before_commit", "after_commit", "error_after_commit"):
        real_connect = sqlite3.connect

        class _Shim:
            Error, IntegrityError = sqlite3.Error, sqlite3.IntegrityError

            @staticmethod
            def connect(path, *a, **k):
                return _Conn(real_connect(path, *a, **k), kill_at)
        disclosure.sqlite3 = _Shim  # wraps only the connection ReplayStore.consume opens
    if kill_at == "corrupt_store":
        with open(db, "r+b") as fh:
            fh.write(b"not a sqlite database" * 8)
    spec = json.loads(Path(spec_file).read_text(encoding="utf-8"))
    request = disclosure.ReleaseRequest(bytes.fromhex(spec["payload"]), "w", "s", ("secret",),
                                        "r", "review", "p1", request_id=spec["request_id"])
    approval = disclosure.DisclosureApproval(spec["principal"], spec["not_before"],
                                             spec["expires_at"], bytes.fromhex(spec["signature"]))

    def deliver(payload: bytes) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", int(port), timeout=90)
        conn.request("POST", "/deliver", body=payload,
                     headers={"X-Request-Id": spec["request_id"], "X-Mode": mode})
        resp = conn.getresponse()
        if resp.status != 200:
            raise RuntimeError("receiver refused")
        resp.read()

    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(spec["public_key"]))
    gate = disclosure.DisclosureGate(
        policy_version="p1", source_scopes=frozenset({"s"}),
        sensitivity_order={"public": 0, "secret": 1},
        recipients={"r": disclosure.ReleaseRecipient("public", "external", deliver)},
        authorities={"owner": disclosure.ReleaseAuthority(key, frozenset({"s"}), frozenset({"r"}),
                                                         frozenset({"review"}))},
        replay_store=store)
    obs = gate.release(request, approval)
    print(json.dumps({"disposition": obs.disposition, "reason": obs.reason, "delivery": obs.delivery}))


def locker(db: str, seconds: str, ready: str) -> None:
    conn = sqlite3.connect(db)
    conn.execute("BEGIN EXCLUSIVE")
    Path(ready).write_text("locked", encoding="utf-8")
    time.sleep(float(seconds))
    conn.rollback()
    conn.close()


# ------------------------------------------------------------------ parent
class Run:
    def __init__(self, scratch: Path):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.scratch = scratch
        self.key = Ed25519PrivateKey.generate()
        self.log = scratch / "receiver.jsonl"
        self.log.write_text("", encoding="utf-8")
        port_file = scratch / "port"
        self.receiver = subprocess.Popen([sys.executable, "-B", str(HERE), "receiver", str(self.log), str(port_file)], creationflags=NO_WINDOW)
        deadline = time.time() + 20
        while not port_file.exists() or not port_file.read_text():
            if time.time() > deadline:
                raise RuntimeError("receiver did not start")
            time.sleep(0.05)
        self.port = port_file.read_text()
        self.n = 0
        self.children = [self.receiver]

    def close(self):
        for p in self.children:
            if p.poll() is None:
                p.kill()
                p.wait(10)

    def slot(self):
        self.n += 1
        return self.scratch / f"spec-{self.n}.json", self.scratch / f"ledger-{self.n}.db"

    def approval(self, lifetime=600, payload=b"synthetic approved output", slot=None):
        from cmcp_runtime.disclosure import ReleaseRequest, approve_exact_output
        path, db = slot or self.slot()
        request = ReleaseRequest(payload, "w", "s", ("secret",), "r", "review", "p1")
        now = int(time.time())
        a = approve_exact_output(request, principal="owner", key=self.key, not_before=now - 5,
                                 expires_at=now + lifetime)
        spec = {"payload": payload.hex(), "request_id": request.request_id, "principal": a.principal,
                "not_before": a.not_before, "expires_at": a.expires_at, "signature": a.signature.hex(),
                "public_key": self.key.public_key().public_bytes_raw().hex()}
        path.write_text(json.dumps(spec), encoding="utf-8")
        return path, db, request.request_id

    def competing(self, n, lock_seconds=None, lifetime=600, tag="c"):
        """Start n senders on one ledger; optionally lock it; approve; then release all."""
        slot = self.slot()
        go = self.scratch / f"go-{tag}-{self.n}"
        procs = [self.sender(slot[0], slot[1], go=go, wait=False) for _ in range(n)]
        deadline = time.time() + 60
        while len(list(self.scratch.glob(go.name + ".ready-*"))) < n:
            if time.time() > deadline:
                raise RuntimeError("senders not ready")
            time.sleep(0.02)
        lock = None
        if lock_seconds:
            ready = self.scratch / f"lock-{tag}-{self.n}"
            lock = subprocess.Popen([sys.executable, "-B", str(HERE), "locker", str(slot[1]),
                                     str(lock_seconds), str(ready)], creationflags=NO_WINDOW)
            self.children.append(lock)
            while not ready.exists():
                time.sleep(0.01)
        _, _, rid = self.approval(lifetime=lifetime, slot=slot)
        go.write_text("go", encoding="utf-8")
        outcomes = [reason(self.finish(p)) for p in procs]
        if lock is not None:
            lock.wait(30)
        return slot, rid, outcomes

    def sender(self, spec, db, mode="ack", kill_at="none", go="-", wait=True):
        cmd = [sys.executable, "-B", str(HERE), "sender", str(spec), str(db), self.port, mode, kill_at, str(go)]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=NO_WINDOW)
        self.children.append(p)
        if not wait:
            return p
        return self.finish(p)

    @staticmethod
    def finish(p, timeout=120):
        out, err = p.communicate(timeout=timeout)
        obs = json.loads(out) if out.strip() else None
        return {"exit": p.returncode, "observation": obs}

    def receipts(self, request_id):
        return sum(1 for line in self.log.read_text(encoding="utf-8").splitlines()
                   if json.loads(line)["request_id"] == request_id)

    @staticmethod
    def rows(db):
        try:
            conn = sqlite3.connect(db)
            try:
                return conn.execute("SELECT COUNT(*) FROM disclosure_attempts").fetchone()[0]
            finally:
                conn.close()
        except sqlite3.Error:
            return "unreadable"


def reason(result):
    obs = result["observation"]
    return "process-killed" if obs is None else obs["reason"]


def run(scratch: Path) -> dict:
    scratch.mkdir(parents=True, exist_ok=True)
    r = Run(scratch)
    cases, checks = [], []
    try:
        # A. kill points on both sides of the ledger commit, then a clean retry.
        expected = {
            "before_commit": {"rows_after_kill": 0, "receipts_after_kill": 0, "retry": "adapter_acknowledged", "final": 1},
            "after_commit": {"rows_after_kill": 1, "receipts_after_kill": 0, "retry": "replay", "final": 0},
            "during_delivery": {"rows_after_kill": 1, "receipts_after_kill": 1, "retry": "replay", "final": 1},
            "ack_dropped": {"rows_after_kill": 1, "receipts_after_kill": 1, "retry": "replay", "final": 1},
        }
        for point, want in expected.items():
            spec, db, rid = r.approval()
            if point == "during_delivery":
                p = r.sender(spec, db, mode="hang", wait=False)
                deadline = time.time() + 30
                while r.receipts(rid) == 0 and time.time() < deadline:
                    time.sleep(0.02)
                p.kill()
                first = r.finish(p)
            elif point == "ack_dropped":
                first = r.sender(spec, db, mode="drop")
            else:
                first = r.sender(spec, db, kill_at=point)
            state = {"rows_after_kill": r.rows(db), "receipts_after_kill": r.receipts(rid)}
            retry = r.sender(spec, db)
            got = {**state, "retry": reason(retry), "final": r.receipts(rid)}
            case = {"case": "kill-" + point, "first_attempt": reason(first), "first_exit": first["exit"],
                    **got, "expected": want, "ok": got == want}
            cases.append(case)
            checks.append(case["ok"] and got["final"] <= 1)

        # B. storage errors during competing attempts.
        # B1: ledger locked for 8 s, longer than sqlite3's default 5 s wait; 8 processes.
        slot, rid, locked = r.competing(8, lock_seconds=8, tag="b1")
        after = [reason(r.sender(*slot))]
        slot2 = slot
        go = r.scratch / "go-b1-after"
        procs = [r.sender(slot2[0], slot2[1], go=go, wait=False) for _ in range(7)]
        while len(list(r.scratch.glob(go.name + ".ready-*"))) < 7:
            time.sleep(0.02)
        go.write_text("go")
        after += [reason(r.finish(p)) for p in procs]
        case = {"case": "storage-locked-8-competing", "during_lock": sorted(locked),
                "after_lock": sorted(after), "receipts": r.receipts(rid)}
        case["ok"] = (locked == ["replay_storage"] * 8 and after.count("adapter_acknowledged") == 1
                      and after.count("replay") == 7 and case["receipts"] == 1)
        cases.append(case); checks.append(case["ok"])

        # B2: lock 3.5 s (inside the wait), approval lifetime about 2 s: expiry during the wait.
        slot, rid, outcomes = r.competing(8, lock_seconds=3.5, lifetime=2, tag="b2")
        case = {"case": "approval-expires-while-waiting-8-competing", "outcomes": sorted(outcomes),
                "rows": r.rows(slot[1]), "receipts": r.receipts(rid)}
        case["ok"] = (outcomes.count("approval_expired_or_early") == 1 and outcomes.count("replay") == 7
                      and case["rows"] == 1 and case["receipts"] == 0)
        cases.append(case); checks.append(case["ok"])

        # B3: corrupted ledger file after the store is opened.
        spec, db, rid = r.approval()
        first = r.sender(spec, db, kill_at="corrupt_store")
        case = {"case": "corrupt-ledger", "outcome": reason(first), "receipts": r.receipts(rid)}
        case["ok"] = case["outcome"] == "replay_storage" and case["receipts"] == 0
        cases.append(case); checks.append(case["ok"])

        # B4: commit succeeds but an error is reported; retry.
        spec, db, rid = r.approval()
        first = r.sender(spec, db, kill_at="error_after_commit")
        retry = r.sender(spec, db)
        case = {"case": "error-reported-after-commit", "outcome": reason(first), "rows": r.rows(db),
                "retry": reason(retry), "receipts": r.receipts(rid)}
        case["ok"] = (case["outcome"] == "replay_storage" and case["rows"] == 1
                      and case["retry"] == "replay" and case["receipts"] == 0)
        cases.append(case); checks.append(case["ok"])

        # C. multi-process race: 10 rounds of 8 processes on one approval.
        rounds = []
        for i in range(10):
            slot, rid, outs = r.competing(8, tag=f"race{i}")
            rounds.append({"acknowledged": outs.count("adapter_acknowledged"), "replay": outs.count("replay"),
                           "receipts": r.receipts(rid)})
        race_ok = all(x == {"acknowledged": 1, "replay": 7, "receipts": 1} for x in rounds)
        cases.append({"case": "process-race-10x8", "rounds": rounds, "ok": race_ok})
        checks.append(race_ok)
    finally:
        r.close()
    return {"experiment": "exact-output-delivery-faults", "cases": cases,
            "cases_passed": sum(checks), "cases_total": len(checks), "criterion_met": all(checks)}


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "receiver":
        receiver(*sys.argv[2:])
    elif cmd == "sender":
        sender(*sys.argv[2:])
    elif cmd == "locker":
        locker(*sys.argv[2:])
    else:
        result = run(Path(sys.argv[2]))
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result["criterion_met"] else 1)
