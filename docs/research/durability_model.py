#!/usr/bin/env python3
"""Crash-state enumeration for the storage protocols in ARCHITECTURE.md 7.9 and 7.10.

Research artifact, not production code. It tests ordering logic under a stated,
pessimistic filesystem model. It is not evidence of durability on any real
filesystem or device. See README.md for the assumptions. The second half models
shutdown during finalisation, and the third models publication probes that can
return an inconclusive result. Both are equally abstract.

Model: file data persists only when that inode has been synced, otherwise a crash
may keep or lose unsynced writes. Directory operations are journalled in order, so
a crash keeps some prefix of them, and any prefix at or after the last directory
sync. A directory operation may persist before the data of the file it names.
"""
import itertools
import sys

EMPTY = ("empty",)


def side(d, phase="receiving", final=None):
    return ("sidecar", d, phase, final)


def run_prefix(ops, n):
    """Yield every crash state possible after the first n ops."""
    done = ops[:n]
    last_dirsync = max((i for i, o in enumerate(done) if o[0] == "syncdir"), default=-1)
    dir_idx = [i for i, o in enumerate(done) if o[0] in ("link", "unlink", "rename")]
    forced = len([i for i in dir_idx if i < last_dirsync])
    writes = [i for i, o in enumerate(done) if o[0] == "write"]
    durable = set()
    for i, o in enumerate(done):
        if o[0] == "sync":
            durable |= {w for w in writes if w < i and done[w][1] == o[1]}
    optional = [w for w in writes if w not in durable]
    for keep in range(forced, len(dir_idx) + 1):
        kept_dir = set(dir_idx[:keep])
        for bits in itertools.product([False, True], repeat=len(optional)):
            kept = durable | {w for w, b in zip(optional, bits) if b}
            data, names = {}, {}
            for i, o in enumerate(done):
                if o[0] == "write" and i in kept:
                    data[o[1]] = o[2]
                elif i in kept_dir:
                    if o[0] == "link":
                        names[o[1]] = o[2]
                    elif o[0] == "unlink":
                        names.pop(o[1], None)
                    elif o[0] == "rename":
                        if o[1] in names:
                            names[o[2]] = names.pop(o[1])
            yield {k: data.get(v, EMPTY) for k, v in names.items()}, {k: v for k, v in names.items()}


def durable_of(ops, n, inode):
    """Highest length guaranteed durable for the partial inode after n ops."""
    best = 0
    last = None
    for o in ops[:n]:
        if o[0] == "write" and o[1] == inode:
            last = o[2]
        elif o[0] == "sync" and o[1] == inode and last is not None:
            best = last[1]
    return best


def checkpoint_old():
    return [("write", "p", ("data", 100)), ("sync", "p"),
            ("write", "t", side(100)), ("link", "m.tmp", "t"), ("rename", "m.tmp", "m")]


def checkpoint_reversed():
    return [("write", "p", ("data", 100)),
            ("write", "t", side(100)), ("sync", "t"), ("link", "m.tmp", "t"), ("rename", "m.tmp", "m"),
            ("syncdir",), ("sync", "p")]


def checkpoint_new():
    return [("write", "p", ("data", 100)), ("sync", "p"),
            ("write", "t", side(100)), ("sync", "t"), ("link", "m.tmp", "t"), ("rename", "m.tmp", "m"),
            ("syncdir",)]


BASE = [("write", "p", ("data", 50)), ("sync", "p"), ("link", "f.part", "p"),
        ("write", "s", side(50)), ("sync", "s"), ("link", "m", "s"), ("syncdir",)]


def check_checkpoint(body):
    ops = BASE + body
    bad = set()
    for n in range(len(BASE), len(ops) + 1):
        floor = durable_of(ops, n, "p")
        for files, names in run_prefix(ops, n):
            meta = files.get("m", EMPTY)
            if meta == EMPTY:
                bad.add("sidecar empty or lost after rename")
            elif meta[1] > floor:
                bad.add("durable_offset exceeds durable data")
    return bad


FULL = ("data", 100)
PREFIX = [("write", "p", FULL), ("sync", "p"), ("link", "f.part", "p"),
          ("write", "s", side(100)), ("sync", "s"), ("link", "m", "s"), ("syncdir",),
          ("write", "t", side(100, "finalizing", "f")), ("sync", "t"),
          ("link", "m.tmp", "t"), ("rename", "m.tmp", "m"), ("syncdir",)]
RENAME = PREFIX + [("rename", "f.part", "f"), ("syncdir",), ("unlink", "m"), ("syncdir",)]
HARDLINK = PREFIX + [("link", "f", "p"), ("syncdir",), ("unlink", "f.part"), ("syncdir",),
                     ("unlink", "m"), ("syncdir",)]


def recover(files, names):
    """ARCHITECTURE.md 7.10. Returns the settled outcome."""
    meta = files.get("m")
    p, f = "f.part" in names, "f" in names
    if meta is None or meta[2] != "finalizing":
        if f and not p:
            return "published"
        if f and p:
            return "UNSAFE two names without a finalizing record"
        return "resumable"
    if f and p:
        if names["f"] != names["f.part"]:
            return "conflict held"
        return "published"  # remove partial name, then sidecar
    if f:
        return "published" if files["f"] == FULL else "UNSAFE incomplete final"
    if p:
        return "publish again" if files["f.part"] == FULL else "UNSAFE incomplete partial"
    return "UNSAFE nothing left"


def check_finalize(ops, old_hardlink_rule=False):
    outcomes, bad = {}, set()
    for n in range(len(PREFIX), len(ops) + 1):
        for files, names in run_prefix(ops, n):
            r = recover(files, names)
            if old_hardlink_rule and "f" in names and "f.part" in names and names["f"] == names["f.part"]:
                r = "STUCK nlink is 2, resume refuses, no recovery"
            outcomes[r] = outcomes.get(r, 0) + 1
            if r.startswith(("UNSAFE", "STUCK")):
                bad.add(r)
    return outcomes, bad


failed = 0
print("Checkpoint protocols")
for label, body, expect_safe in [("published: sync partial, atomic replace", checkpoint_old(), False),
                                 ("variant: sidecar before partial sync", checkpoint_reversed(), False),
                                 ("revised: CP1 to CP6", checkpoint_new(), True)]:
    bad = check_checkpoint(body)
    print(f"  {label:44} {'safe' if not bad else '; '.join(sorted(bad))}")
    failed += (not bad) != expect_safe

print("Finalisation protocols")
for label, ops, old, expect_safe in [("rename no-replace, revised", RENAME, False, True),
                                     ("hard link, revised recovery", HARDLINK, False, True),
                                     ("hard link, published nlink rule", HARDLINK, True, False)]:
    outcomes, bad = check_finalize(ops, old)
    print(f"  {label:44} {outcomes}")
    failed += (not bad) != expect_safe

# ---------------------------------------------------------------------------
# Shutdown and supervision model for ARCHITECTURE.md 7.10.
#
# This explores interleavings of an abstract storage worker with shutdown. It
# contains no real filesystem or runtime. Assumed from Tokio documentation:
# aborting an async task never interrupts an operation that has already started.
# ---------------------------------------------------------------------------

RENAME_STEPS = ["claim", "F1", "F2start", "F2effect", "F2return", "F3", "F5", "commit"]
LINK_STEPS = ["claim", "F1", "F2start", "F2effect", "F2return", "F3", "F4", "F5", "commit"]
ORDER = {"open": 0, "claimed": 1, "intent": 2, "inflight": 3, "published": 4, "cleaned": 5}


class World:
    def __init__(self, fail_at=None):
        self.gate = "open"
        self.ledger = "open"
        self.published = False
        self.outcome = None
        self.commits_attempted = 0
        self.unresolved = False
        self.worker_ended = False
        self.fail_at = fail_at
        self.post_publish_failure = False

    def commit(self, kind, clean=False):
        """First writer wins. Later attempts are ignored."""
        self.commits_attempted += 1
        if self.outcome is None:
            self.outcome = (kind, clean)


def worker_step(w, step):
    """One step of the revised storage worker."""
    if w.worker_ended:
        return
    if step == "claim":
        if w.gate != "open":
            w.worker_ended = True  # lost to cancel: touches nothing
            return
        w.gate = "claimed"
        w.ledger = "claimed"
    elif step == "F1":
        if w.fail_at == "F1":
            w.commit("Failed")
            w.worker_ended = True
            return
        w.ledger = "intent"
    elif step == "F2start":
        w.ledger = "inflight"
    elif step == "F2effect":
        if w.fail_at == "F2effect":  # target exists: nothing was published
            w.commit("Failed")
            w.worker_ended = True
            return
        w.published = True
    elif step == "F2return":
        w.ledger = "published"
    elif step in ("F3", "F4", "F5"):
        if w.fail_at == step:
            w.post_publish_failure = True  # reported on Completed, the sequence stops
            w.commit("Completed", clean=False)
            w.worker_ended = True
    elif step == "commit":
        w.commit("Completed", clean=not w.post_publish_failure)
        w.worker_ended = True


def shutdown_step(w, step):
    if step == "request":
        if w.gate == "open":
            w.gate = "closed"  # same CAS as cancel()
    elif step == "supervise":
        if w.gate == "closed":
            w.commit("Cancelled")
    elif step == "deadline":
        if w.gate == "open":
            w.gate = "closed"
            w.commit("Cancelled")
        elif w.gate == "claimed" and w.outcome is None:
            if ORDER[w.ledger] >= ORDER["published"]:
                w.commit("Completed", clean=False)  # conservative, may understate
            else:
                w.unresolved = True


def probe_step(w):
    """Supervisor after the worker died uncommitted, with every lookup working.

    Inspection failures are modelled in the probe section below.
    """
    if w.gate == "claimed" and w.outcome is None:
        if ORDER[w.ledger] >= ORDER["published"]:
            w.commit("Completed", clean=False)
        elif w.ledger == "inflight":
            w.commit("Completed" if w.published else "Failed", clean=False)
        else:
            w.commit("Failed")  # F2 never started


def interleavings(a, b):
    if not a or not b:
        yield list(a) + list(b)
        return
    for rest in interleavings(a[1:], b):
        yield [a[0]] + rest
    for rest in interleavings(a, b[1:]):
        yield [b[0]] + rest


def check(w, hung):
    problems = []
    kind = w.outcome[0] if w.outcome else None
    if kind == "Cancelled" and (w.published or w.ledger != "open"):
        problems.append("Cancelled, but the worker acted or the file is published")
    if kind == "Failed" and w.published:
        problems.append("Failed, but the file is published")
    if kind == "Completed" and not w.published:
        problems.append("Completed, but the file is not published")
    if w.outcome and w.outcome[1] and w.post_publish_failure:
        problems.append("reported clean after a post-publication failure")
    if kind is None and not (hung and w.gate == "claimed" and w.unresolved):
        problems.append("no outcome, and not reported unresolved")
    return problems


def explore(steps):
    """Worker runs fully, fails at each failable step, hangs, or dies after any step."""
    SHUT = [("s", "request"), ("s", "supervise"), ("s", "deadline")]
    runs = []
    for fail_at in [None, "F1", "F2effect", "F3", "F4", "F5"]:
        if fail_at in steps or fail_at is None:
            runs.append((steps, fail_at, "full"))
    for n in range(len(steps)):
        runs.append((steps[:n], None, "hang"))
        runs.append((steps[:n], None, "die"))
    seen = bad = 0
    tally = {}
    for work, fail_at, mode in runs:
        for order in interleavings([("w", s) for s in work], SHUT):
            w = World(fail_at)
            for who, step in order:
                (worker_step if who == "w" else shutdown_step)(w, step)
            if mode == "die":
                probe_step(w)
            seen += 1
            problems = check(w, mode == "hang")
            bad += bool(problems)
            for p in problems:
                print("   VIOLATION", p, fail_at, mode, order)
            key = w.outcome[0] if w.outcome else "Unresolved"
            tally[key] = tally.get(key, 0) + 1
    return seen, bad, tally


def old_at(steps, at):
    """Published design: the deadline aborts the task and the supervisor commits Cancelled.

    The task drives each step, so abort prevents later steps, but an operation
    already in flight still runs to completion.
    """
    w = World()
    for s in steps[:at]:
        if s == "F2effect":
            w.published = True
        if s == "commit":
            w.commit("Completed")
    if steps[at] == "F2effect":
        w.published = True  # in flight when aborted, it keeps running
    w.commit("Cancelled")
    return w


def new_at(steps, at, hangs=False):
    """Revised design: the same deadline, firing just before steps[at]."""
    w = World()
    for s in steps[:at]:
        worker_step(w, s)
    shutdown_step(w, "request")
    shutdown_step(w, "supervise")
    shutdown_step(w, "deadline")
    if not hangs:
        for s in steps[at:]:
            worker_step(w, s)
    return w


def label(w):
    return w.outcome[0] if w.outcome else ("Unresolved" if w.unresolved else "NONE")


print("\nShutdown deadline at each finalisation step (MODEL, not filesystem evidence)")
print(f"  {'deadline before':17}{'old: outcome':14}{'old: file':11}{'verdict':10}"
      f"{'new: outcome':14}{'new: file':11}new, worker hangs")
old_false = 0
for at, step in enumerate(LINK_STEPS):
    old, new, stuck = old_at(LINK_STEPS, at), new_at(LINK_STEPS, at), new_at(LINK_STEPS, at, True)
    is_false = old.outcome[0] == "Cancelled" and old.published
    old_false += is_false
    file_state = lambda x: "published" if x.published else "partial"
    print(f"  {step:17}{old.outcome[0]:14}{file_state(old):11}{'FALSE' if is_false else 'ok':10}"
          f"{label(new):14}{file_state(new):11}{label(stuck)}")
    failed += bool(check(new, False)) or bool(check(stuck, True))
print(f"  old design reports Cancelled with the file published at {old_false} of {len(LINK_STEPS)} points")
failed += old_false == 0

inflight = old_at(RENAME_STEPS, RENAME_STEPS.index("F2effect"))
print(f"  rename in flight at abort, old design: {inflight.outcome[0]}, published {inflight.published}")
failed += not (inflight.outcome[0] == "Cancelled" and inflight.published)

print("Exhaustive interleavings, revised design (worker completes, fails, hangs, or dies)")
for name, steps in [("rename path", RENAME_STEPS), ("hard-link path", LINK_STEPS)]:
    seen, bad, tally = explore(steps)
    print(f"  {name:16}{seen:6} interleavings, {bad} violations, outcomes {tally}")
    failed += bad != 0

# ---------------------------------------------------------------------------
# Publication probe model for ARCHITECTURE.md 6 and 7.10.
#
# A probe sees lookups, not the truth. Each lookup returns "ours", "other",
# "none", or "error". The superseded rules are kept so the harness can show what
# they did. Filesystem assumptions FA-1 and FA-2 are assumed, except in the
# scenarios that break them on purpose.
# ---------------------------------------------------------------------------

BUDGET = 8  # reconciliation attempts before a record goes dormant


def probe(n, p):
    """The single classification used by the worker, the reconciler, and recovery."""
    if n == "error":
        return "Indeterminate"
    if n == "ours":
        return "Same"  # conclusive whatever the partial name shows
    if p != "ours":
        return "Indeterminate"  # our file is at neither name, nothing is established
    return "Absent" if n == "none" else "Different"


PROBE_TABLE = {
    ("ours", "ours"): "Same", ("ours", "none"): "Same", ("ours", "other"): "Same",
    ("none", "ours"): "Absent",
    ("other", "ours"): "Different",
    ("none", "none"): "Indeterminate", ("other", "none"): "Indeterminate",
    ("none", "other"): "Indeterminate", ("other", "other"): "Indeterminate",
    ("error", "ours"): "Indeterminate", ("error", "none"): "Indeterminate",
    ("error", "other"): "Indeterminate", ("error", "error"): "Indeterminate",
    ("ours", "error"): "Same", ("none", "error"): "Indeterminate",
    ("other", "error"): "Indeterminate",
}


def old_worker_rule(n):
    """ARCHITECTURE.md 7.10 before this revision: anything but a match is a failure."""
    return "Continue" if n == "ours" else "Failed"


def old_postmortem(n):
    """ARCHITECTURE.md 6 before this revision. The ledger was not consulted."""
    return "Completed" if n == "ours" else "Failed"


class Run:
    """One transfer after F1, with an F2 result and a schedule of working lookups."""

    def __init__(self, f2, sight, rename=True):
        self.f2 = f2            # ok, lost_reply, no_effect, conflict
        self.sight = list(sight)  # which lookups fail in each probe: ok, n, p, both
        self.rename = rename
        self.n = "other" if f2 == "conflict" else "none"
        self.p = "ours"
        self.gate = "claimed"
        self.ledger = "intent"
        self.outcome = None
        self.kinds = set()
        self.worker_ended = False
        self.queued = False       # record held by the reconciler
        self.reconciler_live = True
        self.owner = "worker"
        self.unresolved_listed = False
        self.touched_while_unknown = []

    def commit(self, kind):
        self.kinds.add(kind)
        if self.outcome is None:
            self.outcome = kind

    def peek(self):
        fails = self.sight[0] if self.sight else "ok"
        return ("error" if fails in ("n", "both") else self.n,
                "error" if fails in ("p", "both") else self.p)

    def look(self):
        view = self.peek()
        if self.sight:
            self.sight.pop(0)
        return view

    def publish(self):
        self.n = "ours"
        if self.rename:
            self.p = "none"

    def resolve(self, result):
        """Reconciler action on a probe result. It never publishes or deletes."""
        if result == "Same":
            self.ledger = "published"
            self.commit("Completed")
        elif result == "Absent":
            self.commit("Failed")
        elif result == "Different":
            self.commit("FailedFinalExists")
        return result != "Indeterminate"


def p_worker(r, step):
    if r.worker_ended:
        return
    if step == "F2start":
        r.ledger = "inflight"
    elif step == "F2effect":
        if r.f2 in ("ok", "lost_reply"):
            r.publish()
    elif step == "F2return":
        if r.f2 == "ok":
            r.ledger = "published"
            return
        result = probe(*r.look())
        if result == "Same":
            r.ledger = "published"
        elif result == "Absent":
            r.commit("Failed")
            r.worker_ended = True
        elif result == "Different":
            r.commit("FailedFinalExists")
            r.worker_ended = True
        else:
            r.ledger = "unknown"
            r.worker_ended = True
            if r.reconciler_live:
                r.queued, r.owner = True, "reconciler"
            else:
                r.owner = "startup"
    elif step == "commit":
        r.commit("Completed")
        r.worker_ended = True


def p_postmortem(r):
    """Supervisor once the worker has exited. The ledger is read before any probe."""
    if r.outcome is not None:
        return
    if ORDER_P[r.ledger] >= ORDER_P["published"]:
        r.commit("Completed")
    elif r.ledger == "inflight":
        if r.reconciler_live:
            r.queued, r.owner = True, "reconciler"
        else:
            r.owner = "startup"
    elif r.ledger != "unknown":
        r.commit("Failed")


ORDER_P = {"intent": 2, "inflight": 3, "unknown": 3, "published": 4}


def p_reconcile(r):
    if r.queued and r.outcome is None and r.reconciler_live:
        if r.resolve(probe(*r.look())):
            r.queued = False
            r.owner = None


def p_shutdown(r):
    """Deadline: a final pass has run, the reconciler stops, the report is written."""
    if r.outcome is None and ORDER_P[r.ledger] >= ORDER_P["published"]:
        r.commit("Completed")
    r.reconciler_live = False
    if r.outcome is None:
        r.unresolved_listed = True
        if r.queued:
            r.queued, r.owner = False, "startup"


def may_discard(r):
    return r.gate == "closed"


def may_republish(r):
    """A new request for the partial runs recovery first, if it can get the lock."""
    if r.owner in ("worker", "reconciler"):
        return False  # the lock is still held, so this is Held(Busy)
    return startup_new(*r.peek()) == "row 1 publish"


def p_host(r):
    """The host tries discard and retry at this point. Neither may touch an unknown file."""
    if r.outcome is None:
        if may_discard(r):
            r.touched_while_unknown.append("discard")
        if may_republish(r) and ("error" in r.peek() or r.owner in ("worker", "reconciler")):
            r.touched_while_unknown.append("republish")


def p_check(r):
    problems = []
    published = r.n == "ours"
    if r.outcome == "Completed" and not published:
        problems.append("Completed, but the file is not published")
    if r.outcome in ("Failed", "FailedFinalExists") and published:
        problems.append("Failed, but the file is published")
    if len(r.kinds) > 1:
        problems.append(f"conflicting commits {sorted(r.kinds)}")
    if r.outcome is None:
        if r.owner is None:
            problems.append("no outcome and no owner")
        if ORDER_P[r.ledger] >= ORDER_P["published"] and r.worker_ended:
            problems.append("publication known, but no outcome")
        if r.ledger == "intent" and r.worker_ended:
            problems.append("F2 never started, but no outcome")
        if r.touched_while_unknown:
            problems.append("acted on files while publication was unknown")
    return problems


def startup_new(n, p):
    """ARCHITECTURE.md 7.10 recovery, row chosen from the same probe inputs."""
    if n == "ours" and p == "error":
        return "row 7 held"  # published, cleanup waits
    if n == "error" or p == "error" or p == "other":
        return "row 6 held"
    if p == "ours" and n == "none":
        return "row 1 publish"
    if p != "ours" and n == "ours":
        return "row 2 clean"
    if p == "ours" and n == "ours":
        return "row 3 clean"
    if n == "other":
        return "row 4 held"
    return "row 5 held"


RECOVERY_TABLE = {
    ("none", "ours"): "row 1 publish",
    ("ours", "none"): "row 2 clean",
    ("ours", "ours"): "row 3 clean",
    ("other", "ours"): "row 4 held", ("other", "none"): "row 4 held",
    ("none", "none"): "row 5 held",
    ("none", "other"): "row 6 held", ("ours", "other"): "row 6 held", ("other", "other"): "row 6 held",
    ("error", "ours"): "row 6 held", ("error", "none"): "row 6 held", ("error", "other"): "row 6 held",
    ("error", "error"): "row 6 held", ("none", "error"): "row 6 held", ("other", "error"): "row 6 held",
    ("ours", "error"): "row 7 held",
}


def startup_old(n, p):
    """Earlier recovery table, which had no row for a failed lookup, so error read as absent."""
    return startup_new("none" if n == "error" else n, "none" if p == "error" else p)


def startup_safe(n, p, row):
    """A file-changing row is safe only if it rests on lookups that worked."""
    return row.endswith("held") or "error" not in (n, p)


# Direct comparison of the earlier rule and the revised rule.
print("\nPublication probe, earlier and revised rules (MODEL, not filesystem evidence)")
print(f"  {'case':47}{'file':11}{'probe':15}{'earlier':11}{'revised':12}verdict on earlier")
CASES = [
    ("F2 error, published, lookups work", "worker", "ours", "none", True, "intent"),
    ("F2 error, published, lookups fail", "worker", "ours", "none", False, "intent"),
    ("F2 error, not published, lookups fail", "worker", "none", "ours", False, "intent"),
    ("F2 error, not published, lookups work", "worker", "none", "ours", True, "intent"),
    ("F2 error, other file at N, lookups fail", "worker", "other", "ours", False, "intent"),
    ("F2 error, other file at N, lookups work", "worker", "other", "ours", True, "intent"),
    ("hard link done, error, lookups fail", "worker", "ours", "ours", False, "intent"),
    ("worker died in F2, published, lookups fail", "dead", "ours", "none", False, "inflight"),
    ("worker died in F2, unpublished, lookups fail", "dead", "none", "ours", False, "inflight"),
    ("worker died after success, lookups fail", "dead", "ours", "none", False, "published"),
    ("worker died before F2, lookups fail", "dead", "none", "ours", False, "intent"),
]
misclassified = lucky = 0
for name, where, n, p, sees, ledger in CASES:
    vn, vp = (n, p) if sees else ("error", "error")
    result = probe(vn, vp)
    if where == "worker":
        earlier = old_worker_rule(vn)
        revised = {"Same": "Continue", "Absent": "Failed", "Different": "Conflict",
                   "Indeterminate": "Unresolved"}[result]
    else:
        earlier = old_postmortem(vn)
        if ledger == "published":
            revised = "Completed"
        elif ledger == "inflight":
            revised = {"Same": "Completed", "Absent": "Failed", "Different": "Conflict",
                       "Indeterminate": "Unresolved"}[result]
        else:
            revised = "Failed"
    published = n == "ours"
    false_old = earlier == "Failed" and published
    false_new = revised in ("Failed", "Conflict") and published
    if false_old:
        verdict = "FALSE"
    elif earlier == "Failed" and not sees and revised == "Unresolved":
        verdict = "right by luck"
        lucky += 1
    else:
        verdict = "ok"
    misclassified += false_old
    failed += false_new
    print(f"  {name:47}{'published' if published else 'not':11}{result:15}{earlier:11}{revised:12}{verdict}")
print(f"  earlier rules commit Failed with the file published in {misclassified} of {len(CASES)} cases,"
      f" and guess correctly without evidence in {lucky}")
failed += misclassified == 0

bad_table = [k for k, v in PROBE_TABLE.items() if probe(*k) != v]
print(f"  probe truth table: {len(PROBE_TABLE)} lookup pairs, {len(bad_table)} mismatches")
failed += bool(bad_table)


def explore_probes(rename):
    """Worker, reconciler, and shutdown in every order, for every F2 result and lookup schedule."""
    work = ["F2start", "F2effect", "F2return", "commit"]
    others = [[("r", "attempt"), ("r", "attempt"), ("s", "deadline")], [("r", "attempt"), ("r", "attempt")]]
    seen = bad = writes = 0
    tally = {}
    for f2 in ["ok", "lost_reply", "no_effect", "conflict"]:
        for sight in itertools.product(["ok", "n", "p", "both"], repeat=3):
            for mode, cut in [("full", len(work))] + [("die", i) for i in range(len(work))] \
                    + [("hang", i) for i in range(len(work))]:
                steps = [("w", s) for s in work[:cut]]
                if mode != "hang":
                    steps.append(("x", "exit"))
                for rest in others:
                    for order in interleavings(steps, rest):
                        r = Run(f2, sight, rename)
                        for who, step in order:
                            if who == "w":
                                p_worker(r, step)
                            elif who == "x":
                                r.worker_ended = True
                                p_postmortem(r)
                            elif who == "r":
                                names = r.n, r.p
                                p_reconcile(r)
                                writes += (r.n, r.p) != names
                            else:
                                p_shutdown(r)
                            p_host(r)
                        seen += 1
                        problems = p_check(r)
                        if r.outcome is None and mode != "hang" and not r.unresolved_listed:
                            if r.owner != "reconciler":
                                problems.append("no outcome, not reported, and no live owner")
                        bad += bool(problems)
                        for x in problems:
                            print("   VIOLATION", x, f2, sight, mode, order)
                        key = r.outcome or f"Unresolved, {r.owner}"
                        tally[key] = tally.get(key, 0) + 1
    return seen, bad, writes, tally


print("Exhaustive interleavings: F2 result, lookup schedule, worker fate, reconciler, shutdown")
for name, rename in [("rename path", True), ("hard-link path", False)]:
    seen, bad, writes, tally = explore_probes(rename)
    print(f"  {name:16}{seen:6} interleavings, {bad} violations, {writes} probe jobs changed a name")
    print(f"  {'':16}{dict(sorted(tally.items()))}")
    failed += bad != 0 or writes != 0

print("Startup recovery with failed lookups (every true state, every lookup failure)")
bad_rows = [k for k, v in RECOVERY_TABLE.items() if startup_new(*k) != v]
print(f"  recovery truth table: {len(RECOVERY_TABLE)} lookup pairs, {len(bad_rows)} mismatches")
failed += bool(bad_rows)
unsafe_old = unsafe_new = 0
states = [("ours", "none"), ("ours", "ours"), ("none", "ours"), ("other", "ours"), ("none", "none")]
total = 0
for n_true, p_true in states:
    for n_err, p_err in itertools.product([False, True], repeat=2):
        n = "error" if n_err else n_true
        p = "error" if p_err else p_true
        total += 1
        unsafe_old += not startup_safe(n, p, startup_old(n, p))
        unsafe_new += not startup_safe(n, p, startup_new(n, p))
print(f"  {total} combinations. Earlier table changes files on a failed lookup in {unsafe_old},"
      f" revised table in {unsafe_new}")
failed += unsafe_old == 0 or unsafe_new != 0

# The revised rule is only as good as its assumptions. These two runs break them,
# and the result must stay false, so that the limit cannot be forgotten.
print("Assumptions broken on purpose (revised rule is expected to be wrong here)")
stale = Run("lost_reply", ["ok"])
for s in ["F2start", "F2effect"]:
    p_worker(stale, s)
true_n, true_p = stale.n, stale.p
stale.n, stale.p = "none", "ours"  # FA-2 broken: the lookup reports the state before the rename
p_worker(stale, "F2return")
stale.n, stale.p = true_n, true_p
stale_false = stale.outcome == "Failed" and stale.n == "ours"
print(f"  FA-2, stale negative lookup after a lost reply: {stale.outcome}, file published: {stale.n == 'ours'}")
late = Run("no_effect", ["ok"])
for s in ["F2start", "F2effect", "F2return"]:
    p_worker(late, s)
late.publish()  # FA-1 broken: the operation takes effect after it returned an error
late_false = late.outcome == "Failed" and late.n == "ours"
print(f"  FA-1, effect after the error returned: {late.outcome}, file published: {late.n == 'ours'}")
failed += not (stale_false and late_false)


class Reconciler:
    """One thread, one job at a time, a bounded budget per record, explicit re-arming."""

    def __init__(self, records):
        self.left = {r: BUDGET for r in records}
        self.armed = set(records)
        self.attempts = {r: 0 for r in records}
        self.threads = 1
        self.stuck = False
        self.recovery = []        # queued recovery jobs, at most one per partial
        self.ran = {}
        self.running = None       # recovery job the thread is inside
        self.stopped = False

    def tick(self, inspect, recover=None):
        if self.stuck:
            return False
        ready = sorted(r for r in self.armed if self.left[r] > 0)
        if not ready:
            if not self.recovery:
                return False
            p = self.recovery.pop(0)
            self.ran[p] = self.ran.get(p, 0) + 1
            if recover(p) == "hang":
                self.stuck = True
                self.running = p
            return True
        r = ready[0]
        self.left[r] -= 1
        self.attempts[r] += 1
        result = inspect(r)
        if result == "hang":
            self.stuck = True
        elif result != "Indeterminate":
            self.armed.discard(r)
            self.left[r] = 0
        elif self.left[r] == 0:
            self.armed.discard(r)  # dormant
        return True

    def rearm(self, records, partials=()):
        for r in records:
            if r in self.left and r not in self.armed:
                self.armed.add(r)
                self.left[r] = 1
        for p in partials:
            if p not in self.recovery and not self.stopped:
                self.recovery.append(p)

    def stop(self):
        """Shutdown: drop queued recovery jobs, and report one the thread is still inside."""
        self.stopped = True
        self.recovery.clear()
        return [self.running] if self.running else []


print("Reconciliation bounds")
rec = Reconciler(["a", "b"])
steps = 0
while rec.tick(lambda r: "Indeterminate") and steps < 1000:
    steps += 1
dormant = not rec.armed and rec.attempts == {"a": BUDGET, "b": BUDGET}
print(f"  never-readable records: {rec.attempts} attempts, then dormant: {dormant}")
failed += not dormant
idle = not rec.tick(lambda r: "Indeterminate")
rec.rearm(["a"])
rec.rearm(["a"])
one = rec.tick(lambda r: "Indeterminate") and not rec.tick(lambda r: "Indeterminate")
print(f"  no probe while dormant: {idle}, a repeated re-arm gives one attempt: {one}")
failed += not (idle and one)
rec = Reconciler(["a", "b"])
rec.tick(lambda r: "hang")
blocked = not rec.tick(lambda r: "Same")
print(f"  hung probe: threads {rec.threads}, other record waits rather than a thread being added: {blocked}")
failed += not (blocked and rec.threads == 1)

# ---------------------------------------------------------------------------
# Reconciler job permissions for ARCHITECTURE.md 6 "Reconciler jobs" and 7.10.
#
# The thread only executes jobs. A probe job has to leave the disk alone, which
# explore_probes checks. A recovery job follows startup_new, so it cannot drift
# from the table that startup uses.
# ---------------------------------------------------------------------------


class Disk:
    def __init__(self, n, p):
        self.n, self.p, self.sidecar = n, p, True
        self.problems = []
        self.changes = 0
        self.taken = False  # another file reached the final name during the job

    def state(self):
        return self.n, self.p, self.sidecar

    def see(self, faults):
        return ("error" if faults in ("n", "both") else self.n,
                "error" if faults in ("p", "both") else self.p)

    def publish(self, rename):
        if self.n == "ours":
            self.problems.append("published over an existing final name")
        self.changes += 1
        self.n = "ours"
        if rename:
            self.p = "none"

    def remove_partial_name(self):
        if self.n != "ours" or self.p != "ours":
            self.problems.append("removed the partial name without two confirmed names")
        self.changes += 1
        self.p = "none"

    def remove_sidecar(self):
        if self.n != "ours" or self.p == "ours":
            self.problems.append("removed the sidecar before publication finished")
        self.changes += 1
        self.sidecar = False


def recovery_job(d, first, second, f2, rename, busy, steps):
    """One retry job. Stop allows `steps` file-changing steps, None for no stop."""
    left = [steps]

    def go():
        if left[0] == 0:
            return False
        if left[0] is not None:
            left[0] -= 1
        return True

    if busy:
        return "skipped busy"
    row = startup_new(*d.see(first))
    if row.endswith("held"):
        return row
    if row == "row 1 publish":
        if not go():
            return row
        if f2 == "conflict":
            d.n, d.taken = "other", True  # the name was taken first, and F2 cannot replace it
        elif f2 in ("ok", "lost_reply"):
            d.publish(rename)
        if f2 != "ok":
            result = probe(*d.see(second))
            if result == "Absent":
                return "row 1 kept"
            if result == "Different":
                return "row 4 held"
            if result == "Indeterminate":
                return "row 6 held"
    if not go():
        return row  # F3
    if row == "row 3 clean" or (row == "row 1 publish" and not rename):
        if not go():
            return row
        d.remove_partial_name()
    if not go():
        return row
    d.remove_sidecar()
    return "clean"


def check_recovery_job(n, p, first, second, f2, rename, busy, steps):
    """Run a job, then a fault-free recovery after it, as a crash or a later retry would."""
    d = Disk(n, p)
    before = d.state()
    result = recovery_job(d, first, second, f2, rename, busy, steps)
    problems = list(d.problems)
    seen = len(d.problems)
    changed = d.state() != before
    if busy and changed:
        problems.append("changed a file without the lock")
    if "error" in Disk(n, p).see(first) and changed:
        problems.append("changed a file on a failed lookup")
    if result.endswith("held") and not d.sidecar:
        problems.append("cleaned up after an uncertain result")
    if steps is not None and d.changes > steps:
        problems.append("began a step after stop")
    if (n == "other" or d.taken) and d.n != "other":
        problems.append("replaced a file it does not own")
    if "ours" in (n, p) and "ours" not in (d.n, d.p):
        problems.append("lost the file")
    for _ in range(3):
        result = recovery_job(d, "ok", "ok", "ok", rename, False, None)
    problems += d.problems[seen:]
    settled = d.state()
    result = recovery_job(d, "ok", "ok", "ok", rename, False, None)
    if d.state() != settled:
        problems.append("recovery is not idempotent")
    published = d.n == "ours" and d.p != "ours" and not d.sidecar
    if not published and not result.endswith("held"):
        problems.append(f"did not settle: {result}")
    return problems


print("Recovery jobs (every state, lookup failure, F2 result, lock, and stop point)")
STATES = [(x, y) for x in ("ours", "none", "other") for y in ("ours", "none", "other")]
FAULTS = ["ok", "n", "p", "both"]
job_runs = job_bad = 0
for (n, p), first, second, f2, rename, busy, steps in itertools.product(
        STATES, FAULTS, FAULTS, ["ok", "lost_reply", "no_effect", "conflict"],
        [True, False], [False, True], [None, 0, 1, 2, 3]):
    problems = check_recovery_job(n, p, first, second, f2, rename, busy, steps)
    job_runs += 1
    job_bad += bool(problems)
    for x in problems:
        print("   VIOLATION", x, n, p, first, second, f2, rename, busy, steps)
print(f"  {job_runs} runs, each followed by a fault-free recovery, {job_bad} violations")
failed += job_bad != 0


def lock_pass(events):
    """Two recovery passes on one partial, in a chosen order. Returns what went wrong."""
    n, holder, views, acted = "none", None, {}, []
    problems = []
    for who, step in events:
        if step == "lock":
            if holder is None:
                holder = who
            else:
                views[who] = None  # busy, so this pass changes nothing
        elif step == "look":
            if views.get(who, "") is not None:
                views[who] = n
        elif step == "act":
            if views.get(who) is None:
                continue
            if holder != who:
                problems.append("acted without the lock")
            if views[who] != n:
                problems.append("acted on an observation that had gone stale")
            if n == "none":
                n = "ours"
                acted.append(who)
        elif holder == who:
            holder = None
    if len(acted) > 1:
        problems.append("two passes published one partial")
    return problems


PASS = ["lock", "look", "act", "unlock"]
orders = list(interleavings([("job", s) for s in PASS], [("request", s) for s in PASS]))
lock_bad = sum(bool(lock_pass(o)) for o in orders)
print(f"  recovery job against a new request: {len(orders)} orders, {lock_bad} violations")
failed += lock_bad != 0

print("Reconciler with both job types")
rec = Reconciler(["a"])
rec.rearm([], ["p", "p", "q"])
rec.rearm([], ["p"])
order = []
while rec.tick(lambda r: order.append(r) or "Indeterminate", lambda p: order.append(p) or "row 6 held"):
    pass
probes_first = order == ["a"] * BUDGET + ["p", "q"]
print(f"  ready probes run before recovery jobs: {probes_first}")
print(f"  repeated calls give one job per partial, and a row 6 result is not retried: {rec.ran == {'p': 1, 'q': 1}}")
failed += not (probes_first and rec.ran == {"p": 1, "q": 1})
rec.rearm([], ["p"])
again = rec.tick(None, lambda p: "row 6 held") and rec.ran["p"] == 2
print(f"  a later host call gives one more job: {again}")
failed += not again
rec = Reconciler(["a"])
rec.armed.clear()  # waiting out its delay, so a recovery job can run
rec.rearm([], ["p"])
rec.tick(None, lambda p: "row 6 held")
unspent = rec.left["a"] == BUDGET
print(f"  a recovery job spends no record's budget: {unspent}")
failed += not unspent
rec = Reconciler([])
rec.rearm([], ["p", "q"])
rec.tick(None, lambda p: "hang")
waits = not rec.tick(None, lambda p: "row 6 held")
busy_list = rec.stop()
rec.rearm([], ["r"])
stopped = not rec.recovery and busy_list == ["p"]
print(f"  hung recovery job: threads {rec.threads}, others wait: {waits}, stop drops the queue, "
      f"accepts no job, and lists the running one: {stopped}")
failed += not (waits and stopped and rec.threads == 1)

print(f"\nmismatches against expectation: {failed}")
sys.exit(1 if failed else 0)
