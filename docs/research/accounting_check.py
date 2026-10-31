#!/usr/bin/env python3
"""Executable check of the transfer accounting in ARCHITECTURE.md 7.6.

Research artifact, not production code. Exit status is non-zero on any violation.
Symbols: Z size, L file length, D durable offset, E trusted prefix, O overlap limit,
Vt overlap target, P request position, R bytes read, V bytes verified, W bytes
newly written, A validated position.

Every checkpoint in this script goes through plan_checkpoint, the one eligibility
rule in ARCHITECTURE.md 7.9. legacy_target is the earlier CP1 rule, kept only so the
script can show that it decreases D.
"""
import random
import sys


class Mismatch(Exception):
    pass


class Overrun(Exception):
    pass


TRIGGERS = ("timer", "bytes", "cancel", "failure", "finalize")


def plan_checkpoint(a, D, trigger):
    """Returns a target position to record, or None to skip."""
    assert trigger in TRIGGERS
    if a.poisoned:
        return None
    if a.V < a.Vt:
        return None
    if trigger == "finalize":
        # A phase record may repeat D, but only for a fully validated file.
        return a.Z if a.A == a.Z else None
    return a.A if a.A > D else None


def legacy_target(a):
    return a.A  # earlier CP1: T = A, for any caller


class Attempt:
    def __init__(self, Z, L, D, O, source, partial):
        if L < D or L > Z or D > Z:
            raise ValueError("held for host decision or refused before negotiation")
        self.Z, self.O = Z, O
        self.E = min(L, D)
        self.Vt = min(O, self.E)
        self.P = self.E - self.Vt
        self.skips_network = self.E == Z and Z > 0 and self.Vt == 0
        self.sends_resume = self.P > 0 and not self.skips_network
        self.file = bytearray(partial[:L])
        self.original = bytes(self.file)
        self.source = source
        self.R = self.V = self.W = 0
        self.acks = []
        self.truncated = False
        self.poisoned = False  # a sync failed, so nothing here may advance D

    @property
    def A(self):
        return self.P + self.V + self.W

    def _check(self):
        assert self.P + self.R <= self.Z
        assert self.R == self.V + self.W
        assert self.V <= self.Vt
        assert self.W == 0 or self.V == self.Vt
        assert self.A <= self.Z
        if self.W:
            assert len(self.file) == self.E + self.W

    def on_bytes(self, chunk):
        if self.P + self.R + len(chunk) > self.Z:
            raise Overrun()
        i = 0
        while i < len(chunk):
            if self.V < self.Vt:
                n = min(self.Vt - self.V, len(chunk) - i)
                start = self.P + self.V
                if bytes(self.file[start:start + n]) != chunk[i:i + n]:
                    raise Mismatch()
                self.V += n
                self.R += n
            else:
                if not self.truncated:
                    del self.file[self.E:]  # discard any untrusted tail exactly once
                    self.truncated = True
                n = len(chunk) - i
                self.file += chunk[i:i + n]
                self.W += n
                self.R += n
            i += n
        self._check()
        if self.A > self.P:
            if self.acks:
                assert self.A > self.acks[-1]
            self.acks.append(self.A)

    def complete(self):
        return (self.P + self.V + self.W == self.Z and self.V == self.Vt
                and self.R == self.V + self.W and len(self.file) == self.Z)


def pattern(n, seed=7):
    r = random.Random(seed)
    return bytes(r.getrandbits(8) for _ in range(n))


def transfer(Z, L, D, O, chunk=7):
    src = pattern(Z)
    a = Attempt(Z, L, D, O, src, src)
    if a.skips_network:
        return a
    data = src[a.P:]
    for i in range(0, len(data), chunk):
        a.on_bytes(data[i:i + chunk])
    return a


print(f"{'scenario':38}{'Z':>6}{'L':>6}{'D':>6}{'O':>5}{'P':>6}{'Vt':>5}{'V':>5}{'W':>6}  RESUME done old-check")
failed = 0
for label, Z, L, D, O in [
    ("Fresh", 1000, 0, 0, 64),
    ("Normal resume", 1000, 400, 400, 64),
    ("Untrusted tail beyond D", 1000, 500, 400, 64),
    ("Partial smaller than overlap", 1000, 40, 40, 64),
    ("Partial equal to overlap", 1000, 64, 64, 64),
    ("Complete partial, overlap on", 1000, 1000, 1000, 64),
    ("Complete partial, overlap off", 1000, 1000, 1000, 0),
    ("Overlap off, normal resume", 1000, 400, 400, 0),
    ("Zero-length file", 0, 0, 0, 64),
    ("One byte file", 1, 0, 0, 64),
]:
    a = transfer(Z, L, D, O)
    done = a.complete()
    old = a.W == a.R  # the previous rule: written == received
    failed += not done
    print(f"{label:38}{Z:>6}{L:>6}{D:>6}{O:>5}{a.P:>6}{a.Vt:>5}{a.V:>5}{a.W:>6}  "
          f"{str(a.sends_resume):6} {str(done):5} {old}")

# A mismatch leaves the file byte-identical, including any untrusted tail.
src = pattern(1000)
other = bytearray(src)
other[380] ^= 0xFF
a = Attempt(1000, 500, 400, 64, src, bytes(other))
try:
    a.on_bytes(src[a.P:a.P + 64])
    failed += 1
    print("mismatch not detected")
except Mismatch:
    if bytes(a.file) != a.original or a.W != 0 or a.acks:
        failed += 1
        print("mismatch altered state")

# Overrun is refused, including on the final chunk.
a = Attempt(100, 0, 0, 64, src, b"")
try:
    a.on_bytes(bytes(101))
    failed += 1
except Overrun:
    assert a.R == 0

# Checkpoint eligibility at each point of an overlap. E = D = 400, O = 64, Z = 1000.
print("\nCheckpoint firing during a resume (D = 400)")
print(f"{'point':34}{'V':>4}{'W':>4}{'A':>6}{'legacy D':>10}  {'revised, by trigger'}")
src = pattern(1000)


def staged(verified, written):
    a = Attempt(1000, 400, 400, 64, src, src[:400])
    if verified:
        a.on_bytes(src[a.P:a.P + verified])
    if written:
        a.on_bytes(src[a.P + verified:a.P + verified + written])
    return a


for label, verified, written, legacy_bad, expect in [
    ("before overlap starts", 0, 0, True, None),
    ("partway through overlap", 32, 0, True, None),
    ("at overlap boundary, W = 0", 64, 0, False, None),
    ("after new bytes", 64, 10, False, 410),
]:
    a = staged(verified, written)
    legacy = legacy_target(a)
    shown = {t: plan_checkpoint(a, 400, t) for t in TRIGGERS}
    for t in ("timer", "bytes", "cancel", "failure"):
        if shown[t] != expect:
            failed += 1
            print("ELIGIBILITY FAIL", label, t, shown[t])
    if shown["finalize"] is not None:
        failed += 1
        print("finalize allowed on an incomplete file", label)
    if (legacy < 400) != legacy_bad:
        failed += 1
    note = "legacy DECREASES D" if legacy < 400 else "legacy holds D" if legacy == 400 else "both advance"
    print(f"{label:34}{a.V:>4}{a.W:>4}{a.A:>6}{legacy:>10}  {shown['timer']}  ({note})")

# A chunk straddling the boundary is processed whole, so D can only see the result.
a = staged(0, 0)
a.on_bytes(src[a.P:a.P + 74])
if plan_checkpoint(a, 400, "timer") != 410 or a.V != 64 or a.W != 10:
    failed += 1
    print("straddling chunk accounted wrongly")

# Bytes read but not yet processed never count. Only processed bytes move A.
a = staged(32, 0)
unprocessed = src[a.P + 32:a.P + 64]
if plan_checkpoint(a, 400, "timer") is not None or len(unprocessed) != 32:
    failed += 1

# Failed comparison: V stays below Vt, so no caller can record anything.
other = bytearray(src)
other[390] ^= 0xFF
a = Attempt(1000, 400, 400, 64, src, bytes(other[:400]))
a.on_bytes(src[a.P:a.P + 30])
try:
    a.on_bytes(src[a.P + 30:a.P + 64])
    failed += 1
except Mismatch:
    if any(plan_checkpoint(a, 400, t) is not None for t in TRIGGERS):
        failed += 1
        print("checkpoint allowed after mismatch")

# After a failed sync, no caller may advance D, even with new bytes present.
a = staged(64, 10)
a.poisoned = True
if any(plan_checkpoint(a, 400, t) is not None for t in TRIGGERS):
    failed += 1
    print("checkpoint allowed after sync failure")

# Finalisation records a phase even when the position does not move.
a = Attempt(1000, 1000, 1000, 64, src, src)
a.on_bytes(src[a.P:])
if plan_checkpoint(a, 1000, "finalize") != 1000 or plan_checkpoint(a, 1000, "timer") is not None:
    failed += 1
    print("complete partial finalize record wrong")
a = Attempt(1000, 1000, 1000, 0, src, src)
if plan_checkpoint(a, 1000, "finalize") != 1000:
    failed += 1
print("Boundary, straddle, mismatch, sync-failure and finalize-record checks done")

# Randomised runs: checkpoints fire at random, an untrusted tail is garbled between
# attempts, and D must never decrease. The legacy rule runs alongside to show that
# this harness can see the violation.
rng = random.Random(20261031)
runs = fires = skipped = legacy_decreases = 0
for _ in range(4000):
    Z = rng.randint(0, 4000)
    src = pattern(Z, rng.randint(0, 1 << 30))
    L = D = 0
    disk = b""
    O = rng.choice([0, 1, 16, 64, 5000])
    for attempt in range(6):
        a = Attempt(Z, L, D, O, src, disk)
        if a.skips_network:
            break
        data, i = src[a.P:], 0
        cut = len(data) if attempt == 5 else rng.randint(0, len(data))
        while True:
            for trigger in rng.sample(("timer", "bytes"), rng.randint(0, 2)):
                if legacy_target(a) < D:
                    legacy_decreases += 1
                T = plan_checkpoint(a, D, trigger)
                if T is None:
                    skipped += 1
                else:
                    if T <= D or T > a.A or a.V != a.Vt:
                        failed += 1
                        print("bad checkpoint", T, D, a.A)
                    D = T
                    fires += 1
            if i >= cut:
                break
            n = rng.randint(1, 97)
            a.on_bytes(data[i:min(i + n, cut)])
            i += n
        T = plan_checkpoint(a, D, rng.choice(("cancel", "failure")))
        if T is not None:
            if T <= D:
                failed += 1
            D = T
        # Anything past D is untrusted after a crash, so garble it.
        file_now = bytes(a.file)
        tail = bytes(b ^ 0x5A for b in file_now[D:]) if rng.random() < .5 else file_now[D:]
        disk = file_now[:D] + tail
        L = len(disk)
        if a.complete():
            break
    if a.complete() and a.skips_network is False:
        if bytes(a.file) != src:
            failed += 1
            print("random run produced wrong bytes", Z, O)
    if not a.skips_network and not a.complete():
        failed += 1
        print("random run did not complete", Z, O)
    runs += 1
if legacy_decreases == 0:
    failed += 1
    print("harness never reached a state where the legacy rule decreases D")
print(f"\n{runs} randomised multi-attempt runs, {fires} checkpoints recorded, {skipped} skipped")
print(f"legacy rule would have decreased D {legacy_decreases} times, revised rule 0 times")
print(f"failures: {failed}")
sys.exit(1 if failed else 0)
