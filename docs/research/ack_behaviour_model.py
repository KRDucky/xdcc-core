#!/usr/bin/env python3
"""Behavioural model of how an auto-detecting DCC sender may interpret ACK streams.

Research artifact, not production code. Evidence level [M] in PROTOCOL_SPEC.md.
This is an independent model of behaviour described in prose in README.md. It is
not a translation of any upstream source file. It never ran against a real bot.
Exit status is non-zero if any result differs from the published table.
"""
import struct
import sys

GIB = 1 << 30
U32_MAX = (1 << 32) - 1


class SenderView:
    """Tracks what a sender believes the receiver has acknowledged."""

    def __init__(self, size, resume=0, configured_wide=False):
        self.size = size
        self.highwater = resume
        self.resume = resume
        self.large = size > U32_MAX
        self.wide = configured_wide and self.large
        self.decided = self.wide
        self.pending = b""
        self.switched_by_guess = False

    def _narrow_value(self, value):
        if not self.decided:
            self.decided = True
            if self.large and value <= self.resume:
                # B2: the first value is read as the high half of a wide frame.
                self.wide = True
                self.switched_by_guess = True
                self.highwater = value << 32
                self.pending = struct.pack(">I", value) + self.pending
                return
        if self.large:
            # B3: narrow values are lifted past the high-water mark.
            while value < self.highwater:
                value += 1 << 32
        self.highwater = value

    def feed(self, data):
        self.pending += data
        while True:
            need = 8 if self.wide else 4
            if len(self.pending) < need:
                return
            frame, self.pending = self.pending[:need], self.pending[need:]
            if need == 8:
                self.highwater = struct.unpack(">Q", frame)[0]
            else:
                self._narrow_value(struct.unpack(">I", frame)[0])


def run(size, resume, width, initial=False, configured_wide=False, step=64 << 20):
    view = SenderView(size, resume, configured_wide)
    encode = (lambda p: struct.pack(">Q", p)) if width == 8 else (
        lambda p: struct.pack(">I", p & U32_MAX))
    position = resume
    early = False
    if initial:
        view.feed(encode(position))
    while position < size:
        position = min(size, position + step)
        view.feed(encode(position))
        if position < size and view.highwater >= size:
            early = True
    return view.switched_by_guess, view.highwater == size, early


F = 6 * GIB
# name, kwargs, expected (guessed wide, final state correct, high-water at size too early)
CASES = [
    ("Fresh, 4-byte wrapping", dict(size=F, resume=0, width=4), (False, True, False)),
    ("Fresh, 8-byte", dict(size=F, resume=0, width=8), (True, True, False)),
    ("Fresh, 4-byte, initial ACK of 0", dict(size=F, resume=0, width=4, initial=True), (True, False, True)),
    ("Resume 1 GiB, 4-byte", dict(size=F, resume=GIB, width=4), (False, True, False)),
    ("Resume 1 GiB, 8-byte", dict(size=F, resume=GIB, width=8), (True, True, False)),
    ("Resume 1 GiB, 4-byte, initial ACK", dict(size=F, resume=GIB, width=4, initial=True), (True, False, True)),
    ("Resume 5 GiB, 4-byte wrapping", dict(size=F, resume=5 * GIB, width=4), (True, False, True)),
    ("Resume 5 GiB, 8-byte", dict(size=F, resume=5 * GIB, width=8), (True, True, False)),
    ("Resume 5 GiB, 8-byte, initial ACK", dict(size=F, resume=5 * GIB, width=8, initial=True), (True, True, False)),
    ("Forced wide, 4-byte", dict(size=F, resume=0, width=4, configured_wide=True), (False, False, True)),
    ("Forced wide, 8-byte", dict(size=F, resume=0, width=8, configured_wide=True), (False, True, False)),
]

failed = 0
print(f"{'case':40} {'guess wide':11} {'final ok':9} too early")
for name, kwargs, expected in CASES:
    got = run(**kwargs)
    flag = "" if got == expected else "  <-- DIFFERS"
    failed += got != expected
    print(f"{name:40} {str(got[0]):11} {str(got[1]):9} {got[2]}{flag}")
print(f"\n{len(CASES) - failed}/{len(CASES)} cases match PROTOCOL_SPEC.md 11.3")
sys.exit(1 if failed else 0)
