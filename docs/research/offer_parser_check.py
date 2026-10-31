#!/usr/bin/env python3
"""Executable statement of the DCC SEND decision procedure in PROTOCOL_SPEC.md 7.4.

Research artifact, not production code. It checks that the published vectors and
the published rules agree, and that a malformed field never falls through to a
different shape. Exit status is non-zero on any disagreement.
"""
import ipaddress
import random
import sys

U32 = (1 << 32) - 1
U64 = (1 << 64) - 1
TRUNC_LIMIT = 480


class Bad(Exception):
    pass


def digits(t, maximum, err):
    if not (t.isascii() and t.isdigit()) or len(t) > 20 or int(t) > maximum:
        raise Bad(err)
    return int(t)


def is_zero(t):
    return t.isascii() and t.isdigit() and int(t) == 0


def address(t):
    """Returns (ip_text, in_0_slash_8)."""
    if ":" in t:
        try:
            return str(ipaddress.IPv6Address(t)), False
        except ValueError:
            raise Bad("BadAddress")
    if "." in t:
        try:
            ip = ipaddress.IPv4Address(t)
        except ValueError:
            raise Bad("BadAddress")
    else:
        ip = ipaddress.IPv4Address(digits(t, U32, "BadAddress"))
    return str(ip), int(ip) < (1 << 24)


def token_ok(t):
    return 1 <= len(t) <= 64 and t.isascii() and all(33 <= ord(c) <= 126 and c != '"' for c in t)


def fields(shape, name, tail):
    if not name:
        raise Bad("EmptyName")
    if shape == "legacy":
        addr, port = tail
        size = None
    elif shape == "standard":
        addr, port, size = tail
    else:
        addr, _, size, token = tail
        ip, unusable = address(addr)
        if not token_ok(token):
            raise Bad("BadToken")
        return dict(shape=shape, name=name, addr=None if unusable else ip, port=0,
                    size=digits(size, U64, "BadSize"), token=token)
    if is_zero(port):
        raise Bad("PortZeroWithoutToken")
    p = digits(port, 65535, "BadPort")
    ip, unusable = address(addr)
    if unusable:
        raise Bad("ImplausibleAddress")
    return dict(shape=shape, name=name, addr=ip, port=p,
                size=None if size is None else digits(size, U64, "BadSize"), token=None)


def parse(args, final_delim=True, near_limit=False):
    args = args.strip(" ")
    if args.startswith('"'):
        end = args.rfind('" ')
        if end <= 0:
            raise Bad("UnterminatedQuote")
        name, tail = args[1:end], args[end + 2:].split()
        if len(tail) == 2:
            shape = "legacy"
        elif len(tail) == 3:
            shape = "standard"
        elif len(tail) == 4:
            if not is_zero(tail[1]):
                raise Bad("UnexpectedToken")
            shape = "passive"
        else:
            raise Bad("BadFieldCount")
    else:
        t = args.split()
        k = len(t)
        if k < 3:
            raise Bad("TooFewFields")
        if k == 3:
            shape, n = "legacy", 2
        elif k >= 5 and is_zero(t[k - 3]):
            shape, n = "passive", 4
        else:
            shape, n = "standard", 3
        tail = t[k - n:]
        end = len(args)
        for field in reversed(tail):
            end = args.rindex(field, 0, end)
        name = args[:end].rstrip(" ")
    out = fields(shape, name, tail)
    if not final_delim and (shape == "legacy" or near_limit):
        raise Bad("SuspectedTruncation")
    return out


A, B = "3232235777", "2130706433"
# args, expected: ("shape", name, addr, port, size, token) or error name
VECTORS = [
    (f"file.bin {A} 5000 1024", ("standard", "file.bin", "192.168.1.1", 5000, 1024, None)),
    (f'"a b.bin" {A} 5000 1024', ("standard", "a b.bin", "192.168.1.1", 5000, 1024, None)),
    (f"a b.bin {A} 5000 1024", ("standard", "a b.bin", "192.168.1.1", 5000, 1024, None)),
    (f"report 2024 {A} 5000 1024", ("standard", "report 2024", "192.168.1.1", 5000, 1024, None)),
    (f"f.bin {A} 5000 99999999999", ("standard", "f.bin", "192.168.1.1", 5000, 99999999999, None)),
    (f"f.bin {A} 5000 0", ("standard", "f.bin", "192.168.1.1", 5000, 0, None)),
    ("f.bin 2001:db8::1 5000 1024", ("standard", "f.bin", "2001:db8::1", 5000, 1024, None)),
    ("f.bin 192.168.1.1 5000 1024", ("standard", "f.bin", "192.168.1.1", 5000, 1024, None)),
    (f"f.bin  {A}   5000 1024 ", ("standard", "f.bin", "192.168.1.1", 5000, 1024, None)),
    ("file.bin 199 0 1024 77", ("passive", "file.bin", None, 0, 1024, "77")),
    ("a b.bin 199 0 1024 77", ("passive", "a b.bin", None, 0, 1024, "77")),
    (f'"a b.bin" {A} 0 1024 ab-7', ("passive", "a b.bin", "192.168.1.1", 0, 1024, "ab-7")),
    (f"f.bin {A} 5000", ("legacy", "f.bin", "192.168.1.1", 5000, None, None)),
    (f'"a b.bin" {A} 5000', ("legacy", "a b.bin", "192.168.1.1", 5000, None, None)),
    (f"f.bin {A} 70000 1024", "BadPort"),
    (f"f.bin {A} -5000 1024", "BadPort"),
    (f"f.bin {A} 5000 -1", "BadSize"),
    (f"f.bin {A} 5000 +1", "BadSize"),
    (f"f.bin {A} 5000 18446744073709551616", "BadSize"),
    (f"f.bin {A} 5000 1k", "BadSize"),
    (f"f.bin {A} abc 1024", "BadPort"),
    ("f.bin 4294967296 5000 1024", "BadAddress"),
    ("f.bin 999.1.1.1 5000 1024", "BadAddress"),
    ("f.bin host.example 5000 1024", "BadAddress"),
    ("f.bin 5000 1024 77", "ImplausibleAddress"),
    (f"f.bin {A} 5000 1024 77", "ImplausibleAddress"),
    (f'"f.bin" {A} 5000 1024 77', "UnexpectedToken"),
    (f"f.bin {A} 0 1024", "PortZeroWithoutToken"),
    (f"a b.bin {A} 5000", "BadPort"),
    (f"report 2024 {A} 5000", "BadPort"),
    (f"f.bin {A}", "TooFewFields"),
    (f'"a b.bin {A} 5000 1024', "UnterminatedQuote"),
    (f'"" {A} 5000 1024', "EmptyName"),
    (f"f.bin 199 0 1024 {'x' * 65}", "BadToken"),
    (f"f.bin 199 0 -1 77", "BadSize"),
]

failed = 0
for args, want in VECTORS:
    try:
        r = parse(args)
        got = (r["shape"], r["name"], r["addr"], r["port"], r["size"], r["token"])
    except Bad as e:
        got = str(e)
    if got != want:
        failed += 1
        print(f"VECTOR FAIL {args!r}\n  want {want}\n  got  {got}")

# Truncation rules.
for args, final, near, want in [
    (f"f.bin {A} 5000", False, False, "SuspectedTruncation"),
    (f"f.bin {A} 5000 10", False, True, "SuspectedTruncation"),
]:
    try:
        parse(args, final, near)
        got = "accepted"
    except Bad as e:
        got = str(e)
    if got != want:
        failed += 1
        print("TRUNCATION FAIL", args, got)
if parse(f"f.bin {A} 5000 1024", False, False)["size"] != 1024:
    failed += 1

# Property checks with a fixed seed.
rng = random.Random(20261031)
WORDS = ["a", "b.bin", "2024", "0", "ep", "1", "report", "9999999999", "x.y", "0.1"]
ADDRS = [A, B, "16777216", "4294967295", "8.8.8.8", "2001:db8::2"]


def name():
    return " ".join(rng.choice(WORDS) for _ in range(rng.randint(1, 4)))


round_trips = no_fallback = 0
for _ in range(200000):
    n, addr, port, size = name(), rng.choice(ADDRS), rng.randint(1, 65535), rng.randint(0, U64)
    quoted = rng.random() < .3
    wire = f'"{n}"' if quoted else n
    passive = rng.random() < .3
    tail = f"{addr} 0 {size} {rng.randint(1, 9999)}" if passive else f"{addr} {port} {size}"
    r = parse(f"{wire} {tail}")
    if r["name"] != n or r["size"] != size or r["shape"] != ("passive" if passive else "standard"):
        failed += 1
        print("ROUND TRIP FAIL", wire, tail, r)
    round_trips += 1
    # Corrupt exactly one numeric field. The offer must be refused, never reinterpreted.
    bad = rng.choice(["70000", "-1", "1x", "+5", "99999999999999999999999"])
    if not passive:
        mutated = rng.choice([f"{addr} {bad} {size}", f"{addr} {port} {bad}"])
        if bad == "70000" and mutated.endswith(" 70000"):
            continue  # 70000 is a legal size
        try:
            r = parse(f"{wire} {mutated}")
            failed += 1
            print("FALLBACK", wire, mutated, r)
        except Bad:
            no_fallback += 1

print(f"{len(VECTORS)} vectors, {round_trips} round trips, {no_fallback} corrupted offers refused, failures: {failed}")
sys.exit(1 if failed else 0)
