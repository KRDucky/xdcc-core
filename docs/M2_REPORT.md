# M2 safety policies report

**Date:** 2026-11-02. **Authorization:** owner authorized M2. M3 and later milestones,
E1, and publication are not authorized.

**State:** implemented on `codex/m2-safety-policies`, from `main` at `dcc4a32`, and
committed for PR review. **M2 is not complete** until hosted CI passes on Linux, macOS,
and Windows. Local checks pass on Linux. The PR records the commit and CI results, since
this file cannot name its own commit.

This is the policy layer alone. It makes decisions that nothing calls yet, and **it does
not make a download safe**. No socket, file, DNS, runtime, or transfer code exists.
Evidence is unit, property, mutation, and fuzz testing. Nothing ran against a live bot,
client, or network, so no real-world behaviour is claimed.

## Implemented behaviour

| Area | Behaviour | Specification |
|---|---|---|
| Destinations | `NetPolicy::check` gives an `ApprovedAddr` or a named refusal, in a fixed decision order | `SECURITY.md` §4 |
| Filenames | `SafeName::from_wire` and `from_bytes` give one portable component or a refusal. `WireName` is unchanged. | `SECURITY.md` §5 |
| Limits | `Limits::new` validates configuration. It enforces no transfer limit. | `SECURITY.md` §10 |
| Rate limiter | GCRA per nick, in fixed memory, with time passed in | `SECURITY.md` §10 |

Modules are private and the types are re-exported from `policy`, so the public surface
is the types, not the file layout. `src/proto/` is unchanged, so no M1 library code moved.

**Size.** `src/policy/` has 1,116 lines of code before its test modules, or 1,772 with
comments and blanks, about twice the plan's guideline of 500. By module: `net` 381,
`rate` 302, `name` 259, `limits` 157, `mod` 17. Whether to split is the owner's decision.
If split, `net` and `name` carry the acceptance criteria, then `limits` and `rate`.

## Specification corrections

| Case | Correction | Support |
|---|---|---|
| §4 listed NAT64 and 6to4 as denied and as re-evaluated | Denied whole. Decoding only adds refusals. | Regression tests in `net.rs` |
| A /48 was assumed to carry IPv4 | `64:ff9b:1::/48` is never decoded | RFC 8215 |
| §4 had no rule for private relaxation | It relaxes the private class only | Matrix test |
| Precedence was unspecified | Never-allowed, deny, then allow at least as long as the range | `SECURITY.md` §4 |
| §4 omitted bypass-shaped ranges | IPv4-compatible, SIIT, Teredo, and others added | IANA registries, RFC 4291, RFC 4380 |
| IPv6 with no table entry counted as public | Outside `2000::/3` is refused. Found in review: `64:ff9b::1:0:0:1`, `64:ff9c::1`, `400::1`, `4000::1`, and `e000::1` were all approved. | `ipv6_outside_global_unicast_is_never_public` |
| §5 ran NFC last | NFC first, with passes repeated until stable | Hostile corpus, properties |
| §5 reserved list was wrong in both directions | Union with Microsoft's list. Superscript forms added. | Microsoft naming documentation |
| §5 missed the temporary sidecar | `.xdccmeta.tmp` is also reserved | `ARCHITECTURE.md` §7.9 |
| §10 said "5 per minute" | A sustained rate with a burst of 5. At most 9 in any 60 s window. | Sliding-window property |
| §10 said nothing is retained for unmatched offers | The limiter keeps a keyed fingerprint. The engine should consult it after request matching. | `SECURITY.md` §10 |
| `WireName::sanitize` and `store::SafeName` | `SafeName` lives in `policy`, so `proto` needs no dependency | `ARCHITECTURE.md` §4, §8.3 |
| `NetPolicy.passive` | Left out until M8 | Out of scope |
| `ipnet` was planned | Replaced by `IpPrefix`, which handles mapped rules | `ARCHITECTURE.md` §5 |

**First production dependency.** `unicode-normalization` 0.1.26, with `tinyvec`. MSRV
1.36, Unicode 18.0.0 tables, last released 2026-10-16. `Unicode-3.0` was added to both
`deny.toml` files. Both lockfiles pin the same version, so the fuzz harness and the library use
the same tables.

## Implementation deviations from the design

Each was reviewed. All are accepted.

| # | Deviation | Why | Cost | Test |
|---|---|---|---|---|
| 1 | `SafeName` stays `Clone` | The design required it. Only `ApprovedAddr` refuses cloning. | None | `compile_fail` doctests |
| 2 | A new slot inherits the shared bucket | A key that drained the bucket could take a fresh slot and pass the window maximum | Once shared budget is spent, every new nick waits up to one window, even with free slots | `new_keys_wait_for_the_shared_bucket_even_with_a_free_slot` |
| 3 | The casemapping carry also covers tracked keys | Switching a mapping back recovered a spent budget | Affected nicks wait up to one window | `switching_back_cannot_recover_a_spent_budget` |
| 4 | Extra limits: `MAX_BURST`, clamped time, whole-millisecond windows | Keeps all arithmetic free of saturation | A sub-millisecond window is refused | `each_ceiling_is_accepted_and_one_more_is_refused` |
| 5 | Later passes skip NFC unless something was removed | Bounds allocation. The final predicate still checks NFC. | None | Properties, `the_nfc_reservation_is_never_exceeded` |

Refused rather than kept: making the submodules public to satisfy rustdoc links. It widened the
API, so the documentation moved to `policy` and the modules are private.

## Advisor review

Opus reviewed the design before implementation, and the code before the freeze. Advice
was not treated as evidence. Each resolution below has a test, or says why not.

| Area | Finding | Resolution |
|---|---|---|
| Address | `::1` could never be approved, since it decoded to `0.0.0.1` | Decode only when the most specific entry is the transition range. Test: `loopback_exceptions_are_exact`. |
| Address | Metadata hosts sit inside relaxed ranges | Most-specific matching. `allow_private_destinations` matrix test. |
| Address | Mapped rules, and rules containing the mapped range | Canonicalised or refused in `IpPrefix` |
| Filename | `.xdccmeta.tmp` missing from the suffix check | Added, tested in each case form |
| Filename | Hostile names as tracked filenames would break Windows checkout | Seeds use portable names, with hostile bytes inside |
| Filename | The allocation bound relied on standard library internals | Removed. See below. |
| Limiter | "5 per minute" was ambiguous | Sustained rate, documented, with a sliding-window test |
| Limiter | Carry refused every new nick after a mapping change | Limited to nicks with a byte that folds differently |
| Limiter | Flood and retention consequences were unstated | Documented, with tests of the flood and the free-slot path |
| Final | The report had lost the design it refers to | Appended below |
| Final | `irc_line` exceeded M1's figure with no comment | Recorded under limitations |
| Final | `SECURITY.md` §10 called the rate "enforced" with no caller | Reworded. Enforcement starts when M5 and M6 call the policy. |
| Final | CI's 20-minute fuzz timeout was sized for three targets | Raised to 30 minutes |
| Final | The `CONTRIBUTING.md` and CI diffs were unread | Read and confirmed |
| Process | Implementer's passing results predated later edits | Everything was rerun. Nightly doctests were included, since stable does not check `compile_fail` codes. |
| Pre-commit | The three name oracles (`fuzz/src/lib.rs`, `tests/policy_properties.rs`, `tests/hostile_names.rs`) upper-cased stems with Unicode rules, while §5 and the library ignore ASCII case only. `conın$` (U+0131) became `CONIN$` in the oracle, so `policy_name` crashed on a name the library rightly accepts. The CI fuzz job or proptest could have hit it at random. | Oracles use `to_ascii_uppercase`. Seed `dotless-i-conin` and cases in `windows_device_names_and_streams`. No library code changed. |
| Pre-commit | `policy` module docs still said §10 needed correcting | Reworded, since §10 is corrected in this change |

Owner-directed review items:

- **Rate limiter:** deviations 2 to 4 are recorded above and in `SECURITY.md` §10.
- **Allocation bound:** the implementer's 15,387 bytes rested on claims that were false or
  unverified. Re-normalising after a removal can lengthen text, which `normalizing_after_a_removal_can_lengthen_text` shows. The rework goes below.
- **Network vectors:** see `rfc_examples_decode_to_the_published_ipv4_address` and
  `teredo_matches_an_independent_decoder`. RFC 6052 §2.4 and RFC 3056 §5.1 publish examples.
  **RFC 4380 has no worked address**, so the Teredo vector comes from CPython's `ipaddress`, a
  separate implementation rather than a published example.
- **Public API:** modules are private.
- **Metadata:** each entry has a vendor source in `SECURITY.md` §4. None is provisional.

Review of Sonnet's code also found the `2000::/3` gap, and mutation testing found the gaps below.

## Allocation evidence

Decoding, NFC, and the filter each allocate once, at a size this crate computes, so the
bound no longer assumes how the standard library grows a buffer. It still relies on the buffer growth of `unicode-normalization` 0.1.26 for runs of combining marks. That is pinned by both lockfiles, and a version change should repeat this check.

`tests/policy_unicode_tables.rs` checks each Unicode fact for every scalar value, against the shipped tables, and pins the version.

| Input | Bytes allocated |
|---|---|
| Empty, or over 512 bytes, refused | 0 |
| `NetPolicy::check` | 0 |
| Limiter, per call after creation | 0 |
| Worst name in `tests/policy_alloc_bound.rs`, including a sweep of every character normalisation acts on | 12,768 |
| Worst name found by fuzzing, over both runs | 13,478 |
| Computed bound for one name | 14,914 |
| Limit | 16,384 |

Fuzzing found a costlier name than the handwritten cases, so 12,768 is not the worst case. The bound held. Counts are cumulative, so they overstate peak use. Inputs are built outside measured regions.
M2's acceptance has no 16 KiB criterion. It is kept from M1 as a check.

The mark-run term is **a model guarded by measurement**, not proven from source. The element
types (`(u8, char)` and `char`, four inline) were read in `decompose.rs` and `recompose.rs`, but
tinyvec's growth after spilling to the heap was not. The tests and the fuzz harness measure the
real figure, and the fuzz margin against the bound is 1,436 bytes.

## Validation

**Source fingerprint:** `c766dc8aff3d3118161eec6856f79f880062a34a28b2b3c527dcb3a92d1e38f1`,
by the `M1_REPORT.md` method: the SHA-256 of the `sha256sum` listing of tracked and untracked
files under `src`, `tests`, and `fuzz`, plus `Cargo.toml`, `Cargo.lock`, and `deny.toml`, with paths
sorted in the C locale. It was the same before and after fuzzing, and it is the committed
content. The revision reviewed before the pre-commit fixes was `8f264c3c…`.

**Toolchains:** rustc 1.88.0, and rustc 1.101.0-nightly (`3e92e1a2d` 2026-11-01) for fuzzing and
doctests, on the owner's permanent rustup. cargo-fuzz 0.13.2, cargo-deny 0.20.2, cargo-audit
0.22.2, cargo-mutants 27.1.0, Python 3.14.8, CachyOS Linux x86-64.

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | Exit 0 |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | Exit 0 |
| `cargo test --workspace --all-features --locked` | Exit 0, 233 passed, 0 failed |
| `cargo test --workspace --no-default-features --locked` | Exit 0, 233 passed, 0 failed |
| `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked` | Exit 0 |
| `cargo deny --workspace --locked check` | Exit 0 |
| `cargo +nightly test --doc -p xdcc-core --locked` | Exit 0, 12 passed. Checks `compile_fail` codes. |
| From `fuzz/`: `cargo deny --locked check` and `cargo clippy --all-targets --locked -- -D warnings` | Exit 0 |
| `cargo +nightly fuzz build` | Exit 0, six targets |
| The four `docs/research/` scripts | Exit 0 |
| `cargo tree -e normal,build --workspace --locked` | `unicode-normalization` and `tinyvec` only. No Tokio. |
| `cargo audit` | Exit 0, extra to the required list |
| `cargo mutants` on `src/policy/` | 235 mutants: 208 caught, 21 unviable, 1 timeout, 5 missed |

**Mutation testing** ran before the pre-commit fixes. They changed tests, a fuzz oracle, and
one doc comment, but no decision code, so the result stands. It excluded `fmt`, `Display`, and `as_str`. The first run left 22 missed, and tests were added for 17. The 5 left do not change a decision: `truncate` `at > 0` (a leading dot is already stripped), a `|` in a constant builder (bits are disjoint), `>` in `check` (it only picks which refusal is reported), and two `&` to `^` in `probe` (one permutes the start, and the other can shrink the probe window, because out-of-range slots are skipped; insert and lookup skip the same slots, so no bypass results). The timeout is an infinite loop, so it counts as detected.

## Fuzz results

Run from `fuzz/` for 75 s each (`policy_name` for 360 s, because its oracle had changed), with
`-max_total_time` and `-print_final_stats=1`, fresh corpora, and the seeds. The six ran in
parallel on 12 cores. The figures are from this revision, after the pre-commit fixes.

| Target | `-max_len` | Executed units | Exit | Exec/s | Peak RSS | Largest library allocation | Artifacts |
|---|---|---|---|---|---|---|---|
| `policy_name` | 1024 | 1,497,903 | 0 | 4,149 | 499 MiB | 13,363 bytes | 0 |
| `policy_net` | 256 | 10,655,838 | 0 | 140,208 | 487 MiB | 0 | 0 |
| `policy_rate` | 4096 | 1,352,854 | 0 | 17,800 | 538 MiB | 0 | 0 |
| `irc_line` | 20000 | 255,266 | 0 | 3,358 | 431 MiB | 10,100 bytes | 0 |
| `ctcp` | 70000 | 9,373,624 | 0 | 123,337 | 621 MiB | 510 bytes | 0 |
| `dcc_message` | 2048 | 13,584,997 | 0 | 178,749 | 519 MiB | 489 bytes | 0 |

The worst name in the allocation table, 13,478 bytes, came from the earlier run of the
pre-fix revision. The library code is the same, so it still applies.

**M1 evidence is separate.** `fuzz/src/lib.rs` gained a helper, and `fuzz/Cargo.toml` a dependency,
so the M1 harness binaries changed, though no line in their targets, `src/proto/`, or their seeds
did. The three M1 rows are new short smoke runs of this revision. They are not a repeat of M1's 10
million executions and do not replace them. Those remain M1's evidence, for M1's revision, in
`M1_REPORT.md`.

M2 has no execution-count requirement. Fuzzing shows no failure in these executions, not that none
exists. `policy_name` is slow, so it saw far fewer inputs than the others.

## Acceptance status

| Criterion | Status |
|---|---|
| `ApprovedAddr` and `SafeName` cannot be built outside `policy` | **Met**, by `compile_fail` doctests with nightly-checked codes, paired with passing doctests |
| Zero bypass in the corpus, including the CVE-2026-32733 pattern | **Met.** `../../.ssh/authorized_keys` gives `authorized_keys`. |
| Table for every §4 range | **Met**, with first, last, and neighbours |
| Sanitiser properties and idempotence | **Met.** 2,000 cases per property, and in fuzzing. |
| Fuzz target | **Met.** Three targets, at least 60 s each. |
| IPv4-mapped and NAT64 bypass cases | **Met** |
| `SECURITY.md` §4 and §5 match the code | **Met**, by review |
| CI green on Linux, macOS, Windows | **Pending.** Results are recorded on the PR. |
| A reviewable PR, about 500 lines of non-test code | **Partly met.** One PR, as the owner directed, but the code is about twice that. |

## Limitations and open questions

- **Observation for M1, not an M2 regression.** `irc_line` recorded 10,100 bytes here, above both the 10,088 bytes M1 reported and M1's documented framing figure of 8,702 + 1,377 = 10,079. `src/proto/` is unchanged, so this is an input M1's runs did not reach, or a harness cost that figure did not model. It is under the 16 KiB limit. It was not investigated further, and no M1 measurement was changed.
- macOS and Windows are unverified. Only Linux x86-64 ran. The new CI steps have not run on GitHub.
- The metadata list is best-effort, and an address change would not be noticed.
- Deployment-specific NAT64 prefixes cannot be detected.
- An attacker can still offer a public address. `ApprovedAddr` does not authenticate the peer.
- Invisible characters outside the removal list are kept. Some removals affect real names (Q11).
- A flood can delay a new nick, including a requested bot, for up to one window.
- `ApprovedAddr` and the limiter are only useful once later milestones call them. M6 must consult the limiter after request matching, and `net` must recheck before connecting.
- `SafeName` gives no filesystem safety. Symlinks, races, and collisions are assigned to M5.
- `stats_alloc` had its last release in 2022, as noted in M1.
- Project Instructions and Project Context are still not in the repository.

## Files for this milestone

Stage these paths selectively. **`dev/irc-lab/` is the owner's Docker lab and is not part of M2.**

```text
.github/workflows/ci.yml  CONTRIBUTING.md  Cargo.lock  Cargo.toml  README.md  SECURITY.md  deny.toml
docs/ARCHITECTURE.md  docs/DEVELOPMENT_PLAN.md  docs/M1_REPORT.md  docs/M2_REPORT.md
docs/PROJECT_MEMORY.md  docs/SECURITY.md
fuzz/Cargo.lock  fuzz/Cargo.toml  fuzz/deny.toml  fuzz/src/lib.rs
fuzz/fuzz_targets/policy_name.rs  fuzz/fuzz_targets/policy_net.rs  fuzz/fuzz_targets/policy_rate.rs
fuzz/seeds/policy_name/  fuzz/seeds/policy_net/  fuzz/seeds/policy_rate/
src/lib.rs  src/policy/
tests/hostile_names.rs  tests/policy_alloc_bound.rs  tests/policy_properties.rs  tests/policy_unicode_tables.rs
```

## Appendix: design as reviewed before implementation

This is the specification the implementation was built from, kept so review can compare the two.
**`SECURITY.md` takes precedence wherever they differ.** Known differences: the tables are Unicode
18.0.0 rather than 17, GCP's `fd20:ce::254` is verified, the five deviations above apply, and IPv6
outside `2000::/3` is refused.


Layout: `src/policy/{mod,net,name,limits,rate}.rs`, `pub mod policy;` in lib.rs. No Tokio, sockets,
files, DNS, clocks, or serde. `src/proto/` is NOT modified (M1 evidence stays valid).

### N. Network policy (`net.rs`)

Verified sources: RFC 6052 §2.1-2.2, RFC 8215, RFC 3056 §2, RFC 4380 §4, RFC 4291 §2.5.5, IANA IPv4/IPv6
special registries (last updated 2025-10-09), vendor metadata docs.

N1. Types. `IpPrefix` (own small type, no `ipnet`): `IpPrefix::new(IpAddr, u8) -> Result<_, PrefixError>`.
    Refuses length over family maximum and any host bits set. Canonicalizes: an IPv6 prefix inside
    `::ffff:0:0/96` with len >= 96 becomes the IPv4 prefix (len-96). A shorter IPv6 prefix that CONTAINS
    `::ffff:0:0/96` (e.g. `::/0`) is refused as `StraddlesMapped`, because addresses are canonicalized
    first and such a rule could never match the mapped addresses it appears to cover.
N2. `NetPolicyConfig` (non_exhaustive, pub fields, Default) -> `NetPolicy::new(cfg) -> Result<NetPolicy, _>`.
    `allow_private_destinations`, `allow_low_ports`, `deny: Vec<IpPrefix>`, `allow: Vec<IpPrefix>`.
    Refuse more than MAX_RULES = 256 per list. `passive` from the §4 sketch is omitted: passive is M8.
N3. `NetPolicy::check(&self, addr: IpAddr, port: u16) -> Result<ApprovedAddr, NetRefusal>`.
    Decision order, fixed and tested:
    1. Canonicalize with `to_canonical()`.
    2. Port: 0 -> `PortZero`; < 1024 without `allow_low_ports` -> `LowPort`. 1023 refused, 1024 passes.
    3. Compute embedded IPv4 set E (N5). E is computed ONLY when the address's most specific built-in match
       is itself a decodable Transition entry. So `::` and `::1` decode nothing: their most specific
       entries are `::/128` and `::1/128`, not `::/96`. Teredo still decodes, being more specific than 2001::/23.
    4. Never tier, no setting overrides: `0.0.0.0/8`, `::/128`, `224.0.0.0/4`, `240.0.0.0/4` (includes
       255.255.255.255), `ff00::/8`. Applied to the address and every member of E.
    5. Explicit deny: matches the address or any member of E. Always beats allow.
    6. Built-in table lookup on the address: find the MOST SPECIFIC built-in range containing it.
       Public addresses (no match) and E empty -> approved.
    7. Override. A built-in match is cleared only if:
       (a) an allow rule contains the address AND rule.len >= the matched built-in range's len, or
       (b) the range is in the Private class and `allow_private_destinations` is set.
       Rule (a) means a broad `0.0.0.0/0` overrides nothing, and metadata hosts (built-in /32 or /128)
       need an exact-host allow rule. It is one rule, with no special case for metadata.
    8. Members of E are evaluated by steps 4-7 as IPv4 addresses, under the same settings. All must pass.
       So allowing `2002::/16` does not let `2002:7f00:1::` reach loopback unless loopback is also allowed.
N4. Built-in table, class in brackets. Everything in SECURITY.md §4, plus additions marked +:
    [Loopback] 127.0.0.0/8, ::1/128.
    [Private] 10/8, 172.16/12, 192.168/16, fc00::/7, 100.64.0.0/10.
    [LinkLocal] 169.254.0.0/16, fe80::/10, + fec0::/10 (deprecated site-local).
    [Metadata] 169.254.169.254/32, 100.100.100.200/32 (Alibaba), fd00:ec2::254/128 (AWS),
               fd20:ce::254/128 (GCP, seen via a summary, mark unverified in docs). Best-effort; not exhaustive. More specific than the Private
               ranges holding them, so `allow_private_destinations` does not open them.
    [SpecialUse] 192.0.0.0/24, 192.0.2.0/24, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32,
               + 192.88.99.0/24, + 100::/64, + 100:0:0:1::/64, + 2001::/23, + 3fff::/20, + 5f00::/16.
    [Transition] 64:ff9b::/96, 64:ff9b:1::/48, 2002::/16, + ::/96 (IPv4-compatible, RFC 4291 deprecated),
               + ::ffff:0:0:0/96 (SIIT), and 2001::/32 Teredo as a more specific entry than 2001::/23.
    `allow_private_destinations` relaxes the Private class only. Not loopback, link-local, metadata,
    special-use, or transition. Loopback for tests and M4 is reachable only through an explicit allow rule
    (`127.0.0.1/32` or any rule of len >= 8 inside it). Link-local likewise.
    IANA lists some globally reachable entries inside 2001::/23 and 192.0.0.0/24; denying the parents is
    deliberate: no DCC peer belongs there. 192.31.196.0/24, 192.52.193.0/24, 192.175.48.0/24, and
    2620:4f:8000::/48 are not denied. 64:ff9b::/96 is Globally Reachable True in IANA, and is denied anyway,
    see N5.
N5. NAT64 / 6to4 resolution of the §4 ambiguity. DEFAULT: all transition prefixes are denied as whole
    prefixes. Decoding never approves anything by itself; it only adds refusals. Set E:
    - `64:ff9b::/96`: bits 96-127 (RFC 6052 §2.2, /96 row).
    - `2002::/16`: bits 16-47 (RFC 3056 §2).
    - `::/96` and `::ffff:0:0:0/96`: bits 96-127.
    - Teredo `2001::/32`: server bits 32-63; client = bits 96-127 XOR 0xFFFFFFFF (RFC 4380 §4). Both go in E.
    - `64:ff9b:1::/48`: NOT decoded. RFC 8215 says nodes must not assume the existence or location of
      embedded IPv4. Refuse as a whole. An operator's explicit allow (len >= 48) passes it undecoded.
    - Deployment-specific network-specific prefixes (RFC 6052 §2.2, any of /32 /40 /48 /56 /64 /96 inside
      global space) cannot be detected from the address. Say so plainly in docs: this is a limitation, not
      coverage. Never describe translation detection as universal.
N6. `ApprovedAddr`: private fields (canonical IpAddr, NonZeroU16), not Clone/Copy/Default, no From/TryFrom/
    FromStr/Deserialize, read accessors `ip()`, `port()`, `socket_addr()`. Only `check` builds it. Docs state:
    a decision for one endpoint at one moment, does not authenticate the peer, future `net` must call
    `check` again immediately before connecting (SEC-2), and parsing an offer never produces one. No function
    takes `DccOffer` or `OfferEndpoint`; passive offers have nothing to approve.
N7. Refusal enum `NetRefusal` non_exhaustive, naming the reason and class; Copy; no hostile data retained.

### S. Filename policy (`name.rs`)

Verified: Microsoft "Naming Files, Paths, and Namespaces" and "File Streams".

S1. Entry: `SafeName::from_wire(&WireName)` using `WireName::name()` (unquoted bytes, not `as_bytes()`), and
    `SafeName::from_bytes(&[u8])` for host names. Replaces the `WireName::sanitize` sketch and the
    `store::SafeName` placement: `proto` must not depend on `policy`. Record as spec corrections.
S2. Refuse empty or > MAX_INPUT = 512 bytes BEFORE any allocation.
S3. `from_utf8_lossy`. Then iterate `pass` to a fixed point, at most MAX_PASSES = 4; if not stable, refuse
    `Unstable`. Success requires `pass(x) == x` and then `is_valid_safe_name(x)`, a separate predicate
    that shares no transformation code. Thus idempotence holds by construction: `sanitize(out) == out`.
    The loop exists because each step can invalidate another (removal can create a composable pair, NFC
    can create ASCII such as U+212A -> K, U+037E -> `;`, truncation can expose a trailing dot, a prefix can pass 200).
`pass(s)`:
    1. NFC (`unicode-normalization`). First, so that later checks see the final characters.
    2. Keep text after the last `/` or `\`. A trailing separator leaves empty -> refuse.
    3. Remove: C0, DEL, C1, U+00AD, U+034F, U+061C, U+180E, U+200B-U+200F, U+2028-U+202E, U+2060-U+2064,
       U+2066-U+2069, U+FEFF, U+FFF9-U+FFFB, U+E0000-U+E007F. Goes beyond §5; record it.
    4. Replace with `_`: `< > : " | ? *`, plus lookalike separators U+2044, U+2215, U+29F8, U+FF0F, U+FF3C, U+FE68.
       Colon covers ADS (`f.txt:s`, `f.txt::$DATA`) and drive forms (`C:x`).
    5. Strip leading `.`, ASCII space, `-`; strip trailing `.`, ASCII space. Empty -> refuse.
    6. Reserved stem: stem = text before the first `.`, trailing spaces ignored, ASCII case-insensitive.
       Reserved: CON PRN AUX NUL, COM0-9, LPT0-9, COM¹²³, LPT¹²³ (U+00B9, U+00B2, U+00B3), CONIN$, CONOUT$.
       Prefix `_`. Microsoft's list has superscripts and no COM0/LPT0; §5 had the reverse. We take the union:
       COM0/LPT0 stay as portable caution, CONIN$/CONOUT$ are a project choice not on those pages.
       `COM⁴` (U+2074) is not reserved.
    7. Reserved suffix, ASCII case-insensitive: ends with `.xdccpart`, `.xdccmeta`, or `.xdccmeta.tmp`
       (the last is the CP3 temp sidecar, ARCHITECTURE.md §7.9) -> refuse. Tested with each.
    8. Truncate to MAX_OUTPUT = 200 UTF-8 bytes on a char boundary. Extension = text from the last `.`, kept
       only if its stem is nonempty and it is <= MAX_EXTENSION = 32 bytes; otherwise it counts as stem.
       The stem is cut so stem+ext <= 200.
    Percent sequences are literal: no decoding anywhere.
S4. Refusal enum `NameRefusal` non_exhaustive: Empty, TooLong, EmptyAfterSanitizing, ReservedSuffix, Unstable.
    Holds no input bytes.
S5. `SafeName`: private `Box<str>` field, no Default/From/FromStr/Deserialize/DerefMut/AsMut. `as_str()`, `as_bytes()`,
    Display, Debug, Clone, Eq, Hash. Docs: sanitization can cause collisions (`a?b` and `a*b`, `CON`
    and `_CON`), does not authorize overwriting, does not establish containment; symlink, race, exclusive
    create, case-collision on the target filesystem belong to M5 storage (SEC-4, SEC-5).
S6. `WireName` stays unchanged and RESUME keeps using it.

### L. Limits (`limits.rs`)

`LimitsConfig` non_exhaustive, pub fields, Default equals SECURITY.md §10 -> `Limits::new(cfg) -> Result<Limits, LimitsError>`.
Fields: max_concurrent_transfers 4, max_per_bot_transfers 1, max_file_size 64 GiB, read_buffer 256 KiB,
event_ring 256, transfer_mailbox 64, storage_queue 8, irc_inbound 256, irc_outbound 64, finished_outcomes 1024,
reconcile_attempts 8, bot_notice_bytes 512, offers_per_window 5, offer_window 60 s, tracked_offer_keys 1024.
Fixed consts, not configurable: filename input 512, inbound line MAX_LINE_LEN from proto.
Refuse: any zero; per_bot > concurrent; read_buffer over 16 MiB; bot_notice_bytes over 8192; any of the
queue/ring capacities over 1 << 20; concurrent over 4096; concurrent × read_buffer and concurrent × event_ring overflow
or over 64 GiB; offer_window over 1 day; window not representable; emission interval rounds to zero; tracked keys over 1 << 20.
Module docs carry a table: which limit each later layer enforces. Policy enforces none of the transfer ones.

### R. Rate limiter (`rate.rs`)

R1. GCRA, integer milliseconds. `OfferRateLimiter<S = RandomState>`. Time passed as `Duration` since a
    caller-chosen origin. Monotonic in caller terms; no clock read.
    emission = ceil(window_ms / burst), burst tolerance = (burst-1) × emission.
    Allow iff TAT <= now + tolerance, then TAT = max(TAT, now) + emission. Default: 5 at once, then one per 12 s.
    Exact boundary allows. Saturating arithmetic. now converts with saturation.
    SPECIFICATION CORRECTION: §10's "5 per minute" means a SUSTAINED rate of 5 per minute with a burst of 5, not a hard
    cap. The maximum in any half-open 60 s window is 9 (2×burst-1): 5 at t=0, then 12, 24, 36, 48. A hard cap would need
    per-key timestamp logs. Test asserts this maximum with a sliding window over generated schedules.
R2. Backward time: effective now = max(now, high_water). No refill, no panic, no extra budget. Forward jump refills normally.
R3. Keys. `check(&mut self, nick: &[u8], now) -> RateDecision`. Fingerprint = `BuildHasher` over bytes folded
    by the current `CaseMapping`, byte by byte, no allocation, length included. Store only the 64-bit fingerprint,
    never nick bytes. Nick over 512 bytes goes to the shared bucket without hashing.
    Fingerprint collision merges two nicks: over-limits, safe.
R4. Table: fixed-size Vec allocated in `new`, power of two >= tracked keys; probe at most MAX_PROBE = 16 slots from
    the hash. No allocation or growth afterward; each call is O(MAX_PROBE + nick length).
R5. Reclaim only slots whose TAT <= now, meaning fully refilled: forgetting them gives that key exactly the
    budget it already had. Never evict a slot with unrefilled budget, so a flood cannot reset an attacker's budget.
R6. No slot in the probe window -> the key uses one shared overflow bucket with the same parameters. Result
    `LimitedShared` vs `Limited` is distinguishable. A flood exhausts the shared bucket, so untracked keys are refused
    (fail closed); tracked keys are unaffected. Document that a flood can delay a new nick by up to the window.
R7. Casemapping change. `set_casemapping(new)`: if different, old fingerprints cannot be recomputed. A nick with no byte
    that folds differently between the old and new mapping keeps its fingerprint and cannot escape, so only nicks
    with such a byte need care. Set `carry_until = max TAT in table and shared bucket` (O(table), rare, bounded) and remember
    each mapping seen during the carry, at most 3 (fixed array). While now < carry_until, a key with no slot whose bytes fold
    differently under any remembered mapping (checked per byte, no allocation) starts at TAT = carry_until, i.e. no
    budget. Others are unaffected, so a requested bot after a reconnect is normally unaffected.
R9. Flood consequence and §10. About `tracked_keys` unique nicks within one emission interval fill the table and drain the
    shared bucket; offers from any new nick are then refused for up to one window, and a requested bot is usually a new
    nick. §10 says no memory is retained for unmatched offers, yet the limiter holds 64-bit fingerprints of them. Docs state
    both, and that the future engine should consult the limiter only AFTER request matching. Correct §10 accordingly. A test runs a
    flood then a legitimate new nick and asserts the documented behaviour.
R8. `RateConfig { burst, window, tracked_keys }` validated, derived from `Limits`. `with_hasher` constructor for deterministic tests.

### T. Tests

Unit: table for every §4 range plus additions: first, last, and both neighbours; both families; mapped forms of every
IPv4 row; port 0/1/1023/1024/65535; precedence matrix; allow broad vs exact; `allow_private_destinations` matrix with
loopback, multicast, unspecified, metadata; rule canonicalization (`::ffff:10.0.0.0/104` equals `10.0.0.0/8`, in allow and deny).
NAT64/6to4/compat/SIIT/Teredo bypass cases incl. explicit allow of the outer prefix with loopback or metadata inside.
`tests/hostile_names.rs`: corpus in Rust literals (incl. `../../.ssh/authorized_keys`, CVE-2026-32733, Halloy; result `authorized_keys`).
Properties (proptest): validity predicate, NFC, bounded, idempotent, one component, no reserved forms; `check` results equal for an
IPv4 and its mapped form. Compile-fail: `compile_fail` doctests for building, cloning, and defaulting ApprovedAddr and SafeName,
each paired with a passing doctest of the public path. `tests/policy_alloc_bound.rs`: one test, inputs built outside regions; 0 bytes for
oversized input, a computed bound for accepted input; limiter 0 bytes per call after `new`.
Fuzz: `policy_name`, `policy_net`, `policy_rate`. Seeds in fuzz/seeds/<target>/ with safe portable FILENAMES; hostile content only in file bytes.
CI: extend the fuzz job with mkdir first. Do not touch `.gitattributes` unless needed.

Add a test: explicit `::1/128` allow approves `[::1]:1024`; without it, refused.

### D. Dependencies

`unicode-normalization` 0.1.26: first production dependency. `default-features = false` if that keeps `std`-less tables working;
otherwise defaults. MSRV 1.36, Unicode 17.0.0 tables, licence `(MIT OR Apache-2.0) AND Unicode-3.0`; `tinyvec` is `Zlib OR Apache-2.0 OR MIT`.
Add `Unicode-3.0` (and `Zlib` only if cargo-deny needs it) to BOTH deny.toml files. Update both lockfiles. No other production dependency.
