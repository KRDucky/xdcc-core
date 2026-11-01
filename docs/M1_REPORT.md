# M1 protocol codecs report

**Date:** 2026-11-01. **Authorization:** owner authorized M1. M2 and later milestones,
E1, and publication are not authorized.

**State:** implemented on `codex/m1-protocol-codecs`, uncommitted, for independent
review. **M1 is not complete.** Local checks pass, and the fuzz and allocation criteria
are met on Linux, but hosted CI on Linux, macOS, and Windows has not run on this work.

Everything below is codec validation: unit tests, property tests, fuzzing, and a
differential run against this project's own Python model. Nothing was run against a
live bot, client, or network, so **no real-world compatibility is claimed**.

## Implemented behaviour

| Area | Behaviour |
|---|---|
| Framing | `LineFramer` is incremental, uses one fixed buffer, and gives the same frames for any chunking. An oversized line is reported once and discarded through the next LF, and no fragment is ever parsed. |
| IRC messages | Allocation-free. Tag budget 8191 bytes, message budget 510 bytes, independent of each other. Lazy tags, at most 15 parameters. |
| CTCP | One leading delimiter only, and no quoting. The closing delimiter and truncation context are carried on every parse. |
| DCC SEND | Shape first, then fields, with no fallback. Exact bytes and quoting kept. Addresses are untrusted claims. |
| RESUME, ACCEPT | Parsed under the pending attempt's tail, active or passive. Encoders for both. |
| XDCC, outbound | Request builders, validated lines, an explicit relay budget. Nothing is truncated. |
| Casemapping | `ascii`, `rfc1459`, `rfc1459-strict`, confirmed from the Modern IRC docs. `rfc7613` is reported as unsupported. |

The library has no production dependencies. `src/proto/` has 2,031 lines before its
test modules, comments included.

## Design corrections

| Case | Correction |
|---|---|
| `CASEMAPPING` was marked unverified | Confirmed from S2, including the `rfc1459` default when the parameter is absent |
| A body cannot show its line's length, so `SuspectedTruncation` had no evidence | `parse_ctcp` needs a `LineContext`. Only bytes outside the tags count, and the prefix does. |
| §9 rule 3 would abort an attempt on a cut ACCEPT position | The truncation rule now covers RESUME and ACCEPT (§7.5) |
| ACCEPT needs its tail chosen by context | `parse_dcc` takes the pending tail. With none, the result is `Unsolicited`. |
| §7.5 gave no order or position error | Order defined, and `BadPosition` added |
| Python `is_zero` had no length limit, unlike §7.4 | The artifact now follows §7.4. Its printed results did not change. |
| `a 2024 0 16777216 70000` looked like a fallback | It is a passive offer by the grammar, since legacy cannot carry that name. Recorded in §7.4, with a vector. |
| The relay budget had no figure | 109 bytes reserved by default, or the exact source if known. Q20 tracks whether that is enough. |
| `cargo deny` passed without reviewing dev-dependency licences | `include-dev = true` added. The fuzz package gets its own `deny.toml` and run. |

## Independent review findings

All three were reproduced with an external probe on the unmodified code before any
fix. Each regression test below failed on that code, except where noted.

| # | Finding | Before | After | Fix | Regression coverage |
|---|---|---|---|---|---|
| 1 | Outbound builders allocated before refusing | `privmsg` and `ctcp_privmsg`, 1 MiB body: 1,048,590 bytes each | 0 bytes at 389 B, 64 KiB, 1 MiB, and 64 MiB | Length is computed with checked arithmetic and compared before allocating. `encode_ctcp` uses checked arithmetic too. | `alloc_bound`, `budget_arithmetic_saturates_instead_of_overflowing` |
| 2 | Derived `LineFramer::Clone` lost the fixed buffer | Cloned framer, one maximum tagged DCC line: 16,843 bytes | `Clone` removed. Same line: 8,702 + 1,377 = 10,079 bytes. | Nothing used it, and a framer is one stream's position | `compile_fail` doctest, `the_buffer_stays_fixed_through_every_state`, `alloc_bound` |
| 3 | `BotNick::parse` accepted control bytes | 29 of 33 ASCII controls accepted, including tab, ESC, and DEL | 0 of 33 | `u8::is_ascii_control`, reported as `ForbiddenByte` | `every_ascii_control_byte_is_refused_at_every_position`, `the_reported_control_bytes_are_refused`, `printable_and_non_ascii_bytes_keep_their_behaviour` |

Details:

- **Finding 1.** Injection checks still run first, so an oversized hostile body reports `ForbiddenByte`, also at 0 bytes. A line that fits allocates exactly its own length.
- **Finding 2.** `the_buffer_stays_fixed_through_every_state` checks capacity and buffer address when empty, partly filled, just completed, at both maximum budgets, with the buffer full and waiting for LF, in discard mode, and after reset. It passes on the old code too, as a guard, because the fault needed a clone. The `compile_fail` doctest is what fails there.
- **Finding 3.** Bytes above `0x7F` stay allowed, and this is tested for all 128 values, so non-UTF-8 nicks behave as before. No wider nick policy was added.

The extended `ctcp` harness was also checked against the old code, using the seeds
alone. For finding 1, the old `message_line` tripped the exact-size assertion on an
accepted line, because it reserved one byte too many. With only that byte corrected
and the allocate-then-check order kept, `a refused body allocated` fired, at 413 bytes.
For finding 3, the old check tripped the no-control assertion. Finding 2 cannot be
reverted the same way, because the harness no longer compiles against a clone.
`frame_stream` instead asserts an exact buffer size and zero allocation while framing,
which covers the guarantee directly.

## Validation on the corrected revision

**Source fingerprint:** `825bfbdfdc459aa80b4e14399327e2a229f24c398f26e4b2434900dfbf0cab8f`.
It is the SHA-256 of the `sha256sum` listing of every tracked and untracked file under
`src`, `tests`, and `fuzz`, plus `Cargo.toml`, `Cargo.lock`, and `deny.toml`. It was the
same before and after the fuzz runs, and the fuzz binaries were byte-identical. It
describes uncommitted work on top of `2797b59`.

**Toolchains:** rustc 1.88.0 for the checks, rustc 1.101.0-nightly (`f9ceb4a4d`
2026-10-31) and cargo-fuzz 0.13.2 for fuzzing, cargo-deny 0.20.2, Python 3.14.8, on
CachyOS Linux x86-64.

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | Exit 0 |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | Exit 0 |
| `cargo test --workspace --all-features --locked` | Exit 0, 114 passed, 0 failed |
| `cargo test --workspace --no-default-features --locked` | Exit 0, 114 passed, 0 failed |
| `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked` | Exit 0 |
| `cargo deny --workspace --locked check` | Exit 0: advisories, bans, licences, sources ok |
| `cargo deny --locked check`, from `fuzz/` | Exit 0: advisories, bans, licences, sources ok |
| `cargo clippy --all-targets --locked -- -D warnings`, from `fuzz/` | Exit 0 |
| `python3 -I docs/research/ack_behaviour_model.py` | Exit 0, 11 of 11 cases |
| `python3 -I docs/research/offer_parser_check.py` | Exit 0, 35 vectors, 200,000 round trips, 125,592 corrupted offers refused, 0 failures |
| `python3 -I docs/research/accounting_check.py` | Exit 0, 4,000 runs, 0 failures |
| `python3 -I docs/research/durability_model.py` | Exit 0, 0 mismatches |
| `cargo tree -e normal,build --workspace --locked` | No dependencies. Tokio appears in no graph, dev and fuzz included. |
| Rust and Python differential, one-off, not in the repository | 3,000,000 generated offers, 0 disagreements |

## Fuzz results

Run from `fuzz/` with `-runs=10000000 -print_final_stats=1`, each process counting
from zero, using corpora from earlier runs:

```sh
cargo +nightly fuzz run ctcp <corpus> seeds/ctcp -- -runs=10000000 -max_len=70000 -print_final_stats=1
cargo +nightly fuzz run dcc_message <corpus> seeds/dcc_message -- -runs=10000000 -max_len=2048 -print_final_stats=1
cargo +nightly fuzz run irc_line <corpus> seeds/irc_line -- -runs=10000000 -max_len=20000 -print_final_stats=1
```

| Target | Executed units | Exit | Time | Exec/s | Peak RSS | Largest measured library allocation | Artifacts |
|---|---|---|---|---|---|---|---|
| `ctcp` | 10,000,000 | 0 | 79 s | 126,582 | 624 MiB | 510 bytes | 0 |
| `dcc_message` | 10,000,000 | 0 | 59 s | 169,491 | 494 MiB | 490 bytes | 0 |
| `irc_line` | 10,000,000 | 0 | 3,360 s | 2,976 | 557 MiB | 10,088 bytes | 0 |

The logs have no panic or sanitizer error. Peak RSS is the fuzzing process, its corpus
included, and is not a library figure.

**Superseded runs, not counted as evidence.** Earlier executables ran before the review
fixes. `ctcp` and `dcc_message` finished 10 million there. `irc_line` was stopped by
SIGTERM at about 8.87 million when these fixes superseded it, with no artifact. An
earlier `dcc_message` run crashed at about 470,000 executions on a harness bug: it
trusted its own "closed" flag when a `0x01` in the arguments had closed the body. The
library was correct, and that input is now a seed and the test
`an_embedded_delimiter_closes_the_message`.

## Allocation evidence

The limit is 16,384 bytes per input.

- **Method.** `stats_alloc` counts through the global allocator, with no `unsafe` in this project. Counts are cumulative, so reallocation growth counts and frees do not reduce them. That overstates peak use.
- **Library and harness are separate.** Regions open only around library calls. Inputs are built before a region opens, and libFuzzer's own inputs use C allocation, which this allocator never sees. `tests/alloc_bound.rs` holds one test, because the counters are global.
- **Framing bound.** The framer's buffer plus the costliest single line, because each line's values are dropped before the next line. An input with many lines allocates more cumulatively, but no more at once.
- **The check can fire.** A temporary 20,000-byte allocation in `parse_dcc` was reported as `library allocated 20001 bytes` and stopped the run. The code was then restored.

| Input, in `tests/alloc_bound.rs` | Framer | Worst line | Growth while framing |
|---|---|---|---|
| Longest offer, 510-byte message | 8,702 | 1,377 | 0 |
| Many tokens | 8,702 | 1,371 | 0 |
| 200 longest offers | 8,702 | 1,377 | 0 |
| Maximum tags and message, 8,701 bytes | 8,702 | 1,377 | 0 |
| 1 MiB with no newline | 8,702 | 0 | 0 |
| 1 MiB of oversized tags | 8,702 | 0 | 0 |

`worst line` is three decodes of one line, one per pending context, so one decode costs
a third of that.

## Acceptance status

| Criterion | Status |
|---|---|
| All spec vectors pass with the exact documented error | **Met.** All 35 in `tests/dcc_vectors.rs`. |
| 10 million fuzz executions per target with no crash | **Met** on Linux, on this revision |
| No input allocating over 16 KiB | **Met** by measurement and by the documented bound. Largest seen: 10,088 bytes. |
| Three fuzz targets | **Met** |
| Round-trip, never-panic, and numeric-corruption properties | **Met.** 14 property tests, 2,000 cases each. |
| Every parsing rule in §3, §4, §7 has a test | **Met**, except rules with no code to test: §3 "no reply to NOTICE" and §4 rule 6, since nothing here sends a reply |
| No I/O or Tokio in `proto`, `--no-default-features` builds | **Met** |
| Vector cases from I1 to I6 | **Partly met.** `documented_sender_forms` covers I1, I2, I3, I5, and V2, written from `PROTOCOL_SPEC.md` observations. I4 is covered by the closing-quote test. I6 has no dedicated case. |
| CI green on Linux, macOS, Windows | **Not met.** Not run on this work. |
| Reviewable PR, ideally under about 500 lines of non-test code | **Not met.** No PR exists, by instruction, and `proto` is about four times that size. |

## Limitations and open questions

- macOS and Windows are unverified. Only Linux x86-64 ran.
- The new CI `fuzz` job and the fuzz `cargo deny` step have not run on GitHub. The job uses an unpinned nightly, so a later nightly could behave differently.
- Fuzzing shows no failure in these executions, not that none exists. `irc_line` is much slower, because it frames every input twice and handles long lines.
- The large `ctcp` seeds run once at the start of each run, but libFuzzer keeps a smaller corpus, so most executions use small bodies. Refusal takes the same branch at any size, and `tests/alloc_bound.rs` covers up to 64 MiB directly.
- A few bytes of behaviour remain project choices, not evidence: the 480-byte threshold (Q19), the 109-byte reservation (Q20), and strict refusals (Q9, Q18, D16).
- A nonzero-port-plus-token reply has no encoder until M8, and `[CRC]` pack syntax is unverified.
- `stats_alloc` had its last release in 2022. It is a dev-dependency only, and has no advisory in the database used.
- Project Instructions and Project Context are still not in the repository.

## Toolchain used in this session

Temporary directories only, with no shell profile changes. They may disappear.

```sh
export CARGO_HOME=/tmp/xdcc-m0-cargo RUSTUP_HOME=/tmp/xdcc-m0-rustup
export PATH="$CARGO_HOME/bin:/tmp/xdcc-m1-tools/bin:$PATH"
```

cargo-deny is under `/tmp/xdcc-m0-tools/cargo-deny-0.20.2-x86_64-unknown-linux-musl/`.
