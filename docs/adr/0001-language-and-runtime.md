# ADR 0001: Language and runtime

**Status:** Accepted for M0 by owner authorization on 2026-10-31. Later storage
and reconciliation choices (D17 to D19) remain pending; they are not implemented
or implicitly approved by this bootstrap.

**Date:** 2026-10-31

## Context

XDCC Core parses hostile input, writes files named by remote parties, and must run many concurrent long-lived network transfers. It is intended as a reusable library. The project brief specifies Rust, so this ADR records why that fits, and settles the runtime and baseline around it.

Forces:

- Memory safety matters. Parsers process attacker-controlled data.
- A single process may run several multi-hour transfers while holding an IRC session.
- Hosts include CLI tools, daemons, and applications that already have an IRC connection.
- Most protocol logic should be testable with no runtime.

## Decision

1. **Language:** Rust, edition 2024.
2. **Safety:** `#![forbid(unsafe_code)]` in `xdcc-core`. Platform needs go through maintained crates (`cap-std`, `rustix`, `socket2`).
3. **Runtime:** Tokio, multi-thread or current-thread as chosen by the host. The library starts no runtime of its own.
4. **Architecture:** pure core with no runtime dependency (`proto`, `policy`, `machine`, `profile`), and a Tokio shell behind the default `runtime` feature.
5. **Async style:** an actor per session and a task per transfer, communicating over bounded channels. No locks across `.await`.
6. **Minimum Rust:** 1.88, set in `rust-version`, with toolchain 1.88.0 pinned for M0. The planned bound came from `proptest` 1.12 and Tokio 1.54; neither is a dependency at bootstrap. Both empty crates pass local checks on 1.88.0. Re-check dependency requirements when adding them, and raise the MSRV only deliberately.

## Alternatives considered

| Option | Why not |
|---|---|
| C or C++ | Hand-written parsers of hostile input in these languages carry memory-safety risk that Rust removes |
| Go | Capable, but the brief asks for Rust. Less suited to embedding in other language hosts. |
| Runtime-agnostic through `async-trait`-style abstraction | Sockets, timers, and files all need abstracting, for no current consumer |
| `async-std`, `smol` | Smaller ecosystem. Tokio is the expected host runtime. |
| Blocking threads | Workable for one transfer, but poor for cancellation and timers across many |
| `io_uring` runtime | Linux only. No need at the expected throughput. |
| Typestate per state in the public API | Elegant, but runtime-driven events suit an `enum` state better |
| Sans-IO with no provided runtime | Maximum flexibility, with more host work. Available anyway, through `default-features = false`. |

## Consequences

**Positive**

- Memory-safety bugs are excluded by construction in project code.
- Pure logic can be fuzzed and property-tested at high speed.
- Hosts on Tokio integrate directly.
- `--no-default-features` provides codecs and machines for other runtimes.

**Negative**

- Hosts on another runtime must use the pure layer or run a Tokio runtime alongside.
- Partial-file storage does not use `tokio::fs`. Its operations outlive cancelled futures, and tokio recommends dedicated threads for long-lived blocking work. Each transfer has one storage worker thread (`ARCHITECTURE.md` §6). This costs a thread per active transfer, bounded by the transfer limit, plus one reconciler thread per client while it has reconciliation or recovery work.
- The MSRV is relatively recent.
- `IrcLink` is a pair of bounded Tokio-backed channels rather than a trait (`ARCHITECTURE.md` §6). Hosts must run a small pump, but reads and writes cannot block each other, and `Client` needs no generic parameter.

## Verification

- M0 proves the toolchain and MSRV in CI.
- M1 proves the pure layer builds with no default features.
- M6 and M9 confirm that memory and throughput meet acceptance criteria.
