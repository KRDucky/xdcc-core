# Contributing to XDCC Core

The library holds pure protocol codecs from M1 and pure safety policies from M2. Each
later milestone needs separate owner authorization; see
[the development plan](docs/DEVELOPMENT_PLAN.md). No network, storage, or transfer
behavior exists yet.

Linux is the only supported platform. CI and future milestone acceptance target Linux;
Windows and macOS support is out of scope.

## Setup

Install Rust using [rustup](https://rustup.rs/). The repository's
`rust-toolchain.toml` selects Rust 1.88.0, rustfmt, and Clippy. The workspace uses
edition 2024 and declares Rust 1.88 as its minimum supported version (MSRV).

Run from the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo test --workspace --no-default-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo deny --workspace --locked check
```

Install `cargo-deny` separately using the version in `.github/workflows/ci.yml`.
This developer tool may require a newer Rust compiler than the library's MSRV.
The library's only production dependency is `unicode-normalization` (NFC for filenames,
with `tinyvec`), and dev-dependencies get the same licence review (`include-dev` in
`deny.toml`). Commit `Cargo.lock` so CI resolves exactly the reviewed dependency graph
when dependencies are added.

## Fuzzing

`fuzz/` is excluded from the workspace, needs a nightly toolchain, and has its own
lockfile and `deny.toml`. Install `cargo-fuzz` using the version in
`.github/workflows/ci.yml`, then run from `fuzz/`:

```sh
mkdir -p /tmp/irc_line-corpus /tmp/ctcp-corpus /tmp/dcc_message-corpus
mkdir -p /tmp/policy_name-corpus /tmp/policy_net-corpus /tmp/policy_rate-corpus
cargo +nightly fuzz run irc_line /tmp/irc_line-corpus seeds/irc_line -- -max_len=20000
cargo +nightly fuzz run ctcp /tmp/ctcp-corpus seeds/ctcp -- -max_len=70000
cargo +nightly fuzz run dcc_message /tmp/dcc_message-corpus seeds/dcc_message -- -max_len=2048
cargo +nightly fuzz run policy_name /tmp/policy_name-corpus seeds/policy_name -- -max_len=1024
cargo +nightly fuzz run policy_net /tmp/policy_net-corpus seeds/policy_net -- -max_len=256
cargo +nightly fuzz run policy_rate /tmp/policy_rate-corpus seeds/policy_rate -- -max_len=4096
```

Each target fails on over 16 KiB of library allocation for one input, and on a
broken round trip or violated invariant. The policy targets also check that a
rate limiter never grows after construction. `-max_len` is the longest useful
input: 1024 for names (the limit is 512, so oversized input is covered), 256 for the
address layout (header plus eight rules), and 4096 for rate-limiter operation
streams. A crash becomes a seed in `fuzz/seeds/` and a named test. Seed filenames use
lowercase ASCII, digits and hyphens only, so tools and archives handle them safely;
hostile bytes go in the file contents.

## Change scope

- Keep changes small and tied to an authorized milestone.
- Unsafe Rust is forbidden, including tests. `unwrap` and `expect` are denied by
  Clippy outside explicitly annotated test modules.
- Public items require documentation. Treat the API sketches in `docs/` as
  proposals rather than already implemented contracts.
- Add tests appropriate to each behavior and update the affected specification
  and `docs/PROJECT_MEMORY.md`.
- Do not copy reference-client or bot source into this repository. Research
  references are evidence about behavior, not production dependencies.
- Make no bot compatibility or filesystem durability claims without recorded
  test evidence.

The simulator is a separate unpublished crate.

## Review and licensing

Changes are reviewed before merging. This repository uses GPL-3.0-only; see
[LICENSE](LICENSE). No crate is publishable yet. Publishing requires a separate
release decision and a fresh registry-name check.

Report suspected vulnerabilities using [SECURITY.md](SECURITY.md).
