# Contributing to XDCC Core

M0 establishes empty crates and development checks. M1 and later milestones need
separate owner authorization; see [the development plan](docs/DEVELOPMENT_PLAN.md).
No protocol or transfer behavior exists yet.

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
The workspace currently has no third-party dependencies. Commit `Cargo.lock` so
CI resolves exactly the reviewed dependency graph when dependencies are added.

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

The simulator is a separate unpublished crate. Future `cargo-fuzz` targets belong
in `fuzz/`, excluded from the normal workspace; M0 does not create fuzz targets.

## Review and licensing

Changes are reviewed before merging. This repository uses GPL-3.0-only; see
[LICENSE](LICENSE). No crate is publishable at M0. Publishing requires a separate
release decision and a fresh registry-name check.

Report suspected vulnerabilities using [SECURITY.md](SECURITY.md).
