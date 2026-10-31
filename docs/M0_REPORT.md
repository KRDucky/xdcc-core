# M0 bootstrap report

**Date:** 2026-10-31. **Authorization:** owner approved M0 in this chat.

**State:** implemented and verified locally on Linux. Hosted CI, review, and merge
are pending. M0's full definition of done therefore remains open. M1 and later
milestones, E1, publication, and the pending storage decisions are not authorized.

## Changes

- Root `xdcc-core` library and unpublished `crates/xdcc-sim` library stub.
- Edition 2024, workspace resolver 3, Rust 1.88 MSRV, pinned 1.88.0 toolchain.
- Shared lint policy: unsafe forbidden, public documentation required, and
  `unwrap_used` / `expect_used` denied outside explicitly annotated test modules.
- One bootstrap smoke test per crate. No protocol or transfer implementation.
- Lockfile, build-artifact exclusions, and dependency policy with cargo-deny 0.20.2.
- CI for Rust checks on Linux, macOS, and Windows, plus dependency-policy and
  Python research jobs on Linux. All external actions use commit revisions.
- README, contributor guide, root security-reporting policy, and project-memory
  updates.

No third-party crate dependencies are added. Runtime dependencies and feature
flags will be introduced when their implementation milestones require them.
`fuzz/` is excluded from the workspace, but no fuzz package exists yet.

Both crates set `publish = false`; the library remains the intended future
published package. The crates.io API returned HTTP 404 for `xdcc-core` on
2026-10-31. This does not reserve the name or authorize publication.

## Local evidence

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | Pass |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | Pass |
| `cargo test --workspace --all-features --locked` | Pass: two smoke tests |
| `cargo test --workspace --no-default-features --locked` | Pass: two smoke tests |
| `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked` | Pass |
| `cargo deny --workspace --locked --offline check` | Pass: advisories, bans, licences, sources |
| Workspace metadata | Both members: edition 2024, MSRV 1.88, unpublished, zero dependencies |
| Lint rejection probes in a temporary workspace | Unsafe, undocumented public item, `unwrap`, and `expect` each rejected; explicitly allowed test-only unwrap accepted |
| TOML and workflow structure | Parses; three operating systems; read-only repository permission; actions pinned |
| Four existing Python research scripts | All exit 0 |

The dependency check first fetched the public advisory database successfully;
the final check used that cached database offline. The cargo-deny release archive
was checked against its published SHA-256 before use:
`9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f`.

These checks validate the bootstrap and existing research models. They establish
no protocol functionality, bot compatibility, or actual filesystem durability.
The two feature-mode commands currently exercise the same dependency-free crates;
feature isolation becomes meaningful when features and dependencies are added.

## Toolchain used in this session

Rust was installed in temporary, project-specific directories without modifying
shell profiles. To use it while these directories remain present:

```sh
export CARGO_HOME=/tmp/xdcc-m0-cargo
export RUSTUP_HOME=/tmp/xdcc-m0-rustup
export PATH="$CARGO_HOME/bin:$PATH"
cargo test --workspace --locked
```

The cargo-deny binary used locally is under
`/tmp/xdcc-m0-tools/cargo-deny-0.20.2-x86_64-unknown-linux-musl/`.
Temporary installations may disappear after cleanup or reboot. A normal durable
installation is documented in `CONTRIBUTING.md`; it was not made to the user's
home directory in this session.

## Outstanding

D8 is resolved: on 2026-10-31 the owner supplied `sec.krd.hub@proton.me` as the
private security contact. Root `SECURITY.md` now directs reports to that address.

- **Hosted CI:** configured but not run in this session. Windows and macOS checks
  are not claimed as passing.
- **Review and merge:** no commit, push, pull request, or merge performed. Existing
  Phase 0 files and M0 changes remain available for review in the working tree.
- **Next milestone:** M1 requires separate authorization.
