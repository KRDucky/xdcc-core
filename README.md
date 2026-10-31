# XDCC Core

A Rust library for XDCC protocol handling and reliable DCC downloads.

**Status:** M0 bootstrap. The workspace contains an empty library and an
unpublished simulator stub. Downloads and protocol parsing are not implemented,
and no real-world compatibility is claimed.

## Development

Rust 1.88.0, edition 2024. Install [rustup](https://rustup.rs/), then run:

```sh
cargo test --workspace --locked
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the complete check list.

## Design documents

- [Architecture and proposed API](docs/ARCHITECTURE.md)
- [Protocol research](docs/PROTOCOL_SPEC.md)
- [Compatibility and open questions](docs/COMPATIBILITY.md)
- [Security model](docs/SECURITY.md)
- [Development plan](docs/DEVELOPMENT_PLAN.md)
- [Project status and decisions](docs/PROJECT_MEMORY.md)

Implementation authorization currently covers M0 only. Later milestones and
publication require separate authorization.

Licensed under [GPL-3.0-only](LICENSE). Security reporting: [SECURITY.md](SECURITY.md).
