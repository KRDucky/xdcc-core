//! XDCC Core: protocol handling and reliable file downloads.
//!
//! [`proto`] holds the pure protocol codecs from M1. Transfer APIs are proposed
//! in `docs/ARCHITECTURE.md`; no download functionality is implemented yet.

#![forbid(unsafe_code)]

pub mod proto;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    #[test]
    fn workspace_smoke_test() {
        assert_eq!(env!("CARGO_PKG_NAME"), "xdcc-core");
    }
}
