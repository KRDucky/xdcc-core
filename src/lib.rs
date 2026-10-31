//! XDCC Core: protocol handling and reliable file downloads.
//!
//! This crate is an empty M0 bootstrap. Protocol and transfer APIs are proposed
//! in `docs/ARCHITECTURE.md`; no download functionality is implemented yet.

#![forbid(unsafe_code)]

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    #[test]
    fn workspace_smoke_test() {
        assert_eq!(env!("CARGO_PKG_NAME"), "xdcc-core");
    }
}
