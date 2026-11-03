//! XDCC Core: protocol handling and reliable file downloads.
//!
//! [`proto`] holds the pure protocol codecs from M1. [`policy`] holds the M2
//! safety decisions: destination addresses, filenames, offer rate limits and
//! resource limits. Neither touches a socket, a file, or a clock. Transfer APIs
//! are proposed in `docs/ARCHITECTURE.md`; no download functionality is
//! implemented yet.
//!
//! The only production dependency is `unicode-normalization`, used by the
//! filename policy.

#![forbid(unsafe_code)]

pub mod policy;
pub mod proto;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    #[test]
    fn workspace_smoke_test() {
        assert_eq!(env!("CARGO_PKG_NAME"), "xdcc-core");
    }
}
