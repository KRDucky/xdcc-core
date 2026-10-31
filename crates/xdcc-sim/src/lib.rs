//! Unpublished simulated XDCC bot harness.
//!
//! M0 provides only this crate stub. Bot behavior and fault injection arrive in M4.

#![forbid(unsafe_code)]

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    #[test]
    fn workspace_smoke_test() {
        assert_eq!(env!("CARGO_PKG_NAME"), "xdcc-sim");
    }
}
