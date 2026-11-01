//! DCC parsing with the context bytes chosen by the fuzzer.

#![no_main]

use libfuzzer_sys::fuzz_target;
use xdcc_core::proto::{DccMessage, DccParseError, LineContext, parse_ctcp, parse_dcc};
use xdcc_core_fuzz::{PENDING, check_bound, check_round_trip, measured};

const KINDS: [&[u8]; 4] = [b"SEND ", b"RESUME ", b"ACCEPT ", b""];

fuzz_target!(|data: &[u8]| {
    let Some((&selector, args)) = data.split_first() else {
        return;
    };
    let kind = KINDS[usize::from(selector & 3)];
    let pending = PENDING[usize::from(selector >> 2 & 3) % PENDING.len()];
    let closed = selector & 16 != 0;
    let near = selector & 32 != 0;

    let mut body = Vec::with_capacity(args.len() + 16);
    body.extend_from_slice(b"\x01DCC ");
    body.extend_from_slice(kind);
    body.extend_from_slice(args);
    if closed {
        body.push(1);
    }
    let line = LineContext::new(if near { 480 } else { 100 });
    let Ok(ctcp) = parse_ctcp(&body, line) else {
        return;
    };
    let (result, bytes) = measured(|| parse_dcc(&ctcp, pending));
    check_bound(bytes);

    if let Ok(message) = &result {
        check_round_trip(message, pending);
    }

    // Ask the parser, since a 0x01 inside `args` also closes the body.
    if ctcp.final_delimiter() {
        assert_ne!(
            result.as_ref().err(),
            Some(&DccParseError::SuspectedTruncation)
        );
    } else if let Ok(DccMessage::Send(_) | DccMessage::Resume(_) | DccMessage::Accept(_)) = result {
        assert!(!near, "unclosed message accepted near the limit");
    }
});
