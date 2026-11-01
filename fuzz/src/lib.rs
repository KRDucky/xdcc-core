//! Checks shared by the fuzz targets.
//!
//! A target panics on any broken property, so a completed run shows that the
//! property held for every execution. Allocation is measured with a counting
//! global allocator, inside regions that open only around library calls. Inputs
//! come from libFuzzer through C allocation, which this allocator never sees, so
//! the counts are library allocations and not harness ones.

use std::alloc::System;
use std::sync::atomic::{AtomicUsize, Ordering};

use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use xdcc_core::proto::{
    DccMessage, Frame, IrcMessage, LineContext, LineFramer, MAX_LINE_LEN, ReplyTailKind,
    inbound_ctcp, parse_ctcp, parse_dcc,
};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

/// The M1 limit on what one input may make the library allocate.
pub const LIMIT: usize = 16 * 1024;

static WORST: AtomicUsize = AtomicUsize::new(0);

/// Runs `call` and returns its result with the bytes it allocated.
///
/// Counts are cumulative, so reallocation growth and freed memory both count.
pub fn measured<T>(call: impl FnOnce() -> T) -> (T, usize) {
    let region = Region::new(GLOBAL);
    let value = call();
    (value, region.change().bytes_allocated)
}

/// Enforces the limit, and logs each new worst case so a run can report it.
pub fn check_bound(bytes: usize) {
    assert!(
        bytes <= LIMIT,
        "library allocated {bytes} bytes for one input"
    );
    if bytes > WORST.fetch_max(bytes, Ordering::Relaxed) {
        eprintln!("XDCC_ALLOC_WORST {bytes}");
    }
}

/// The contexts a RESUME or ACCEPT can be parsed under.
pub const PENDING: [Option<ReplyTailKind>; 3] = [
    None,
    Some(ReplyTailKind::Active),
    Some(ReplyTailKind::Passive),
];

/// Whatever the parser accepts must re-encode to the same value.
pub fn check_round_trip(message: &DccMessage, pending: Option<ReplyTailKind>) {
    let Ok(body) = message.encode() else {
        return;
    };
    let ctcp = parse_ctcp(&body, LineContext::new(0));
    assert!(ctcp.is_ok(), "encoded body did not parse");
    if let Ok(ctcp) = ctcp {
        assert_eq!(parse_dcc(&ctcp, pending).as_ref(), Ok(message));
    }
}

/// Decodes one framed line through every layer. Returns the bytes allocated.
pub fn decode_line(line: &[u8]) -> usize {
    let (message, parse_bytes) = measured(|| IrcMessage::parse(line));
    let Ok(message) = message else {
        return parse_bytes;
    };
    assert!(message.message_len() <= xdcc_core::proto::MAX_MESSAGE_LEN);
    let (_, tag_bytes) = measured(|| message.tags().count());
    let (inbound, ctcp_bytes) = measured(|| inbound_ctcp(&message));
    let mut total = parse_bytes + tag_bytes + ctcp_bytes;
    if let Some(Ok(inbound)) = inbound {
        for pending in PENDING {
            let (result, bytes) = measured(|| parse_dcc(&inbound.ctcp, pending));
            total += bytes;
            if let Ok(decoded) = &result {
                check_round_trip(decoded, pending);
            }
            let (_, bytes) = measured(|| drop(result));
            total += bytes;
        }
    }
    total
}

/// Frames a stream with one split, and decodes every line.
///
/// Returns the frames as a list, so a target can compare two chunkings. The
/// bound is the framer's buffer plus the costliest line, since each line's
/// values are dropped before the next line is read.
pub fn frame_stream(first: &[u8], second: &[u8]) -> Vec<Result<Vec<u8>, String>> {
    let (mut framer, framer_bytes) = measured(LineFramer::new);
    let mut frames = Vec::new();
    let mut worst_line = 0;
    let mut push_bytes = 0;
    for mut rest in [first, second] {
        while !rest.is_empty() {
            let reborrow = &mut framer;
            let (step, bytes) = measured(move || reborrow.push(rest));
            push_bytes += bytes;
            assert!(step.consumed > 0, "framer made no progress");
            rest = &rest[step.consumed..];
            match step.frame {
                Some(Frame::Line(line)) => {
                    assert!(line.len() <= MAX_LINE_LEN + 1);
                    worst_line = worst_line.max(decode_line(line));
                    frames.push(Ok(line.to_vec()));
                }
                Some(Frame::Oversized(reason)) => frames.push(Err(format!("{reason:?}"))),
                _ => {}
            }
            assert!(framer.pending() <= MAX_LINE_LEN + 1);
        }
    }
    // The buffer is allocated once, and framing must never grow it.
    assert_eq!(framer_bytes, MAX_LINE_LEN + 1, "framer buffer changed size");
    assert_eq!(push_bytes, 0, "framer allocated while framing");
    check_bound(framer_bytes + worst_line);
    frames
}
