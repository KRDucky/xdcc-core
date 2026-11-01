//! Checks the M1 bound: no input makes the library allocate over 16 KiB.
//!
//! This binary holds one test, because the counters are global and a second
//! test would run concurrently. So the allocator sees only that test
//! and the harness thread waiting for it. The harness builds each input before
//! a region opens. Counts are cumulative, which overstates peak use.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::alloc::System;

use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use xdcc_core::proto::{
    BotNick, CtcpEncodeError, Frame, IrcMessage, LineBudget, LineContext, LineFramer, MAX_LINE_LEN,
    MAX_MESSAGE_LEN, MAX_TAG_SECTION_LEN, NameError, OutboundError, OutboundLine, ReplyTailKind,
    WireName, ctcp_privmsg, encode_ctcp, inbound_ctcp, parse_ctcp, parse_dcc, privmsg,
};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

const LIMIT: usize = 16 * 1024;

/// What the library allocated for one input, by stage.
struct Measured {
    framer: usize,
    push: usize,
    worst_line: usize,
}

/// Measures framing and decoding of `input`, which the caller already built.
///
/// Decoded values are dropped between lines, so the bound is the framer's
/// buffer plus the most any one line needs. The framer must never grow.
fn library_bytes(input: &[u8]) -> Measured {
    let region = Region::new(GLOBAL);
    let mut framer = LineFramer::new();
    let framer_bytes = region.change().bytes_allocated;

    let mut push = 0;
    let mut worst_line = 0;
    let mut rest = input;
    while !rest.is_empty() {
        let region = Region::new(GLOBAL);
        let step = framer.push(rest);
        push += region.change().bytes_allocated;
        rest = &rest[step.consumed..];
        if let Some(Frame::Line(line)) = step.frame {
            let region = Region::new(GLOBAL);
            if let Ok(message) = IrcMessage::parse(line) {
                let _ = message.tags().count();
                if let Some(Ok(inbound)) = inbound_ctcp(&message) {
                    for pending in [
                        None,
                        Some(ReplyTailKind::Active),
                        Some(ReplyTailKind::Passive),
                    ] {
                        drop(parse_dcc(&inbound.ctcp, pending));
                    }
                }
            }
            worst_line = worst_line.max(region.change().bytes_allocated);
        }
    }
    Measured {
        framer: framer_bytes,
        push,
        worst_line,
    }
}

#[test]
fn library_allocations_stay_within_the_bound() {
    framer_allocates_once_and_a_failed_decode_allocates_nothing();
    hostile_inputs_stay_within_the_bound();
    maximum_budgets_stay_within_the_bound();
    oversized_outbound_values_are_refused_before_allocating();
    a_line_at_the_limit_allocates_only_itself();
}

fn hostile_inputs_stay_within_the_bound() {
    // Each line fills the 510-byte budget, so these reach the decoder.
    let head = b":b!u@h PRIVMSG me :\x01DCC SEND ".as_slice();
    let tail = b" 3232235777 5000 1024\x01".as_slice();
    let name_len = MAX_MESSAGE_LEN - head.len() - tail.len();
    let offer = [head, &vec![b'n'; name_len], tail, b"\r\n"].concat();
    let many_tokens = [head, &b"a ".repeat(name_len / 2 - 1), b"a", tail, b"\r\n"].concat();
    let tags = [
        b"@".as_slice(),
        &b"a=b;".repeat(2000),
        b" ",
        head,
        b"f",
        tail,
        b"\r\n",
    ]
    .concat();
    let cases: [(&str, Vec<u8>, bool); 7] = [
        ("empty", Vec::new(), false),
        ("longest offer", offer.clone(), true),
        ("many tokens", many_tokens, true),
        ("many tags", tags, true),
        ("many offers", offer.repeat(200), true),
        ("one megabyte, no newline", vec![b'x'; 1 << 20], false),
        ("one megabyte of oversized tags", vec![b'@'; 1 << 20], false),
    ];
    for (name, input, decodes) in &cases {
        let got = library_bytes(input);
        let (framer, line) = (got.framer, got.worst_line);
        println!("{name:32} framer {framer:6} bytes, worst line {line:5} bytes");
        assert_eq!(got.push, 0, "{name}: the framer grew");
        assert!(framer + line <= LIMIT, "{name}: {framer} + {line}");
        assert_eq!(
            line > 0,
            *decodes,
            "{name} must reach the decoder or must not"
        );
    }
}

fn framer_allocates_once_and_a_failed_decode_allocates_nothing() {
    assert_eq!(library_bytes(b"").framer, MAX_LINE_LEN + 1);

    let body = b"\x01DCC SEND f.bin 3232235777 70000 1024\x01";
    let ctcp = parse_ctcp(body, LineContext::new(100)).unwrap();
    let region = Region::new(GLOBAL);
    assert!(parse_dcc(&ctcp, None).is_err());
    assert_eq!(region.change().bytes_allocated, 0);
}

/// The largest line the budgets allow, at both limits at once.
fn maximum_budgets_stay_within_the_bound() {
    let tags = [b"@".as_slice(), &vec![b'a'; MAX_TAG_SECTION_LEN - 2], b" "].concat();
    let head = b":b!u@h PRIVMSG me :\x01DCC SEND ".as_slice();
    let tail = b" 3232235777 5000 1024\x01".as_slice();
    let name = vec![b'n'; MAX_MESSAGE_LEN - head.len() - tail.len()];
    for terminator in [&b"\r\n"[..], b"\n"] {
        let input = [&tags[..], head, &name, tail, terminator].concat();
        let got = library_bytes(&input);
        println!(
            "maximum tagged line             framer {:6} bytes, worst line {:5} bytes",
            got.framer, got.worst_line
        );
        assert_eq!(got.push, 0, "the framer grew at the maximum line");
        assert!(got.worst_line > 0, "the line must reach the decoder");
        assert!(got.framer + got.worst_line <= LIMIT);
    }
}

/// Inputs are built before each region opens, so only the library is counted.
fn oversized_outbound_values_are_refused_before_allocating() {
    let bot = BotNick::parse(b"Bot").unwrap();
    let budget = LineBudget::default();
    let overhead = b"PRIVMSG Bot :".len();
    for size in [budget.limit() - overhead + 1, 1 << 16, 1 << 20, 1 << 26] {
        let plain = vec![b'x'; size];
        let mut ctcp = vec![b'x'; size];
        ctcp[0] = 1;
        ctcp[size - 1] = 1;
        let too_long = Err(OutboundError::TooLong {
            len: overhead + size,
            limit: budget.limit(),
        });

        let region = Region::new(GLOBAL);
        let result = privmsg(&bot, &plain, budget);
        let bytes = region.change().bytes_allocated;
        println!("privmsg of {size:9} bytes: {bytes} bytes allocated");
        assert_eq!(result, too_long, "privmsg {size}");
        assert_eq!(bytes, 0, "privmsg {size}");

        let region = Region::new(GLOBAL);
        let result = ctcp_privmsg(&bot, &ctcp, budget);
        let bytes = region.change().bytes_allocated;
        println!("ctcp_privmsg of {size:9} bytes: {bytes} bytes allocated");
        assert_eq!(result, too_long, "ctcp_privmsg {size}");
        assert_eq!(bytes, 0, "ctcp_privmsg {size}");

        // Injection is still named as injection, however long the value is.
        let mut hostile = vec![b'x'; size];
        hostile[size / 2] = b'\n';
        let region = Region::new(GLOBAL);
        let result = privmsg(&bot, &hostile, budget);
        let bytes = region.change().bytes_allocated;
        assert_eq!(result, Err(OutboundError::ForbiddenByte), "{size}");
        assert_eq!(bytes, 0, "hostile {size}");

        if size > MAX_MESSAGE_LEN {
            let region = Region::new(GLOBAL);
            let line = OutboundLine::new(&plain, budget);
            let tag = encode_ctcp(b"X", &plain);
            let nick = BotNick::parse(&plain);
            let name = WireName::new(&plain);
            let bytes = region.change().bytes_allocated;
            assert!(matches!(line, Err(OutboundError::TooLong { .. })));
            assert_eq!(tag, Err(CtcpEncodeError::TooLong));
            assert_eq!(nick, Err(OutboundError::BadNick));
            assert_eq!(name, Err(NameError::TooLong));
            assert_eq!(bytes, 0, "other builders {size}");
        }
    }
}

fn a_line_at_the_limit_allocates_only_itself() {
    let bot = BotNick::parse(b"Bot").unwrap();
    let budget = LineBudget::default();
    let overhead = b"PRIVMSG Bot :".len();
    let body = vec![b'x'; budget.limit() - overhead];

    let region = Region::new(GLOBAL);
    let line = privmsg(&bot, &body, budget).unwrap();
    let bytes = region.change().bytes_allocated;
    assert_eq!(line.as_bytes().len(), budget.limit());
    assert_eq!(bytes, budget.limit());
}
