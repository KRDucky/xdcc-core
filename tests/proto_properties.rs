//! Property tests for the protocol codecs.
//!
//! Round trips compare decoded values. Name and token bytes must match exactly.
//! Numbers and addresses are compared as values, because `00123` and `123`, or a
//! dotted and a decimal address, decode to the same value by design.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::{NonZeroU16, NonZeroU32};

use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;
use xdcc_core::proto::{
    BotNick, CaseMapping, DccAccept, DccMessage, DccOffer, DccParseError, DccResume, Frame,
    IrcMessage, LineBudget, LineContext, LineFramer, MAX_LINE_LEN, MAX_MESSAGE_LEN, OfferEndpoint,
    OutboundLine, PackRef, ReplyTail, ReplyTailKind, Token, WireName, XdccCase, XdccCommand,
    XdccPackForm, XdccStyle, XdccVerb, encode_ctcp, inbound_ctcp, parse_ctcp, parse_dcc,
};

const SHORT: LineContext = LineContext::new(100);

fn word() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        Just(b"a".to_vec()),
        Just(b"report".to_vec()),
        Just(b"2024".to_vec()),
        Just(b"0".to_vec()),
        Just(b"x.y".to_vec()),
        Just(b"9999999999".to_vec()),
        Just(b"\xff\xfe".to_vec()),
        proptest::collection::vec(any::<u8>(), 1..12).prop_map(|bytes| {
            bytes
                .into_iter()
                .filter(|byte| !matches!(byte, 0 | 1 | b'\r' | b'\n' | b' ' | b'"'))
                .collect()
        }),
    ]
    .prop_filter("word needs a byte", |word: &Vec<u8>| !word.is_empty())
}

fn join(words: &[Vec<u8>], gap: usize) -> Vec<u8> {
    words.join(&vec![b' '; gap][..])
}

fn wire_name() -> impl Strategy<Value = WireName> {
    (
        proptest::collection::vec(word(), 1..5),
        1usize..3,
        any::<bool>(),
    )
        .prop_map(|(words, gap, quoted)| {
            let name = join(&words, gap);
            let wire = if quoted {
                [b"\"", &name[..], b"\""].concat()
            } else {
                name
            };
            WireName::new(&wire).unwrap()
        })
}

fn token() -> impl Strategy<Value = Token> {
    "[!#-~]{1,64}".prop_map(|text| Token::new(text.as_bytes()).unwrap())
}

fn routable_v4() -> impl Strategy<Value = IpAddr> {
    (16_777_216u32..=u32::MAX).prop_map(|value| IpAddr::V4(Ipv4Addr::from(value)))
}

fn address() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        routable_v4(),
        any::<u128>().prop_map(|value| IpAddr::V6(Ipv6Addr::from(value))),
    ]
}

fn port() -> impl Strategy<Value = NonZeroU16> {
    (1u16..=65535).prop_map(|value| NonZeroU16::new(value).unwrap())
}

fn offer() -> impl Strategy<Value = DccOffer> {
    let active = (address(), port(), any::<Option<u64>>())
        .prop_map(|(addr, port, size)| (OfferEndpoint::Active { addr, port }, size));
    let passive = (token(), proptest::option::of(address()), any::<u64>()).prop_map(
        |(token, claimed_addr, size)| {
            (
                OfferEndpoint::Passive {
                    token,
                    claimed_addr,
                },
                Some(size),
            )
        },
    );
    (wire_name(), prop_oneof![active, passive])
        .prop_map(|(wire_name, (endpoint, size))| DccOffer {
            wire_name,
            endpoint,
            size,
        })
        // The parser refuses this shape on purpose, so it has no encoding.
        .prop_filter("legacy names need quotes", |offer| {
            offer.size.is_some()
                || offer.wire_name.is_quoted()
                || !offer.wire_name.as_bytes().contains(&b' ')
        })
}

fn tail() -> impl Strategy<Value = ReplyTail> {
    prop_oneof![
        port().prop_map(|port| ReplyTail::Active { port }),
        token().prop_map(|token| ReplyTail::Passive { token }),
    ]
}

fn pending(tail: &ReplyTail) -> ReplyTailKind {
    match tail {
        ReplyTail::Active { .. } => ReplyTailKind::Active,
        _ => ReplyTailKind::Passive,
    }
}

fn frames(framer: &mut LineFramer, mut input: &[u8], out: &mut Vec<Result<Vec<u8>, String>>) {
    while !input.is_empty() {
        let step = framer.push(input);
        input = &input[step.consumed..];
        match step.frame {
            Some(Frame::Line(line)) => out.push(Ok(line.to_vec())),
            Some(Frame::Oversized(why)) => out.push(Err(format!("{why:?}"))),
            _ => {}
        }
        assert!(framer.pending() <= MAX_LINE_LEN + 1);
    }
}

/// Bytes rich in line breaks and in lengths around each budget.
fn stream() -> impl Strategy<Value = Vec<u8>> {
    let piece = prop_oneof![
        Just(b"\r\n".to_vec()),
        Just(b"\n".to_vec()),
        Just(b"\r".to_vec()),
        Just(b"@".to_vec()),
        Just(b" ".to_vec()),
        (505usize..515).prop_map(|n| vec![b'x'; n]),
        (8185usize..8195).prop_map(|n| vec![b't'; n]),
        proptest::collection::vec(any::<u8>(), 0..40),
    ];
    proptest::collection::vec(piece, 0..12).prop_map(|pieces| pieces.concat())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 2000,
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("regressions"))),
        ..ProptestConfig::default()
    })]

    #[test]
    fn offers_round_trip(offer in offer()) {
        let message = DccMessage::Send(offer);
        let body = message.encode().unwrap();
        let ctcp = parse_ctcp(&body, SHORT).unwrap();
        prop_assert!(ctcp.final_delimiter());
        prop_assert_eq!(parse_dcc(&ctcp, None).unwrap(), message);
    }

    #[test]
    fn resume_and_accept_round_trip(
        wire_name in wire_name(),
        tail in tail(),
        position in any::<u64>(),
    ) {
        let kind = Some(pending(&tail));
        for message in [
            DccMessage::Resume(DccResume { wire_name: wire_name.clone(), tail, position }),
            DccMessage::Accept(DccAccept { wire_name: wire_name.clone(), tail, position }),
        ] {
            let body = message.encode().unwrap();
            let parsed = parse_dcc(&parse_ctcp(&body, SHORT).unwrap(), kind).unwrap();
            prop_assert_eq!(parsed, message);
        }
    }

    /// Non-canonical numbers decode to the same value, and only the text changes.
    #[test]
    fn normalised_fields_reach_a_fixed_point(
        name in wire_name(),
        zeros in 0usize..4,
        value in 1u16..=65535,
        size in 0u64..1 << 40,
    ) {
        let pad = "0".repeat(zeros);
        let args = [
            b"\x01DCC SEND ", name.as_bytes(),
            format!("  8.8.8.8  {pad}{value}  {pad}{size} \x01").as_bytes(),
        ].concat();
        let first = parse_dcc(&parse_ctcp(&args, SHORT).unwrap(), None).unwrap();
        let DccMessage::Send(offer) = &first else { panic!("not an offer") };
        prop_assert_eq!(offer.wire_name.as_bytes(), name.as_bytes());
        prop_assert_eq!(offer.size, Some(size));
        let body = first.encode().unwrap();
        let second = parse_dcc(&parse_ctcp(&body, SHORT).unwrap(), None).unwrap();
        prop_assert_eq!(second.encode().unwrap(), body.clone());
        prop_assert_eq!(second, first);
    }

    #[test]
    fn corrupting_one_number_is_refused_and_never_reinterpreted(
        name in wire_name(),
        addr in routable_v4(),
        port in port(),
        size in any::<u64>(),
        token in token(),
        bad in prop::sample::select(vec!["70000", "-1", "1x", "+5", "99999999999999999999999"]),
        field in 0usize..2,
    ) {
        let IpAddr::V4(v4) = addr else { unreachable!() };
        let addr = u32::from(v4);
        let token = String::from_utf8(token.as_bytes().to_vec()).unwrap();
        let name = name.as_bytes();
        let wire = WireName::new(name).unwrap();
        let cases: Vec<(String, DccParseError)> = if field == 0 {
            let mut cases = vec![(format!("{addr} {bad} {size}"), DccParseError::BadPort)];
            // Legacy cannot carry an unquoted multi-word name, so such a string was
            // never a legacy offer. `a 2024 0 <addr> 70000` is a passive offer.
            if wire.is_quoted() || !name.contains(&b' ') {
                cases.push((format!("{addr} {bad}"), DccParseError::BadPort));
            }
            cases
        } else if bad == "70000" {
            return Ok(()); // 70000 is a legal size
        } else {
            vec![
                (format!("{addr} {port} {bad}"), DccParseError::BadSize),
                (format!("{addr} 0 {bad} {token}"), DccParseError::BadSize),
            ]
        };
        for (tail, want) in cases {
            let body = [b"\x01DCC SEND ", name, b" ", tail.as_bytes(), b"\x01"].concat();
            let got = parse_dcc(&parse_ctcp(&body, SHORT).unwrap(), None);
            prop_assert_eq!(got, Err(want), "{:?}", String::from_utf8_lossy(&body));
        }
    }

    #[test]
    fn missing_delimiter_near_the_limit_is_always_suspected(offer in offer()) {
        let mut body = DccMessage::Send(offer).encode().unwrap();
        body.pop();
        let near = parse_ctcp(&body, LineContext::new(480)).unwrap();
        prop_assert_eq!(parse_dcc(&near, None), Err(DccParseError::SuspectedTruncation));
    }

    #[test]
    fn framing_ignores_chunk_boundaries(input in stream(), cuts in proptest::collection::vec(any::<prop::sample::Index>(), 0..8)) {
        let mut whole = Vec::new();
        frames(&mut LineFramer::new(), &input, &mut whole);

        let mut points: Vec<usize> = cuts.iter().map(|cut| cut.index(input.len() + 1)).collect();
        points.push(input.len());
        points.sort_unstable();
        let mut framer = LineFramer::new();
        let mut chunked = Vec::new();
        let mut start = 0;
        for point in points {
            frames(&mut framer, &input[start..point], &mut chunked);
            start = point;
        }
        prop_assert_eq!(chunked, whole);
    }

    #[test]
    fn framed_lines_always_meet_the_parser_budgets(input in stream()) {
        let mut lines = Vec::new();
        frames(&mut LineFramer::new(), &input, &mut lines);
        for line in lines.into_iter().flatten() {
            prop_assert!(line.len() <= MAX_LINE_LEN + 1);
            if let Ok(message) = IrcMessage::parse(&line) {
                prop_assert!(message.message_len() <= MAX_MESSAGE_LEN);
            }
        }
    }

    #[test]
    fn parsers_never_panic(input in proptest::collection::vec(any::<u8>(), 0..700)) {
        if let Ok(message) = IrcMessage::parse(&input) {
            let _ = message.tags().count();
            let _ = inbound_ctcp(&message);
        }
        for pending in [None, Some(ReplyTailKind::Active), Some(ReplyTailKind::Passive)] {
            let body = [b"\x01DCC ", &input[..]].concat();
            if let Ok(ctcp) = parse_ctcp(&body, LineContext::new(input.len())) {
                let _ = parse_dcc(&ctcp, pending);
            }
        }
    }

    #[test]
    fn arbitrary_dcc_args_never_panic(
        words in proptest::collection::vec(prop_oneof![
            Just("\"".to_string()), Just("0".to_string()), Just("00".to_string()),
            Just("SEND".to_string()), Just("3232235777".to_string()), Just("199".to_string()),
            Just("::1".to_string()), Just("t".to_string()), Just("5000".to_string()),
            "[ -~]{0,6}",
        ], 0..9),
        kind in prop::sample::select(vec!["SEND", "RESUME", "ACCEPT"]),
    ) {
        let body = format!("\x01DCC {kind} {}\x01", words.join(" "));
        for pending in [None, Some(ReplyTailKind::Active), Some(ReplyTailKind::Passive)] {
            let parsed = parse_dcc(&parse_ctcp(body.as_bytes(), SHORT).unwrap(), pending);
            if let Ok(message) = parsed {
                // Whatever is accepted must re-encode to the same value.
                let again = message.encode().unwrap();
                let reparsed = parse_dcc(&parse_ctcp(&again, SHORT).unwrap(), pending).unwrap();
                prop_assert_eq!(reparsed, message);
            }
        }
    }

    #[test]
    fn ctcp_round_trips_bytes(
        tag in "[A-Za-z]{1,8}",
        args in proptest::collection::vec(any::<u8>().prop_filter("delimiter", |b| !matches!(b, 0 | 1 | b'\r' | b'\n')), 0..200),
    ) {
        let body = encode_ctcp(tag.as_bytes(), &args).unwrap();
        let parsed = parse_ctcp(&body, SHORT).unwrap();
        prop_assert_eq!(parsed.tag(), tag.as_bytes());
        prop_assert_eq!(parsed.args(), &args[..]);
        prop_assert!(parsed.final_delimiter());
    }

    #[test]
    fn accepted_outbound_lines_are_always_safe(
        line in proptest::collection::vec(any::<u8>(), 0..520),
        reserved in 0usize..520,
    ) {
        let budget = LineBudget::reserving(reserved);
        if let Ok(accepted) = OutboundLine::new(&line, budget) {
            prop_assert!(accepted.as_bytes().len() <= budget.limit());
            prop_assert!(!accepted.as_bytes().iter().any(|b| matches!(b, 0 | b'\r' | b'\n')));
            prop_assert!(accepted.to_wire().ends_with(b"\r\n"));
        }
    }

    #[test]
    fn outbound_dcc_lines_parse_back(
        name in wire_name(),
        tail in tail(),
        position in any::<u64>(),
    ) {
        let bot = BotNick::parse(b"Bot").unwrap();
        let kind = Some(pending(&tail));
        let message = DccMessage::Resume(DccResume { wire_name: name, tail, position });
        let body = message.encode().unwrap();
        let line = xdcc_core::proto::ctcp_privmsg(&bot, &body, LineBudget::default()).unwrap();
        let parsed = IrcMessage::parse(line.as_bytes()).unwrap();
        let inbound = inbound_ctcp(&parsed).unwrap().unwrap();
        prop_assert_eq!(parse_dcc(&inbound.ctcp, kind).unwrap(), message);
    }

    #[test]
    fn xdcc_requests_are_one_plain_privmsg(
        number in 1u32..=u32::MAX,
        crc in any::<u32>(),
        use_crc in any::<bool>(),
        lower in any::<bool>(),
        get in any::<bool>(),
        bare in any::<bool>(),
    ) {
        let pack = if use_crc {
            PackRef::Crc32(crc)
        } else {
            PackRef::Number(NonZeroU32::new(number).unwrap())
        };
        let style = XdccStyle {
            case: if lower { XdccCase::Lower } else { XdccCase::Upper },
            verb: if get { XdccVerb::Get } else { XdccVerb::Send },
            pack_form: if bare { XdccPackForm::Bare } else { XdccPackForm::Hash },
        };
        let bot = BotNick::parse(b"Bot").unwrap();
        let line = XdccCommand::Send(pack).to_line(&bot, style, LineBudget::default()).unwrap();
        let parsed = IrcMessage::parse(line.as_bytes()).unwrap();
        prop_assert_eq!(parsed.command(), b"PRIVMSG");
        prop_assert_eq!(parsed.params().len(), 2);
        prop_assert_eq!(inbound_ctcp(&parsed), None);
    }

    #[test]
    fn folding_is_an_equivalence(
        left in proptest::collection::vec(any::<u8>(), 0..16),
        right in proptest::collection::vec(any::<u8>(), 0..16),
    ) {
        for mapping in [CaseMapping::Ascii, CaseMapping::Rfc1459, CaseMapping::Rfc1459Strict] {
            prop_assert!(mapping.eq(&left, &left));
            prop_assert_eq!(mapping.eq(&left, &right), mapping.eq(&right, &left));
            let folded: Vec<u8> = left.iter().map(|&b| mapping.fold(b)).collect();
            prop_assert!(mapping.eq(&left, &folded));
        }
    }
}
