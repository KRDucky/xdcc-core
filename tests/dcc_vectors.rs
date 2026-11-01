//! The executable vectors from `docs/research/offer_parser_check.py`, with exact
//! outcomes, plus cases from `PROTOCOL_SPEC.md` §7 and §9.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::IpAddr;

use xdcc_core::proto::{
    DccKind, DccMessage, DccOffer, DccParseError, LineContext, OfferEndpoint, ReplyTail,
    ReplyTailKind, parse_ctcp, parse_dcc,
};

const A: &str = "3232235777";
const SHORT: LineContext = LineContext::new(100);
const NEAR: LineContext = LineContext::new(480);

fn body(args: &[u8], kind: &str, closed: bool) -> Vec<u8> {
    let mut body = [b"\x01DCC ", kind.as_bytes(), b" ", args].concat();
    if closed {
        body.push(1);
    }
    body
}

fn offer_with(args: &[u8], closed: bool, line: LineContext) -> Result<DccOffer, DccParseError> {
    let body = body(args, "SEND", closed);
    match parse_dcc(&parse_ctcp(&body, line).unwrap(), None)? {
        DccMessage::Send(offer) => Ok(offer),
        other => panic!("not an offer: {other:?}"),
    }
}

fn offer(args: &str) -> Result<DccOffer, DccParseError> {
    offer_with(args.as_bytes(), true, SHORT)
}

#[derive(Debug, PartialEq)]
enum Shape {
    Standard,
    Passive,
    Legacy,
}

/// The Python vector tuple, as decoded.
type Decoded = (
    Shape,
    Vec<u8>,
    Option<IpAddr>,
    u16,
    Option<u64>,
    Option<Vec<u8>>,
);

/// Mirrors the Python vector tuple: shape, name, address, port, size, token.
type Want<'a> = (
    Shape,
    &'a str,
    Option<&'a str>,
    u16,
    Option<u64>,
    Option<&'a str>,
);

fn describe(offer: &DccOffer) -> Decoded {
    let name = offer.wire_name.name().to_vec();
    match offer.endpoint {
        OfferEndpoint::Active { addr, port } => {
            let shape = if offer.size.is_some() {
                Shape::Standard
            } else {
                Shape::Legacy
            };
            (shape, name, Some(addr), port.get(), offer.size, None)
        }
        OfferEndpoint::Passive {
            token,
            claimed_addr,
        } => {
            let token = Some(token.as_bytes().to_vec());
            (Shape::Passive, name, claimed_addr, 0, offer.size, token)
        }
        _ => panic!("unknown endpoint"),
    }
}

#[track_caller]
fn accepted(args: &str, want: Want<'_>) {
    let got = describe(&offer(args).unwrap_or_else(|e| panic!("{args}: {e:?}")));
    let (shape, name, addr, port, size, token) = want;
    assert_eq!(got.0, shape, "{args}");
    assert_eq!(got.1, name.as_bytes(), "{args}");
    assert_eq!(got.2, addr.map(|a| a.parse().unwrap()), "{args}");
    assert_eq!(got.3, port, "{args}");
    assert_eq!(got.4, size, "{args}");
    assert_eq!(got.5.as_deref(), token.map(str::as_bytes), "{args}");
}

#[track_caller]
fn refused(args: &str, want: DccParseError) {
    assert_eq!(offer(args).map(|_| ()), Err(want), "{args}");
}

#[test]
fn all_thirty_five_research_vectors() {
    use DccParseError::*;
    use Shape::{Legacy, Passive, Standard};
    let ip = Some("192.168.1.1");

    accepted(
        &format!("file.bin {A} 5000 1024"),
        (Standard, "file.bin", ip, 5000, Some(1024), None),
    );
    accepted(
        &format!("\"a b.bin\" {A} 5000 1024"),
        (Standard, "a b.bin", ip, 5000, Some(1024), None),
    );
    accepted(
        &format!("a b.bin {A} 5000 1024"),
        (Standard, "a b.bin", ip, 5000, Some(1024), None),
    );
    accepted(
        &format!("report 2024 {A} 5000 1024"),
        (Standard, "report 2024", ip, 5000, Some(1024), None),
    );
    accepted(
        &format!("f.bin {A} 5000 99999999999"),
        (Standard, "f.bin", ip, 5000, Some(99_999_999_999), None),
    );
    accepted(
        &format!("f.bin {A} 5000 0"),
        (Standard, "f.bin", ip, 5000, Some(0), None),
    );
    accepted(
        "f.bin 2001:db8::1 5000 1024",
        (
            Standard,
            "f.bin",
            Some("2001:db8::1"),
            5000,
            Some(1024),
            None,
        ),
    );
    accepted(
        "f.bin 192.168.1.1 5000 1024",
        (Standard, "f.bin", ip, 5000, Some(1024), None),
    );
    accepted(
        &format!("f.bin  {A}   5000 1024 "),
        (Standard, "f.bin", ip, 5000, Some(1024), None),
    );
    accepted(
        "file.bin 199 0 1024 77",
        (Passive, "file.bin", None, 0, Some(1024), Some("77")),
    );
    accepted(
        "a b.bin 199 0 1024 77",
        (Passive, "a b.bin", None, 0, Some(1024), Some("77")),
    );
    accepted(
        &format!("\"a b.bin\" {A} 0 1024 ab-7"),
        (Passive, "a b.bin", ip, 0, Some(1024), Some("ab-7")),
    );
    accepted(
        &format!("f.bin {A} 5000"),
        (Legacy, "f.bin", ip, 5000, None, None),
    );
    accepted(
        &format!("\"a b.bin\" {A} 5000"),
        (Legacy, "a b.bin", ip, 5000, None, None),
    );

    refused(&format!("f.bin {A} 70000 1024"), BadPort);
    refused(&format!("f.bin {A} -5000 1024"), BadPort);
    refused(&format!("f.bin {A} 5000 -1"), BadSize);
    refused(&format!("f.bin {A} 5000 +1"), BadSize);
    refused(&format!("f.bin {A} 5000 18446744073709551616"), BadSize);
    refused(&format!("f.bin {A} 5000 1k"), BadSize);
    refused(&format!("f.bin {A} abc 1024"), BadPort);
    refused("f.bin 4294967296 5000 1024", BadAddress);
    refused("f.bin 999.1.1.1 5000 1024", BadAddress);
    refused("f.bin host.example 5000 1024", BadAddress);
    refused("f.bin 5000 1024 77", ImplausibleAddress);
    refused(&format!("f.bin {A} 5000 1024 77"), ImplausibleAddress);
    refused(&format!("\"f.bin\" {A} 5000 1024 77"), UnexpectedToken);
    refused(&format!("f.bin {A} 0 1024"), PortZeroWithoutToken);
    refused(&format!("a b.bin {A} 5000"), BadPort);
    refused(&format!("report 2024 {A} 5000"), BadPort);
    refused(&format!("f.bin {A}"), TooFewFields);
    refused(&format!("\"a b.bin {A} 5000 1024"), UnterminatedQuote);
    refused(&format!("\"\" {A} 5000 1024"), EmptyName);
    refused(&format!("f.bin 199 0 1024 {}", "x".repeat(65)), BadToken);
    refused("f.bin 199 0 -1 77", BadSize);
}

#[test]
fn research_truncation_rules() {
    let legacy = format!("f.bin {A} 5000");
    assert_eq!(
        offer_with(legacy.as_bytes(), false, SHORT).map(|_| ()),
        Err(DccParseError::SuspectedTruncation)
    );
    let cut = format!("f.bin {A} 5000 10");
    assert_eq!(
        offer_with(cut.as_bytes(), false, NEAR).map(|_| ()),
        Err(DccParseError::SuspectedTruncation)
    );
    let short = format!("f.bin {A} 5000 1024");
    assert_eq!(
        offer_with(short.as_bytes(), false, SHORT).unwrap().size,
        Some(1024)
    );
}

#[test]
fn truncation_applies_to_each_shape_and_only_without_the_delimiter() {
    for args in [
        format!("f.bin {A} 5000 1024"),
        "f.bin 199 0 1024 77".to_string(),
    ] {
        assert!(offer_with(args.as_bytes(), false, SHORT).is_ok(), "{args}");
        assert_eq!(
            offer_with(args.as_bytes(), false, NEAR).map(|_| ()),
            Err(DccParseError::SuspectedTruncation),
            "{args}"
        );
        assert!(offer_with(args.as_bytes(), true, NEAR).is_ok(), "{args}");
    }
    let legacy = format!("\"f.bin\" {A} 5000");
    assert!(offer_with(legacy.as_bytes(), true, NEAR).is_ok());
}

#[test]
fn a_field_error_outranks_suspected_truncation() {
    let bad = format!("f.bin {A} 70000 1024");
    assert_eq!(
        offer_with(bad.as_bytes(), false, NEAR).map(|_| ()),
        Err(DccParseError::BadPort)
    );
}

#[test]
fn wire_name_keeps_quotes_and_internal_spaces_exactly() {
    let quoted = offer(&format!("\"a  b.bin\" {A} 5000 1024")).unwrap();
    assert_eq!(quoted.wire_name.as_bytes(), b"\"a  b.bin\"");
    assert_eq!(quoted.wire_name.name(), b"a  b.bin");
    assert!(quoted.wire_name.is_quoted());

    let plain = offer(&format!("  a   b  c.bin  {A} 5000 1024")).unwrap();
    assert_eq!(plain.wire_name.as_bytes(), b"a   b  c.bin");
    assert!(!plain.wire_name.is_quoted());
}

#[test]
fn non_utf8_names_survive() {
    let args = [b"caf\xe9 \xff.bin 3232235777 5000 1024".as_slice()].concat();
    let parsed = offer_with(&args, true, SHORT).unwrap();
    assert_eq!(parsed.wire_name.as_bytes(), b"caf\xe9 \xff.bin");

    let quoted = b"\"\xfe\xff\" 3232235777 5000 1024";
    let parsed = offer_with(quoted, true, SHORT).unwrap();
    assert_eq!(parsed.wire_name.as_bytes(), b"\"\xfe\xff\"");
}

#[test]
fn closing_quote_is_the_last_quote_followed_by_a_space() {
    let parsed = offer(&format!("\"a\" b\" {A} 5000 1024")).unwrap();
    assert_eq!(parsed.wire_name.name(), b"a\" b");
    refused(
        &format!("\" {A} 5000 1024"),
        DccParseError::UnterminatedQuote,
    );
    refused("\"name\"", DccParseError::UnterminatedQuote);
}

#[test]
fn quoted_tail_counts() {
    refused("\"f\" 1", DccParseError::BadFieldCount);
    refused("\"f\" 1 2 3 4 5", DccParseError::BadFieldCount);
    refused("\"f\" 1 2 3 4 5 6 7 8 9", DccParseError::BadFieldCount);
    refused("\"\" 1 2 3 4 5", DccParseError::BadFieldCount);
}

#[test]
fn zero_valued_port_selects_passive_in_any_spelling() {
    accepted(
        "f 199 00 5 t",
        (Shape::Passive, "f", None, 0, Some(5), Some("t")),
    );
    accepted(
        "\"f\" 199 000 5 t",
        (Shape::Passive, "f", None, 0, Some(5), Some("t")),
    );
}

#[test]
fn a_zero_longer_than_a_number_is_not_zero_valued() {
    let zeros = "0".repeat(21);
    refused(
        &format!("\"f\" {A} {zeros} 5 t"),
        DccParseError::UnexpectedToken,
    );
    refused(&format!("f {A} {zeros} 5"), DccParseError::BadPort);
}

#[test]
fn numbers_may_have_leading_zeros_up_to_twenty_digits() {
    accepted(
        "f 192.168.1.1 05000 001",
        (
            Shape::Standard,
            "f",
            Some("192.168.1.1"),
            5000,
            Some(1),
            None,
        ),
    );
    refused(
        &format!("f {A} 5000 {}1", "0".repeat(20)),
        DccParseError::BadSize,
    );
    accepted(
        &format!("f {A} 65535 18446744073709551615"),
        (
            Shape::Standard,
            "f",
            Some("192.168.1.1"),
            65535,
            Some(u64::MAX),
            None,
        ),
    );
}

#[test]
fn validation_order_decides_the_reported_error() {
    use DccParseError::*;
    // Standard and legacy: port zero, port, address, implausible address, size.
    refused("f host 0 -1", PortZeroWithoutToken);
    refused("f host abc -1", BadPort);
    refused("f host 5000 -1", BadAddress);
    refused("f 5 5000 -1", ImplausibleAddress);
    refused(&format!("f {A} 5000 -1"), BadSize);
    // Passive: address, token, size.
    refused(&format!("f host 0 -1 {}", "x".repeat(65)), BadAddress);
    refused(&format!("f 199 0 -1 {}", "x".repeat(65)), BadToken);
    refused("f 199 0 -1 ok", BadSize);
}

#[test]
fn addresses_are_parsed_as_untrusted_literals() {
    use DccParseError::*;
    accepted(
        "f 4294967295 5 1",
        (
            Shape::Standard,
            "f",
            Some("255.255.255.255"),
            5,
            Some(1),
            None,
        ),
    );
    accepted(
        "f 16777216 5 1",
        (Shape::Standard, "f", Some("1.0.0.0"), 5, Some(1), None),
    );
    accepted(
        "f ::ffff:8.8.8.8 5 1",
        (
            Shape::Standard,
            "f",
            Some("::ffff:8.8.8.8"),
            5,
            Some(1),
            None,
        ),
    );
    // Private and loopback claims parse. Refusing them is the policy layer's job.
    accepted(
        "f 2130706433 5 1",
        (Shape::Standard, "f", Some("127.0.0.1"), 5, Some(1), None),
    );
    refused("f 16777215 5 1", ImplausibleAddress);
    refused("f 0 5 1", ImplausibleAddress);
    refused("f 0.0.0.1 5 1", ImplausibleAddress);
    refused("f 1.2.3 5 1", BadAddress);
    refused("f 01.2.3.4 5 1", BadAddress);
    refused("f fe80::1%eth0 5 1", BadAddress);
    refused("f :::: 5 1", BadAddress);
    let args = b"f \xff:\xfe 5 1";
    assert_eq!(offer_with(args, true, SHORT).map(|_| ()), Err(BadAddress));
}

#[test]
fn passive_address_is_syntax_checked_but_a_zero_network_claim_is_dropped() {
    accepted(
        "f 199 0 5 t",
        (Shape::Passive, "f", None, 0, Some(5), Some("t")),
    );
    accepted(
        "f 0.0.0.1 0 5 t",
        (Shape::Passive, "f", None, 0, Some(5), Some("t")),
    );
    accepted(
        "f 2001:db8::9 0 5 t",
        (
            Shape::Passive,
            "f",
            Some("2001:db8::9"),
            0,
            Some(5),
            Some("t"),
        ),
    );
    refused("f host.example 0 5 t", DccParseError::BadAddress);
}

#[test]
fn token_alphabet_and_length() {
    let longest = "x".repeat(64);
    accepted(
        &format!("f 199 0 5 {longest}"),
        (Shape::Passive, "f", None, 0, Some(5), Some(&longest)),
    );
    accepted(
        "f 199 0 5 !~",
        (Shape::Passive, "f", None, 0, Some(5), Some("!~")),
    );
    refused("f 199 0 5 a\"b", DccParseError::BadToken);
    let args = b"f 199 0 5 \x7f";
    assert_eq!(
        offer_with(args, true, SHORT).map(|_| ()),
        Err(DccParseError::BadToken)
    );
}

#[test]
fn a_malformed_standard_offer_never_falls_back() {
    // Each would be a legal shorter or passive offer if a parser retried.
    for args in [
        format!("f.bin {A} 5000 x"),
        format!("f.bin {A} x 1024"),
        format!("{A} 5000 x 1024"),
        format!("a {A} 70000 1024"),
    ] {
        assert!(offer(&args).is_err(), "{args}");
    }
}

#[test]
fn a_multi_word_name_ending_in_zero_is_read_as_the_grammar_says() {
    // Legacy never carries this name, so the shape is passive, not a fallback.
    accepted(
        "a 2024 0 16777216 70000",
        (
            Shape::Passive,
            "a",
            None,
            0,
            Some(16_777_216),
            Some("70000"),
        ),
    );
}

/// From fuzzing. A `0x01` inside the arguments closes the body, so it counts as
/// the final delimiter and nothing after it is part of the offer.
#[test]
fn an_embedded_delimiter_closes_the_message() {
    let ctcp = parse_ctcp(b"\x01DCC SEND \x10\" 0 0 10 0\x010", NEAR).unwrap();
    assert!(ctcp.final_delimiter());
    let DccMessage::Send(parsed) = parse_dcc(&ctcp, None).unwrap() else {
        panic!("not an offer");
    };
    assert_eq!(parsed.wire_name.as_bytes(), b"\x10\"");
    assert_eq!(parsed.size, Some(10));
}

#[test]
fn matching_of_tag_and_type_ignores_ascii_case() {
    let parsed = parse_ctcp(b"\x01dcc send f 3232235777 5 1\x01", SHORT).unwrap();
    assert!(matches!(parse_dcc(&parsed, None), Ok(DccMessage::Send(_))));
    let parsed = parse_ctcp(b"\x01DcC SeNd f 3232235777 5 1\x01", SHORT).unwrap();
    assert!(matches!(parse_dcc(&parsed, None), Ok(DccMessage::Send(_))));
}

#[test]
fn other_dcc_types_are_named_and_never_treated_as_send() {
    let cases: [(&[u8], DccKind); 7] = [
        (b"\x01DCC TSEND f 1 2 3\x01", DccKind::Turbo),
        (b"\x01TDCC SEND f 3232235777 5 1\x01", DccKind::Turbo),
        (b"\x01DCC SSEND f 3232235777 5 1\x01", DccKind::SecureSend),
        (b"\x01DCC CHAT chat 3232235777 5\x01", DccKind::Chat),
        (b"\x01DCC SCHAT chat 3232235777 5\x01", DccKind::SecureChat),
        (b"\x01DCC NEWTHING f\x01", DccKind::Unknown),
        (b"\x01DCC SE\x01", DccKind::Unknown),
    ];
    for (input, kind) in cases {
        let parsed = parse_ctcp(input, SHORT).unwrap();
        assert_eq!(
            parse_dcc(&parsed, None),
            Ok(DccMessage::Other { kind }),
            "{input:?}"
        );
    }
}

#[test]
fn other_ctcp_and_empty_dcc_are_refused() {
    let parsed = parse_ctcp(b"\x01VERSION\x01", SHORT).unwrap();
    assert_eq!(parse_dcc(&parsed, None), Err(DccParseError::NotDcc));
    for input in [&b"\x01DCC\x01"[..], b"\x01DCC \x01", b"\x01DCC    \x01"] {
        let parsed = parse_ctcp(input, SHORT).unwrap();
        assert_eq!(
            parse_dcc(&parsed, None),
            Err(DccParseError::MissingType),
            "{input:?}"
        );
    }
    assert_eq!(offer("").map(|_| ()), Err(DccParseError::TooFewFields));
}

/// Cases shaped after senders recorded in `PROTOCOL_SPEC.md` §2. They were
/// written from that document's observations, not captured from live software.
#[test]
fn documented_sender_forms() {
    // I1: iroffer quotes names with spaces, and its passive token is an integer.
    accepted(
        "\"pack one.mkv\" 1572395042 40001 734003200",
        (
            Shape::Standard,
            "pack one.mkv",
            Some("93.184.216.34"),
            40001,
            Some(734_003_200),
            None,
        ),
    );
    accepted(
        "\"pack one.mkv\" 1572395042 0 734003200 12",
        (
            Shape::Passive,
            "pack one.mkv",
            Some("93.184.216.34"),
            0,
            Some(734_003_200),
            Some("12"),
        ),
    );
    // I2: irssi as an unquoted name with spaces.
    accepted(
        "my file.iso 1572395042 40001 5",
        (
            Shape::Standard,
            "my file.iso",
            Some("93.184.216.34"),
            40001,
            Some(5),
            None,
        ),
    );
    // I3: HexChat's literal 199 in a passive offer.
    accepted(
        "hc.bin 199 0 734003200 3",
        (
            Shape::Passive,
            "hc.bin",
            None,
            0,
            Some(734_003_200),
            Some("3"),
        ),
    );
    // I5: KVIrc accepts dotted IPv4.
    accepted(
        "k.bin 93.184.216.34 40001 5",
        (
            Shape::Standard,
            "k.bin",
            Some("93.184.216.34"),
            40001,
            Some(5),
            None,
        ),
    );
    // I1, I2, I5: textual IPv6.
    accepted(
        "v6.bin 2606:2800:220:1::1 40001 5",
        (
            Shape::Standard,
            "v6.bin",
            Some("2606:2800:220:1::1"),
            40001,
            Some(5),
            None,
        ),
    );
    // V2 v6.33: a size above 32 bits.
    accepted(
        "big.bin 1572395042 40001 6442450944",
        (
            Shape::Standard,
            "big.bin",
            Some("93.184.216.34"),
            40001,
            Some(6_442_450_944),
            None,
        ),
    );
}

fn reply(
    input: &[u8],
    line: LineContext,
    pending: Option<ReplyTailKind>,
) -> Result<DccMessage, DccParseError> {
    parse_dcc(&parse_ctcp(input, line).unwrap(), pending)
}

fn accept(
    input: &[u8],
    pending: ReplyTailKind,
) -> Result<(Vec<u8>, ReplyTail, u64), DccParseError> {
    match reply(input, SHORT, Some(pending))? {
        DccMessage::Accept(a) => Ok((a.wire_name.as_bytes().to_vec(), a.tail, a.position)),
        other => panic!("not an accept: {other:?}"),
    }
}

#[test]
fn active_accept_tail() {
    let (name, tail, position) = accept(
        b"\x01DCC ACCEPT file.ext 5000 1024\x01",
        ReplyTailKind::Active,
    )
    .unwrap();
    assert_eq!(name, b"file.ext");
    assert!(matches!(tail, ReplyTail::Active { port } if port.get() == 5000));
    assert_eq!(position, 1024);
}

#[test]
fn passive_accept_tail() {
    let (name, tail, position) = accept(
        b"\x01DCC ACCEPT a b.bin 0 1024 ab-7\x01",
        ReplyTailKind::Passive,
    )
    .unwrap();
    assert_eq!(name, b"a b.bin");
    assert!(matches!(tail, ReplyTail::Passive { token } if token.as_bytes() == b"ab-7"));
    assert_eq!(position, 1024);
}

#[test]
fn quoted_accept_uses_the_same_closing_rule() {
    let (name, _, position) =
        accept(b"\x01DCC ACCEPT \"a b\" 5000 7\x01", ReplyTailKind::Active).unwrap();
    assert_eq!(name, b"\"a b\"");
    assert_eq!(position, 7);
    let (name, _, _) = accept(b"\x01DCC ACCEPT \"a b\" 0 7 t\x01", ReplyTailKind::Passive).unwrap();
    assert_eq!(name, b"\"a b\"");
}

#[test]
fn accept_failures_are_exact() {
    use DccParseError::*;
    use ReplyTailKind::{Active, Passive};
    let cases: [(&[u8], ReplyTailKind, DccParseError); 15] = [
        (b"\x01DCC ACCEPT f 70000 1\x01", Active, BadPort),
        (b"\x01DCC ACCEPT f 0 1\x01", Active, BadPort),
        (b"\x01DCC ACCEPT f x 1\x01", Active, BadPort),
        (b"\x01DCC ACCEPT f 5000 -1\x01", Active, BadPosition),
        (
            b"\x01DCC ACCEPT f 5000 18446744073709551616\x01",
            Active,
            BadPosition,
        ),
        (b"\x01DCC ACCEPT 5000 1\x01", Active, TooFewFields),
        (b"\x01DCC ACCEPT \"f\" 5000 1 t\x01", Active, BadFieldCount),
        (b"\x01DCC ACCEPT \"\" 5000 1\x01", Active, EmptyName),
        (b"\x01DCC ACCEPT \"f 5000 1\x01", Active, UnterminatedQuote),
        (b"\x01DCC ACCEPT f 5 1 t\x01", Passive, BadPort),
        (b"\x01DCC ACCEPT f 0 x t\x01", Passive, BadPosition),
        (b"\x01DCC ACCEPT f 0 1 a\"b\x01", Passive, BadToken),
        (b"\x01DCC ACCEPT 0 1 t\x01", Passive, TooFewFields),
        (b"\x01DCC ACCEPT \"f\" 5000 1\x01", Passive, BadFieldCount),
        (b"\x01DCC ACCEPT \"f\" 0 1\x01", Passive, BadFieldCount),
    ];
    for (input, pending, want) in cases {
        assert_eq!(accept(input, pending).map(|_| ()), Err(want), "{input:?}");
    }
}

#[test]
fn accept_with_no_pending_attempt_is_unsolicited() {
    assert_eq!(
        reply(b"\x01DCC ACCEPT f 5000 1\x01", SHORT, None),
        Err(DccParseError::Unsolicited)
    );
    assert_eq!(
        reply(b"\x01DCC RESUME f 5000 1\x01", SHORT, None),
        Err(DccParseError::Unsolicited)
    );
}

#[test]
fn a_cut_accept_is_refused_rather_than_read_as_a_position_mismatch() {
    let cut = b"\x01DCC ACCEPT f 5000 10";
    assert_eq!(
        reply(cut, NEAR, Some(ReplyTailKind::Active)),
        Err(DccParseError::SuspectedTruncation)
    );
    assert!(reply(cut, SHORT, Some(ReplyTailKind::Active)).is_ok());
    let closed = b"\x01DCC ACCEPT f 5000 10\x01";
    assert!(reply(closed, NEAR, Some(ReplyTailKind::Active)).is_ok());
}

#[test]
fn context_decides_the_tail_with_no_guessing() {
    // Under an active attempt a passive-shaped reply keeps its first fields in the name.
    let (name, tail, position) =
        accept(b"\x01DCC ACCEPT f 0 1024 77\x01", ReplyTailKind::Active).unwrap();
    assert_eq!(name, b"f 0");
    assert!(matches!(tail, ReplyTail::Active { port } if port.get() == 1024));
    assert_eq!(position, 77);
    // Port 1024 will not match the pending attempt, so the session drops it.
}

#[test]
fn resume_parses_with_the_same_rules() {
    let parsed = reply(
        b"\x01DCC RESUME \"a b\" 5000 7\x01",
        SHORT,
        Some(ReplyTailKind::Active),
    )
    .unwrap();
    let DccMessage::Resume(resume) = parsed else {
        panic!("not a resume");
    };
    assert_eq!(resume.wire_name.as_bytes(), b"\"a b\"");
    assert_eq!(resume.position, 7);
}
