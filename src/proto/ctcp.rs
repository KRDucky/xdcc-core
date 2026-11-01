//! CTCP extraction and encoding, with no quoting layer in either direction.

use std::fmt;

use crate::proto::casemap::CaseMapping;
use crate::proto::irc::{IrcMessage, MAX_MESSAGE_LEN};

const DELIMITER: u8 = 0x01;

/// The line length treated as possibly cut by a server, without CRLF.
pub const DEFAULT_TRUNCATION_THRESHOLD: usize = 480;

/// How long the carrying line was.
///
/// Every CTCP parse needs this, so the evidence for `SuspectedTruncation` cannot
/// be lost between the IRC layer and the DCC layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineContext {
    message_len: usize,
    threshold: usize,
}

impl LineContext {
    /// Uses `message_len` bytes outside the tag section, without CRLF.
    pub const fn new(message_len: usize) -> Self {
        Self {
            message_len,
            threshold: DEFAULT_TRUNCATION_THRESHOLD,
        }
    }

    /// Reads the length from a parsed message.
    pub fn of(message: &IrcMessage<'_>) -> Self {
        Self::new(message.message_len())
    }

    /// Replaces the default threshold.
    pub const fn with_threshold(mut self, threshold: usize) -> Self {
        self.threshold = threshold;
        self
    }

    /// True if the line reached the threshold. Tags never count.
    pub const fn near_limit(&self) -> bool {
        self.message_len >= self.threshold
    }
}

/// Why a message body is not usable CTCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CtcpError {
    /// The first byte is not `0x01`. An embedded delimiter is plain text.
    NotCtcp,
    /// There is no tag after the delimiter.
    EmptyTag,
    /// The body contains CR, LF, or NUL.
    ForbiddenByte,
    /// The body exceeds [`MAX_MESSAGE_LEN`].
    TooLong,
}

impl fmt::Display for CtcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotCtcp => "not a CTCP message",
            Self::EmptyTag => "empty CTCP tag",
            Self::ForbiddenByte => "CTCP body contains CR, LF, or NUL",
            Self::TooLong => "CTCP body is too long",
        })
    }
}

impl std::error::Error for CtcpError {}

/// One CTCP message, borrowing from the body it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ctcp<'a> {
    tag: &'a [u8],
    args: &'a [u8],
    final_delimiter: bool,
    near_limit: bool,
}

impl<'a> Ctcp<'a> {
    /// The tag, in the case received. Compare it ignoring ASCII case.
    pub fn tag(&self) -> &'a [u8] {
        self.tag
    }

    /// The bytes after the tag and its separating space.
    pub fn args(&self) -> &'a [u8] {
        self.args
    }

    /// True if the closing `0x01` was present.
    pub fn final_delimiter(&self) -> bool {
        self.final_delimiter
    }

    /// True if the carrying line reached the truncation threshold.
    pub fn near_limit(&self) -> bool {
        self.near_limit
    }
}

/// Parses a PRIVMSG or NOTICE body.
///
/// The body ends at the next `0x01` or at the end of the message, and anything
/// after that delimiter is ignored. Low-level and CTCP-level quoting are not
/// applied.
pub fn parse_ctcp(body: &[u8], line: LineContext) -> Result<Ctcp<'_>, CtcpError> {
    let Some(rest) = body.strip_prefix(&[DELIMITER]) else {
        return Err(CtcpError::NotCtcp);
    };
    if body.len() > MAX_MESSAGE_LEN {
        return Err(CtcpError::TooLong);
    }
    if body.iter().any(|&byte| matches!(byte, b'\r' | b'\n' | 0)) {
        return Err(CtcpError::ForbiddenByte);
    }
    let end = rest.iter().position(|&byte| byte == DELIMITER);
    let content = &rest[..end.unwrap_or(rest.len())];
    let (tag, args) = match content.iter().position(|&byte| byte == b' ') {
        Some(space) => (&content[..space], &content[space + 1..]),
        None => (content, &content[content.len()..]),
    };
    if tag.is_empty() {
        return Err(CtcpError::EmptyTag);
    }
    Ok(Ctcp {
        tag,
        args,
        final_delimiter: end.is_some(),
        near_limit: line.near_limit(),
    })
}

/// Why a CTCP body cannot be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CtcpEncodeError {
    /// The tag is empty or contains a space.
    BadTag,
    /// A field contains `0x01`, CR, LF, or NUL.
    ForbiddenByte,
    /// The body would exceed [`MAX_MESSAGE_LEN`].
    TooLong,
}

impl fmt::Display for CtcpEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BadTag => "invalid CTCP tag",
            Self::ForbiddenByte => "CTCP field contains a forbidden byte",
            Self::TooLong => "CTCP body is too long",
        })
    }
}

impl std::error::Error for CtcpEncodeError {}

/// Builds `0x01 tag [SPACE args] 0x01`, always with the closing delimiter.
pub fn encode_ctcp(tag: &[u8], args: &[u8]) -> Result<Vec<u8>, CtcpEncodeError> {
    if tag.is_empty() || tag.contains(&b' ') {
        return Err(CtcpEncodeError::BadTag);
    }
    let forbidden = |byte: &u8| matches!(*byte, DELIMITER | b'\r' | b'\n' | 0);
    if tag.iter().any(forbidden) || args.iter().any(forbidden) {
        return Err(CtcpEncodeError::ForbiddenByte);
    }
    let separator = usize::from(!args.is_empty());
    let len = tag
        .len()
        .checked_add(args.len())
        .and_then(|len| len.checked_add(separator + 2))
        .filter(|&len| len <= MAX_MESSAGE_LEN)
        .ok_or(CtcpEncodeError::TooLong)?;
    let mut body = Vec::with_capacity(len);
    body.push(DELIMITER);
    body.extend_from_slice(tag);
    if !args.is_empty() {
        body.push(b' ');
        body.extend_from_slice(args);
    }
    body.push(DELIMITER);
    Ok(body)
}

/// The IRC command that carried a CTCP message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CtcpCarrier {
    /// A query.
    Privmsg,
    /// A reply.
    Notice,
}

/// A CTCP message with the IRC context needed to judge it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InboundCtcp<'a> {
    /// The command that carried it.
    pub carrier: CtcpCarrier,
    /// The first parameter, as received.
    pub target: &'a [u8],
    /// The sending nick, if the message had a source.
    pub sender: Option<&'a [u8]>,
    /// The CTCP message.
    pub ctcp: Ctcp<'a>,
}

impl InboundCtcp<'_> {
    /// True only for a PRIVMSG addressed to `own_nick`.
    ///
    /// A DCC offer sent any other way must be logged and ignored
    /// (`PROTOCOL_SPEC.md` §4 rule 5).
    pub fn may_carry_dcc_offer(&self, own_nick: &[u8], mapping: CaseMapping) -> bool {
        self.carrier == CtcpCarrier::Privmsg && mapping.eq(self.target, own_nick)
    }
}

/// Extracts CTCP from a PRIVMSG or NOTICE.
///
/// Returns `None` for any other command, for a missing body, or for plain text,
/// including text with an embedded `0x01`.
pub fn inbound_ctcp<'a>(message: &IrcMessage<'a>) -> Option<Result<InboundCtcp<'a>, CtcpError>> {
    let carrier = if message.command().eq_ignore_ascii_case(b"PRIVMSG") {
        CtcpCarrier::Privmsg
    } else if message.command().eq_ignore_ascii_case(b"NOTICE") {
        CtcpCarrier::Notice
    } else {
        return None;
    };
    let [target, body] = *message.params() else {
        return None;
    };
    match parse_ctcp(body, LineContext::of(message)) {
        Err(CtcpError::NotCtcp) => None,
        Err(error) => Some(Err(error)),
        Ok(ctcp) => Some(Ok(InboundCtcp {
            carrier,
            target,
            sender: message.source_nick(),
            ctcp,
        })),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const SHORT: LineContext = LineContext::new(50);

    #[test]
    fn tag_args_and_delimiter_are_separate() {
        let c = parse_ctcp(b"\x01DCC SEND a 1 2 3\x01", SHORT).unwrap();
        assert_eq!(c.tag(), b"DCC");
        assert_eq!(c.args(), b"SEND a 1 2 3");
        assert!(c.final_delimiter());
        assert!(!c.near_limit());
    }

    #[test]
    fn missing_final_delimiter_is_accepted_and_recorded() {
        let c = parse_ctcp(b"\x01VERSION", SHORT).unwrap();
        assert_eq!(c.tag(), b"VERSION");
        assert_eq!(c.args(), b"");
        assert!(!c.final_delimiter());
    }

    #[test]
    fn body_ends_at_the_next_delimiter() {
        let c = parse_ctcp(b"\x01PING 1\x01 trailing \x01DCC x\x01", SHORT).unwrap();
        assert_eq!(c.args(), b"1");
        assert!(c.final_delimiter());
    }

    #[test]
    fn only_a_leading_delimiter_makes_ctcp() {
        for body in [&b"hello \x01DCC SEND a 1 2 3\x01"[..], b"", b" \x01DCC"] {
            assert_eq!(parse_ctcp(body, SHORT), Err(CtcpError::NotCtcp), "{body:?}");
        }
    }

    #[test]
    fn empty_tags_are_refused() {
        for body in [&b"\x01"[..], b"\x01\x01", b"\x01 x\x01"] {
            assert_eq!(
                parse_ctcp(body, SHORT),
                Err(CtcpError::EmptyTag),
                "{body:?}"
            );
        }
    }

    #[test]
    fn neither_quoting_layer_is_applied() {
        let c = parse_ctcp(b"\x01X a\\\\b\x10n\\a\x01", SHORT).unwrap();
        assert_eq!(c.args(), b"a\\\\b\x10n\\a");
        let body = encode_ctcp(b"X", b"a\\\\b\x10n").unwrap();
        assert_eq!(body, b"\x01X a\\\\b\x10n\x01");
    }

    #[test]
    fn threshold_is_inclusive_and_configurable() {
        assert!(!LineContext::new(479).near_limit());
        assert!(LineContext::new(480).near_limit());
        assert!(LineContext::new(100).with_threshold(100).near_limit());
        assert!(
            parse_ctcp(b"\x01X", LineContext::new(480))
                .unwrap()
                .near_limit()
        );
    }

    #[test]
    fn tags_do_not_count_toward_the_threshold() {
        let tags = vec![b'a'; 4000];
        let line = [b"@".to_vec(), tags, b" PRIVMSG me :\x01X\x01".to_vec()].concat();
        let m = IrcMessage::parse(&line).unwrap();
        let inbound = inbound_ctcp(&m).unwrap().unwrap();
        assert!(!inbound.ctcp.near_limit());
    }

    #[test]
    fn the_prefix_counts_toward_the_threshold() {
        let name = vec![b'n'; 470];
        let line = [b":".to_vec(), name, b" PRIVMSG me :\x01X".to_vec()].concat();
        let m = IrcMessage::parse(&line).unwrap();
        assert!(inbound_ctcp(&m).unwrap().unwrap().ctcp.near_limit());
    }

    #[test]
    fn oversized_and_forbidden_bodies_are_refused() {
        let long = [vec![1u8], vec![b'x'; MAX_MESSAGE_LEN]].concat();
        assert_eq!(parse_ctcp(&long, SHORT), Err(CtcpError::TooLong));
        for body in [&b"\x01A\rb"[..], b"\x01A\nb", b"\x01A\0b"] {
            assert_eq!(parse_ctcp(body, SHORT), Err(CtcpError::ForbiddenByte));
        }
    }

    #[test]
    fn encoder_refuses_injection() {
        assert_eq!(encode_ctcp(b"", b"x"), Err(CtcpEncodeError::BadTag));
        assert_eq!(encode_ctcp(b"A B", b"x"), Err(CtcpEncodeError::BadTag));
        for bad in [&b"a\x01b"[..], b"a\rb", b"a\nb", b"a\0b"] {
            assert_eq!(encode_ctcp(b"X", bad), Err(CtcpEncodeError::ForbiddenByte));
            assert_eq!(encode_ctcp(bad, b""), Err(CtcpEncodeError::ForbiddenByte));
        }
    }

    #[test]
    fn encoder_boundary() {
        let fits = vec![b'x'; MAX_MESSAGE_LEN - 5];
        assert_eq!(encode_ctcp(b"AB", &fits).unwrap().len(), MAX_MESSAGE_LEN);
        let over = vec![b'x'; MAX_MESSAGE_LEN - 4];
        assert_eq!(encode_ctcp(b"AB", &over), Err(CtcpEncodeError::TooLong));
    }

    #[test]
    fn offers_are_eligible_only_by_privmsg_to_our_nick() {
        let check = |line: &[u8]| {
            let m = IrcMessage::parse(line).unwrap();
            inbound_ctcp(&m)
                .unwrap()
                .unwrap()
                .may_carry_dcc_offer(b"Me[1]", CaseMapping::Rfc1459)
        };
        assert!(check(b":b!u@h PRIVMSG Me[1] :\x01DCC SEND a 1 2 3\x01"));
        assert!(check(b":b!u@h privmsg me{1} :\x01DCC SEND a 1 2 3\x01"));
        assert!(!check(b":b!u@h NOTICE Me[1] :\x01DCC SEND a 1 2 3\x01"));
        assert!(!check(b":b!u@h PRIVMSG #chan :\x01DCC SEND a 1 2 3\x01"));
        assert!(!check(
            b":b!u@h PRIVMSG other,Me[1] :\x01DCC SEND a 1 2 3\x01"
        ));
    }

    #[test]
    fn inbound_ignores_what_is_not_ctcp() {
        for line in [
            &b"PING :\x01X\x01"[..],
            b"PRIVMSG me :plain \x01DCC SEND a 1 2 3\x01",
            b"PRIVMSG me",
            b"PRIVMSG",
        ] {
            let m = IrcMessage::parse(line).unwrap();
            assert_eq!(inbound_ctcp(&m), None, "{line:?}");
        }
    }

    #[test]
    fn inbound_keeps_sender_and_carrier() {
        let m = IrcMessage::parse(b":bot!u@h NOTICE me :\x01VERSION x\x01").unwrap();
        let c = inbound_ctcp(&m).unwrap().unwrap();
        assert_eq!(c.carrier, CtcpCarrier::Notice);
        assert_eq!(c.sender, Some(&b"bot"[..]));
        assert_eq!(c.target, b"me");
    }
}
