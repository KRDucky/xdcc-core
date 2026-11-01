//! Validated outbound lines, with an explicit length budget.

use std::fmt;

use crate::proto::irc::MAX_MESSAGE_LEN;

const PRIVMSG_HEAD: &[u8] = b"PRIVMSG ";
const PRIVMSG_SEPARATOR: &[u8] = b" :";

/// How many bytes of an outbound line a client may use.
///
/// A server relays a line with `:nick!user@host ` in front, and the 512-byte
/// limit applies to the relayed form. So the sender's own budget is smaller than
/// 510, by an amount it may not know exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineBudget {
    reserved: usize,
}

impl LineBudget {
    /// Reserved when the relayed source is unknown.
    ///
    /// This allows `:` plus a 30-byte nick, `!`, a 12-byte user, `@`, a 63-byte
    /// host, and a space. These are common limits, not guarantees.
    pub const DEFAULT_RESERVED: usize = 109;

    /// Reserves a fixed number of bytes.
    pub const fn reserving(reserved: usize) -> Self {
        Self { reserved }
    }

    /// Reserves exactly what a known source needs, such as `nick!user@host`.
    pub const fn for_source(source: &[u8]) -> Self {
        Self::reserving(source.len().saturating_add(2))
    }

    /// The longest line, without CRLF, that fits this budget.
    pub const fn limit(&self) -> usize {
        MAX_MESSAGE_LEN.saturating_sub(self.reserved)
    }
}

impl Default for LineBudget {
    fn default() -> Self {
        Self::reserving(Self::DEFAULT_RESERVED)
    }
}

/// Why an outbound value was refused. Nothing is ever truncated to fit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OutboundError {
    /// The line or nick is empty.
    Empty,
    /// A value contains a byte it must not carry, such as CR, LF, or NUL.
    ForbiddenByte,
    /// A line starts with `@`. This crate sends no tags.
    Tagged,
    /// The nick is not usable as a single target.
    BadNick,
    /// The line is longer than the budget allows.
    TooLong {
        /// The line's length.
        len: usize,
        /// The budget's limit.
        limit: usize,
    },
}

impl fmt::Display for OutboundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty outbound value"),
            Self::ForbiddenByte => f.write_str("outbound value contains a forbidden byte"),
            Self::Tagged => f.write_str("outbound tags are not supported"),
            Self::BadNick => f.write_str("invalid nick"),
            Self::TooLong { len, limit } => {
                write!(
                    f,
                    "outbound line of {len} bytes exceeds the limit of {limit}"
                )
            }
        }
    }
}

impl std::error::Error for OutboundError {}

/// A line safe to send, without its terminator.
#[derive(Clone, PartialEq, Eq)]
pub struct OutboundLine(Vec<u8>);

impl OutboundLine {
    /// Validates a line, refusing CR, LF, NUL, tags, and anything over budget.
    pub fn new(line: &[u8], budget: LineBudget) -> Result<Self, OutboundError> {
        check_line(line, budget)?;
        Ok(Self(line.to_vec()))
    }

    /// The line without its terminator.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The bytes to write. Lines are always sent with CRLF.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut wire = Vec::with_capacity(self.0.len() + 2);
        wire.extend_from_slice(&self.0);
        wire.extend_from_slice(b"\r\n");
        wire
    }
}

impl fmt::Debug for OutboundLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OutboundLine({:?})", self.0.escape_ascii().to_string())
    }
}

fn has_line_break_or_nul(bytes: &[u8]) -> bool {
    bytes.iter().any(|&byte| matches!(byte, b'\r' | b'\n' | 0))
}

fn check_line(line: &[u8], budget: LineBudget) -> Result<(), OutboundError> {
    if line.is_empty() {
        return Err(OutboundError::Empty);
    }
    if has_line_break_or_nul(line) {
        return Err(OutboundError::ForbiddenByte);
    }
    if line[0] == b'@' {
        return Err(OutboundError::Tagged);
    }
    if line.len() > budget.limit() {
        return Err(OutboundError::TooLong {
            len: line.len(),
            limit: budget.limit(),
        });
    }
    Ok(())
}

/// A nick that is safe to use as a message target.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BotNick(Vec<u8>);

impl BotNick {
    /// The longest nick accepted.
    pub const MAX_LEN: usize = 64;

    /// Accepts one nick.
    ///
    /// It refuses spaces, ASCII control bytes including DEL, and whatever would
    /// address something else: a list, a mask, a channel, or a leading `:`. Bytes
    /// above `0x7F` are allowed, since a nick need not be ASCII or UTF-8.
    pub fn parse(nick: &[u8]) -> Result<Self, OutboundError> {
        if nick.is_empty() {
            return Err(OutboundError::Empty);
        }
        if nick.len() > Self::MAX_LEN {
            return Err(OutboundError::BadNick);
        }
        if nick.iter().any(u8::is_ascii_control) {
            return Err(OutboundError::ForbiddenByte);
        }
        if nick
            .iter()
            .any(|&byte| matches!(byte, b' ' | b',' | b'!' | b'@' | b'*' | b'?'))
            || matches!(nick[0], b':' | b'#' | b'&' | b'+' | b'$')
        {
            return Err(OutboundError::BadNick);
        }
        Ok(Self(nick.to_vec()))
    }

    /// The nick's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for BotNick {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BotNick({:?})", self.0.escape_ascii().to_string())
    }
}

/// The length of `PRIVMSG <bot> :<body>`, or `None` if it overflows.
fn line_len(bot: usize, body: usize) -> Option<usize> {
    PRIVMSG_HEAD
        .len()
        .checked_add(bot)?
        .checked_add(PRIVMSG_SEPARATOR.len())?
        .checked_add(body)
}

/// Builds the line only after it is known to fit, so a refused body costs nothing.
fn message_line(
    bot: &BotNick,
    body: &[u8],
    budget: LineBudget,
) -> Result<OutboundLine, OutboundError> {
    if has_line_break_or_nul(body) {
        return Err(OutboundError::ForbiddenByte);
    }
    let limit = budget.limit();
    let len = line_len(bot.0.len(), body.len()).unwrap_or(usize::MAX);
    if len > limit {
        return Err(OutboundError::TooLong { len, limit });
    }
    let mut line = Vec::with_capacity(len);
    line.extend_from_slice(PRIVMSG_HEAD);
    line.extend_from_slice(&bot.0);
    line.extend_from_slice(PRIVMSG_SEPARATOR);
    line.extend_from_slice(body);
    Ok(OutboundLine(line))
}

/// Builds a PRIVMSG of plain text. A `0x01` in `text` is refused.
pub fn privmsg(
    bot: &BotNick,
    text: &[u8],
    budget: LineBudget,
) -> Result<OutboundLine, OutboundError> {
    if text.contains(&0x01) {
        return Err(OutboundError::ForbiddenByte);
    }
    message_line(bot, text, budget)
}

/// Builds a PRIVMSG from a CTCP body made by [`encode_ctcp`] or [`DccMessage::encode`].
///
/// The body must be one complete delimited CTCP message.
///
/// [`encode_ctcp`]: crate::proto::encode_ctcp
/// [`DccMessage::encode`]: crate::proto::DccMessage::encode
pub fn ctcp_privmsg(
    bot: &BotNick,
    body: &[u8],
    budget: LineBudget,
) -> Result<OutboundLine, OutboundError> {
    let delimiters = body.iter().filter(|&&byte| byte == 0x01).count();
    if delimiters != 2 || body.first() != Some(&0x01) || body.last() != Some(&0x01) {
        return Err(OutboundError::ForbiddenByte);
    }
    message_line(bot, body, budget)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn bot() -> BotNick {
        BotNick::parse(b"Bot").unwrap()
    }

    #[test]
    fn default_budget_keeps_room_for_a_relayed_source() {
        let budget = LineBudget::default();
        assert_eq!(budget.limit(), 401);
        let source = [
            vec![b'n'; 30],
            b"!".to_vec(),
            vec![b'u'; 12],
            b"@".to_vec(),
            vec![b'h'; 63],
        ]
        .concat();
        assert_eq!(LineBudget::for_source(&source), budget);
    }

    #[test]
    fn budget_boundaries() {
        let budget = LineBudget::reserving(100);
        let fits = vec![b'x'; 410];
        assert!(OutboundLine::new(&fits, budget).is_ok());
        let over = vec![b'x'; 411];
        assert_eq!(
            OutboundLine::new(&over, budget),
            Err(OutboundError::TooLong {
                len: 411,
                limit: 410
            })
        );
        assert!(OutboundLine::new(&vec![b'x'; 510], LineBudget::reserving(0)).is_ok());
        assert_eq!(
            OutboundLine::new(&vec![b'x'; 511], LineBudget::reserving(0)),
            Err(OutboundError::TooLong {
                len: 511,
                limit: 510
            })
        );
    }

    #[test]
    fn a_reservation_past_the_limit_leaves_nothing() {
        assert_eq!(LineBudget::reserving(usize::MAX).limit(), 0);
        assert_eq!(LineBudget::for_source(&[0; 600]).limit(), 0);
        assert!(OutboundLine::new(b"x", LineBudget::reserving(510)).is_err());
    }

    #[test]
    fn a_relayed_line_at_the_limit_fits_the_real_limit() {
        let source = b"nick!user@host.example";
        let budget = LineBudget::for_source(source);
        let line = OutboundLine::new(&vec![b'x'; budget.limit()], budget).unwrap();
        let relayed = source.len() + 2 + line.as_bytes().len() + 2;
        assert_eq!(relayed, 512);
    }

    #[test]
    fn injection_is_refused() {
        for line in [&b"PRIVMSG a :b\r\nQUIT"[..], b"A\rB", b"A\nB", b"A\0B"] {
            assert_eq!(
                OutboundLine::new(line, LineBudget::default()),
                Err(OutboundError::ForbiddenByte),
                "{line:?}"
            );
        }
        assert_eq!(
            OutboundLine::new(b"", LineBudget::default()),
            Err(OutboundError::Empty)
        );
        assert_eq!(
            OutboundLine::new(b"@a=1 PING", LineBudget::default()),
            Err(OutboundError::Tagged)
        );
    }

    #[test]
    fn lines_are_sent_with_crlf() {
        let line = OutboundLine::new(b"PING :x", LineBudget::default()).unwrap();
        assert_eq!(line.as_bytes(), b"PING :x");
        assert_eq!(line.to_wire(), b"PING :x\r\n");
    }

    #[test]
    fn nicks_address_exactly_one_target() {
        assert!(BotNick::parse(b"[Bot]|xdcc-1").is_ok());
        assert!(BotNick::parse(&[b'a'; BotNick::MAX_LEN]).is_ok());
        let bad: [(&[u8], OutboundError); 13] = [
            (b"", OutboundError::Empty),
            (b"a\rb", OutboundError::ForbiddenByte),
            (b"a\nb", OutboundError::ForbiddenByte),
            (b"a\0b", OutboundError::ForbiddenByte),
            (b"a\x01b", OutboundError::ForbiddenByte),
            (b"a b", OutboundError::BadNick),
            (b"a,b", OutboundError::BadNick),
            (b"a!b", OutboundError::BadNick),
            (b"a@b", OutboundError::BadNick),
            (b"a*", OutboundError::BadNick),
            (b":a", OutboundError::BadNick),
            (b"#chan", OutboundError::BadNick),
            (b"$*", OutboundError::BadNick),
        ];
        for (nick, want) in bad {
            assert_eq!(BotNick::parse(nick), Err(want), "{nick:?}");
        }
        assert_eq!(
            BotNick::parse(&[b'a'; BotNick::MAX_LEN + 1]),
            Err(OutboundError::BadNick)
        );
    }

    #[test]
    fn every_ascii_control_byte_is_refused_at_every_position() {
        let controls: Vec<u8> = (0x00..=0x1F).chain([0x7F]).collect();
        assert_eq!(controls.len(), 33);
        for byte in controls {
            for nick in [[byte, b'a', b'b'], [b'a', byte, b'b'], [b'a', b'b', byte]] {
                assert_eq!(
                    BotNick::parse(&nick),
                    Err(OutboundError::ForbiddenByte),
                    "{nick:?}"
                );
            }
        }
    }

    #[test]
    fn the_reported_control_bytes_are_refused() {
        for nick in [&b"bot\tname"[..], b"bot\x1bname", b"bot\x7fname"] {
            assert_eq!(BotNick::parse(nick), Err(OutboundError::ForbiddenByte));
        }
    }

    #[test]
    fn printable_and_non_ascii_bytes_keep_their_behaviour() {
        for byte in 0x21..=0x7E_u8 {
            let nick = [b'a', byte, b'b'];
            let refused = matches!(byte, b',' | b'!' | b'@' | b'*' | b'?');
            assert_eq!(BotNick::parse(&nick).is_err(), refused, "{nick:?}");
        }
        for byte in 0x80..=0xFF_u8 {
            let nick = [b'a', byte, b'b'];
            assert_eq!(BotNick::parse(&nick).unwrap().as_bytes(), nick);
        }
        assert!(BotNick::parse("n\u{e4}me".as_bytes()).is_ok());
    }

    #[test]
    fn budget_arithmetic_saturates_instead_of_overflowing() {
        assert_eq!(line_len(10, usize::MAX), None);
        assert_eq!(line_len(usize::MAX, 0), None);
        assert_eq!(line_len(3, 4), Some(b"PRIVMSG abc :defg".len()));
    }

    #[test]
    fn privmsg_refuses_control_bytes_in_text() {
        for text in [&b"a\r\nQUIT"[..], b"\x01DCC x\x01", b"a\0"] {
            assert_eq!(
                privmsg(&bot(), text, LineBudget::default()),
                Err(OutboundError::ForbiddenByte),
                "{text:?}"
            );
        }
        let line = privmsg(&bot(), b"hi there", LineBudget::default()).unwrap();
        assert_eq!(line.as_bytes(), b"PRIVMSG Bot :hi there");
    }

    #[test]
    fn ctcp_body_must_be_one_delimited_message() {
        let good = crate::proto::encode_ctcp(b"X", b"y").unwrap();
        let line = ctcp_privmsg(&bot(), &good, LineBudget::default()).unwrap();
        assert_eq!(line.as_bytes(), b"PRIVMSG Bot :\x01X y\x01");
        for body in [
            &b"plain"[..],
            b"\x01X",
            b"X\x01",
            b"\x01X\x01Y\x01",
            b"\x01",
            b"",
        ] {
            assert_eq!(
                ctcp_privmsg(&bot(), body, LineBudget::default()),
                Err(OutboundError::ForbiddenByte),
                "{body:?}"
            );
        }
    }

    #[test]
    fn long_message_fails_instead_of_truncating() {
        let text = vec![b'x'; 500];
        assert!(matches!(
            privmsg(&bot(), &text, LineBudget::default()),
            Err(OutboundError::TooLong { .. })
        ));
    }
}
