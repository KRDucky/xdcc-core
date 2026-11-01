//! DCC SEND, RESUME, and ACCEPT, as defined by `PROTOCOL_SPEC.md` §7 and §9.
//!
//! The shape is chosen first, from token count and one literal check, and field
//! values are validated afterwards. A field that fails refuses the whole message,
//! so a malformed standard offer can never become a legacy one.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;

use crate::proto::ctcp::Ctcp;
use crate::proto::irc::MAX_MESSAGE_LEN;
use crate::proto::number::{is_zero_valued, parse_decimal};

/// The longest passive token.
pub const MAX_TOKEN_LEN: usize = 64;

/// The most fields any tail has.
const MAX_TAIL: usize = 4;

/// Why a DCC message was refused. Each one is a refusal of the whole message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DccParseError {
    /// The CTCP tag is not a DCC tag.
    NotDcc,
    /// There is no DCC type.
    MissingType,
    /// An unquoted form has too few tokens.
    TooFewFields,
    /// A quoted form has the wrong number of tail fields.
    BadFieldCount,
    /// The name is empty.
    EmptyName,
    /// A quoted name has no closing quote followed by a space.
    UnterminatedQuote,
    /// A quoted form has four tail fields and a nonzero port.
    UnexpectedToken,
    /// An offer has port zero and no token.
    PortZeroWithoutToken,
    /// The port is not a number from 1 to 65535.
    BadPort,
    /// The address is not IPv4 or IPv6.
    BadAddress,
    /// An active offer claims an address in `0.0.0.0/8`, so its fields have shifted.
    ImplausibleAddress,
    /// The size is not a 64-bit number.
    BadSize,
    /// The position is not a 64-bit number.
    BadPosition,
    /// The token is not 1 to 64 printable ASCII bytes, excluding space and `"`.
    BadToken,
    /// The closing delimiter is missing and the message may have been cut.
    SuspectedTruncation,
    /// A RESUME or ACCEPT arrived with no pending attempt to give its tail.
    Unsolicited,
    /// The name cannot be a [`WireName`].
    ///
    /// [`parse_ctcp`](crate::proto::parse_ctcp) already bounds the body and refuses
    /// forbidden bytes, so this is a guard and not an expected outcome.
    BadName,
}

impl fmt::Display for DccParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotDcc => "not a DCC message",
            Self::MissingType => "missing DCC type",
            Self::TooFewFields => "too few fields",
            Self::BadFieldCount => "wrong number of fields after a quoted name",
            Self::EmptyName => "empty filename",
            Self::UnterminatedQuote => "unterminated quoted filename",
            Self::UnexpectedToken => "token with a nonzero port",
            Self::PortZeroWithoutToken => "port zero without a token",
            Self::BadPort => "invalid port",
            Self::BadAddress => "invalid address",
            Self::ImplausibleAddress => "implausible active address",
            Self::BadSize => "invalid size",
            Self::BadPosition => "invalid position",
            Self::BadToken => "invalid token",
            Self::SuspectedTruncation => "message may have been truncated",
            Self::Unsolicited => "unsolicited RESUME or ACCEPT",
            Self::BadName => "invalid filename",
        })
    }
}

impl std::error::Error for DccParseError {}

/// Why bytes cannot be a [`WireName`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NameError {
    /// The name is empty, including a quoted empty name.
    Empty,
    /// The name exceeds [`MAX_MESSAGE_LEN`].
    TooLong,
    /// The name contains CR, LF, NUL, or `0x01`.
    ForbiddenByte,
    /// A quoted name lacks its closing quote.
    UnterminatedQuote,
    /// An unquoted name has a leading or trailing space.
    OuterSpace,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "empty name",
            Self::TooLong => "name is too long",
            Self::ForbiddenByte => "name contains a forbidden byte",
            Self::UnterminatedQuote => "unterminated quoted name",
            Self::OuterSpace => "unquoted name has an outer space",
        })
    }
}

impl std::error::Error for NameError {}

/// The exact filename field a sender used, quotes included.
///
/// This is untrusted, may not be UTF-8, and is not a path. Echo it in RESUME.
/// Filesystem use needs the sanitiser in a later milestone.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct WireName(Vec<u8>);

impl WireName {
    /// Validates a filename field in its wire form.
    pub fn new(wire: &[u8]) -> Result<Self, NameError> {
        if wire.is_empty() {
            return Err(NameError::Empty);
        }
        if wire.len() > MAX_MESSAGE_LEN {
            return Err(NameError::TooLong);
        }
        if wire
            .iter()
            .any(|&byte| matches!(byte, b'\r' | b'\n' | 0 | 0x01))
        {
            return Err(NameError::ForbiddenByte);
        }
        if wire.first() == Some(&b'"') {
            if wire.len() < 2 || wire.last() != Some(&b'"') {
                return Err(NameError::UnterminatedQuote);
            }
            if wire.len() == 2 {
                return Err(NameError::Empty);
            }
        } else if wire.first() == Some(&b' ') || wire.last() == Some(&b' ') {
            return Err(NameError::OuterSpace);
        }
        Ok(Self(wire.to_vec()))
    }

    /// The exact field bytes, for echoing.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// True if the sender quoted the name.
    pub fn is_quoted(&self) -> bool {
        self.0.first() == Some(&b'"')
    }

    /// The name without its quotes.
    pub fn name(&self) -> &[u8] {
        if self.is_quoted() {
            &self.0[1..self.0.len() - 1]
        } else {
            &self.0
        }
    }
}

impl fmt::Debug for WireName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WireName({:?})", self.0.escape_ascii().to_string())
    }
}

/// Bytes that are not a valid passive token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenError;

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid passive token")
    }
}

impl std::error::Error for TokenError {}

/// An opaque passive correlation value. It is not a secret.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Token {
    bytes: [u8; MAX_TOKEN_LEN],
    len: u8,
}

impl Token {
    /// Accepts 1 to 64 bytes of printable ASCII, excluding space and `"`.
    pub fn new(field: &[u8]) -> Result<Self, TokenError> {
        let valid = (1..=MAX_TOKEN_LEN).contains(&field.len())
            && field
                .iter()
                .all(|&byte| (33..=126).contains(&byte) && byte != b'"');
        if !valid {
            return Err(TokenError);
        }
        let mut bytes = [0; MAX_TOKEN_LEN];
        bytes[..field.len()].copy_from_slice(field);
        Ok(Self {
            bytes,
            len: field.len() as u8,
        })
    }

    /// The token, for echoing verbatim.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Token({:?})", self.as_bytes().escape_ascii().to_string())
    }
}

/// Where an offer says the data is. The address is a claim, not an approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OfferEndpoint {
    /// The sender is listening.
    Active {
        /// The claimed address.
        addr: IpAddr,
        /// The claimed port.
        port: NonZeroU16,
    },
    /// The receiver must listen. The address is never connected to.
    Passive {
        /// The correlation value to echo.
        token: Token,
        /// The address, unless it was in `0.0.0.0/8`.
        claimed_addr: Option<IpAddr>,
    },
}

/// A `DCC SEND` offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DccOffer {
    /// The exact filename field.
    pub wire_name: WireName,
    /// The claimed endpoint.
    pub endpoint: OfferEndpoint,
    /// The claimed size. `None` for the legacy shape.
    pub size: Option<u64>,
}

/// The tail of a RESUME or ACCEPT, identifying the pending attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReplyTail {
    /// `<port> <position>`.
    Active {
        /// The port from the offer.
        port: NonZeroU16,
    },
    /// `0 <position> <token>`.
    Passive {
        /// The token from the offer.
        token: Token,
    },
}

/// Which tail the pending attempt expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReplyTailKind {
    /// The attempt came from an active offer.
    Active,
    /// The attempt came from a passive offer.
    Passive,
}

/// A `DCC RESUME`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DccResume {
    /// The name, echoed from the offer.
    pub wire_name: WireName,
    /// The identifying tail.
    pub tail: ReplyTail,
    /// The requested position.
    pub position: u64,
}

/// A `DCC ACCEPT`. Its name is not compared, since senders may rewrite it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DccAccept {
    /// The name as the sender wrote it.
    pub wire_name: WireName,
    /// The identifying tail.
    pub tail: ReplyTail,
    /// The accepted position.
    pub position: u64,
}

/// A DCC type that is parsed but not supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DccKind {
    /// `DCC TSEND`, or anything under the `TDCC` tag.
    Turbo,
    /// `DCC SSEND`.
    SecureSend,
    /// `DCC CHAT`.
    Chat,
    /// `DCC SCHAT`.
    SecureChat,
    /// Any other type.
    Unknown,
}

/// A decoded DCC message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DccMessage {
    /// An offer.
    Send(DccOffer),
    /// A resume request.
    Resume(DccResume),
    /// A resume acceptance.
    Accept(DccAccept),
    /// A type this crate does not handle. Its arguments are not read.
    Other {
        /// What it was.
        kind: DccKind,
    },
}

/// Why a message cannot be encoded as a parseable DCC message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DccEncodeError {
    /// [`DccMessage::Other`] has no wire form here.
    Unsupported,
    /// A legacy offer with an unquoted multi-word name would be refused on parsing.
    LegacyNameNeedsQuotes,
    /// The address would not survive parsing unchanged.
    UnrepresentableAddress,
    /// A legacy offer cannot be passive.
    PassiveNeedsSize,
    /// The body would exceed the message budget.
    TooLong,
}

impl fmt::Display for DccEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "message type cannot be encoded",
            Self::LegacyNameNeedsQuotes => "legacy offer needs a quoted multi-word name",
            Self::UnrepresentableAddress => "address would not survive parsing",
            Self::PassiveNeedsSize => "passive offer needs a size",
            Self::TooLong => "DCC body is too long",
        })
    }
}

impl std::error::Error for DccEncodeError {}

impl DccMessage {
    /// Encodes the canonical CTCP body.
    ///
    /// IPv4 is written as a decimal number, and an absent passive address as `0`.
    pub fn encode(&self) -> Result<Vec<u8>, DccEncodeError> {
        let mut args = Vec::with_capacity(MAX_MESSAGE_LEN);
        match self {
            Self::Send(offer) => encode_offer(offer, &mut args)?,
            Self::Resume(reply) => {
                args.extend_from_slice(b"RESUME ");
                encode_reply(&reply.wire_name, &reply.tail, reply.position, &mut args);
            }
            Self::Accept(reply) => {
                args.extend_from_slice(b"ACCEPT ");
                encode_reply(&reply.wire_name, &reply.tail, reply.position, &mut args);
            }
            Self::Other { .. } => return Err(DccEncodeError::Unsupported),
        }
        crate::proto::encode_ctcp(b"DCC", &args).map_err(|_| DccEncodeError::TooLong)
    }
}

fn push_number(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(value.to_string().as_bytes());
}

fn push_address(out: &mut Vec<u8>, addr: IpAddr) {
    match addr {
        IpAddr::V4(v4) => push_number(out, u64::from(u32::from(v4))),
        IpAddr::V6(v6) => out.extend_from_slice(v6.to_string().as_bytes()),
    }
}

fn in_zero_network(addr: IpAddr) -> bool {
    matches!(addr, IpAddr::V4(v4) if v4.octets()[0] == 0)
}

fn encode_offer(offer: &DccOffer, args: &mut Vec<u8>) -> Result<(), DccEncodeError> {
    args.extend_from_slice(b"SEND ");
    args.extend_from_slice(offer.wire_name.as_bytes());
    args.push(b' ');
    match offer.endpoint {
        OfferEndpoint::Active { addr, port } => {
            if in_zero_network(addr) {
                return Err(DccEncodeError::UnrepresentableAddress);
            }
            if offer.size.is_none()
                && !offer.wire_name.is_quoted()
                && offer.wire_name.as_bytes().contains(&b' ')
            {
                return Err(DccEncodeError::LegacyNameNeedsQuotes);
            }
            push_address(args, addr);
            args.push(b' ');
            push_number(args, u64::from(port.get()));
            if let Some(size) = offer.size {
                args.push(b' ');
                push_number(args, size);
            }
        }
        OfferEndpoint::Passive {
            token,
            claimed_addr,
        } => {
            let Some(size) = offer.size else {
                return Err(DccEncodeError::PassiveNeedsSize);
            };
            match claimed_addr {
                Some(addr) if in_zero_network(addr) => {
                    return Err(DccEncodeError::UnrepresentableAddress);
                }
                Some(addr) => push_address(args, addr),
                None => args.push(b'0'),
            }
            args.extend_from_slice(b" 0 ");
            push_number(args, size);
            args.push(b' ');
            args.extend_from_slice(token.as_bytes());
        }
    }
    Ok(())
}

fn encode_reply(name: &WireName, tail: &ReplyTail, position: u64, args: &mut Vec<u8>) {
    args.extend_from_slice(name.as_bytes());
    args.push(b' ');
    match tail {
        ReplyTail::Active { port } => {
            push_number(args, u64::from(port.get()));
            args.push(b' ');
            push_number(args, position);
        }
        ReplyTail::Passive { token } => {
            args.extend_from_slice(b"0 ");
            push_number(args, position);
            args.push(b' ');
            args.extend_from_slice(token.as_bytes());
        }
    }
}

/// Decodes a DCC message from CTCP.
///
/// `pending` tells the parser which tail a RESUME or ACCEPT must have. With
/// `None`, either is refused as [`DccParseError::Unsolicited`], because its
/// shape cannot be chosen.
///
/// The result is untrusted. A well-formed offer is not an approved one.
pub fn parse_dcc(
    ctcp: &Ctcp<'_>,
    pending: Option<ReplyTailKind>,
) -> Result<DccMessage, DccParseError> {
    let turbo = ctcp.tag().eq_ignore_ascii_case(b"TDCC");
    if !turbo && !ctcp.tag().eq_ignore_ascii_case(b"DCC") {
        return Err(DccParseError::NotDcc);
    }
    let args = trim_spaces(ctcp.args());
    let (kind, rest) = match args.iter().position(|&byte| byte == b' ') {
        Some(space) => (&args[..space], &args[space + 1..]),
        None => (args, &args[args.len()..]),
    };
    if kind.is_empty() {
        return Err(DccParseError::MissingType);
    }
    if turbo {
        return Ok(DccMessage::Other {
            kind: DccKind::Turbo,
        });
    }
    let is = |name: &[u8]| kind.eq_ignore_ascii_case(name);
    if is(b"SEND") {
        parse_send(rest, ctcp).map(DccMessage::Send)
    } else if is(b"RESUME") {
        let (wire_name, tail, position) = parse_reply(rest, ctcp, pending)?;
        Ok(DccMessage::Resume(DccResume {
            wire_name,
            tail,
            position,
        }))
    } else if is(b"ACCEPT") {
        let (wire_name, tail, position) = parse_reply(rest, ctcp, pending)?;
        Ok(DccMessage::Accept(DccAccept {
            wire_name,
            tail,
            position,
        }))
    } else {
        let kind = if is(b"TSEND") {
            DccKind::Turbo
        } else if is(b"SSEND") {
            DccKind::SecureSend
        } else if is(b"CHAT") {
            DccKind::Chat
        } else if is(b"SCHAT") {
            DccKind::SecureChat
        } else {
            DccKind::Unknown
        };
        Ok(DccMessage::Other { kind })
    }
}

fn trim_spaces(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|&byte| byte != b' ')
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|&byte| byte != b' ')
        .map_or(start, |at| at + 1);
    &bytes[start..end]
}

/// The last tokens of a field, found from the right with no allocation.
struct Tail<'a> {
    /// Token count, stopping at `MAX_TAIL + 1`.
    count: usize,
    /// Tokens from the right.
    tokens: [&'a [u8]; MAX_TAIL],
    /// Where each of those tokens starts.
    starts: [usize; MAX_TAIL],
}

impl<'a> Tail<'a> {
    fn of(bytes: &'a [u8]) -> Self {
        let mut tail = Self {
            count: 0,
            tokens: [&[]; MAX_TAIL],
            starts: [0; MAX_TAIL],
        };
        let mut end = bytes.len();
        while tail.count <= MAX_TAIL {
            while end > 0 && bytes[end - 1] == b' ' {
                end -= 1;
            }
            if end == 0 {
                break;
            }
            let mut start = end;
            while start > 0 && bytes[start - 1] != b' ' {
                start -= 1;
            }
            if tail.count < MAX_TAIL {
                tail.tokens[tail.count] = &bytes[start..end];
                tail.starts[tail.count] = start;
            }
            tail.count += 1;
            end = start;
        }
        tail
    }

    /// The last `N` tokens, in wire order.
    fn fields<const N: usize>(&self) -> [&'a [u8]; N] {
        let mut fields: [&[u8]; N] = [&[]; N];
        for (at, field) in fields.iter_mut().enumerate() {
            *field = self.tokens[N - 1 - at];
        }
        fields
    }

    /// Everything left of the last `n` tokens, without trailing spaces.
    fn name_before(&self, bytes: &'a [u8], n: usize) -> &'a [u8] {
        trim_spaces(&bytes[..self.starts[n - 1]])
    }
}

/// Splits a quoted field at the last `"` followed by a space.
fn split_quoted(args: &[u8]) -> Result<(&[u8], &[u8]), DccParseError> {
    let closing = args
        .windows(2)
        .rposition(|pair| pair == b"\" ")
        .filter(|&at| at > 0)
        .ok_or(DccParseError::UnterminatedQuote)?;
    Ok((&args[..=closing], &args[closing + 2..]))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    Legacy,
    Standard,
    Passive,
}

fn parse_send(args: &[u8], ctcp: &Ctcp<'_>) -> Result<DccOffer, DccParseError> {
    let args = trim_spaces(args);
    let (shape, wire, tail) = if args.first() == Some(&b'"') {
        let (wire, rest) = split_quoted(args)?;
        let tail = Tail::of(rest);
        let shape = match tail.count {
            2 => Shape::Legacy,
            3 => Shape::Standard,
            4 if is_zero_valued(tail.tokens[2]) => Shape::Passive,
            4 => return Err(DccParseError::UnexpectedToken),
            _ => return Err(DccParseError::BadFieldCount),
        };
        (shape, wire, tail)
    } else {
        let tail = Tail::of(args);
        let (shape, fields) = match tail.count {
            0..=2 => return Err(DccParseError::TooFewFields),
            3 => (Shape::Legacy, 2),
            count if count > 4 && is_zero_valued(tail.tokens[2]) => (Shape::Passive, 4),
            _ => (Shape::Standard, 3),
        };
        (shape, tail.name_before(args, fields), tail)
    };
    if wire.is_empty() || wire == b"\"\"" {
        return Err(DccParseError::EmptyName);
    }
    let (endpoint, size) = match shape {
        Shape::Legacy => {
            let [addr, port] = tail.fields::<2>();
            (active_endpoint(addr, port)?, None)
        }
        Shape::Standard => {
            let [addr, port, size] = tail.fields::<3>();
            let endpoint = active_endpoint(addr, port)?;
            (endpoint, Some(parse_size(size)?))
        }
        Shape::Passive => {
            let [addr, _, size, token] = tail.fields::<4>();
            let claimed = parse_address(addr)?;
            let token = Token::new(token).map_err(|_| DccParseError::BadToken)?;
            let size = parse_size(size)?;
            let endpoint = OfferEndpoint::Passive {
                token,
                claimed_addr: Some(claimed).filter(|&addr| !in_zero_network(addr)),
            };
            (endpoint, Some(size))
        }
    };
    if !ctcp.final_delimiter() && (shape == Shape::Legacy || ctcp.near_limit()) {
        return Err(DccParseError::SuspectedTruncation);
    }
    Ok(DccOffer {
        wire_name: owned_name(wire)?,
        endpoint,
        size,
    })
}

fn active_endpoint(addr: &[u8], port: &[u8]) -> Result<OfferEndpoint, DccParseError> {
    if is_zero_valued(port) {
        return Err(DccParseError::PortZeroWithoutToken);
    }
    let port = parse_port(port)?;
    let addr = parse_address(addr)?;
    if in_zero_network(addr) {
        return Err(DccParseError::ImplausibleAddress);
    }
    Ok(OfferEndpoint::Active { addr, port })
}

fn parse_port(field: &[u8]) -> Result<NonZeroU16, DccParseError> {
    parse_decimal(field)
        .and_then(|value| u16::try_from(value).ok())
        .and_then(NonZeroU16::new)
        .ok_or(DccParseError::BadPort)
}

fn parse_size(field: &[u8]) -> Result<u64, DccParseError> {
    parse_decimal(field).ok_or(DccParseError::BadSize)
}

/// Reads an address. A hostname is refused, and nothing is ever resolved.
fn parse_address(field: &[u8]) -> Result<IpAddr, DccParseError> {
    if field.contains(&b':') {
        return std::str::from_utf8(field)
            .ok()
            .and_then(|text| text.parse::<Ipv6Addr>().ok())
            .map(IpAddr::V6)
            .ok_or(DccParseError::BadAddress);
    }
    if field.contains(&b'.') {
        return std::str::from_utf8(field)
            .ok()
            .and_then(|text| text.parse::<Ipv4Addr>().ok())
            .map(IpAddr::V4)
            .ok_or(DccParseError::BadAddress);
    }
    parse_decimal(field)
        .and_then(|value| u32::try_from(value).ok())
        .map(|value| IpAddr::V4(Ipv4Addr::from(value)))
        .ok_or(DccParseError::BadAddress)
}

/// Builds the name last, so a refused message allocates nothing.
fn owned_name(wire: &[u8]) -> Result<WireName, DccParseError> {
    WireName::new(wire).map_err(|error| match error {
        NameError::Empty => DccParseError::EmptyName,
        NameError::UnterminatedQuote => DccParseError::UnterminatedQuote,
        _ => DccParseError::BadName,
    })
}

fn parse_reply(
    args: &[u8],
    ctcp: &Ctcp<'_>,
    pending: Option<ReplyTailKind>,
) -> Result<(WireName, ReplyTail, u64), DccParseError> {
    let Some(kind) = pending else {
        return Err(DccParseError::Unsolicited);
    };
    let fields = match kind {
        ReplyTailKind::Active => 2,
        ReplyTailKind::Passive => 3,
    };
    let args = trim_spaces(args);
    let (wire, tail) = if args.first() == Some(&b'"') {
        let (wire, rest) = split_quoted(args)?;
        let tail = Tail::of(rest);
        if tail.count != fields {
            return Err(DccParseError::BadFieldCount);
        }
        (wire, tail)
    } else {
        let tail = Tail::of(args);
        if tail.count <= fields {
            return Err(DccParseError::TooFewFields);
        }
        (tail.name_before(args, fields), tail)
    };
    if wire.is_empty() || wire == b"\"\"" {
        return Err(DccParseError::EmptyName);
    }
    let (reply_tail, position) = match kind {
        ReplyTailKind::Active => {
            let [port, position] = tail.fields::<2>();
            let port = parse_port(port)?;
            let position = parse_decimal(position).ok_or(DccParseError::BadPosition)?;
            (ReplyTail::Active { port }, position)
        }
        ReplyTailKind::Passive => {
            let [port, position, token] = tail.fields::<3>();
            if !is_zero_valued(port) {
                return Err(DccParseError::BadPort);
            }
            let position = parse_decimal(position).ok_or(DccParseError::BadPosition)?;
            let token = Token::new(token).map_err(|_| DccParseError::BadToken)?;
            (ReplyTail::Passive { token }, position)
        }
    };
    // A cut position would otherwise abort the attempt as a mismatch.
    if !ctcp.final_delimiter() && ctcp.near_limit() {
        return Err(DccParseError::SuspectedTruncation);
    }
    Ok((owned_name(wire)?, reply_tail, position))
}
