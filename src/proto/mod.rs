//! Pure, byte-oriented protocol codecs.
//!
//! Nothing in this module performs I/O, reads a clock, or needs a runtime. Every
//! parser works on `&[u8]`, because IRC is byte-oriented and filenames must
//! survive byte-exact for RESUME. See `docs/PROTOCOL_SPEC.md`.
//!
//! Parsed values are untrusted. An address in a [`DccOffer`] is what a remote
//! party claimed, not an approved destination, and a [`WireName`] is not a safe
//! filename. Those decisions belong to later layers.
//!
//! # Memory bounds
//!
//! [`LineFramer`] allocates one fixed buffer of [`MAX_LINE_LEN`] + 1 bytes when
//! created. [`IrcMessage`], [`Ctcp`], and the numeric and token fields do not
//! allocate. A decoded DCC message allocates only its name, which is at most
//! [`MAX_MESSAGE_LEN`] bytes. Token lists are never collected, so input size
//! cannot grow a parser's working memory. Encoders and outbound builders check
//! the final length first, so a refused value allocates nothing.
//!
//! # Round trips
//!
//! `parse_dcc(encode(m)) == m` holds for every encodable message. The reverse,
//! `encode(parse(s)) == s`, holds only for canonical text. Name and token bytes
//! are preserved exactly, including quoting and internal spaces. Numbers and
//! addresses are normalised: `00123` encodes as `123`, a dotted IPv4 address as
//! its decimal form, and runs of spaces between fields as one space.

mod casemap;
mod ctcp;
mod dcc;
mod framing;
mod irc;
mod number;
mod outbound;
mod xdcc;

pub use casemap::{CaseMapping, UnsupportedCaseMapping};
pub use ctcp::{
    Ctcp, CtcpCarrier, CtcpEncodeError, CtcpError, DEFAULT_TRUNCATION_THRESHOLD, InboundCtcp,
    LineContext, encode_ctcp, inbound_ctcp, parse_ctcp,
};
pub use dcc::{
    DccAccept, DccEncodeError, DccKind, DccMessage, DccOffer, DccParseError, DccResume,
    MAX_TOKEN_LEN, NameError, OfferEndpoint, ReplyTail, ReplyTailKind, Token, TokenError, WireName,
    parse_dcc,
};
pub use framing::{Frame, LineFramer, Oversized, Step};
pub use irc::{
    IrcError, IrcMessage, MAX_LINE_LEN, MAX_MESSAGE_LEN, MAX_PARAMS, MAX_TAG_SECTION_LEN, Tag, Tags,
};
pub use outbound::{BotNick, LineBudget, OutboundError, OutboundLine, ctcp_privmsg, privmsg};
pub use xdcc::{PackRef, XdccCase, XdccCommand, XdccPackForm, XdccStyle, XdccVerb};
