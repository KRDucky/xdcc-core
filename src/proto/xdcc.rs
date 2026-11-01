//! XDCC request builders.
//!
//! No specification exists. The commands are iroffer-dinoex behaviour, and other
//! bot families are unverified (`PROTOCOL_SPEC.md` §5), so the form is a value a
//! profile can change.

use std::num::NonZeroU32;

use crate::proto::outbound::{BotNick, LineBudget, OutboundError, OutboundLine, privmsg};

/// A pack, by number or by the CRC32 of its file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PackRef {
    /// A pack number.
    Number(NonZeroU32),
    /// A CRC32, written `[ABCD1234]`.
    Crc32(u32),
}

/// A request to a bot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum XdccCommand {
    /// Request a pack.
    Send(PackRef),
    /// Ask for a pack's metadata.
    Info(PackRef),
    /// Request a listing.
    List,
    /// Show this nick's queue position.
    Queue,
    /// Abort this nick's transfer.
    Cancel,
    /// Leave the queue, or one queue entry.
    Remove(Option<NonZeroU32>),
}

/// The case of the words in a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum XdccCase {
    /// `XDCC SEND`.
    #[default]
    Upper,
    /// `xdcc send`.
    Lower,
}

/// The word used to request a pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum XdccVerb {
    /// `SEND`.
    #[default]
    Send,
    /// `GET`.
    Get,
}

/// How a pack number is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum XdccPackForm {
    /// `#5`.
    #[default]
    Hash,
    /// `5`.
    Bare,
}

/// The wire form of a request. The default is `XDCC SEND #<n>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct XdccStyle {
    /// Word case.
    pub case: XdccCase,
    /// The request verb.
    pub verb: XdccVerb,
    /// The pack number form.
    pub pack_form: XdccPackForm,
}

impl XdccCommand {
    /// Encodes the message text.
    pub fn encode(&self, style: XdccStyle) -> Vec<u8> {
        let mut text = Vec::with_capacity(32);
        text.extend_from_slice(b"XDCC ");
        match self {
            Self::Send(pack) => {
                text.extend_from_slice(match style.verb {
                    XdccVerb::Send => b"SEND ",
                    XdccVerb::Get => b"GET ",
                });
                push_pack(&mut text, *pack, style);
            }
            Self::Info(pack) => {
                text.extend_from_slice(b"INFO ");
                push_pack(&mut text, *pack, style);
            }
            Self::List => text.extend_from_slice(b"LIST"),
            Self::Queue => text.extend_from_slice(b"QUEUE"),
            Self::Cancel => text.extend_from_slice(b"CANCEL"),
            Self::Remove(None) => text.extend_from_slice(b"REMOVE"),
            Self::Remove(Some(entry)) => {
                text.extend_from_slice(format!("REMOVE {entry}").as_bytes());
            }
        }
        if style.case == XdccCase::Lower {
            lower_words(&mut text);
        }
        text
    }

    /// Builds the plain PRIVMSG for this request.
    pub fn to_line(
        &self,
        bot: &BotNick,
        style: XdccStyle,
        budget: LineBudget,
    ) -> Result<OutboundLine, OutboundError> {
        privmsg(bot, &self.encode(style), budget)
    }
}

fn push_pack(text: &mut Vec<u8>, pack: PackRef, style: XdccStyle) {
    match pack {
        PackRef::Number(number) => {
            if style.pack_form == XdccPackForm::Hash {
                text.push(b'#');
            }
            text.extend_from_slice(number.to_string().as_bytes());
        }
        PackRef::Crc32(crc) => text.extend_from_slice(format!("[{crc:08X}]").as_bytes()),
    }
}

/// Lowers everything but a bracketed CRC, whose case is a value.
fn lower_words(text: &mut [u8]) {
    let end = text
        .iter()
        .position(|&byte| byte == b'[')
        .unwrap_or(text.len());
    text[..end].make_ascii_lowercase();
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn pack(n: u32) -> PackRef {
        PackRef::Number(NonZeroU32::new(n).unwrap())
    }

    #[test]
    fn default_form_is_the_documented_rule() {
        let text = XdccCommand::Send(pack(5)).encode(XdccStyle::default());
        assert_eq!(text, b"XDCC SEND #5");
    }

    #[test]
    fn style_changes_case_verb_and_pack_form() {
        let style = XdccStyle {
            case: XdccCase::Lower,
            verb: XdccVerb::Get,
            pack_form: XdccPackForm::Bare,
        };
        assert_eq!(XdccCommand::Send(pack(12)).encode(style), b"xdcc get 12");
    }

    #[test]
    fn every_command_encodes() {
        let style = XdccStyle::default();
        let cases: [(XdccCommand, &[u8]); 7] = [
            (
                XdccCommand::Send(PackRef::Crc32(0xAB12)),
                b"XDCC SEND [0000AB12]",
            ),
            (XdccCommand::Info(pack(7)), b"XDCC INFO #7"),
            (XdccCommand::List, b"XDCC LIST"),
            (XdccCommand::Queue, b"XDCC QUEUE"),
            (XdccCommand::Cancel, b"XDCC CANCEL"),
            (XdccCommand::Remove(None), b"XDCC REMOVE"),
            (XdccCommand::Remove(NonZeroU32::new(3)), b"XDCC REMOVE 3"),
        ];
        for (command, want) in cases {
            assert_eq!(command.encode(style), want);
        }
    }

    #[test]
    fn lower_case_leaves_a_crc_alone() {
        let style = XdccStyle {
            case: XdccCase::Lower,
            ..XdccStyle::default()
        };
        let text = XdccCommand::Send(PackRef::Crc32(0xABCD_1234)).encode(style);
        assert_eq!(text, b"xdcc send [ABCD1234]");
    }

    #[test]
    fn requests_become_plain_privmsgs() {
        let bot = BotNick::parse(b"Bot").unwrap();
        let line = XdccCommand::Send(pack(5))
            .to_line(&bot, XdccStyle::default(), LineBudget::default())
            .unwrap();
        assert_eq!(line.to_wire(), b"PRIVMSG Bot :XDCC SEND #5\r\n");
    }

    #[test]
    fn a_tiny_budget_fails_explicitly() {
        let bot = BotNick::parse(b"Bot").unwrap();
        let result =
            XdccCommand::List.to_line(&bot, XdccStyle::default(), LineBudget::reserving(500));
        assert!(matches!(result, Err(OutboundError::TooLong { .. })));
    }
}
