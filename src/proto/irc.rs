//! One IRC message, parsed from a line without its terminator.

use std::fmt;

/// The most bytes of a message outside the tag section, without CRLF.
///
/// RFC 2812 allows 512 bytes including CRLF.
pub const MAX_MESSAGE_LEN: usize = 510;

/// The most bytes in a tag section, including the leading `@` and trailing space.
pub const MAX_TAG_SECTION_LEN: usize = 8191;

/// The longest possible line without its terminator.
pub const MAX_LINE_LEN: usize = MAX_TAG_SECTION_LEN + MAX_MESSAGE_LEN;

/// The most parameters in a message. The last one absorbs anything further.
pub const MAX_PARAMS: usize = 15;

/// Why a line is not a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IrcError {
    /// The line contains CR, LF, or NUL.
    ForbiddenByte,
    /// The tag section exceeds [`MAX_TAG_SECTION_LEN`].
    TagsTooLong,
    /// The part after the tags exceeds [`MAX_MESSAGE_LEN`].
    MessageTooLong,
    /// A `:` was not followed by a source.
    EmptyPrefix,
    /// There is no command.
    MissingCommand,
    /// The command is not letters or exactly three digits.
    BadCommand,
}

impl fmt::Display for IrcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ForbiddenByte => "line contains CR, LF, or NUL",
            Self::TagsTooLong => "tag section is too long",
            Self::MessageTooLong => "message is too long",
            Self::EmptyPrefix => "empty message source",
            Self::MissingCommand => "message has no command",
            Self::BadCommand => "invalid command",
        })
    }
}

impl std::error::Error for IrcError {}

/// One IRCv3 tag, with its value still escaped as received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag<'a> {
    /// The key, including any `+` or vendor prefix.
    pub key: &'a [u8],
    /// The raw value. `None` if the tag has no `=`.
    pub value: Option<&'a [u8]>,
}

/// Iterates tags lazily, so a long tag section is never collected.
#[derive(Debug, Clone)]
pub struct Tags<'a> {
    rest: Option<&'a [u8]>,
}

impl<'a> Iterator for Tags<'a> {
    type Item = Tag<'a>;

    fn next(&mut self) -> Option<Tag<'a>> {
        loop {
            let rest = self.rest?;
            let (tag, after) = match rest.iter().position(|&byte| byte == b';') {
                Some(at) => (&rest[..at], Some(&rest[at + 1..])),
                None => (rest, None),
            };
            self.rest = after;
            if tag.is_empty() {
                continue;
            }
            return Some(match tag.iter().position(|&byte| byte == b'=') {
                Some(at) => Tag {
                    key: &tag[..at],
                    value: Some(&tag[at + 1..]),
                },
                None => Tag {
                    key: tag,
                    value: None,
                },
            });
        }
    }
}

/// A parsed message borrowing from its line. Parsing does not allocate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrcMessage<'a> {
    tags: Option<&'a [u8]>,
    source: Option<&'a [u8]>,
    command: &'a [u8],
    params: [&'a [u8]; MAX_PARAMS],
    param_count: usize,
    message_len: usize,
}

impl<'a> IrcMessage<'a> {
    /// Parses a line with no terminator.
    ///
    /// The tag and message budgets are independent, so spare tag space cannot
    /// lengthen a message. Spaces between fields may repeat. Bytes need not be
    /// UTF-8.
    pub fn parse(line: &'a [u8]) -> Result<Self, IrcError> {
        if line.iter().any(|&byte| matches!(byte, b'\r' | b'\n' | 0)) {
            return Err(IrcError::ForbiddenByte);
        }
        let (tags, message) = split_tags(line)?;
        if message.len() > MAX_MESSAGE_LEN {
            return Err(IrcError::MessageTooLong);
        }
        let mut rest = skip_spaces(message);
        let source = match rest.strip_prefix(b":") {
            Some(after) => {
                let (source, after) = split_word(after);
                if source.is_empty() {
                    return Err(IrcError::EmptyPrefix);
                }
                rest = skip_spaces(after);
                Some(source)
            }
            None => None,
        };
        let (command, after) = split_word(rest);
        if command.is_empty() {
            return Err(IrcError::MissingCommand);
        }
        if !is_command(command) {
            return Err(IrcError::BadCommand);
        }
        let (params, param_count) = split_params(after);
        Ok(Self {
            tags,
            source,
            command,
            params,
            param_count,
            message_len: message.len(),
        })
    }

    /// The tags, in order. Values stay escaped, because no codec here reads them.
    pub fn tags(&self) -> Tags<'a> {
        Tags { rest: self.tags }
    }

    /// The full source, such as `nick!user@host`, if present.
    pub fn source(&self) -> Option<&'a [u8]> {
        self.source
    }

    /// The nick or server name part of the source.
    pub fn source_nick(&self) -> Option<&'a [u8]> {
        let source = self.source?;
        let end = source
            .iter()
            .position(|&byte| matches!(byte, b'!' | b'@'))
            .unwrap_or(source.len());
        Some(&source[..end])
    }

    /// The command, in the case received.
    pub fn command(&self) -> &'a [u8] {
        self.command
    }

    /// The parameters. A trailing parameter is included, without its colon.
    pub fn params(&self) -> &[&'a [u8]] {
        &self.params[..self.param_count]
    }

    /// Bytes outside the tag section, without CRLF.
    ///
    /// This is what a server's 512-byte limit acts on, so it is the length to
    /// compare with a truncation threshold.
    pub fn message_len(&self) -> usize {
        self.message_len
    }
}

fn split_tags(line: &[u8]) -> Result<(Option<&[u8]>, &[u8]), IrcError> {
    let Some(after_at) = line.strip_prefix(b"@") else {
        return Ok((None, line));
    };
    let Some(space) = after_at.iter().position(|&byte| byte == b' ') else {
        if line.len() > MAX_TAG_SECTION_LEN {
            return Err(IrcError::TagsTooLong);
        }
        return Err(IrcError::MissingCommand);
    };
    if space + 2 > MAX_TAG_SECTION_LEN {
        return Err(IrcError::TagsTooLong);
    }
    Ok((Some(&after_at[..space]), &after_at[space + 1..]))
}

fn skip_spaces(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|&byte| byte != b' ')
        .unwrap_or(bytes.len());
    &bytes[start..]
}

fn split_word(bytes: &[u8]) -> (&[u8], &[u8]) {
    let end = bytes
        .iter()
        .position(|&byte| byte == b' ')
        .unwrap_or(bytes.len());
    bytes.split_at(end)
}

fn is_command(command: &[u8]) -> bool {
    command.iter().all(u8::is_ascii_alphabetic)
        || (command.len() == 3 && command.iter().all(u8::is_ascii_digit))
}

fn split_params(mut rest: &[u8]) -> ([&[u8]; MAX_PARAMS], usize) {
    let mut params: [&[u8]; MAX_PARAMS] = [&[]; MAX_PARAMS];
    let mut count = 0;
    loop {
        rest = skip_spaces(rest);
        if rest.is_empty() {
            return (params, count);
        }
        if let Some(trailing) = rest.strip_prefix(b":") {
            params[count] = trailing;
            return (params, count + 1);
        }
        if count == MAX_PARAMS - 1 {
            params[count] = rest;
            return (params, MAX_PARAMS);
        }
        let (param, after) = split_word(rest);
        params[count] = param;
        count += 1;
        rest = after;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_source_command_and_trailing() {
        let m = IrcMessage::parse(b":bot!u@h.example PRIVMSG me :hello  there ").unwrap();
        assert_eq!(m.source(), Some(&b"bot!u@h.example"[..]));
        assert_eq!(m.source_nick(), Some(&b"bot"[..]));
        assert_eq!(m.command(), b"PRIVMSG");
        assert_eq!(m.params(), [&b"me"[..], b"hello  there "]);
    }

    #[test]
    fn server_source_is_its_own_nick() {
        let m = IrcMessage::parse(b":irc.example 001 me :hi").unwrap();
        assert_eq!(m.source_nick(), Some(&b"irc.example"[..]));
        assert_eq!(m.command(), b"001");
    }

    #[test]
    fn repeated_spaces_separate_fields() {
        let m = IrcMessage::parse(b":a  CMD   x  y").unwrap();
        assert_eq!(m.params(), [&b"x"[..], b"y"]);
        assert_eq!(IrcMessage::parse(b"CMD x  ").unwrap().params(), [&b"x"[..]]);
    }

    #[test]
    fn empty_trailing_is_a_parameter() {
        assert_eq!(
            IrcMessage::parse(b"CMD x :").unwrap().params(),
            [&b"x"[..], b""]
        );
    }

    #[test]
    fn non_utf8_survives() {
        let m = IrcMessage::parse(b"PRIVMSG me :\xff\xfe").unwrap();
        assert_eq!(m.params()[1], b"\xff\xfe");
    }

    #[test]
    fn fifteenth_parameter_absorbs_the_rest() {
        let m = IrcMessage::parse(b"C 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 :17").unwrap();
        assert_eq!(m.params().len(), MAX_PARAMS);
        assert_eq!(m.params()[13], b"14");
        assert_eq!(m.params()[14], b"15 16 :17");
    }

    #[test]
    fn tags_are_lazy_and_keep_raw_values() {
        let m = IrcMessage::parse(b"@a=1;+b;;c=x\\sy;d= :s CMD").unwrap();
        let tags: Vec<_> = m.tags().collect();
        assert_eq!(tags.len(), 4);
        assert_eq!(
            tags[0],
            Tag {
                key: b"a",
                value: Some(b"1")
            }
        );
        assert_eq!(
            tags[1],
            Tag {
                key: b"+b",
                value: None
            }
        );
        assert_eq!(tags[2].value, Some(&b"x\\sy"[..]));
        assert_eq!(tags[3].value, Some(&b""[..]));
    }

    #[test]
    fn budgets_are_independent() {
        let exact = [
            vec![b'@'],
            vec![b'a'; MAX_TAG_SECTION_LEN - 2],
            b" ".to_vec(),
        ]
        .concat();
        let body = |n| [b"C ".to_vec(), vec![b'x'; n - 2]].concat();

        let line = [exact.clone(), body(MAX_MESSAGE_LEN)].concat();
        assert_eq!(line.len(), MAX_LINE_LEN);
        assert_eq!(
            IrcMessage::parse(&line).unwrap().message_len(),
            MAX_MESSAGE_LEN
        );

        // Spare tag space does not lengthen a message.
        let line = [b"@a ".to_vec(), body(MAX_MESSAGE_LEN + 1)].concat();
        assert_eq!(IrcMessage::parse(&line), Err(IrcError::MessageTooLong));

        // A short message does not lengthen the tags.
        let over = [
            vec![b'@'],
            vec![b'a'; MAX_TAG_SECTION_LEN - 1],
            b" C".to_vec(),
        ]
        .concat();
        assert_eq!(IrcMessage::parse(&over), Err(IrcError::TagsTooLong));

        assert_eq!(
            IrcMessage::parse(&body(MAX_MESSAGE_LEN + 1)),
            Err(IrcError::MessageTooLong)
        );
        assert!(IrcMessage::parse(&body(MAX_MESSAGE_LEN)).is_ok());
    }

    #[test]
    fn tag_section_with_no_space_is_refused() {
        assert_eq!(IrcMessage::parse(b"@a=1"), Err(IrcError::MissingCommand));
        let long = vec![b'@'; MAX_TAG_SECTION_LEN + 1];
        assert_eq!(IrcMessage::parse(&long), Err(IrcError::TagsTooLong));
    }

    #[test]
    fn malformed_lines_are_refused() {
        let cases: [(&[u8], IrcError); 9] = [
            (b"", IrcError::MissingCommand),
            (b"   ", IrcError::MissingCommand),
            (b":", IrcError::EmptyPrefix),
            (b": CMD", IrcError::EmptyPrefix),
            (b":src", IrcError::MissingCommand),
            (b"@t :src", IrcError::MissingCommand),
            (b"12", IrcError::BadCommand),
            (b"C1 x", IrcError::BadCommand),
            (b"1234 x", IrcError::BadCommand),
        ];
        for (line, want) in cases {
            assert_eq!(IrcMessage::parse(line), Err(want), "{line:?}");
        }
    }

    #[test]
    fn control_bytes_are_refused_anywhere() {
        for line in [
            &b"CMD a\rb"[..],
            b"CMD a\nb",
            b"CMD a\0b",
            b"@a\0 CMD",
            b"CMD\r",
        ] {
            assert_eq!(
                IrcMessage::parse(line),
                Err(IrcError::ForbiddenByte),
                "{line:?}"
            );
        }
    }
}
