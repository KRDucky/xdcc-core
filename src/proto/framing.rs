//! Incremental, bounded line framing.

use crate::proto::irc::{MAX_LINE_LEN, MAX_MESSAGE_LEN, MAX_TAG_SECTION_LEN};

/// Which budget an oversized line exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Oversized {
    /// The tag section passed [`MAX_TAG_SECTION_LEN`].
    Tags,
    /// The message outside the tags passed [`MAX_MESSAGE_LEN`].
    Message,
}

/// What the framer found in the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Frame<'a> {
    /// A complete line, without its terminator.
    Line(&'a [u8]),
    /// A line was refused. Reported once for each oversized line.
    Oversized(Oversized),
}

/// The result of one [`LineFramer::push`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step<'a> {
    /// Bytes taken from the input. Call `push` again with the rest.
    pub consumed: usize,
    /// A frame, if one ended within those bytes.
    pub frame: Option<Frame<'a>>,
}

/// Splits a byte stream into lines, using one fixed buffer.
///
/// LF ends a line, and one CR before it is removed. A CR elsewhere is not a
/// terminator, so it stays in the line for [`IrcMessage::parse`] to refuse. Empty
/// lines are skipped. Frames do not depend on how the stream was chunked.
///
/// # Oversized lines
///
/// The budget is checked as bytes arrive, so memory never grows past the buffer,
/// even if no LF ever comes. On the first byte over budget the framer reports
/// [`Frame::Oversized`], clears the buffer, and discards through the next LF.
/// No fragment of an oversized line is ever returned, because a cut line can
/// parse as a shorter, valid one. The line after that LF frames normally. A host
/// can watch [`LineFramer::is_discarding`] to apply its own limit on the wait.
///
/// [`IrcMessage::parse`]: crate::proto::IrcMessage::parse
///
/// ```
/// use xdcc_core::proto::{Frame, LineFramer};
///
/// let mut framer = LineFramer::new();
/// let mut rest: &[u8] = b"PING :a\r\nPI";
/// while !rest.is_empty() {
///     let step = framer.push(rest);
///     rest = &rest[step.consumed..];
///     if let Some(Frame::Line(line)) = step.frame {
///         assert_eq!(line, b"PING :a");
///     }
/// }
/// assert_eq!(framer.pending(), 2);
/// ```
///
/// A framer is not `Clone`. It is one connection's position in a stream, and a
/// cloned `Vec` need not keep its spare capacity, which would break the fixed
/// buffer guarantee.
///
/// ```compile_fail
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<xdcc_core::proto::LineFramer>();
/// ```
#[derive(Debug)]
pub struct LineFramer {
    buffer: Vec<u8>,
    /// Where the part after the tag section starts, once known.
    message_start: Option<usize>,
    discarding: bool,
    finished_line: bool,
}

impl Default for LineFramer {
    fn default() -> Self {
        Self::new()
    }
}

impl LineFramer {
    /// Creates a framer, allocating its whole buffer.
    pub fn new() -> Self {
        Self {
            // One extra byte holds a CR after a maximum-length line.
            buffer: Vec::with_capacity(MAX_LINE_LEN + 1),
            message_start: None,
            discarding: false,
            finished_line: false,
        }
    }

    /// Reads input until a frame ends or the input runs out.
    pub fn push(&mut self, input: &[u8]) -> Step<'_> {
        if self.finished_line {
            self.clear_line();
        }
        let mut consumed = 0;
        while consumed < input.len() {
            if self.discarding {
                match input[consumed..].iter().position(|&byte| byte == b'\n') {
                    Some(at) => {
                        consumed += at + 1;
                        self.discarding = false;
                    }
                    None => consumed = input.len(),
                }
                continue;
            }
            let byte = input[consumed];
            consumed += 1;
            if byte == b'\n' {
                if self.buffer.last() == Some(&b'\r') {
                    self.buffer.pop();
                }
                if self.buffer.is_empty() {
                    self.clear_line();
                    continue;
                }
                self.finished_line = true;
                return Step {
                    consumed,
                    frame: Some(Frame::Line(&self.buffer)),
                };
            }
            if let Some(reason) = self.accept(byte) {
                self.clear_line();
                self.discarding = true;
                return Step {
                    consumed,
                    frame: Some(Frame::Oversized(reason)),
                };
            }
        }
        Step {
            consumed,
            frame: None,
        }
    }

    /// Bytes held for an unfinished line. They are never returned without a terminator.
    pub fn pending(&self) -> usize {
        if self.finished_line {
            0
        } else {
            self.buffer.len()
        }
    }

    /// True while bytes of an oversized line are being dropped.
    pub fn is_discarding(&self) -> bool {
        self.discarding
    }

    /// Forgets all state, for a new connection. A held fragment is dropped.
    pub fn reset(&mut self) {
        self.clear_line();
        self.discarding = false;
    }

    fn clear_line(&mut self) {
        self.buffer.clear();
        self.message_start = None;
        self.finished_line = false;
    }

    fn message_len(&self) -> usize {
        self.buffer.len() - self.message_start.unwrap_or(0)
    }

    /// Stores a byte, or names the budget it would break.
    fn accept(&mut self, byte: u8) -> Option<Oversized> {
        let tagged = self.buffer.first() == Some(&b'@') || (self.buffer.is_empty() && byte == b'@');
        if tagged && self.message_start.is_none() {
            if self.buffer.len() == MAX_TAG_SECTION_LEN {
                return Some(Oversized::Tags);
            }
            self.buffer.push(byte);
            if byte == b' ' {
                self.message_start = Some(self.buffer.len());
            }
            return None;
        }
        // A byte past the budget is allowed only if it is the CR before LF.
        if self.message_len() > MAX_MESSAGE_LEN {
            return Some(Oversized::Message);
        }
        if self.message_len() == MAX_MESSAGE_LEN && byte != b'\r' {
            return Some(Oversized::Message);
        }
        self.buffer.push(byte);
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    enum Owned {
        Line(Vec<u8>),
        Over(Oversized),
    }

    fn frames(framer: &mut LineFramer, mut input: &[u8]) -> Vec<Owned> {
        let mut out = Vec::new();
        while !input.is_empty() {
            let step = framer.push(input);
            assert!(step.consumed > 0);
            input = &input[step.consumed..];
            match step.frame {
                Some(Frame::Line(line)) => out.push(Owned::Line(line.to_vec())),
                Some(Frame::Oversized(reason)) => out.push(Owned::Over(reason)),
                None => {}
            }
        }
        out
    }

    fn line(text: &[u8]) -> Owned {
        Owned::Line(text.to_vec())
    }

    #[test]
    fn crlf_and_lone_lf_both_end_a_line() {
        let mut f = LineFramer::new();
        assert_eq!(
            frames(&mut f, b"A b\r\nC d\n"),
            [line(b"A b"), line(b"C d")]
        );
    }

    #[test]
    fn empty_lines_are_skipped() {
        let mut f = LineFramer::new();
        assert_eq!(frames(&mut f, b"\r\n\n\r\nA\r\n"), [line(b"A")]);
    }

    #[test]
    fn only_one_cr_is_removed_and_inner_cr_stays() {
        let mut f = LineFramer::new();
        assert_eq!(
            frames(&mut f, b"A\r\r\nB\rC\n"),
            [line(b"A\r"), line(b"B\rC")]
        );
    }

    #[test]
    fn a_line_split_at_every_boundary_is_identical() {
        let stream = b":a!b@c PRIVMSG me :x y\r\nPING :z\n\r\n@t=1 C\r\n";
        let want = frames(&mut LineFramer::new(), stream);
        for cut in 0..=stream.len() {
            let mut f = LineFramer::new();
            let mut got = frames(&mut f, &stream[..cut]);
            got.extend(frames(&mut f, &stream[cut..]));
            assert_eq!(got, want, "cut at {cut}");
        }
    }

    #[test]
    fn unterminated_input_stays_pending_and_is_never_returned() {
        let mut f = LineFramer::new();
        assert_eq!(frames(&mut f, b"PING"), []);
        assert_eq!(f.pending(), 4);
        f.reset();
        assert_eq!(f.pending(), 0);
        assert_eq!(frames(&mut f, b"X\n"), [line(b"X")]);
    }

    #[test]
    fn message_boundary_with_each_terminator() {
        let exact = vec![b'x'; MAX_MESSAGE_LEN];
        let mut f = LineFramer::new();
        for end in [&b"\r\n"[..], b"\n"] {
            let input = [exact.clone(), end.to_vec()].concat();
            assert_eq!(frames(&mut f, &input), [line(&exact)]);
        }
        let over = [exact.clone(), b"x\n".to_vec()].concat();
        assert_eq!(frames(&mut f, &over), [Owned::Over(Oversized::Message)]);
        // A CR that turns out not to end the line is an extra byte, not a terminator.
        let cr = [exact.clone(), b"\rb\nN\n".to_vec()].concat();
        assert_eq!(
            frames(&mut f, &cr),
            [Owned::Over(Oversized::Message), line(b"N")]
        );
        let cr_lf_only = [exact, b"\r".to_vec()].concat();
        assert_eq!(frames(&mut f, &cr_lf_only), []);
        assert_eq!(f.pending(), MAX_MESSAGE_LEN + 1);
    }

    #[test]
    fn tag_boundary_is_independent_of_the_message_budget() {
        let tags = [
            vec![b'@'],
            vec![b'a'; MAX_TAG_SECTION_LEN - 2],
            b" ".to_vec(),
        ]
        .concat();
        let message = vec![b'x'; MAX_MESSAGE_LEN];
        let full = [tags.clone(), message.clone()].concat();
        assert_eq!(full.len(), MAX_LINE_LEN);
        let mut f = LineFramer::new();
        let input = [full.clone(), b"\r\n".to_vec()].concat();
        assert_eq!(frames(&mut f, &input), [line(&full)]);

        let over = [tags, message, b"x\nN\n".to_vec()].concat();
        assert_eq!(
            frames(&mut f, &over),
            [Owned::Over(Oversized::Message), line(b"N")]
        );

        let long_tags = [
            vec![b'@'],
            vec![b'a'; MAX_TAG_SECTION_LEN],
            b" C\nN\n".to_vec(),
        ]
        .concat();
        assert_eq!(
            frames(&mut f, &long_tags),
            [Owned::Over(Oversized::Tags), line(b"N")]
        );
    }

    #[test]
    fn long_tag_section_with_no_space_reaches_the_parser() {
        let tags = [vec![b'@'], vec![b'a'; 1000]].concat();
        let input = [tags.clone(), b"\r\n".to_vec()].concat();
        assert_eq!(frames(&mut LineFramer::new(), &input), [line(&tags)]);
    }

    #[test]
    fn oversized_input_without_a_newline_stays_bounded() {
        let mut f = LineFramer::new();
        let capacity = f.buffer.capacity();
        let chunk = vec![b'x'; 4096];
        let mut seen = 0;
        for _ in 0..1000 {
            seen += frames(&mut f, &chunk).len();
            assert!(f.pending() <= MAX_MESSAGE_LEN + 1);
        }
        assert_eq!(seen, 1, "reported once");
        assert!(f.is_discarding());
        assert_eq!(f.buffer.capacity(), capacity);
        assert_eq!(frames(&mut f, b"tail\nA\n"), [line(b"A")]);
        assert!(!f.is_discarding());
    }

    #[test]
    fn no_fragment_of_an_oversized_line_survives() {
        let input = [vec![b'x'; 2000], b"PRIVMSG me :evil\r\n".to_vec()].concat();
        assert_eq!(
            frames(&mut LineFramer::new(), &input),
            [Owned::Over(Oversized::Message)]
        );
    }

    /// The buffer is allocated once, and no state or budget ever regrows it.
    #[test]
    fn the_buffer_stays_fixed_through_every_state() {
        let tags = [
            vec![b'@'],
            vec![b'a'; MAX_TAG_SECTION_LEN - 2],
            b" ".to_vec(),
        ]
        .concat();
        let message = vec![b'x'; MAX_MESSAGE_LEN];
        let maximum = [tags, message].concat();
        assert_eq!(maximum.len(), MAX_LINE_LEN);

        let mut f = LineFramer::new();
        let capacity = f.buffer.capacity();
        assert_eq!(capacity, MAX_LINE_LEN + 1);
        let start = f.buffer.as_ptr();
        let check = |f: &LineFramer, state: &str| {
            assert_eq!(f.buffer.capacity(), capacity, "{state}");
            assert_eq!(f.buffer.as_ptr(), start, "{state}");
        };
        check(&f, "empty");

        assert_eq!(frames(&mut f, b"PART"), []);
        check(&f, "partly filled");
        assert_eq!(frames(&mut f, b"IAL\n"), [line(b"PARTIAL")]);
        check(&f, "completed line");

        // Stop at a finished line, so the next call sees that state directly.
        let step = f.push(b"DONE\nNEXT");
        assert_eq!(step.consumed, 5);
        assert!(f.finished_line);
        check(&f, "line just returned");
        assert_eq!(frames(&mut f, b"NEXT\n"), [line(b"NEXT")]);

        let input = [maximum.clone(), b"\r\n".to_vec()].concat();
        assert_eq!(frames(&mut f, &input), [line(&maximum)]);
        check(&f, "maximum tag and message budgets");

        let held = [maximum.clone(), b"\r".to_vec()].concat();
        assert_eq!(frames(&mut f, &held), []);
        assert_eq!(f.pending(), f.buffer.capacity());
        check(&f, "buffer full, waiting for LF");
        assert_eq!(frames(&mut f, b"\n"), [line(&maximum)]);

        assert_eq!(frames(&mut f, &vec![b'x'; 20_000]).len(), 1);
        assert!(f.is_discarding());
        check(&f, "discard mode");
        assert_eq!(frames(&mut f, b"\nA\n"), [line(b"A")]);

        frames(&mut f, b"PART");
        f.reset();
        check(&f, "reset");
    }

    #[test]
    fn reset_leaves_discard_mode() {
        let mut f = LineFramer::new();
        frames(&mut f, &vec![b'x'; 1000]);
        assert!(f.is_discarding());
        f.reset();
        assert_eq!(frames(&mut f, b"A\n"), [line(b"A")]);
    }
}
