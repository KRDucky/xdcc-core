//! Remote filenames reduced to a single, portable path component.

use std::borrow::Cow;
use std::fmt;

use unicode_normalization::{IsNormalized, UnicodeNormalization, is_nfc_quick};

use crate::proto::WireName;

/// The longest input accepted, in bytes.
pub const MAX_INPUT: usize = 512;

/// The longest result, in bytes.
pub const MAX_OUTPUT: usize = 200;

/// The longest extension kept when truncating, dot included.
pub const MAX_EXTENSION: usize = 32;

/// The most passes tried before the input is called unstable.
pub const MAX_PASSES: usize = 4;

/// Why a name was refused. It holds none of the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NameRefusal {
    /// The input is empty.
    Empty,
    /// The input exceeds [`MAX_INPUT`] bytes.
    TooLong,
    /// Nothing is left after sanitising.
    EmptyAfterSanitizing,
    /// The name ends in `.xdccpart`, `.xdccmeta` or `.xdccmeta.tmp`.
    ReservedSuffix,
    /// The passes did not settle, or the result failed its final check.
    Unstable,
}

impl fmt::Display for NameRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "empty filename",
            Self::TooLong => "filename is too long",
            Self::EmptyAfterSanitizing => "nothing is left of the filename",
            Self::ReservedSuffix => "filename uses a reserved suffix",
            Self::Unstable => "filename did not settle",
        })
    }
}

impl std::error::Error for NameRefusal {}

/// A filename that is one portable path component.
///
/// It has no separators, no control or invisible characters, no characters that
/// Windows forbids, no leading dot, space or dash, no trailing dot or space, no
/// reserved device stem, and no reserved suffix. It is NFC and at most
/// [`MAX_OUTPUT`] bytes. It does not establish containment, and sanitising can
/// make two different remote names equal. See the [`policy` documentation](crate::policy).
///
/// ```
/// use xdcc_core::policy::SafeName;
///
/// let name = SafeName::from_bytes(b"../../.ssh/authorized_keys")?;
/// assert_eq!(name.as_str(), "authorized_keys");
/// # Ok::<(), xdcc_core::policy::NameRefusal>(())
/// ```
///
/// It cannot be built by hand:
///
/// ```compile_fail,E0451
/// use xdcc_core::policy::SafeName;
///
/// let _ = SafeName { text: "../x".into() };
/// ```
///
/// It has no default:
///
/// ```compile_fail,E0599
/// let _ = xdcc_core::policy::SafeName::default();
/// ```
///
/// It cannot be converted from text:
///
/// ```compile_fail,E0277
/// use xdcc_core::policy::SafeName;
///
/// let _: SafeName = "../x".into();
/// ```
///
/// It cannot be parsed from text:
///
/// ```compile_fail,E0277
/// use xdcc_core::policy::SafeName;
///
/// let _ = "../x".parse::<SafeName>().unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SafeName {
    text: Box<str>,
}

impl SafeName {
    /// Sanitises the unquoted name of a DCC offer.
    ///
    /// This uses [`WireName::name`], so quotes are not part of the name.
    pub fn from_wire(name: &WireName) -> Result<Self, NameRefusal> {
        Self::from_bytes(name.name())
    }

    /// Sanitises raw bytes, such as a name a host supplies.
    ///
    /// Empty and oversized input is refused before anything is allocated.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NameRefusal> {
        if bytes.is_empty() {
            return Err(NameRefusal::Empty);
        }
        if bytes.len() > MAX_INPUT {
            return Err(NameRefusal::TooLong);
        }
        let mut current = decode_lossy(bytes);
        let mut normalize = true;
        for _ in 0..MAX_PASSES {
            let (next, removed) = pass(&current, normalize)?;
            // Only removal can break NFC in a result that already was NFC, so
            // later passes skip the costly check unless something was removed.
            normalize = removed;
            if next == *current {
                return if is_valid_safe_name(&next) {
                    Ok(Self {
                        text: next.into_boxed_str(),
                    })
                } else {
                    Err(NameRefusal::Unstable)
                };
            }
            current = Cow::Owned(next);
        }
        Err(NameRefusal::Unstable)
    }

    /// The name.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The name as UTF-8 bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.text.as_bytes()
    }
}

impl fmt::Display for SafeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// Lossy UTF-8 decoding into one exact allocation, so its size does not depend
/// on how the standard library grows a buffer. Each invalid sequence becomes one
/// U+FFFD, as in `String::from_utf8_lossy`.
fn decode_lossy(bytes: &[u8]) -> Cow<'_, str> {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return Cow::Borrowed(text);
    }
    let exact = bytes.utf8_chunks().fold(0, |size, chunk| {
        let replacement = if chunk.invalid().is_empty() {
            0
        } else {
            char::REPLACEMENT_CHARACTER.len_utf8()
        };
        size + chunk.valid().len() + replacement
    });
    let mut text = String::with_capacity(exact);
    for chunk in bytes.utf8_chunks() {
        text.push_str(chunk.valid());
        if !chunk.invalid().is_empty() {
            text.push(char::REPLACEMENT_CHARACTER);
        }
    }
    Cow::Owned(text)
}

/// The most bytes NFC can produce from `text`. Canonical decomposition at most
/// triples a character, composition never lengthens that, and U+FFFD maps to
/// itself. `tests/policy_unicode_tables.rs` checks this for every character.
fn nfc_capacity(text: &str) -> usize {
    text.chars()
        .map(|c| {
            if c == char::REPLACEMENT_CHARACTER {
                c.len_utf8()
            } else {
                3 * c.len_utf8()
            }
        })
        .sum()
}

/// Characters that are deleted.
fn is_removed(c: char) -> bool {
    c.is_control()
        || matches!(
            u32::from(c),
            0xAD | 0x034F
                | 0x061C
                | 0x180E
                | 0x200B..=0x200F
                | 0x2028..=0x202E
                | 0x2060..=0x2064
                | 0x2066..=0x2069
                | 0xFEFF
                | 0xFFF9..=0xFFFB
                | 0xE0000..=0xE007F
        )
}

/// Characters that become `_`.
fn is_replaced(c: char) -> bool {
    matches!(
        c,
        '<' | '>'
            | ':'
            | '"'
            | '|'
            | '?'
            | '*'
            | '\u{2044}'
            | '\u{2215}'
            | '\u{29F8}'
            | '\u{FF0F}'
            | '\u{FF3C}'
            | '\u{FE68}'
    )
}

/// Stems Windows treats as devices. Superscript digits are listed separately by
/// Microsoft, so they are spelled out here.
const RESERVED_STEMS: [&str; 30] = [
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM0",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "LPT0",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
    "COM\u{B9}",
    "COM\u{B2}",
    "COM\u{B3}",
    "LPT\u{B9}",
    "LPT\u{B2}",
    "LPT\u{B3}",
];

const RESERVED_DEVICES: [&str; 2] = ["CONIN$", "CONOUT$"];

const RESERVED_SUFFIXES: [&str; 3] = [".xdccpart", ".xdccmeta", ".xdccmeta.tmp"];

/// True if the text before the first dot, ignoring trailing spaces, is reserved.
fn has_reserved_stem(text: &str) -> bool {
    let stem = text.split_once('.').map_or(text, |(stem, _)| stem);
    let stem = stem.trim_end_matches(' ');
    RESERVED_STEMS
        .iter()
        .chain(RESERVED_DEVICES.iter())
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
}

fn has_reserved_suffix(text: &str) -> bool {
    let bytes = text.as_bytes();
    RESERVED_SUFFIXES.iter().any(|suffix| {
        bytes
            .len()
            .checked_sub(suffix.len())
            .and_then(|start| bytes.get(start..))
            .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix.as_bytes()))
    })
}

/// One sanitising pass. Each buffer is sized once, so the allocation is known.
///
/// `normalize` may be false only if `input` is already NFC. The result says
/// whether any character was removed.
fn pass(input: &str, normalize: bool) -> Result<(String, bool), NameRefusal> {
    let normalized: Cow<'_, str> = if !normalize || is_nfc_quick(input.chars()) == IsNormalized::Yes
    {
        Cow::Borrowed(input)
    } else {
        let mut owned = String::with_capacity(nfc_capacity(input));
        owned.extend(input.nfc());
        Cow::Owned(owned)
    };

    let component = normalized
        .rfind(['/', '\\'])
        .map_or(&*normalized, |at| normalized.get(at + 1..).unwrap_or(""));
    if component.is_empty() {
        return Err(NameRefusal::EmptyAfterSanitizing);
    }

    // Replacements are never longer than what they replace, and a reserved
    // stem adds one byte, so this capacity is never exceeded.
    let mut text = String::with_capacity(component.len() + 1);
    let mut removed = false;
    for c in component.chars() {
        if is_removed(c) {
            removed = true;
        } else {
            text.push(if is_replaced(c) { '_' } else { c });
        }
    }

    let kept = text.trim_start_matches(['.', ' ', '-']).len();
    let leading = text.len().saturating_sub(kept);
    text.drain(..leading);
    let end = text.trim_end_matches(['.', ' ']).len();
    text.truncate(end);
    if text.is_empty() {
        return Err(NameRefusal::EmptyAfterSanitizing);
    }

    if has_reserved_stem(&text) {
        text.insert(0, '_');
    }
    if has_reserved_suffix(&text) {
        return Err(NameRefusal::ReservedSuffix);
    }
    truncate(&mut text);
    Ok((text, removed))
}

/// Cuts to [`MAX_OUTPUT`] bytes on a character boundary, keeping a short
/// extension when the text has a non-empty stem.
fn truncate(text: &mut String) {
    if text.len() <= MAX_OUTPUT {
        return;
    }
    let extension = match text.rfind('.') {
        Some(at) if at > 0 && text.len() - at <= MAX_EXTENSION => text.len() - at,
        _ => 0,
    };
    let stem_end = text.len() - extension;
    let mut cut = MAX_OUTPUT - extension;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text.replace_range(cut..stem_end, "");
}

/// The acceptance check. It reads the result and transforms nothing.
fn is_valid_safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_OUTPUT
        && !name
            .chars()
            .any(|c| c == '/' || c == '\\' || is_removed(c) || is_replaced(c))
        && !name.starts_with(['.', ' ', '-'])
        && !name.ends_with(['.', ' '])
        && !has_reserved_stem(name)
        && !has_reserved_suffix(name)
        && (is_nfc_quick(name.chars()) == IsNormalized::Yes || name.nfc().eq(name.chars()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn the_nfc_reservation_is_never_exceeded() {
        assert_eq!(nfc_capacity("\u{1D160}"), 12);
        assert_eq!(nfc_capacity("\u{FFFD}"), 3);
        assert_eq!(nfc_capacity("a\u{E9}"), 9);
        for c in (0..=char::MAX as u32).filter_map(char::from_u32) {
            let text = c.to_string().repeat(3);
            let normalized: String = text.nfc().collect();
            assert!(
                normalized.len() <= nfc_capacity(&text),
                "U+{:04X}",
                u32::from(c)
            );
        }
    }

    #[test]
    fn lossy_decoding_matches_the_standard_library() {
        let mut inputs: Vec<Vec<u8>> = Vec::new();
        for first in 0..=255u8 {
            for second in 0..=255u8 {
                inputs.push(vec![first, second]);
                inputs.push(vec![b'a', first, second, 0xE2, 0x82]);
            }
        }
        inputs.push(vec![0xF0, 0x90, 0x80]);
        inputs.push(vec![0xED, 0xA0, 0x80]);
        inputs.push(vec![0xF4, 0x90, 0x80, 0x80]);
        for input in inputs {
            let decoded = decode_lossy(&input);
            assert_eq!(decoded, String::from_utf8_lossy(&input), "{input:?}");
            if let Cow::Owned(owned) = decoded {
                assert_eq!(owned.capacity(), owned.len(), "{input:?}");
            }
        }
    }

    fn clean(input: &str) -> String {
        SafeName::from_bytes(input.as_bytes())
            .unwrap_or_else(|error| panic!("{input:?} refused: {error}"))
            .as_str()
            .to_owned()
    }

    fn refused(input: &str) -> NameRefusal {
        SafeName::from_bytes(input.as_bytes()).unwrap_err()
    }

    #[test]
    fn plain_names_pass_unchanged() {
        for name in [
            "file.txt",
            "a",
            "My Show - 01 [1080p].mkv",
            "名前.bin",
            "a b.tar.gz",
            "x_y-z",
        ] {
            assert_eq!(clean(name), name);
        }
    }

    #[test]
    fn directory_parts_are_dropped() {
        let cases = [
            ("../../.ssh/authorized_keys", "authorized_keys"),
            ("..\\..\\windows\\system32\\x.dll", "x.dll"),
            ("/etc/passwd", "passwd"),
            ("C:\\Users\\x\\y.txt", "y.txt"),
            ("a/b\\c/d.txt", "d.txt"),
            ("dir/..", ""),
        ];
        for (input, expected) in cases {
            if expected.is_empty() {
                assert_eq!(refused(input), NameRefusal::EmptyAfterSanitizing, "{input}");
            } else {
                assert_eq!(clean(input), expected, "{input}");
            }
        }
        for input in ["a/", "a\\", "/", "..", "...", ".", "../"] {
            assert_eq!(refused(input), NameRefusal::EmptyAfterSanitizing, "{input}");
        }
    }

    #[test]
    fn controls_and_invisibles_are_removed() {
        assert_eq!(clean("a\u{0}b\u{7}c\td\ne"), "abcde");
        assert_eq!(clean("a\u{7f}b\u{85}c\u{9f}d"), "abcd");
        for c in [
            '\u{AD}',
            '\u{34F}',
            '\u{61C}',
            '\u{180E}',
            '\u{200B}',
            '\u{200F}',
            '\u{2028}',
            '\u{202A}',
            '\u{202E}',
            '\u{2060}',
            '\u{2064}',
            '\u{2066}',
            '\u{2069}',
            '\u{FEFF}',
            '\u{FFF9}',
            '\u{FFFB}',
            '\u{E0000}',
            '\u{E0041}',
            '\u{E007F}',
        ] {
            assert_eq!(clean(&format!("a{c}b")), "ab", "{:X}", u32::from(c));
        }
        // Neighbours of the ranges stay.
        for c in [
            '\u{AE}',
            '\u{34E}',
            '\u{2010}',
            '\u{200A}',
            '\u{2065}',
            '\u{206A}',
            '\u{FFF8}',
            '\u{FFFC}',
            '\u{E0080}',
        ] {
            assert_eq!(
                clean(&format!("a{c}b")),
                format!("a{c}b"),
                "{:X}",
                u32::from(c)
            );
        }
    }

    #[test]
    fn forbidden_characters_become_underscores() {
        assert_eq!(clean("a<b>c:d\"e|f?g*h"), "a_b_c_d_e_f_g_h");
        assert_eq!(
            clean("a\u{2044}b\u{2215}c\u{29F8}d\u{FF0F}e\u{FF3C}f\u{FE68}g"),
            "a_b_c_d_e_f_g"
        );
        // Colon covers alternate data streams and drive forms.
        assert_eq!(clean("f.txt:stream"), "f.txt_stream");
        assert_eq!(clean("f.txt::$DATA"), "f.txt__$DATA");
        assert_eq!(clean("C:x"), "C_x");
        assert_eq!(clean("a?b"), clean("a*b"));
    }

    #[test]
    fn leading_and_trailing_junk_is_stripped() {
        let cases = [
            (".hidden", "hidden"),
            ("..x", "x"),
            ("-rf", "rf"),
            ("--option.txt", "option.txt"),
            (" . - name", "name"),
            ("name. . ", "name"),
            ("name.", "name"),
            ("a-", "a-"),
            (".-.a.-.", "a.-"),
        ];
        for (input, expected) in cases {
            assert_eq!(clean(input), expected, "{input:?}");
        }
        assert_eq!(refused("   "), NameRefusal::EmptyAfterSanitizing);
        assert_eq!(refused("-.- "), NameRefusal::EmptyAfterSanitizing);
    }

    #[test]
    fn reserved_stems_get_a_prefix() {
        for stem in [
            "CON",
            "con",
            "Prn",
            "AUX",
            "nul",
            "COM0",
            "com9",
            "LPT1",
            "lpt0",
            "COM\u{B9}",
            "com\u{B2}",
            "LPT\u{B3}",
            "CONIN$",
            "conout$",
        ] {
            assert_eq!(clean(stem), format!("_{stem}"), "{stem}");
            assert_eq!(clean(&format!("{stem}.txt")), format!("_{stem}.txt"));
            assert_eq!(clean(&format!("{stem} .txt")), format!("_{stem} .txt"));
        }
        for fine in [
            "COM10",
            "CONS",
            "COM",
            "LPT",
            "COM\u{2074}",
            "XCON",
            "NULL",
            "AUX2",
            "_CON",
            "CON-1",
        ] {
            assert_eq!(clean(fine), fine, "{fine}");
        }
        assert_eq!(clean(".CON"), "_CON");
        assert_eq!(clean("C\u{200B}ON"), "_CON");
        assert_eq!(clean("CON.tar.gz"), "_CON.tar.gz");
        // The stem ends at the first dot, so a later dot does not help.
        assert_eq!(clean("a.CON"), "a.CON");
    }

    #[test]
    fn reserved_suffixes_are_refused_in_any_case() {
        for name in [
            "a.xdccpart",
            "a.xdccmeta",
            "a.xdccmeta.tmp",
            "a.XDCCPART",
            "a.XdccMeta",
            "a.xdccMETA.TMP",
            "a.b.xdccpart",
            "a.xdccpart. ",
            "a.xdccpart.",
            "a.xdcc\u{200B}part",
        ] {
            assert_eq!(refused(name), NameRefusal::ReservedSuffix, "{name}");
        }
        for fine in [
            "a.xdccpart.txt",
            "xdccpart",
            "a_xdccmeta",
            "a.xdccmetax",
            "a.xdccpar",
            "a.xdccmeta.tmp2",
        ] {
            assert_eq!(clean(fine), fine, "{fine}");
        }
    }

    #[test]
    fn unicode_is_normalised_first() {
        assert_eq!(clean("e\u{301}"), "\u{e9}");
        // U+212A KELVIN SIGN becomes K, and U+037E becomes an ordinary semicolon.
        assert_eq!(clean("\u{212A}"), "K");
        assert_eq!(clean("a\u{37E}b"), "a;b");
        // Removal joins a composable pair, which a later pass then composes.
        assert_eq!(clean("e\u{200B}\u{301}"), "\u{e9}");
        assert_eq!(clean("e\u{AD}\u{301}x"), "\u{e9}x");
    }

    #[test]
    fn long_names_keep_a_short_extension() {
        let name = clean(&format!("{}.txt", "a".repeat(300)));
        assert_eq!(name.len(), MAX_OUTPUT);
        assert!(name.ends_with("a.txt"));

        let multibyte = clean(&"\u{e9}".repeat(150));
        assert_eq!(multibyte, "\u{e9}".repeat(100));
        let three = clean(&"\u{4e2d}".repeat(100));
        assert_eq!(three.len(), 198);

        // An extension over the limit counts as stem.
        let long_ext = clean(&format!("x.{}", "e".repeat(300)));
        assert_eq!(long_ext.len(), MAX_OUTPUT);
        assert!(long_ext.starts_with("x.eee"));

        let edge = clean(&format!(
            "{}.{}",
            "a".repeat(300),
            "e".repeat(MAX_EXTENSION - 1)
        ));
        assert_eq!(edge.len(), MAX_OUTPUT);
        assert!(edge.ends_with(&format!(".{}", "e".repeat(MAX_EXTENSION - 1))));
        let over = clean(&format!(
            "{}.{}",
            "a".repeat(300),
            "e".repeat(MAX_EXTENSION)
        ));
        assert_eq!(over.len(), MAX_OUTPUT);
        assert!(!over.ends_with('e') || over.contains('.'));

        let mut dotted = format!(".{}", "a".repeat(300));
        truncate(&mut dotted);
        assert_eq!(dotted.len(), MAX_OUTPUT);
        let mut exact = "a".repeat(MAX_OUTPUT);
        truncate(&mut exact);
        assert_eq!(exact.len(), MAX_OUTPUT);
    }

    #[test]
    fn truncation_that_exposes_a_dot_is_settled_by_a_later_pass() {
        let name = clean(&format!("{}.{}", "a".repeat(199), "b".repeat(50)));
        assert_eq!(name, "a".repeat(199));
        let spaced = clean(&format!("{} {}", "a".repeat(199), "b".repeat(50)));
        assert_eq!(spaced, "a".repeat(199));
    }

    #[test]
    fn truncation_that_exposes_a_reserved_suffix_is_refused_by_a_later_pass() {
        let name = format!("{}.xdccmeta{}", "x".repeat(MAX_OUTPUT - 9), "z".repeat(40));
        assert_eq!(refused(&name), NameRefusal::ReservedSuffix);
    }

    #[test]
    fn a_prefix_that_passes_the_limit_is_cut_again() {
        let name = format!("CON{}", "a".repeat(300));
        assert_eq!(clean(&name).len(), MAX_OUTPUT);
        // CON with a long extension, so the prefix pushes it over.
        let reserved = format!("CON.{}", "e".repeat(MAX_OUTPUT));
        let got = clean(&reserved);
        assert_eq!(got.len(), MAX_OUTPUT);
        assert!(got.starts_with("_CON."));
    }

    #[test]
    fn size_limits_apply_to_the_input() {
        assert_eq!(SafeName::from_bytes(b""), Err(NameRefusal::Empty));
        assert_eq!(
            SafeName::from_bytes(&vec![b'a'; MAX_INPUT + 1]),
            Err(NameRefusal::TooLong)
        );
        assert_eq!(
            SafeName::from_bytes(&vec![b'a'; MAX_INPUT])
                .unwrap()
                .as_str()
                .len(),
            MAX_OUTPUT
        );
        assert_eq!(
            SafeName::from_bytes(&vec![0xff; MAX_INPUT])
                .unwrap()
                .as_str()
                .len(),
            198
        );
    }

    #[test]
    fn invalid_utf8_becomes_the_replacement_character() {
        assert_eq!(
            SafeName::from_bytes(b"\xffa").unwrap().as_str(),
            "\u{FFFD}a"
        );
        assert_eq!(
            SafeName::from_bytes(b"a\xc3").unwrap().as_str(),
            "a\u{FFFD}"
        );
    }

    #[test]
    fn percent_sequences_stay_literal() {
        assert_eq!(clean("..%2F..%2Fetc%2Fpasswd"), "%2F..%2Fetc%2Fpasswd");
        assert_eq!(clean("a%5Cb%00c"), "a%5Cb%00c");
    }

    #[test]
    fn wire_names_use_the_unquoted_bytes() {
        let quoted = WireName::new(b"\"../my file.txt\"").unwrap();
        assert_eq!(
            SafeName::from_wire(&quoted).unwrap().as_str(),
            "my file.txt"
        );
        let plain = WireName::new(b"x.bin").unwrap();
        assert_eq!(SafeName::from_wire(&plain).unwrap().as_str(), "x.bin");
        let spaced = WireName::new(b"\" lead\"").unwrap();
        assert_eq!(SafeName::from_wire(&spaced).unwrap().as_str(), "lead");
    }

    #[test]
    fn results_are_valid_and_sanitising_them_again_changes_nothing() {
        for input in [
            "../x",
            "CON",
            "a\u{200B}b",
            "e\u{200B}\u{301}",
            "\u{212A}.txt",
            "x ",
            "..a..",
        ] {
            let once = SafeName::from_bytes(input.as_bytes()).unwrap();
            assert!(is_valid_safe_name(once.as_str()), "{input:?}");
            let twice = SafeName::from_bytes(once.as_bytes()).unwrap();
            assert_eq!(once, twice, "{input:?}");
        }
    }

    #[test]
    fn collisions_are_real() {
        assert_eq!(clean("a?b"), clean("a*b"));
        assert_eq!(clean("CON"), clean("_CON"));
        assert_eq!(clean("../x"), clean("x"));
    }

    #[test]
    fn the_validity_predicate_rejects_each_failure() {
        for bad in [
            "",
            "a/b",
            "a\\b",
            "a\u{0}",
            "a<",
            "a:b",
            ".a",
            " a",
            "-a",
            "a.",
            "a ",
            "CON",
            "con.txt",
            "a.xdccpart",
            "e\u{301}",
            "\u{200B}",
            &"a".repeat(MAX_OUTPUT + 1),
        ] {
            assert!(!is_valid_safe_name(bad), "{bad:?}");
        }
        for good in ["a", "_CON", "a.b", "\u{e9}", "COM10"] {
            assert!(is_valid_safe_name(good), "{good:?}");
        }
    }

    #[test]
    fn display_and_bytes_match() {
        let name = SafeName::from_bytes(b"x.bin").unwrap();
        assert_eq!(name.to_string(), "x.bin");
        assert_eq!(name.as_bytes(), b"x.bin");
    }
}
