//! IRC nick comparison under the server's `CASEMAPPING`.

use std::fmt;

/// How a server compares case-insensitive names.
///
/// The values and their definitions come from the `CASEMAPPING` section of
/// Modern IRC docs. `rfc7613` is deliberately unsupported, since it is a PRECIS
/// comparison and needs Unicode tables this crate does not carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum CaseMapping {
    /// `A-Z` fold to `a-z`.
    Ascii,
    /// As `Ascii`, and `[`, `]`, `\`, `~` fold to `{`, `}`, `|`, `^`.
    ///
    /// This is the default, because clients should assume it when a server does
    /// not publish the parameter.
    #[default]
    Rfc1459,
    /// As `Rfc1459`, except that `~` and `^` are distinct.
    Rfc1459Strict,
}

/// The server advertised a casemapping this crate cannot perform.
///
/// Callers should fail closed rather than compare under a guessed mapping, since
/// a false match would attribute a message to the wrong nick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedCaseMapping;

impl fmt::Display for UnsupportedCaseMapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unsupported CASEMAPPING value")
    }
}

impl std::error::Error for UnsupportedCaseMapping {}

impl CaseMapping {
    /// Reads the value of an ISUPPORT `CASEMAPPING=` token. Values are exact.
    pub fn from_isupport(value: &[u8]) -> Result<Self, UnsupportedCaseMapping> {
        match value {
            b"ascii" => Ok(Self::Ascii),
            b"rfc1459" => Ok(Self::Rfc1459),
            b"rfc1459-strict" => Ok(Self::Rfc1459Strict),
            _ => Err(UnsupportedCaseMapping),
        }
    }

    /// The token value for this mapping.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ascii => "ascii",
            Self::Rfc1459 => "rfc1459",
            Self::Rfc1459Strict => "rfc1459-strict",
        }
    }

    /// Folds one byte to its lower-case equivalent. Bytes above `0x7F` are unchanged.
    pub const fn fold(self, byte: u8) -> u8 {
        match (self, byte) {
            (Self::Rfc1459 | Self::Rfc1459Strict, b'[') => b'{',
            (Self::Rfc1459 | Self::Rfc1459Strict, b']') => b'}',
            (Self::Rfc1459 | Self::Rfc1459Strict, b'\\') => b'|',
            (Self::Rfc1459, b'~') => b'^',
            _ => byte.to_ascii_lowercase(),
        }
    }

    /// Compares two names under this mapping, without allocating.
    pub fn eq(self, left: &[u8], right: &[u8]) -> bool {
        left.len() == right.len()
            && left
                .iter()
                .zip(right)
                .all(|(&a, &b)| self.fold(a) == self.fold(b))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn default_is_rfc1459_as_documented_for_an_absent_parameter() {
        assert_eq!(CaseMapping::default(), CaseMapping::Rfc1459);
    }

    #[test]
    fn isupport_values_round_trip() {
        for mapping in [
            CaseMapping::Ascii,
            CaseMapping::Rfc1459,
            CaseMapping::Rfc1459Strict,
        ] {
            assert_eq!(
                CaseMapping::from_isupport(mapping.as_str().as_bytes()),
                Ok(mapping)
            );
        }
    }

    #[test]
    fn unknown_and_unsupported_values_are_reported() {
        for value in [&b"rfc7613"[..], b"RFC1459", b"", b"unicode"] {
            assert_eq!(
                CaseMapping::from_isupport(value),
                Err(UnsupportedCaseMapping)
            );
        }
    }

    #[test]
    fn folding_matches_each_definition() {
        type Case<'a> = (&'a [u8], &'a [u8], bool, bool, bool);
        let cases: [Case<'_>; 6] = [
            (b"Bot", b"bOT", true, true, true),
            (b"a[b]", b"a{b}", false, true, true),
            (b"a\\b", b"a|b", false, true, true),
            (b"a~b", b"a^b", false, true, false),
            (b"bot", b"bots", false, false, false),
            (b"\xc3\x89", b"\xc3\xa9", false, false, false),
        ];
        for (left, right, ascii, rfc1459, strict) in cases {
            assert_eq!(CaseMapping::Ascii.eq(left, right), ascii, "{left:?}");
            assert_eq!(CaseMapping::Rfc1459.eq(left, right), rfc1459, "{left:?}");
            assert_eq!(
                CaseMapping::Rfc1459Strict.eq(left, right),
                strict,
                "{left:?}"
            );
        }
    }
}
