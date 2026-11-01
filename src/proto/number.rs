//! Checked decimal fields, as defined by `PROTOCOL_SPEC.md` §7.4.

/// The longest digit string accepted for any number.
const MAX_DIGITS: usize = 20;

/// Parses one or more ASCII digits, at most 20 characters, without overflow.
///
/// A sign, a suffix, or an empty field is not a number.
pub(crate) fn parse_decimal(field: &[u8]) -> Option<u64> {
    if field.is_empty() || field.len() > MAX_DIGITS {
        return None;
    }
    field.iter().try_fold(0u64, |value, &byte| {
        if !byte.is_ascii_digit() {
            return None;
        }
        value.checked_mul(10)?.checked_add(u64::from(byte - b'0'))
    })
}

/// True for a number equal to zero, such as `0` or `00`.
pub(crate) fn is_zero_valued(field: &[u8]) -> bool {
    parse_decimal(field) == Some(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn accepts_full_u64_range() {
        assert_eq!(parse_decimal(b"0"), Some(0));
        assert_eq!(parse_decimal(b"00123"), Some(123));
        assert_eq!(parse_decimal(b"18446744073709551615"), Some(u64::MAX));
    }

    #[test]
    fn refuses_anything_else() {
        for field in [
            &b""[..],
            b"-1",
            b"+5",
            b"1k",
            b" 1",
            b"1 ",
            b"0x10",
            b"\xd9\xa1",
            b"18446744073709551616",
            b"99999999999999999999",
            b"000000000000000000001",
        ] {
            assert_eq!(parse_decimal(field), None, "{field:?}");
        }
    }

    #[test]
    fn zero_valued_obeys_the_number_length_limit() {
        assert!(is_zero_valued(b"0"));
        assert!(is_zero_valued(b"00000000000000000000"));
        assert!(!is_zero_valued(b"000000000000000000000"));
        assert!(!is_zero_valued(b""));
        assert!(!is_zero_valued(b"-0"));
    }
}
