//! Checks every Unicode fact the allocation bound rests on, for every scalar
//! value, against the tables this crate actually ships. If a future Unicode
//! update breaks one, this fails rather than the bound quietly becoming false.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use unicode_normalization::UnicodeNormalization;
use unicode_normalization::char::canonical_combining_class;

fn scalars() -> impl Iterator<Item = char> {
    (0..=char::MAX as u32).filter_map(char::from_u32)
}

/// The sanitiser's removal set, restated.
fn removed(c: char) -> bool {
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

fn nfd(c: char) -> String {
    std::iter::once(c).nfd().collect()
}

#[test]
fn the_tables_are_the_reviewed_unicode_version() {
    assert_eq!(unicode_normalization::UNICODE_VERSION, (18, 0, 0));
}

#[test]
fn decomposition_is_at_most_three_bytes_per_input_byte() {
    let worst = scalars()
        .map(|c| (nfd(c).len() * 1000 / c.len_utf8(), c))
        .max()
        .unwrap();
    assert!(worst.0 <= 3000, "{worst:?}");
}

#[test]
fn composition_never_outgrows_the_decomposed_form() {
    // A singleton such as U+037E may shrink, so only composites are compared.
    for c in scalars().filter(|&c| nfd(c).chars().count() > 1) {
        assert!(c.len_utf8() <= nfd(c).len(), "U+{:04X}", u32::from(c));
    }
}

#[test]
fn a_character_gives_at_most_one_non_starter_per_input_byte() {
    for c in scalars() {
        let marks = nfd(c)
            .chars()
            .filter(|&m| canonical_combining_class(m) != 0)
            .count();
        assert!(marks <= c.len_utf8(), "U+{:04X}: {marks}", u32::from(c));
    }
}

#[test]
fn a_non_starter_in_nfc_output_takes_at_least_two_bytes() {
    for c in scalars().filter(|&c| canonical_combining_class(c) != 0) {
        assert!(c.len_utf8() >= 2, "U+{:04X}", u32::from(c));
    }
}

#[test]
fn normalization_never_produces_a_removed_character() {
    for c in scalars() {
        if removed(c) {
            assert_eq!(nfd(c), c.to_string(), "U+{:04X}", u32::from(c));
        } else {
            assert!(!nfd(c).chars().any(removed), "U+{:04X}", u32::from(c));
        }
    }
}

/// The false assumption the bound once held: re-normalising after a removal
/// can make text longer, so later passes must not assume it never grows.
#[test]
fn normalizing_after_a_removal_can_lengthen_text() {
    let joined = "\u{E9}\u{323}";
    let normalized: String = joined.nfc().collect();
    assert_eq!(normalized, "\u{1EB9}\u{301}");
    assert!(normalized.len() > joined.len());
}

#[test]
fn replacement_character_is_a_stable_starter() {
    assert_eq!(canonical_combining_class('\u{FFFD}'), 0);
    assert_eq!(nfd('\u{FFFD}'), "\u{FFFD}");
}
