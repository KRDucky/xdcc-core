//! Hostile filenames, as Rust literals so no hostile name is a tracked file.
//!
//! Every accepted name is also run through a checker that is written here and
//! shares nothing with the library.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use unicode_normalization::UnicodeNormalization;
use xdcc_core::policy::{NameRefusal, SafeName};
use xdcc_core::proto::WireName;

/// The properties every accepted name must have, restated independently.
fn assert_portable(name: &str) {
    assert!(!name.is_empty() && name.len() <= 200, "{name:?}");
    for c in name.chars() {
        assert!(
            !matches!(c, '/' | '\\' | '<' | '>' | ':' | '"' | '|' | '?' | '*'),
            "{name:?}"
        );
        assert!(!c.is_control(), "{name:?}");
        let code = u32::from(c);
        assert!(
            !matches!(code,
                0xAD | 0x34F | 0x61C | 0x180E | 0x200B..=0x200F | 0x2028..=0x202E
                | 0x2060..=0x2064 | 0x2066..=0x2069 | 0xFEFF | 0xFFF9..=0xFFFB
                | 0xE0000..=0xE007F | 0x2044 | 0x2215 | 0x29F8 | 0xFF0F | 0xFF3C | 0xFE68),
            "{name:?}"
        );
    }
    assert!(!name.starts_with(['.', ' ', '-']), "{name:?}");
    assert!(!name.ends_with(['.', ' ']), "{name:?}");
    let stem = name
        .split('.')
        .next()
        .unwrap()
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    let reserved = [
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "CONIN$",
        "CONOUT$",
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
    assert!(!reserved.contains(&stem.as_str()), "{name:?}");
    let lower = name.to_ascii_lowercase();
    for suffix in [".xdccpart", ".xdccmeta", ".xdccmeta.tmp"] {
        assert!(!lower.ends_with(suffix), "{name:?}");
    }
    assert!(name.nfc().eq(name.chars()), "{name:?} is not NFC");
}

fn accepted(input: &[u8]) -> String {
    let name = SafeName::from_bytes(input)
        .unwrap_or_else(|error| panic!("{:?} refused: {error}", String::from_utf8_lossy(input)));
    assert_portable(name.as_str());
    let again = SafeName::from_bytes(name.as_bytes()).unwrap();
    assert_eq!(again, name, "not idempotent for {:?}", name.as_str());
    name.as_str().to_owned()
}

#[test]
fn traversal_keeps_only_the_last_component() {
    let cases: &[(&str, &str)] = &[
        // The pattern behind CVE-2026-32733, the Halloy path traversal.
        ("../../.ssh/authorized_keys", "authorized_keys"),
        ("..\\..\\.ssh\\authorized_keys", "authorized_keys"),
        ("~/.ssh/authorized_keys", "authorized_keys"),
        ("/etc/passwd", "passwd"),
        ("/", ""),
        ("....//....//x", "x"),
        ("foo/../bar", "bar"),
        ("a/./b", "b"),
        (".../x", "x"),
        ("./.", ""),
        ("C:\\Windows\\System32\\cmd.exe", "cmd.exe"),
        ("\\\\?\\C:\\x.bin", "x.bin"),
        ("\\\\server\\share\\x.bin", "x.bin"),
        ("//server/share/x.bin", "x.bin"),
        ("C:x", "C_x"),
        ("C:", "C_"),
    ];
    for &(input, expected) in cases {
        if expected.is_empty() {
            assert_eq!(
                SafeName::from_bytes(input.as_bytes()),
                Err(NameRefusal::EmptyAfterSanitizing),
                "{input:?}"
            );
        } else {
            assert_eq!(accepted(input.as_bytes()), expected, "{input:?}");
        }
    }
}

#[test]
fn wire_names_from_offers() {
    let quoted = WireName::new(b"\"../../.ssh/authorized_keys\"").unwrap();
    assert_eq!(
        SafeName::from_wire(&quoted).unwrap().as_str(),
        "authorized_keys"
    );
    let plain = WireName::new(b"../../.ssh/authorized_keys").unwrap();
    assert_eq!(
        SafeName::from_wire(&plain).unwrap().as_str(),
        "authorized_keys"
    );
    // The quotes are not part of the name, so they cannot hide a dot.
    let dots = WireName::new(b"\"..\"").unwrap();
    assert_eq!(
        SafeName::from_wire(&dots),
        Err(NameRefusal::EmptyAfterSanitizing)
    );
}

#[test]
fn percent_sequences_are_never_decoded() {
    assert_eq!(accepted(b"..%2F..%2Fetc%2Fpasswd"), "%2F..%2Fetc%2Fpasswd");
    assert_eq!(accepted(b"%2e%2e%2f%2e%2e%2fx"), "%2e%2e%2f%2e%2e%2fx");
    assert_eq!(accepted(b"%5c..%5cx"), "%5c..%5cx");
    assert_eq!(accepted(b"x%00.txt"), "x%00.txt");
}

#[test]
fn windows_device_names_and_streams() {
    let cases: &[(&str, &str)] = &[
        ("CON", "_CON"),
        ("con", "_con"),
        ("cOn.TXT", "_cOn.TXT"),
        ("NUL.tar.gz", "_NUL.tar.gz"),
        ("PRN ", "_PRN"),
        ("AUX .txt", "_AUX .txt"),
        ("COM1", "_COM1"),
        ("COM0.log", "_COM0.log"),
        ("lpt9.log", "_lpt9.log"),
        ("COM\u{B9}.txt", "_COM\u{B9}.txt"),
        ("LPT\u{B2}", "_LPT\u{B2}"),
        ("CONIN$", "_CONIN$"),
        ("CONOUT$.txt", "_CONOUT$.txt"),
        ("C\u{200B}ON", "_CON"),
        ("\u{FF23}ON", "\u{FF23}ON"),
        ("COM\u{2074}", "COM\u{2074}"),
        ("COM10", "COM10"),
        ("CON-", "CON-"),
        // Stems compare ignoring ASCII case only. U+0131 (dotless i) upper-cases
        // to `I` under Unicode rules, but `conın$` is not `CONIN$`. Found by the
        // fuzz oracle, which had used Unicode case.
        ("conin$", "_conin$"),
        ("con\u{131}n$", "con\u{131}n$"),
        ("file.txt:Zone.Identifier", "file.txt_Zone.Identifier"),
        ("file.txt::$DATA", "file.txt__$DATA"),
        ("file.txt:stream:$DATA", "file.txt_stream_$DATA"),
        ("x. .", "x"),
        ("x.exe ", "x.exe"),
        ("x.exe. . ", "x.exe"),
    ];
    for &(input, expected) in cases {
        assert_eq!(accepted(input.as_bytes()), expected, "{input:?}");
    }
}

#[test]
fn bidirectional_and_invisible_characters() {
    let cases: &[(&str, &str)] = &[
        ("invoice\u{202E}fdp.exe", "invoicefdp.exe"),
        ("\u{202E}txt.exe", "txt.exe"),
        ("a\u{2066}b\u{2069}c", "abc"),
        ("a\u{200B}\u{200C}\u{200D}b", "ab"),
        ("\u{FEFF}name", "name"),
        ("na\u{AD}me", "name"),
        ("a\u{E0041}\u{E007F}b", "ab"),
        ("x\u{2028}y\u{2029}z", "xyz"),
        ("\u{200B}.hidden", "hidden"),
        (".\u{200B}.\u{200B}/x", "x"),
        ("a\u{FFF9}b\u{FFFB}", "ab"),
    ];
    for &(input, expected) in cases {
        assert_eq!(accepted(input.as_bytes()), expected, "{input:?}");
    }
}

#[test]
fn look_alike_separators_become_underscores() {
    let cases: &[(&str, &str)] = &[
        ("..\u{2215}..\u{2215}x", "_.._x"),
        ("a\u{2044}b", "a_b"),
        ("a\u{29F8}b", "a_b"),
        ("a\u{FF0F}b", "a_b"),
        ("a\u{FF3C}b", "a_b"),
        ("a\u{FE68}b", "a_b"),
        ("\u{FF0E}\u{FF0E}\u{FF0F}x", "\u{FF0E}\u{FF0E}_x"),
    ];
    for &(input, expected) in cases {
        assert_eq!(accepted(input.as_bytes()), expected, "{input:?}");
    }
}

#[test]
fn control_characters_and_nul_are_removed() {
    let cases: &[(&[u8], &str)] = &[
        (b"a\0.txt", "a.txt"),
        (b"x.txt\0.exe", "x.txt.exe"),
        (b"a\r\nb", "ab"),
        (b"a\tb", "ab"),
        (b"\x1b[31mred", "[31mred"),
        (b"a\x7fb", "ab"),
        (b"\xc2\x85line", "line"),
        (b"name\0", "name"),
    ];
    for &(input, expected) in cases {
        assert_eq!(accepted(input), expected, "{input:?}");
    }
}

#[test]
fn invalid_utf8_cannot_smuggle_a_separator() {
    // Overlong encodings of `/` and `.` must not decode to ASCII.
    let overlong_slash = accepted(b"..\xc0\xaf..\xc0\xafetc");
    assert!(!overlong_slash.contains('/'));
    assert_eq!(
        overlong_slash,
        "\u{FFFD}\u{FFFD}..\u{FFFD}\u{FFFD}etc".trim_start_matches('.')
    );
    assert_eq!(
        accepted(b"\xc0\xae\xc0\xae"),
        "\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD}"
    );
    assert_eq!(accepted(b"\xff\xfe"), "\u{FFFD}\u{FFFD}");
    assert_eq!(accepted(b"a\x80b"), "a\u{FFFD}b");
    assert_eq!(accepted(b"\xed\xa0\x80"), "\u{FFFD}\u{FFFD}\u{FFFD}");
}

#[test]
fn leading_dots_dashes_and_spaces() {
    let cases: &[(&str, &str)] = &[
        (".bashrc", "bashrc"),
        ("..hidden", "hidden"),
        ("-rf", "rf"),
        ("--help", "help"),
        ("- - x", "x"),
        (" .x", "x"),
        ("x.", "x"),
        ("x ", "x"),
        ("x. ", "x"),
        ("-", ""),
        ("--", ""),
        (".", ""),
        ("..", ""),
        (" ", ""),
        ("  .  ", ""),
    ];
    for &(input, expected) in cases {
        if expected.is_empty() {
            assert_eq!(
                SafeName::from_bytes(input.as_bytes()),
                Err(NameRefusal::EmptyAfterSanitizing),
                "{input:?}"
            );
        } else {
            assert_eq!(accepted(input.as_bytes()), expected, "{input:?}");
        }
    }
}

#[test]
fn reserved_suffixes_cannot_be_forged() {
    for input in [
        "a.xdccpart",
        "a.XDCCMETA",
        "dir/a.xdccmeta.tmp",
        "a.xdcc\u{200B}part",
        "a.xdccpart..",
        "a.xdccpart \u{200B} ",
        "a.xdcc\u{AD}meta.t\u{200D}mp",
    ] {
        assert_eq!(
            SafeName::from_bytes(input.as_bytes()),
            Err(NameRefusal::ReservedSuffix),
            "{input:?}"
        );
    }
    for input in [
        "a.xdccpart.bin",
        "xdccpart",
        "a.xdccmeta2",
        "a.xdccmeta.tmp.old",
    ] {
        assert_eq!(accepted(input.as_bytes()), input);
    }
}

#[test]
fn normalisation_cannot_reopen_a_hole() {
    // U+212A KELVIN SIGN is K after NFC, so the stem rule must see K.
    assert_eq!(accepted("\u{212A}".as_bytes()), "K");
    // U+037E is an ordinary semicolon after NFC, which is allowed.
    assert_eq!(accepted("a\u{37E}b".as_bytes()), "a;b");
    // A removable character between a base and a mark hides a composition.
    assert_eq!(accepted("e\u{200B}\u{301}".as_bytes()), "\u{e9}");
    assert_eq!(accepted("e\u{AD}\u{200B}\u{301}".as_bytes()), "\u{e9}");
    // U+226E is the composed form of `<` and U+0338, and is not a `<`.
    assert_eq!(accepted("<\u{338}".as_bytes()), "\u{226E}");
}

#[test]
fn long_names_are_cut_and_still_safe() {
    let long = "a".repeat(512);
    assert_eq!(accepted(long.as_bytes()).len(), 200);
    let with_ext = format!("{}.mkv", "b".repeat(500));
    let got = accepted(with_ext.as_bytes());
    assert_eq!(got.len(), 200);
    assert!(got.ends_with("b.mkv"));
    let trailing_dot = format!("{}.{}", "c".repeat(199), "d".repeat(50));
    assert_eq!(accepted(trailing_dot.as_bytes()), "c".repeat(199));
    let wide = "\u{1F600}".repeat(128);
    assert_eq!(accepted(wide.as_bytes()).len(), 200);
    assert_eq!(
        SafeName::from_bytes(&vec![b'a'; 513]),
        Err(NameRefusal::TooLong)
    );
    assert_eq!(SafeName::from_bytes(b""), Err(NameRefusal::Empty));
}

#[test]
fn collisions_are_expected_and_documented() {
    assert_eq!(accepted(b"a?b"), accepted(b"a*b"));
    assert_eq!(accepted(b"CON"), accepted(b"_CON"));
    assert_eq!(accepted(b"../x"), accepted(b"x"));
    assert_eq!(accepted(b".x"), accepted(b"x"));
}

#[test]
fn ordinary_names_are_untouched() {
    for name in [
        "Some.Show.S01E02.1080p.WEB-DL.x264-GRP.mkv",
        "[Group] Title - 01 (1080p) [ABCD1234].mkv",
        "archive.tar.gz",
        "\u{540D}\u{524D}.bin",
        "caf\u{e9}.txt",
        "a b  c.txt",
        "100%.txt",
        "x_y-z.v1.2.3",
    ] {
        assert_eq!(accepted(name.as_bytes()), name);
    }
}
