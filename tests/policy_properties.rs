//! Property tests for the safety policies.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::hash::{BuildHasherDefault, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;
use unicode_normalization::UnicodeNormalization;
use xdcc_core::policy::{
    IpPrefix, Limits, LimitsConfig, NameRefusal, NetPolicy, NetPolicyConfig, NetRefusal,
    OfferRateLimiter, RateConfig, SafeName,
};
use xdcc_core::proto::CaseMapping;

/// Characters that exercise every step of the sanitiser.
const INTERESTING: &[char] = &[
    '/',
    '\\',
    '.',
    ' ',
    '-',
    '_',
    ':',
    '<',
    '>',
    '"',
    '|',
    '?',
    '*',
    '%',
    '$',
    '\0',
    '\n',
    '\u{7f}',
    '\u{85}',
    '\u{AD}',
    '\u{34F}',
    '\u{200B}',
    '\u{200E}',
    '\u{202E}',
    '\u{2066}',
    '\u{FEFF}',
    '\u{E0041}',
    '\u{2044}',
    '\u{2215}',
    '\u{FF0F}',
    '\u{212A}',
    '\u{37E}',
    '\u{301}',
    '\u{323}',
    '\u{338}',
    '\u{FFFD}',
    'e',
    'E',
    'C',
    'O',
    'N',
    'U',
    'L',
    'P',
    'R',
    'A',
    'X',
    'M',
    'T',
    'D',
    'c',
    'o',
    'n',
    'x',
    'd',
    'p',
    'a',
    'r',
    't',
    'm',
    'e',
    't',
    'a',
    '0',
    '1',
    '9',
    '\u{B9}',
    '\u{B2}',
    '\u{2074}',
    '\u{1D160}',
    '\u{4e2d}',
    '\u{e9}',
];

fn name_text() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        prop_oneof![
            4 => proptest::sample::select(INTERESTING),
            1 => any::<char>(),
        ],
        0..260,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

fn name_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        3 => name_text().prop_map(String::into_bytes),
        1 => proptest::collection::vec(any::<u8>(), 0..600),
        1 => (name_text(), proptest::collection::vec(any::<u8>(), 0..8))
            .prop_map(|(text, junk)| [text.as_bytes(), &junk].concat()),
    ]
}

/// What a result must satisfy, stated without the library's helpers.
fn check_name(name: &str) -> Result<(), TestCaseError> {
    prop_assert!(!name.is_empty());
    prop_assert!(name.len() <= 200);
    prop_assert!(name.nfc().eq(name.chars()), "not NFC: {:?}", name);
    prop_assert!(!name.contains(['/', '\\']), "separator: {:?}", name);
    prop_assert!(name != "." && name != "..");
    prop_assert!(!name.starts_with(['.', ' ', '-']), "{:?}", name);
    prop_assert!(!name.ends_with(['.', ' ']), "{:?}", name);
    for c in name.chars() {
        prop_assert!(!c.is_control(), "{:?}", name);
        prop_assert!(!"<>:\"|?*".contains(c), "{:?}", name);
        let code = u32::from(c);
        prop_assert!(
            !matches!(code,
                0xAD | 0x34F | 0x61C | 0x180E | 0x200B..=0x200F | 0x2028..=0x202E
                | 0x2060..=0x2064 | 0x2066..=0x2069 | 0xFEFF | 0xFFF9..=0xFFFB
                | 0xE0000..=0xE007F | 0x2044 | 0x2215 | 0x29F8 | 0xFF0F | 0xFF3C | 0xFE68),
            "{:?}",
            name
        );
    }
    let stem = name
        .split('.')
        .next()
        .unwrap()
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    let devices = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"];
    prop_assert!(!devices.contains(&stem.as_str()), "{:?}", name);
    for prefix in ["COM", "LPT"] {
        if let Some(rest) = stem.strip_prefix(prefix) {
            prop_assert!(
                !matches!(
                    rest,
                    "0" | "1"
                        | "2"
                        | "3"
                        | "4"
                        | "5"
                        | "6"
                        | "7"
                        | "8"
                        | "9"
                        | "\u{B9}"
                        | "\u{B2}"
                        | "\u{B3}"
                ),
                "{:?}",
                name
            );
        }
    }
    let lower = name.to_ascii_lowercase();
    for suffix in [".xdccpart", ".xdccmeta", ".xdccmeta.tmp"] {
        prop_assert!(!lower.ends_with(suffix), "{:?}", name);
    }
    Ok(())
}

fn v4_policy(private: bool, low: bool, allow: &[(u32, u8)], deny: &[(u32, u8)]) -> NetPolicy {
    let prefix = |&(bits, len): &(u32, u8)| {
        let masked = if len == 0 {
            0
        } else {
            bits & (u32::MAX << (32 - u32::from(len)))
        };
        IpPrefix::new(IpAddr::V4(Ipv4Addr::from(masked)), len).unwrap()
    };
    let mut config = NetPolicyConfig::default();
    config.allow_private_destinations = private;
    config.allow_low_ports = low;
    config.allow = allow.iter().map(prefix).collect();
    config.deny = deny.iter().map(prefix).collect();
    NetPolicy::new(config).unwrap()
}

fn rules() -> impl Strategy<Value = Vec<(u32, u8)>> {
    proptest::collection::vec((any::<u32>(), 0u8..=32), 0..4)
}

/// An address that falls in one of the sensitive ranges more often than chance.
fn v4_address() -> impl Strategy<Value = u32> {
    prop_oneof![
        any::<u32>(),
        any::<u32>().prop_map(|n| u32::from_be_bytes([127, 0, 0, 0]) | (n & 0x00ff_ffff)),
        any::<u32>().prop_map(|n| u32::from_be_bytes([10, 0, 0, 0]) | (n & 0x00ff_ffff)),
        any::<u32>().prop_map(|n| u32::from_be_bytes([169, 254, 0, 0]) | (n & 0xffff)),
        any::<u32>().prop_map(|n| u32::from_be_bytes([192, 168, 0, 0]) | (n & 0xffff)),
        any::<u32>().prop_map(|n| u32::from_be_bytes([0, 0, 0, 0]) | (n & 0x00ff_ffff)),
        any::<u32>().prop_map(|n| 0xe000_0000 | (n & 0x1fff_ffff)),
        Just(u32::from_be_bytes([169, 254, 169, 254])),
        Just(u32::from_be_bytes([100, 100, 100, 200])),
        Just(u32::MAX),
    ]
}

fn port() -> impl Strategy<Value = u16> {
    prop_oneof![
        any::<u16>(),
        Just(0),
        Just(1),
        Just(1023),
        Just(1024),
        Just(65535)
    ]
}

#[derive(Default)]
struct Fnv(u64);

impl Hasher for Fnv {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 = (self.0 ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
}

type Fixed = BuildHasherDefault<Fnv>;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 2000,
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("regressions"))),
        ..ProptestConfig::default()
    })]

    #[test]
    fn accepted_names_are_valid_and_stable(input in name_bytes()) {
        match SafeName::from_bytes(&input) {
            Ok(name) => {
                check_name(name.as_str())?;
                let again = SafeName::from_bytes(name.as_bytes());
                prop_assert_eq!(again.as_ref(), Ok(&name));
            }
            Err(error) => {
                // Refusals are limited to the documented reasons.
                prop_assert!(matches!(
                    error,
                    NameRefusal::Empty
                        | NameRefusal::TooLong
                        | NameRefusal::EmptyAfterSanitizing
                        | NameRefusal::ReservedSuffix
                ), "{:?}", error);
                if input.is_empty() {
                    prop_assert_eq!(error, NameRefusal::Empty);
                }
                if input.len() > 512 {
                    prop_assert_eq!(error, NameRefusal::TooLong);
                }
            }
        }
    }

    #[test]
    fn a_name_inside_a_path_is_the_same_as_the_name_alone(
        name in "[a-zA-Z0-9_]{1,20}\\.[a-z]{1,4}",
        dirs in proptest::collection::vec("[a-z.]{0,8}", 0..4),
        backslash in any::<bool>(),
    ) {
        let separator = if backslash { "\\" } else { "/" };
        let path = format!("{}{}{}", dirs.join(separator), separator, name);
        let alone = SafeName::from_bytes(name.as_bytes());
        let nested = SafeName::from_bytes(path.as_bytes());
        prop_assert_eq!(alone, nested);
    }

    #[test]
    fn ipv4_and_its_mapped_form_get_the_same_answer(
        bits in v4_address(),
        port in port(),
        private in any::<bool>(),
        low in any::<bool>(),
        allow in rules(),
        deny in rules(),
    ) {
        let policy = v4_policy(private, low, &allow, &deny);
        let plain = Ipv4Addr::from(bits);
        let mapped = plain.to_ipv6_mapped();
        prop_assert_eq!(
            policy.check(IpAddr::V4(plain), port),
            policy.check(IpAddr::V6(mapped), port)
        );
    }

    #[test]
    fn the_never_tier_ignores_every_setting(
        offset in any::<u32>(),
        family in 0usize..3,
        port in port(),
        allow in rules(),
        private in any::<bool>(),
        low in any::<bool>(),
    ) {
        let bits = match family {
            0 => offset & 0x00ff_ffff,
            1 => 0xe000_0000 | (offset & 0x1fff_ffff),
            _ => 0xf000_0000 | (offset & 0x0fff_ffff),
        };
        let policy = v4_policy(private, low, &allow, &[]);
        let result = policy.check(IpAddr::V4(Ipv4Addr::from(bits)), port);
        prop_assert!(result.is_err());
        if port != 0 && (port >= 1024 || low) {
            let is_always = matches!(result, Err(NetRefusal::Always { .. }));
            prop_assert!(is_always);
        }
    }

    #[test]
    fn ports_decide_alone_for_a_public_address(port in any::<u16>(), low in any::<bool>()) {
        let mut config = NetPolicyConfig::default();
        config.allow_low_ports = low;
        let policy = NetPolicy::new(config).unwrap();
        let result = policy.check(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), port);
        prop_assert_eq!(result.is_ok(), port != 0 && (low || port >= 1024));
    }

    #[test]
    fn decoding_adds_refusals_and_never_approves(
        bits in v4_address(),
        client in v4_address(),
        shape in 0usize..5,
        private in any::<bool>(),
        allow in rules(),
        deny in rules(),
    ) {
        // The outer prefix is allowed, so only the embedded address can refuse.
        let outer = [
            ("64:ff9b::", 96u8),
            ("2002::", 16),
            ("::", 96),
            ("::ffff:0:0:0", 96),
            ("2001::", 32),
        ][shape];
        let embedded = Ipv4Addr::from(bits).octets();
        let client_bits = !client;
        let address = match shape {
            0 => Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0,
                u16::from_be_bytes([embedded[0], embedded[1]]),
                u16::from_be_bytes([embedded[2], embedded[3]])),
            1 => Ipv6Addr::new(0x2002,
                u16::from_be_bytes([embedded[0], embedded[1]]),
                u16::from_be_bytes([embedded[2], embedded[3]]), 0, 0, 0, 0, 1),
            2 => Ipv6Addr::new(0, 0, 0, 0, 0, 0,
                u16::from_be_bytes([embedded[0], embedded[1]]),
                u16::from_be_bytes([embedded[2], embedded[3]])),
            3 => Ipv6Addr::new(0, 0, 0, 0, 0xffff, 0,
                u16::from_be_bytes([embedded[0], embedded[1]]),
                u16::from_be_bytes([embedded[2], embedded[3]])),
            _ => Ipv6Addr::new(0x2001, 0,
                u16::from_be_bytes([embedded[0], embedded[1]]),
                u16::from_be_bytes([embedded[2], embedded[3]]), 0, 0,
                u16::from_be_bytes([(client_bits >> 24) as u8, (client_bits >> 16) as u8]),
                u16::from_be_bytes([(client_bits >> 8) as u8, client_bits as u8])),
        };
        // `::` and `::1` are more specific than `::/96`, and decode nothing.
        prop_assume!(!(shape == 2 && bits <= 1));
        let mut config = NetPolicyConfig::default();
        config.allow_private_destinations = private;
        config.allow = allow
            .iter()
            .map(|&(b, l)| {
                let masked = if l == 0 { 0 } else { b & (u32::MAX << (32 - u32::from(l))) };
                IpPrefix::new(IpAddr::V4(Ipv4Addr::from(masked)), l).unwrap()
            })
            .collect();
        config.deny = deny
            .iter()
            .map(|&(b, l)| {
                let masked = if l == 0 { 0 } else { b & (u32::MAX << (32 - u32::from(l))) };
                IpPrefix::new(IpAddr::V4(Ipv4Addr::from(masked)), l).unwrap()
            })
            .collect();
        let without = NetPolicy::new(config.clone()).unwrap();
        config
            .allow
            .push(IpPrefix::new(IpAddr::V6(outer.0.parse().unwrap()), outer.1).unwrap());
        let with = NetPolicy::new(config).unwrap();

        // Without the outer allow rule the whole prefix is refused.
        prop_assert!(without.check(IpAddr::V6(address), 6000).is_err());

        // With it, the answer is exactly the answer for the embedded addresses.
        let mut expected = without.check(IpAddr::V4(Ipv4Addr::from(bits)), 6000).is_ok();
        if shape == 4 {
            expected &= without.check(IpAddr::V4(Ipv4Addr::from(client)), 6000).is_ok();
        }
        prop_assert_eq!(with.check(IpAddr::V6(address), 6000).is_ok(), expected);
    }

    #[test]
    fn mapped_rules_equal_ipv4_rules(bits in any::<u32>(), len in 0u8..=32, probe in any::<u32>()) {
        let masked = if len == 0 { 0 } else { bits & (u32::MAX << (32 - u32::from(len))) };
        let plain = IpPrefix::new(IpAddr::V4(Ipv4Addr::from(masked)), len).unwrap();
        let mapped = IpPrefix::new(
            IpAddr::V6(Ipv4Addr::from(masked).to_ipv6_mapped()),
            len + 96,
        )
        .unwrap();
        prop_assert_eq!(plain, mapped);
        // Used as deny rules, both refuse the same set.
        let mut one = NetPolicyConfig::default();
        one.deny = vec![plain];
        let mut two = NetPolicyConfig::default();
        two.deny = vec![mapped];
        let (one, two) = (NetPolicy::new(one).unwrap(), NetPolicy::new(two).unwrap());
        let host = IpAddr::V4(Ipv4Addr::from(probe));
        prop_assert_eq!(one.check(host, 6000), two.check(host, 6000));
    }

    #[test]
    fn prefixes_with_host_bits_are_never_accepted(bits in any::<u128>(), len in 0u8..=128) {
        let addr = Ipv6Addr::from(bits);
        let host_bits = if len == 128 { 0 } else { bits & (u128::MAX >> len) };
        if let Ok(prefix) = IpPrefix::new(IpAddr::V6(addr), len) {
            prop_assert_eq!(host_bits, 0);
            // A rule never changes meaning when rebuilt from its parts.
            prop_assert_eq!(IpPrefix::new(prefix.addr(), prefix.len()), Ok(prefix));
        }
    }

    #[test]
    fn accepted_limits_keep_their_relations(
        concurrent in 0usize..5000,
        per_bot in 0usize..5000,
        read_buffer in 0usize..(32 << 20),
        ring in 0usize..(2 << 20),
        notice in 0usize..10_000,
        burst in 0usize..(2 << 20),
        window_ms in 0u64..100_000_000,
        keys in 0usize..(2 << 20),
    ) {
        let mut config = LimitsConfig::default();
        config.max_concurrent_transfers = concurrent;
        config.max_per_bot_transfers = per_bot;
        config.read_buffer = read_buffer;
        config.event_ring = ring;
        config.bot_notice_bytes = notice;
        config.offers_per_window = burst;
        config.offer_window = Duration::from_millis(window_ms);
        config.tracked_offer_keys = keys;
        if let Ok(limits) = Limits::new(&config) {
            let accepted = limits.config();
            prop_assert!(accepted.max_per_bot_transfers >= 1);
            prop_assert!(accepted.max_per_bot_transfers <= accepted.max_concurrent_transfers);
            prop_assert!(accepted.max_concurrent_transfers <= 4096);
            prop_assert!(accepted.read_buffer >= 1 && accepted.read_buffer <= 16 << 20);
            prop_assert!(accepted.bot_notice_bytes >= 1 && accepted.bot_notice_bytes <= 8192);
            prop_assert!(accepted.event_ring >= 1 && accepted.event_ring <= 1 << 20);
            prop_assert!(accepted.tracked_offer_keys >= 1 && accepted.tracked_offer_keys <= 1 << 20);
            prop_assert!(accepted.offer_window >= Duration::from_millis(1));
            prop_assert!(accepted.offer_window <= Duration::from_secs(86_400));
            let total = accepted.max_concurrent_transfers as u64 * accepted.read_buffer as u64;
            prop_assert!(total <= 64 << 30);
            prop_assert!(OfferRateLimiter::new(&limits.rate_config()).is_ok());
        }
    }

    #[test]
    fn no_key_exceeds_twice_the_burst_less_one_in_a_window(
        burst in 1usize..6,
        window_s in 1u64..120,
        keys in 1usize..6,
        schedule in proptest::collection::vec(
            (0usize..8, 0u64..40_000, any::<bool>(), 0usize..4),
            1..160,
        ),
    ) {
        let mut config = RateConfig::default();
        config.burst = burst;
        config.window = Duration::from_secs(window_s);
        config.tracked_keys = keys;
        let mut limiter = OfferRateLimiter::with_hasher(&config, Fixed::default()).unwrap();
        let window = window_s * 1000;
        let nicks: [&[u8]; 8] = [b"Bot", b"bot", b"Bot[1]", b"bot{1}", b"x~y", b"x^y", b"other", b"z"];
        let mappings = [
            CaseMapping::Rfc1459,
            CaseMapping::Ascii,
            CaseMapping::Rfc1459Strict,
        ];

        let mut clock = 0u64;
        let mut high = 0u64;
        let mut allowed: Vec<Vec<u64>> = vec![Vec::new(); nicks.len()];
        for (nick, step, backwards, mapping) in schedule {
            clock = if backwards { clock.saturating_sub(step / 2) } else { clock + step };
            high = high.max(clock);
            // Only some steps change the mapping, so the carry logic is
            // exercised without being swamped.
            if mapping < 3 && step % 3 == 0 {
                limiter.set_casemapping(mappings[mapping]);
            }
            let decision = limiter.check(nicks[nick], Duration::from_millis(clock));
            if decision.is_allowed() {
                allowed[nick].push(high);
            }
        }
        for times in &allowed {
            for (index, &start) in times.iter().enumerate() {
                let inside = times[index..].iter().take_while(|&&t| t < start + window).count();
                prop_assert!(inside < 2 * burst, "{} in one window of {}", inside, window);
            }
        }
        prop_assert_eq!(limiter.slot_count(), keys.next_power_of_two());
    }

    #[test]
    fn a_single_key_gets_the_documented_rate(
        burst in 1usize..8,
        window_s in 1u64..90,
        gaps in proptest::collection::vec(0u64..30_000, 1..80),
    ) {
        let mut config = RateConfig::default();
        config.burst = burst;
        config.window = Duration::from_secs(window_s);
        let mut limiter = OfferRateLimiter::with_hasher(&config, Fixed::default()).unwrap();
        let emission = (window_s * 1000).div_ceil(burst as u64);
        // A reference GCRA with plain integers.
        let mut tat = 0u64;
        let mut now = 0u64;
        for gap in gaps {
            now += gap;
            let expected = tat <= now + (burst as u64 - 1) * emission;
            if expected {
                tat = tat.max(now) + emission;
            }
            let got = limiter.check(b"nick", Duration::from_millis(now)).is_allowed();
            prop_assert_eq!(got, expected);
        }
    }
}
