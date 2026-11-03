//! Checks the M2 allocation bounds for the policy layer.
//!
//! This binary holds one test, because the counters are global and a second
//! test would run concurrently. Inputs are built before a region opens, so only
//! the library is counted. Counts are cumulative, and include reallocation
//! growth, which overstates peak use.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::alloc::System;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use xdcc_core::policy::{
    IpPrefix, Limits, LimitsConfig, MAX_INPUT, MAX_NICK_LEN, MAX_OUTPUT, MAX_RULES, NameRefusal,
    NetPolicy, NetPolicyConfig, OfferRateLimiter, RateConfig, RateDecision, SafeName,
};
use xdcc_core::proto::{CaseMapping, WireName};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

/// The M1 limit on what one input may make the library allocate.
const LIMIT: usize = 16 * 1024;

/// Runs `call` and returns its result with the bytes it allocated.
fn measured<T>(call: impl FnOnce() -> T) -> (T, usize) {
    let region = Region::new(GLOBAL);
    let value = call();
    (value, region.change().bytes_allocated)
}

// The bound on one name, from how `SafeName` allocates. Decoding, NFC and the
// filter each allocate once, at a size this crate computes, so no term depends
// on how the standard library grows a buffer. The one exception is the NFC
// crate's own run buffers below. Each Unicode fact is checked for every scalar
// value by `tests/policy_unicode_tables.rs`.
//
// The first pass sees 512 input bytes: x invalid and v valid.
// - Lossy decoding allocates only if x > 0, at most T = 3x + v bytes.
// - The NFC string is `nfc_capacity`: 3 bytes per U+FFFD and 3x every other
//   byte, so at most 3 * 512. It does not grow.
// - The filter buffer is that plus 1.
// - NFC keeps a run of m non-starters in two buffers of 8 and 4 bytes per entry
//   that double from 4 entries, costing 12 * next_power_of_two(m). A character
//   gives at most one non-starter per input byte, and U+FFFD ends a run, so
//   m <= v. These buffers belong to `unicode-normalization` 0.1.26.
//
// Every later pass sees at most MAX_OUTPUT bytes. Re-normalising after a removal
// can lengthen text (`é` then U+0323 becomes U+1EB9 then U+0301), so the 3x
// limit is used. A non-starter in NFC output takes at least 2 bytes, so a run
// has at most MAX_OUTPUT / 2 entries. NFC never produces a removed character, so
// removal happens in the first pass only. So pass 2 normalises, passes 3 and 4
// only filter, and the final check repeats the run once.
const fn marks(run: usize) -> usize {
    12 * run.next_power_of_two()
}

const NFC_CAPACITY: usize = 3 * MAX_INPUT;

fn first_pass_bound() -> usize {
    (0..=MAX_INPUT)
        .map(|invalid| {
            let valid = MAX_INPUT - invalid;
            let lossy = if invalid > 0 { 3 * invalid + valid } else { 0 };
            lossy + NFC_CAPACITY + (NFC_CAPACITY + 1) + marks(valid.max(1))
        })
        .max()
        .unwrap_or(0)
}

const SECOND_PASS: usize = 3 * MAX_OUTPUT + (3 * MAX_OUTPUT + 1) + marks(MAX_OUTPUT / 2);
const FILTER_ONLY: usize = MAX_OUTPUT + 1;

fn name_bound() -> usize {
    first_pass_bound() + SECOND_PASS + 2 * FILTER_ONLY + marks(MAX_OUTPUT / 2)
}

#[test]
fn policy_allocations_stay_within_the_bound() {
    names_stay_within_the_computed_bound();
    refused_names_allocate_nothing_before_the_first_pass();
    the_network_policy_allocates_nothing();
    the_limiter_allocates_only_in_new();
    limits_allocate_nothing();
}

/// Fills the input with each character that normalisation can act on. Inputs
/// are built before the region opens. Refused inputs count the same.
fn sweep_every_character_with_a_normalization(bound: usize) -> usize {
    let mut worst = 0;
    for c in (0..=char::MAX as u32).filter_map(char::from_u32) {
        let mut decomposed = 0;
        unicode_normalization::char::decompose_canonical(c, |_| decomposed += 1);
        if decomposed < 2 && unicode_normalization::char::canonical_combining_class(c) == 0 {
            continue;
        }
        let input = c.to_string().repeat(MAX_INPUT / c.len_utf8()).into_bytes();
        let (_, bytes) = measured(|| SafeName::from_bytes(&input));
        assert!(bytes <= bound, "U+{:04X}: {bytes} > {bound}", u32::from(c));
        worst = worst.max(bytes);
    }
    worst
}

/// Inputs that cost the most, each of which is accepted.
fn worst_accepted_names() -> Vec<(&'static str, Vec<u8>)> {
    let mark = "\u{301}";
    let mut mixed = vec![0xff; 100];
    mixed.extend(mark.repeat(200).into_bytes());
    vec![
        ("512 invalid bytes", vec![0xff; MAX_INPUT]),
        ("256 combining marks", mark.repeat(256).into_bytes()),
        (
            "base and 255 marks",
            format!("a{}", mark.repeat(255)).into_bytes(),
        ),
        (
            "removal, then 250 marks",
            format!("e\u{200B}{}", mark.repeat(250)).into_bytes(),
        ),
        (
            "marks split by a removable",
            format!("{}\u{200B}{}", mark.repeat(50), mark.repeat(200)).into_bytes(),
        ),
        ("invalid bytes, then marks", mixed),
        (
            "128 expanding characters",
            "\u{1D160}".repeat(128).into_bytes(),
        ),
        ("reordered marks", "\u{301}\u{323}".repeat(120).into_bytes()),
        (
            "256 U+0344, two marks each",
            "\u{344}".repeat(256).into_bytes(),
        ),
        (
            "base and 255 U+0344",
            format!("a{}", "\u{344}".repeat(255)).into_bytes(),
        ),
        (
            "removal, then 254 U+0344",
            format!("e\u{200B}{}", "\u{344}".repeat(254)).into_bytes(),
        ),
        ("longest plain name", vec![b'a'; MAX_INPUT]),
        (
            "removal that makes NFC longer",
            "\u{E9}\u{200D}\u{323}".repeat(60).into_bytes(),
        ),
    ]
}

fn names_stay_within_the_computed_bound() {
    let bound = name_bound();
    assert!(
        bound <= LIMIT,
        "the computed bound {bound} passes the limit"
    );
    let mut worst = 0;
    for (label, input) in worst_accepted_names() {
        let (result, bytes) = measured(|| SafeName::from_bytes(&input));
        let name = result.unwrap_or_else(|error| panic!("{label}: {error}"));
        println!(
            "{label:30} {:3} bytes in, {:3} out, {bytes:5} allocated",
            input.len(),
            name.as_str().len()
        );
        assert!(name.as_str().len() <= MAX_OUTPUT);
        assert!(bytes <= bound, "{label}: {bytes} > {bound}");
        worst = worst.max(bytes);
    }
    worst = worst.max(sweep_every_character_with_a_normalization(bound));
    println!("worst accepted name: {worst} bytes, computed bound {bound}, limit {LIMIT}");

    // A refusal found in a later pass costs no more than an acceptance.
    let late = format!("{}.xdccmeta{}", "x".repeat(MAX_OUTPUT - 9), "z".repeat(40));
    let (result, bytes) = measured(|| SafeName::from_bytes(late.as_bytes()));
    assert_eq!(result, Err(NameRefusal::ReservedSuffix));
    assert!(bytes <= bound);

    // A quoted wire name takes the same path.
    let wire = WireName::new(b"\"../../.ssh/authorized_keys\"").unwrap();
    let (result, bytes) = measured(|| SafeName::from_wire(&wire));
    assert_eq!(result.unwrap().as_str(), "authorized_keys");
    assert!(bytes <= bound);
}

fn refused_names_allocate_nothing_before_the_first_pass() {
    for size in [MAX_INPUT + 1, 1 << 16, 1 << 20, 1 << 26] {
        let input = vec![b'a'; size];
        let (result, bytes) = measured(|| SafeName::from_bytes(&input));
        assert_eq!(result, Err(NameRefusal::TooLong), "{size}");
        assert_eq!(bytes, 0, "oversized {size}");
    }
    let (result, bytes) = measured(|| SafeName::from_bytes(b""));
    assert_eq!(result, Err(NameRefusal::Empty));
    assert_eq!(bytes, 0);
    // The last separator ends the component, so nothing is built.
    for input in [&b"dir/"[..], b"a\\", b"/"] {
        let (result, bytes) = measured(|| SafeName::from_bytes(input));
        assert_eq!(result, Err(NameRefusal::EmptyAfterSanitizing));
        assert_eq!(bytes, 0, "{input:?}");
    }
    // Other refusals build one small buffer at most.
    for input in [&b"..."[..], b"a.xdccpart", b"   "] {
        let (result, bytes) = measured(|| SafeName::from_bytes(input));
        assert!(result.is_err());
        assert!(bytes <= 2 * (input.len() + 1), "{input:?}: {bytes}");
    }
}

fn the_network_policy_allocates_nothing() {
    let rule = IpPrefix::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 0)), 24).unwrap();
    let wide = IpPrefix::new(
        IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0)),
        32,
    )
    .unwrap();
    let mut config = NetPolicyConfig::default();
    config.deny = vec![rule; MAX_RULES];
    config.allow = vec![wide; MAX_RULES];
    config.allow_private_destinations = true;
    let policy = NetPolicy::new(config).unwrap();
    let hosts: Vec<IpAddr> = [
        "8.8.8.8",
        "8.8.9.9",
        "10.1.1.1",
        "127.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "::ffff:127.0.0.1",
        "::ffff:8.8.9.9",
        "::",
        "::1",
        "fe80::1",
        "2606:4700::1",
        "64:ff9b::7f00:1",
        "2002:7f00:1::",
        "2001:0:7f00:1:0:0:f7f7:f7f7",
        "::7f00:1",
        "ff02::1",
    ]
    .iter()
    .map(|host| host.parse().unwrap())
    .collect();
    let (outcomes, bytes) = measured(|| {
        let mut approved = 0;
        for &host in &hosts {
            for port in [0, 80, 1023, 1024, 6000, 65535] {
                approved += usize::from(policy.check(host, port).is_ok());
            }
        }
        approved
    });
    assert!(outcomes > 0);
    assert_eq!(bytes, 0, "check allocated");
    let (prefix, bytes) = measured(|| IpPrefix::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0));
    assert!(prefix.is_err());
    assert_eq!(bytes, 0);
}

fn the_limiter_allocates_only_in_new() {
    let mut config = RateConfig::default();
    config.tracked_keys = 4096;
    let (limiter, built) = measured(|| OfferRateLimiter::new(&config));
    let mut limiter = limiter.unwrap();
    let slots = limiter.slot_count();
    assert_eq!(slots, 4096);
    // One slot is a flag and two 64-bit counters.
    assert!(
        (slots * 16..=slots * 32).contains(&built),
        "new allocated {built}"
    );
    println!("limiter of {slots} slots: new allocated {built} bytes");

    let nicks: Vec<Vec<u8>> = (0..20_000u32)
        .map(|n| format!("Nick{n}[x]").into_bytes())
        .collect();
    let oversized = vec![b'x'; MAX_NICK_LEN + 1];
    let huge = vec![b'x'; 1 << 20];
    let (limited, bytes) = measured(|| {
        let mut limited = 0;
        let mut now = Duration::ZERO;
        for (index, nick) in nicks.iter().enumerate() {
            if index % 5000 == 4999 {
                limiter.set_casemapping(if index % 10_000 == 4999 {
                    CaseMapping::Ascii
                } else {
                    CaseMapping::Rfc1459Strict
                });
            }
            for decision in [
                limiter.check(nick, now),
                limiter.check(nick, now),
                limiter.check(&oversized, now),
                limiter.check(&huge, now),
                limiter.check(b"", now),
            ] {
                limited += usize::from(decision != RateDecision::Allowed);
            }
            now += Duration::from_millis(7);
        }
        limited
    });
    assert!(limited > 0);
    assert_eq!(bytes, 0, "the limiter allocated after new");
    assert_eq!(limiter.slot_count(), slots);
}

fn limits_allocate_nothing() {
    let config = LimitsConfig::default();
    let (limits, bytes) = measured(|| Limits::new(&config));
    let limits = limits.unwrap();
    assert_eq!(bytes, 0);
    let (rate, bytes) = measured(|| limits.rate_config());
    assert_eq!(rate, RateConfig::default());
    assert_eq!(bytes, 0);
}
