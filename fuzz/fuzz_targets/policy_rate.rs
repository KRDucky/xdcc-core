//! Offer rate limiter: the documented bound, no growth, no allocation.
//!
//! Layout: burst, window seconds, tracked keys, then operations. An operation
//! is a control byte, nick bytes, and a two-byte time step. The control byte
//! holds the nick length (31 means an oversized nick) in its low five bits, and
//! flags for scaling the step to seconds, going backwards, and switching the
//! casemapping.

#![no_main]

use std::hash::{BuildHasherDefault, Hasher};
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use xdcc_core::policy::{MAX_NICK_LEN, OfferRateLimiter, RateConfig, RateDecision};
use xdcc_core::proto::CaseMapping;
use xdcc_core_fuzz::{check_bound, measured};

/// A fixed hasher, so a crash reproduces.
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

fuzz_target!(|data: &[u8]| {
    let [burst, window, keys, operations @ ..] = data else {
        return;
    };
    let mut rest = operations;
    let mut config = RateConfig::default();
    config.burst = usize::from(burst % 8) + 1;
    config.window = Duration::from_secs(u64::from(window % 120) + 1);
    config.tracked_keys = usize::from(keys % 64) + 1;
    let Ok(mut limiter) =
        OfferRateLimiter::with_hasher(&config, BuildHasherDefault::<Fnv>::default())
    else {
        return;
    };
    let slots = limiter.slot_count();
    let window_ms = u64::try_from(config.window.as_millis()).unwrap_or(u64::MAX);
    let ceiling = 2 * config.burst - 1;

    let mappings = [
        CaseMapping::Ascii,
        CaseMapping::Rfc1459,
        CaseMapping::Rfc1459Strict,
    ];
    let mut clock = 0u64;
    let mut high = 0u64;
    let mut allowed: Vec<(Vec<u8>, u64)> = Vec::new();
    while let [control, tail @ ..] = rest {
        let length = usize::from(control & 31);
        let oversized = length == 31;
        let take = if oversized { 0 } else { length.min(tail.len()) };
        let (nick_bytes, after) = tail.split_at(take);
        let [step_high, step_low, after @ ..] = after else {
            break;
        };
        rest = after;

        let nick: Vec<u8> = if oversized {
            vec![*step_high; MAX_NICK_LEN + 1]
        } else {
            nick_bytes.to_vec()
        };
        let step = u64::from(u16::from_be_bytes([*step_high, *step_low]));
        let step = if control & 32 != 0 { step * 1000 } else { step };
        clock = if control & 64 != 0 {
            clock.saturating_sub(step)
        } else {
            clock.saturating_add(step)
        };
        high = high.max(clock);
        if control & 128 != 0 {
            limiter.set_casemapping(mappings[usize::from(*step_low) % mappings.len()]);
        }

        let (decision, bytes) = measured(|| limiter.check(&nick, Duration::from_millis(clock)));
        check_bound(bytes);
        assert_eq!(bytes, 0, "the limiter allocated after new");
        assert_eq!(limiter.slot_count(), slots, "the table changed size");
        if decision == RateDecision::Allowed {
            allowed.push((nick.clone(), high));
            // No nick gets more than 2 * burst - 1 offers in any window.
            let inside = allowed
                .iter()
                .filter(|(other, at)| *other == nick && high.saturating_sub(*at) < window_ms)
                .count();
            assert!(inside <= ceiling, "{inside} offers in one window");
        }
    }
});
