//! Per-nick offer rate limiting with fixed memory.

use std::collections::hash_map::RandomState;
use std::fmt;
use std::hash::{BuildHasher, Hasher};
use std::time::Duration;

use crate::proto::CaseMapping;

/// The most slots examined for one key.
pub const MAX_PROBE: usize = 16;

/// Nicks longer than this skip hashing and use the shared bucket.
pub const MAX_NICK_LEN: usize = 512;

/// The most keys a limiter can track.
pub const MAX_TRACKED_KEYS: usize = 1 << 20;

/// The largest burst a limiter accepts.
pub const MAX_BURST: usize = 1 << 20;

/// The longest window a limiter accepts.
pub const MAX_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// Keeps `now + tolerance + emission` from saturating.
const MAX_NOW_MS: u64 = u64::MAX / 2;

/// The mappings remembered while a change is carried.
const REMEMBERED: usize = 3;

/// Why a [`RateConfig`] was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RateConfigError {
    /// `burst` is zero.
    ZeroBurst,
    /// `burst` exceeds [`MAX_BURST`].
    BurstTooLarge,
    /// `tracked_keys` is zero.
    ZeroTrackedKeys,
    /// `tracked_keys` exceeds [`MAX_TRACKED_KEYS`].
    TooManyTrackedKeys,
    /// `window` is zero.
    ZeroWindow,
    /// `window` exceeds [`MAX_WINDOW`].
    WindowTooLong,
    /// `window` is not a whole number of milliseconds.
    WindowNotRepresentable,
    /// `window` is under one millisecond, so the emission interval would be zero.
    EmissionIntervalZero,
}

impl fmt::Display for RateConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ZeroBurst => "burst is zero",
            Self::BurstTooLarge => "burst is too large",
            Self::ZeroTrackedKeys => "tracked keys is zero",
            Self::TooManyTrackedKeys => "too many tracked keys",
            Self::ZeroWindow => "window is zero",
            Self::WindowTooLong => "window is too long",
            Self::WindowNotRepresentable => "window is not a whole number of milliseconds",
            Self::EmissionIntervalZero => "emission interval rounds to zero",
        })
    }
}

impl std::error::Error for RateConfigError {}

/// The parameters of an [`OfferRateLimiter`].
///
/// The type is `non_exhaustive`: start from [`Default`] and assign fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RateConfig {
    /// Offers a key may make at once, and per `window` when sustained.
    pub burst: usize,
    /// The span over which `burst` offers are earned back.
    pub window: Duration,
    /// How many keys the table is sized for.
    pub tracked_keys: usize,
}

impl Default for RateConfig {
    fn default() -> Self {
        Self {
            burst: 5,
            window: Duration::from_secs(60),
            tracked_keys: 1024,
        }
    }
}

impl RateConfig {
    /// Checks every field and returns the emission interval in milliseconds.
    pub(crate) fn emission_ms(&self) -> Result<u64, RateConfigError> {
        if self.burst == 0 {
            return Err(RateConfigError::ZeroBurst);
        }
        if self.burst > MAX_BURST {
            return Err(RateConfigError::BurstTooLarge);
        }
        if self.tracked_keys == 0 {
            return Err(RateConfigError::ZeroTrackedKeys);
        }
        if self.tracked_keys > MAX_TRACKED_KEYS {
            return Err(RateConfigError::TooManyTrackedKeys);
        }
        if self.window.is_zero() {
            return Err(RateConfigError::ZeroWindow);
        }
        if self.window > MAX_WINDOW {
            return Err(RateConfigError::WindowTooLong);
        }
        let millis = u64::try_from(self.window.as_millis()).unwrap_or(u64::MAX);
        if millis == 0 {
            return Err(RateConfigError::EmissionIntervalZero);
        }
        if self.window.subsec_nanos() % 1_000_000 != 0 {
            return Err(RateConfigError::WindowNotRepresentable);
        }
        let burst = u64::try_from(self.burst).unwrap_or(u64::MAX);
        let emission = millis.div_ceil(burst);
        if emission == 0 {
            return Err(RateConfigError::EmissionIntervalZero);
        }
        Ok(emission)
    }

    /// Checks every field.
    pub fn validate(&self) -> Result<(), RateConfigError> {
        self.emission_ms().map(|_| ())
    }
}

/// What the limiter decided for one offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RateDecision {
    /// The offer is within the rate.
    Allowed,
    /// The key has used its budget.
    Limited,
    /// The key has no slot and the shared overflow bucket has no budget.
    ///
    /// This is the signature of a flood of distinct nicks.
    LimitedShared,
}

impl RateDecision {
    /// True for [`RateDecision::Allowed`].
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }
}

#[derive(Debug, Clone, Copy)]
struct Slot {
    used: bool,
    fingerprint: u64,
    /// Theoretical arrival time in milliseconds.
    tat: u64,
}

const EMPTY: Slot = Slot {
    used: false,
    fingerprint: 0,
    tat: 0,
};

enum Probe {
    Found(usize),
    Free(usize),
    Full,
}

/// A fixed-memory GCRA limiter keyed by IRC nick.
///
/// See the [`policy` documentation](crate::policy) for what it does and does not promise.
pub struct OfferRateLimiter<S = RandomState> {
    hasher: S,
    slots: Vec<Slot>,
    shared_tat: u64,
    emission: u64,
    tolerance: u64,
    high_water: u64,
    mapping: CaseMapping,
    carry_until: u64,
    remembered: [Option<CaseMapping>; REMEMBERED],
}

impl<S> fmt::Debug for OfferRateLimiter<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OfferRateLimiter")
            .field("slots", &self.slots.len())
            .field("mapping", &self.mapping)
            .finish_non_exhaustive()
    }
}

impl OfferRateLimiter<RandomState> {
    /// Builds a limiter with a randomly keyed hasher.
    ///
    /// The key makes it impractical for a remote party to aim fingerprints at
    /// one probe window.
    pub fn new(config: &RateConfig) -> Result<Self, RateConfigError> {
        Self::with_hasher(config, RandomState::new())
    }
}

impl<S: BuildHasher> OfferRateLimiter<S> {
    /// Builds a limiter with a chosen hasher, for deterministic tests.
    pub fn with_hasher(config: &RateConfig, hasher: S) -> Result<Self, RateConfigError> {
        let emission = config.emission_ms()?;
        let burst = u64::try_from(config.burst).unwrap_or(u64::MAX);
        let tolerance = burst.saturating_sub(1).saturating_mul(emission);
        let size = config.tracked_keys.next_power_of_two();
        Ok(Self {
            hasher,
            slots: vec![EMPTY; size],
            shared_tat: 0,
            emission,
            tolerance,
            high_water: 0,
            mapping: CaseMapping::default(),
            carry_until: 0,
            remembered: [None; REMEMBERED],
        })
    }

    /// The number of slots, which never changes.
    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// The casemapping nicks are currently folded under.
    pub fn casemapping(&self) -> CaseMapping {
        self.mapping
    }

    /// Decides one offer from `nick`, at `now` since the caller's origin.
    ///
    /// Allocates nothing.
    pub fn check(&mut self, nick: &[u8], now: Duration) -> RateDecision {
        let now = self.advance(now);
        if self.carry_until <= now {
            self.remembered = [None; REMEMBERED];
        }
        if nick.len() > MAX_NICK_LEN {
            return self.check_shared(now, 0);
        }
        let floor = if self.carry_affects(nick) {
            self.carry_until
        } else {
            0
        };
        let fingerprint = self.fingerprint(nick);
        match self.probe(fingerprint, now) {
            Probe::Found(index) => {
                let Some(slot) = self.slots.get_mut(index) else {
                    return RateDecision::Limited;
                };
                match gcra(slot.tat.max(floor), now, self.emission, self.tolerance) {
                    Some(tat) => {
                        slot.tat = tat;
                        RateDecision::Allowed
                    }
                    None => RateDecision::Limited,
                }
            }
            Probe::Free(index) => {
                // Inheriting the shared bucket stops a key from drawing on it and
                // then claiming a fresh slot for a second budget.
                let start = floor.max(self.shared_tat);
                match gcra(start, now, self.emission, self.tolerance) {
                    Some(tat) => {
                        if let Some(slot) = self.slots.get_mut(index) {
                            *slot = Slot {
                                used: true,
                                fingerprint,
                                tat,
                            };
                        }
                        RateDecision::Allowed
                    }
                    // The shared bucket is the reason if it set the start.
                    None if self.shared_tat > floor => RateDecision::LimitedShared,
                    None => RateDecision::Limited,
                }
            }
            Probe::Full => self.check_shared(now, floor),
        }
    }

    /// Switches the casemapping that later nicks are folded under.
    ///
    /// Fingerprints already stored cannot be recomputed. A nick with a byte that
    /// folds differently under the old and new mapping would look new, so such
    /// nicks start with no spare budget until every existing bucket has
    /// refilled.
    pub fn set_casemapping(&mut self, mapping: CaseMapping) {
        if mapping == self.mapping {
            return;
        }
        if self.carry_until <= self.high_water {
            self.remembered = [None; REMEMBERED];
        }
        let newest = self
            .slots
            .iter()
            .filter(|slot| slot.used)
            .map(|slot| slot.tat)
            .fold(self.shared_tat, u64::max);
        self.carry_until = self.carry_until.max(newest);
        for entry in &mut self.remembered {
            if *entry == Some(mapping) {
                *entry = None;
            }
        }
        let old = self.mapping;
        if !self.remembered.contains(&Some(old)) {
            match self.remembered.iter_mut().find(|entry| entry.is_none()) {
                Some(entry) => *entry = Some(old),
                // Unreachable while only three mappings exist. Failing closed
                // keeps differing nicks limited if more are ever added.
                None => self.carry_until = u64::MAX,
            }
        }
        self.mapping = mapping;
    }

    /// Converts the caller's time and keeps it from running backwards.
    fn advance(&mut self, now: Duration) -> u64 {
        let millis = u64::try_from(now.as_millis()).unwrap_or(u64::MAX);
        let effective = millis.min(MAX_NOW_MS).max(self.high_water);
        self.high_water = effective;
        effective
    }

    fn fingerprint(&self, nick: &[u8]) -> u64 {
        let mut hasher = self.hasher.build_hasher();
        hasher.write_usize(nick.len());
        for &byte in nick {
            hasher.write_u8(self.mapping.fold(byte));
        }
        hasher.finish()
    }

    /// True if a remembered mapping would have folded `nick` differently.
    fn carry_affects(&self, nick: &[u8]) -> bool {
        self.remembered.iter().flatten().any(|&old| {
            old != self.mapping
                && nick
                    .iter()
                    .any(|&byte| old.fold(byte) != self.mapping.fold(byte))
        })
    }

    /// Looks through the whole probe window before offering a free slot, so a
    /// key never gets a second slot.
    fn probe(&self, fingerprint: u64, now: u64) -> Probe {
        let mask = self.slots.len().saturating_sub(1);
        let start = usize::try_from(fingerprint & (mask as u64)).unwrap_or(0);
        let mut free = None;
        for step in 0..MAX_PROBE {
            let index = start.wrapping_add(step) & mask;
            let Some(slot) = self.slots.get(index) else {
                continue;
            };
            if slot.used && slot.fingerprint == fingerprint {
                return Probe::Found(index);
            }
            // Only a fully refilled slot may be reused.
            if free.is_none() && (!slot.used || slot.tat <= now) {
                free = Some(index);
            }
        }
        free.map_or(Probe::Full, Probe::Free)
    }

    fn check_shared(&mut self, now: u64, floor: u64) -> RateDecision {
        match gcra(
            self.shared_tat.max(floor),
            now,
            self.emission,
            self.tolerance,
        ) {
            Some(tat) => {
                self.shared_tat = tat;
                RateDecision::Allowed
            }
            None => RateDecision::LimitedShared,
        }
    }
}

/// Returns the new theoretical arrival time if an offer is allowed.
fn gcra(tat: u64, now: u64, emission: u64, tolerance: u64) -> Option<u64> {
    (tat <= now.saturating_add(tolerance)).then(|| tat.max(now).saturating_add(emission))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::hash::BuildHasherDefault;

    /// FNV-1a, so tests do not depend on a random key.
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

    fn limiter(burst: usize, window_s: u64, keys: usize) -> OfferRateLimiter<Fixed> {
        let config = RateConfig {
            burst,
            window: Duration::from_secs(window_s),
            tracked_keys: keys,
        };
        OfferRateLimiter::with_hasher(&config, Fixed::default()).unwrap()
    }

    fn config(burst: usize, window: Duration, tracked_keys: usize) -> RateConfig {
        RateConfig {
            burst,
            window,
            tracked_keys,
        }
    }

    #[test]
    fn each_ceiling_is_accepted_and_one_more_is_refused() {
        let day = Duration::from_secs(86_400);
        assert_eq!(MAX_WINDOW, day);
        let minute = Duration::from_secs(60);
        assert_eq!(config(MAX_BURST, day, 1).validate(), Ok(()));
        assert_eq!(
            config(MAX_BURST + 1, day, 1).validate(),
            Err(RateConfigError::BurstTooLarge)
        );
        assert_eq!(config(1, minute, MAX_TRACKED_KEYS).validate(), Ok(()));
        assert_eq!(
            config(1, minute, MAX_TRACKED_KEYS + 1).validate(),
            Err(RateConfigError::TooManyTrackedKeys)
        );
        assert_eq!(
            config(1, day + Duration::from_millis(1), 1).validate(),
            Err(RateConfigError::WindowTooLong)
        );
    }

    #[test]
    fn a_nick_of_the_maximum_length_is_tracked_and_a_longer_one_is_not() {
        let longest = vec![b'n'; MAX_NICK_LEN];
        let mut limiter = limiter(1, 60, 4);
        assert!(limiter.check(&longest, at(0)).is_allowed());
        assert_eq!(limiter.check(&longest, at(0)), RateDecision::Limited);

        let over = vec![b'n'; MAX_NICK_LEN + 1];
        assert!(limiter.check(&over, at(0)).is_allowed());
        assert_eq!(limiter.check(&over, at(0)), RateDecision::LimitedShared);
    }

    /// Slots must spread across the table, or most of it would go unused.
    #[test]
    fn keys_spread_across_the_whole_table() {
        let mut limiter = limiter(1, 60, 256);
        let mut tracked = 0;
        for index in 0..200u32 {
            let nick = format!("nick{index}");
            limiter.check(nick.as_bytes(), at(0));
            tracked += usize::from(limiter.check(nick.as_bytes(), at(0)) == RateDecision::Limited);
        }
        assert!(tracked > MAX_PROBE * 4, "{tracked}");
    }

    #[test]
    fn debug_shows_size_and_no_nick() {
        let mut limiter = limiter(1, 60, 4);
        limiter.check(b"secretnick", at(0));
        let text = format!("{limiter:?}");
        assert!(text.contains("slots: 4"), "{text}");
        assert!(!text.contains("secretnick"), "{text}");
    }

    /// A new key inherits the shared bucket even when a slot is free, so a key
    /// that spent the shared budget cannot take a fresh slot. The cost is that
    /// other new keys wait too, for at most one window.
    #[test]
    fn new_keys_wait_for_the_shared_bucket_even_with_a_free_slot() {
        let mut limiter = limiter(3, 60, 1);
        assert!(limiter.check(b"holder", at(0)).is_allowed());
        for _ in 0..3 {
            assert!(limiter.check(b"flood", at(19)).is_allowed());
        }
        assert_eq!(limiter.check(b"flood", at(19)), RateDecision::LimitedShared);
        // The holder's bucket refilled at 20 s, so its slot is free again.
        assert_eq!(
            limiter.check(b"newcomer", at(20)),
            RateDecision::LimitedShared
        );
        assert_eq!(
            limiter.check(b"newcomer", at(38)),
            RateDecision::LimitedShared
        );
        assert_eq!(limiter.check(b"newcomer", at(39)), RateDecision::Allowed);
    }

    fn at(secs: u64) -> Duration {
        Duration::from_secs(secs)
    }

    #[test]
    fn default_admits_five_then_one_every_twelve_seconds() {
        let mut limiter = limiter(5, 60, 16);
        for _ in 0..5 {
            assert_eq!(limiter.check(b"bot", at(0)), RateDecision::Allowed);
        }
        assert_eq!(limiter.check(b"bot", at(0)), RateDecision::Limited);
        assert_eq!(
            limiter.check(b"bot", Duration::from_millis(11_999)),
            RateDecision::Limited
        );
        // The exact boundary allows.
        assert_eq!(limiter.check(b"bot", at(12)), RateDecision::Allowed);
        assert_eq!(limiter.check(b"bot", at(12)), RateDecision::Limited);
    }

    #[test]
    fn nine_offers_fit_in_one_window() {
        let mut limiter = limiter(5, 60, 16);
        let mut allowed = 0;
        for secs in [0, 0, 0, 0, 0, 12, 24, 36, 48, 59] {
            allowed += usize::from(limiter.check(b"bot", at(secs)).is_allowed());
        }
        assert_eq!(allowed, 9);
        assert!(limiter.check(b"bot", at(60)).is_allowed());
    }

    #[test]
    fn backward_time_neither_refills_nor_panics() {
        let mut limiter = limiter(2, 60, 16);
        assert!(limiter.check(b"a", at(100)).is_allowed());
        assert!(limiter.check(b"a", at(100)).is_allowed());
        assert_eq!(limiter.check(b"a", at(0)), RateDecision::Limited);
        assert_eq!(limiter.check(b"a", Duration::ZERO), RateDecision::Limited);
        assert!(limiter.check(b"a", at(130)).is_allowed());
    }

    #[test]
    fn extreme_times_are_clamped() {
        let mut limiter = limiter(2, 60, 16);
        assert!(limiter.check(b"a", Duration::MAX).is_allowed());
        assert!(limiter.check(b"a", Duration::MAX).is_allowed());
        assert_eq!(limiter.check(b"a", Duration::MAX), RateDecision::Limited);
    }

    #[test]
    fn nicks_fold_under_the_current_mapping() {
        let mut limiter = limiter(1, 60, 16);
        assert!(limiter.check(b"Bot[1]", at(0)).is_allowed());
        assert_eq!(limiter.check(b"bot{1}", at(0)), RateDecision::Limited);
        assert_eq!(limiter.check(b"BOT[1]", at(0)), RateDecision::Limited);
    }

    #[test]
    fn oversized_nicks_use_the_shared_bucket() {
        let mut limiter = limiter(1, 60, 16);
        let long = vec![b'x'; MAX_NICK_LEN + 1];
        assert!(limiter.check(&long, at(0)).is_allowed());
        assert_eq!(limiter.check(&long, at(0)), RateDecision::LimitedShared);
        // A new key inherits the drained shared bucket instead of a fresh
        // budget, and the decision says the shared bucket is the cause.
        assert_eq!(limiter.check(b"fine", at(0)), RateDecision::LimitedShared);
        assert!(limiter.check(b"fine", at(60)).is_allowed());
    }

    /// Sends every nick to the same fingerprint.
    #[derive(Default)]
    struct Constant;

    impl Hasher for Constant {
        fn finish(&self) -> u64 {
            0
        }
        fn write(&mut self, _bytes: &[u8]) {}
    }

    #[test]
    fn colliding_fingerprints_share_one_bucket_which_only_limits_more() {
        let config = RateConfig {
            burst: 1,
            tracked_keys: 16,
            ..RateConfig::default()
        };
        let mut limiter =
            OfferRateLimiter::with_hasher(&config, BuildHasherDefault::<Constant>::default())
                .unwrap();
        assert!(limiter.check(b"one", at(0)).is_allowed());
        assert_eq!(limiter.check(b"two", at(0)), RateDecision::Limited);
    }

    #[test]
    fn a_slot_with_budget_left_is_never_evicted() {
        let mut limiter = limiter(5, 60, 1);
        for _ in 0..5 {
            assert!(limiter.check(b"attacked", at(0)).is_allowed());
        }
        // Another key finds the only slot taken, and uses the shared bucket.
        assert!(limiter.check(b"other", at(0)).is_allowed());
        assert_eq!(limiter.check(b"attacked", at(1)), RateDecision::Limited);
        assert_eq!(limiter.check(b"attacked", at(11)), RateDecision::Limited);
    }

    #[test]
    fn a_refilled_slot_is_reclaimed() {
        let mut limiter = limiter(5, 60, 1);
        assert!(limiter.check(b"first", at(0)).is_allowed());
        // At 12 s the first key's bucket is empty again, so the slot is free.
        assert!(limiter.check(b"second", at(12)).is_allowed());
        for _ in 0..4 {
            assert!(limiter.check(b"second", at(12)).is_allowed());
        }
        assert_eq!(limiter.check(b"second", at(12)), RateDecision::Limited);
    }

    #[test]
    fn a_flood_of_new_nicks_delays_a_new_nick_but_not_a_tracked_one() {
        // Sixteen keys fill a table of sixteen slots, each with its budget used.
        let mut limiter = limiter(5, 60, 16);
        for key in 0..16 {
            let nick = format!("tracked{key}");
            let uses = if key == 0 { 1 } else { 5 };
            for _ in 0..uses {
                assert!(limiter.check(nick.as_bytes(), at(0)).is_allowed());
            }
        }
        // The next five new nicks drain the shared bucket.
        for key in 0..5 {
            let nick = format!("flood{key}");
            assert!(limiter.check(nick.as_bytes(), at(0)).is_allowed());
        }
        assert_eq!(limiter.check(b"flood5", at(0)), RateDecision::LimitedShared);
        // A real new nick is delayed, and says why.
        assert_eq!(limiter.check(b"friend", at(0)), RateDecision::LimitedShared);
        assert_eq!(
            limiter.check(b"friend", Duration::from_millis(11_999)),
            RateDecision::LimitedShared
        );
        // A tracked key keeps its own budget throughout.
        assert!(limiter.check(b"tracked0", at(0)).is_allowed());
        // The shared bucket earns one offer per emission interval, and a flood
        // that continues takes it before the real nick does.
        assert!(limiter.check(b"flood6", at(12)).is_allowed());
        assert_eq!(
            limiter.check(b"friend", at(12)),
            RateDecision::LimitedShared
        );
        // Once the tracked buckets refill, their slots are reclaimed.
        assert!(limiter.check(b"friend", at(60)).is_allowed());
    }

    #[test]
    fn changing_the_casemapping_does_not_reset_a_budget() {
        let mut limiter = limiter(1, 60, 16);
        assert_eq!(limiter.casemapping(), CaseMapping::Rfc1459);
        assert!(limiter.check(b"a[1]", at(0)).is_allowed());
        assert!(limiter.check(b"plain", at(0)).is_allowed());
        limiter.set_casemapping(CaseMapping::Ascii);
        assert_eq!(limiter.casemapping(), CaseMapping::Ascii);
        // `[` folds differently, so this nick looks new and must not escape.
        assert_eq!(limiter.check(b"a[1]", at(0)), RateDecision::Limited);
        // A nick with no such byte keeps its fingerprint and its own state.
        assert_eq!(limiter.check(b"plain", at(0)), RateDecision::Limited);
        // A fresh nick with no such byte is unaffected.
        assert!(limiter.check(b"newcomer", at(0)).is_allowed());
        // A fresh nick with such a byte is held until the old buckets refill.
        assert_eq!(limiter.check(b"b[2]", at(30)), RateDecision::Limited);
        assert!(limiter.check(b"b[2]", at(60)).is_allowed());
        assert!(limiter.check(b"a[1]", at(120)).is_allowed());
    }

    #[test]
    fn switching_back_cannot_recover_a_spent_budget() {
        let mut limiter = limiter(2, 60, 16);
        assert!(limiter.check(b"a[1]", at(0)).is_allowed());
        limiter.set_casemapping(CaseMapping::Ascii);
        assert!(limiter.check(b"a[1]", at(0)).is_allowed());
        limiter.set_casemapping(CaseMapping::Rfc1459);
        // The first slot is still there with its old arrival time.
        assert_eq!(limiter.check(b"a[1]", at(0)), RateDecision::Limited);
        // Setting the same mapping again changes nothing.
        limiter.set_casemapping(CaseMapping::Rfc1459);
        assert_eq!(limiter.check(b"a[1]", at(0)), RateDecision::Limited);
        assert!(limiter.check(b"a[1]", at(30)).is_allowed());
    }

    #[test]
    fn the_carry_ends_when_everything_has_refilled() {
        let mut limiter = limiter(1, 60, 16);
        assert!(limiter.check(b"a[1]", at(0)).is_allowed());
        limiter.set_casemapping(CaseMapping::Ascii);
        assert!(limiter.check(b"b[1]", at(60)).is_allowed());
        assert_eq!(limiter.check(b"b[1]", at(60)), RateDecision::Limited);
        assert!(limiter.check(b"b[1]", at(120)).is_allowed());
    }

    #[test]
    fn config_validation_names_each_problem() {
        let base = RateConfig::default();
        type Change = fn(&mut RateConfig);
        let cases: [(Change, RateConfigError); 8] = [
            (|c| c.burst = 0, RateConfigError::ZeroBurst),
            (|c| c.burst = MAX_BURST + 1, RateConfigError::BurstTooLarge),
            (|c| c.tracked_keys = 0, RateConfigError::ZeroTrackedKeys),
            (
                |c| c.tracked_keys = MAX_TRACKED_KEYS + 1,
                RateConfigError::TooManyTrackedKeys,
            ),
            (|c| c.window = Duration::ZERO, RateConfigError::ZeroWindow),
            (
                |c| c.window = MAX_WINDOW + Duration::from_millis(1),
                RateConfigError::WindowTooLong,
            ),
            (
                |c| c.window = Duration::from_micros(1500),
                RateConfigError::WindowNotRepresentable,
            ),
            (
                |c| c.window = Duration::from_micros(999),
                RateConfigError::EmissionIntervalZero,
            ),
        ];
        for (change, expected) in cases {
            let mut config = base;
            change(&mut config);
            assert_eq!(config.validate(), Err(expected));
        }
        assert_eq!(base.validate(), Ok(()));
        assert_eq!(base.emission_ms(), Ok(12_000));
    }

    #[test]
    fn emission_rounds_up() {
        let config = RateConfig {
            burst: 7,
            window: Duration::from_millis(100),
            ..RateConfig::default()
        };
        assert_eq!(config.emission_ms(), Ok(15));
    }
}
