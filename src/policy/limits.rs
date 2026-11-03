//! Resource limits and who enforces them.

use std::fmt;
use std::time::Duration;

use crate::policy::name::MAX_INPUT;
use crate::policy::rate::{RateConfig, RateConfigError};
use crate::proto::MAX_LINE_LEN;

/// The longest filename input. Not configurable.
pub const FILENAME_INPUT_LEN: usize = MAX_INPUT;

/// The longest inbound line. Not configurable.
pub const INBOUND_LINE_LEN: usize = MAX_LINE_LEN;

/// The most any queue or ring capacity, or tracked key count, may be.
pub const MAX_CAPACITY: usize = 1 << 20;

/// The most concurrent transfers a configuration may allow.
pub const MAX_CONCURRENT_TRANSFERS: usize = 4096;

/// The largest read buffer.
pub const MAX_READ_BUFFER: usize = 16 << 20;

/// The largest retained bot notice.
pub const MAX_BOT_NOTICE_BYTES: usize = 8192;

/// The most memory the buffer and ring products may account for.
pub const MAX_TOTAL_BYTES: u64 = 64 << 30;

/// Tunable limits. Start from [`Default`], which matches `SECURITY.md` §10.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct LimitsConfig {
    /// Transfers running at once.
    pub max_concurrent_transfers: usize,
    /// Transfers running at once with one bot.
    pub max_per_bot_transfers: usize,
    /// The largest file accepted, in bytes.
    pub max_file_size: u64,
    /// Bytes read from a socket at once.
    pub read_buffer: usize,
    /// Events kept per transfer.
    pub event_ring: usize,
    /// Messages queued to a transfer.
    pub transfer_mailbox: usize,
    /// Jobs queued to a storage worker.
    pub storage_queue: usize,
    /// Messages queued from IRC.
    pub irc_inbound: usize,
    /// Messages queued to IRC.
    pub irc_outbound: usize,
    /// Finished outcomes retained.
    pub finished_outcomes: usize,
    /// Reconciliation attempts per record.
    pub reconcile_attempts: usize,
    /// Bytes of a bot notice retained.
    pub bot_notice_bytes: usize,
    /// Offers a nick may make at once, and per window when sustained.
    pub offers_per_window: usize,
    /// The span over which `offers_per_window` is earned back.
    pub offer_window: Duration,
    /// Nicks the rate limiter tracks.
    pub tracked_offer_keys: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_concurrent_transfers: 4,
            max_per_bot_transfers: 1,
            max_file_size: 64 << 30,
            read_buffer: 256 << 10,
            event_ring: 256,
            transfer_mailbox: 64,
            storage_queue: 8,
            irc_inbound: 256,
            irc_outbound: 64,
            finished_outcomes: 1024,
            reconcile_attempts: 8,
            bot_notice_bytes: 512,
            offers_per_window: 5,
            offer_window: Duration::from_secs(60),
            tracked_offer_keys: 1024,
        }
    }
}

/// Why a [`LimitsConfig`] was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LimitsError {
    /// A limit that must be positive is zero. The field name is fixed text.
    Zero(&'static str),
    /// A limit is over its ceiling. The field name is fixed text.
    TooLarge(&'static str),
    /// `max_per_bot_transfers` exceeds `max_concurrent_transfers`.
    PerBotExceedsConcurrent,
    /// Buffers or rings for every transfer would overflow or pass 64 GiB.
    MemoryProduct,
    /// The rate fields are invalid.
    Rate(RateConfigError),
}

impl fmt::Display for LimitsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero(field) => write!(f, "{field} is zero"),
            Self::TooLarge(field) => write!(f, "{field} is too large"),
            Self::PerBotExceedsConcurrent => {
                f.write_str("per-bot transfers exceed concurrent transfers")
            }
            Self::MemoryProduct => f.write_str("buffers for all transfers are too large"),
            Self::Rate(error) => write!(f, "rate limit: {error}"),
        }
    }
}

impl std::error::Error for LimitsError {}

/// A validated set of limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Limits {
    config: LimitsConfig,
}

impl Limits {
    /// Checks every limit and keeps the configuration.
    pub fn new(config: &LimitsConfig) -> Result<Self, LimitsError> {
        let positive = [
            ("max_concurrent_transfers", config.max_concurrent_transfers),
            ("max_per_bot_transfers", config.max_per_bot_transfers),
            ("read_buffer", config.read_buffer),
            ("event_ring", config.event_ring),
            ("transfer_mailbox", config.transfer_mailbox),
            ("storage_queue", config.storage_queue),
            ("irc_inbound", config.irc_inbound),
            ("irc_outbound", config.irc_outbound),
            ("finished_outcomes", config.finished_outcomes),
            ("reconcile_attempts", config.reconcile_attempts),
            ("bot_notice_bytes", config.bot_notice_bytes),
        ];
        for (field, value) in positive {
            if value == 0 {
                return Err(LimitsError::Zero(field));
            }
        }
        if config.max_file_size == 0 {
            return Err(LimitsError::Zero("max_file_size"));
        }
        if config.max_per_bot_transfers > config.max_concurrent_transfers {
            return Err(LimitsError::PerBotExceedsConcurrent);
        }
        if config.max_concurrent_transfers > MAX_CONCURRENT_TRANSFERS {
            return Err(LimitsError::TooLarge("max_concurrent_transfers"));
        }
        if config.read_buffer > MAX_READ_BUFFER {
            return Err(LimitsError::TooLarge("read_buffer"));
        }
        if config.bot_notice_bytes > MAX_BOT_NOTICE_BYTES {
            return Err(LimitsError::TooLarge("bot_notice_bytes"));
        }
        let capacities = [
            ("event_ring", config.event_ring),
            ("transfer_mailbox", config.transfer_mailbox),
            ("storage_queue", config.storage_queue),
            ("irc_inbound", config.irc_inbound),
            ("irc_outbound", config.irc_outbound),
            ("finished_outcomes", config.finished_outcomes),
            ("reconcile_attempts", config.reconcile_attempts),
            ("tracked_offer_keys", config.tracked_offer_keys),
        ];
        for (field, value) in capacities {
            if value > MAX_CAPACITY {
                return Err(LimitsError::TooLarge(field));
            }
        }
        for each in [config.read_buffer, config.event_ring] {
            let total = u64::try_from(config.max_concurrent_transfers)
                .ok()
                .zip(u64::try_from(each).ok())
                .and_then(|(count, size)| count.checked_mul(size));
            if total.is_none_or(|total| total > MAX_TOTAL_BYTES) {
                return Err(LimitsError::MemoryProduct);
            }
        }
        Limits::rate_of(config)
            .validate()
            .map_err(LimitsError::Rate)?;
        Ok(Self { config: *config })
    }

    fn rate_of(config: &LimitsConfig) -> RateConfig {
        RateConfig {
            burst: config.offers_per_window,
            window: config.offer_window,
            tracked_keys: config.tracked_offer_keys,
        }
    }

    /// The validated values.
    pub const fn config(&self) -> &LimitsConfig {
        &self.config
    }

    /// The rate limiter parameters these limits imply.
    pub fn rate_config(&self) -> RateConfig {
        Self::rate_of(&self.config)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn the_rate_config_carries_the_configured_values() {
        let limits = Limits::new(&LimitsConfig {
            offers_per_window: 7,
            offer_window: Duration::from_secs(90),
            tracked_offer_keys: 33,
            ..LimitsConfig::default()
        })
        .unwrap();
        let rate = limits.rate_config();
        assert_eq!(rate.burst, 7);
        assert_eq!(rate.window, Duration::from_secs(90));
        assert_eq!(rate.tracked_keys, 33);
    }

    #[test]
    fn defaults_are_valid_and_match_the_security_table() {
        let limits = Limits::new(&LimitsConfig::default()).unwrap();
        assert_eq!(limits, Limits::default());
        let config = limits.config();
        assert_eq!(config.max_concurrent_transfers, 4);
        assert_eq!(config.max_file_size, 64 * 1024 * 1024 * 1024);
        assert_eq!(config.read_buffer, 256 * 1024);
        assert_eq!(config.offer_window, Duration::from_secs(60));
        assert_eq!(FILENAME_INPUT_LEN, 512);
        assert_eq!(INBOUND_LINE_LEN, MAX_LINE_LEN);
        assert_eq!(limits.rate_config(), RateConfig::default());
    }

    fn refused(change: impl FnOnce(&mut LimitsConfig)) -> LimitsError {
        let mut config = LimitsConfig::default();
        change(&mut config);
        Limits::new(&config).unwrap_err()
    }

    #[test]
    fn every_zero_is_refused() {
        type Change = fn(&mut LimitsConfig);
        let cases: [(&str, Change); 12] = [
            ("max_concurrent_transfers", |c| {
                c.max_concurrent_transfers = 0
            }),
            ("max_per_bot_transfers", |c| c.max_per_bot_transfers = 0),
            ("max_file_size", |c| c.max_file_size = 0),
            ("read_buffer", |c| c.read_buffer = 0),
            ("event_ring", |c| c.event_ring = 0),
            ("transfer_mailbox", |c| c.transfer_mailbox = 0),
            ("storage_queue", |c| c.storage_queue = 0),
            ("irc_inbound", |c| c.irc_inbound = 0),
            ("irc_outbound", |c| c.irc_outbound = 0),
            ("finished_outcomes", |c| c.finished_outcomes = 0),
            ("reconcile_attempts", |c| c.reconcile_attempts = 0),
            ("bot_notice_bytes", |c| c.bot_notice_bytes = 0),
        ];
        for (field, change) in cases {
            assert_eq!(refused(change), LimitsError::Zero(field));
        }
        assert_eq!(
            refused(|c| c.offers_per_window = 0),
            LimitsError::Rate(RateConfigError::ZeroBurst)
        );
        assert_eq!(
            refused(|c| c.offer_window = Duration::ZERO),
            LimitsError::Rate(RateConfigError::ZeroWindow)
        );
        assert_eq!(
            refused(|c| c.tracked_offer_keys = 0),
            LimitsError::Rate(RateConfigError::ZeroTrackedKeys)
        );
    }

    #[test]
    fn ceilings_and_relations_are_enforced() {
        assert_eq!(
            refused(|c| c.max_per_bot_transfers = 5),
            LimitsError::PerBotExceedsConcurrent
        );
        assert_eq!(
            refused(|c| c.read_buffer = MAX_READ_BUFFER + 1),
            LimitsError::TooLarge("read_buffer")
        );
        assert_eq!(
            refused(|c| c.bot_notice_bytes = MAX_BOT_NOTICE_BYTES + 1),
            LimitsError::TooLarge("bot_notice_bytes")
        );
        assert_eq!(
            refused(|c| c.event_ring = MAX_CAPACITY + 1),
            LimitsError::TooLarge("event_ring")
        );
        assert_eq!(
            refused(|c| c.tracked_offer_keys = MAX_CAPACITY + 1),
            LimitsError::TooLarge("tracked_offer_keys")
        );
        assert_eq!(
            refused(|c| c.max_concurrent_transfers = MAX_CONCURRENT_TRANSFERS + 1),
            LimitsError::TooLarge("max_concurrent_transfers")
        );
        assert_eq!(
            refused(|c| c.offer_window = Duration::from_secs(86_401)),
            LimitsError::Rate(RateConfigError::WindowTooLong)
        );
    }

    #[test]
    fn the_ceilings_keep_the_memory_product_at_or_under_the_cap() {
        // 4096 transfers of 16 MiB is exactly 64 GiB, so the largest accepted
        // pair passes and one more byte trips the buffer ceiling first. The
        // product check is a second guard behind the ceilings.
        let mut config = LimitsConfig {
            max_concurrent_transfers: MAX_CONCURRENT_TRANSFERS,
            read_buffer: MAX_READ_BUFFER,
            ..LimitsConfig::default()
        };
        assert!(Limits::new(&config).is_ok());
        config.read_buffer += 1;
        assert_eq!(
            Limits::new(&config),
            Err(LimitsError::TooLarge("read_buffer"))
        );
        assert_eq!(
            u64::try_from(MAX_CONCURRENT_TRANSFERS * MAX_READ_BUFFER),
            Ok(MAX_TOTAL_BYTES)
        );
    }

    #[test]
    fn window_precision_is_checked() {
        assert_eq!(
            refused(|c| c.offer_window = Duration::from_micros(1500)),
            LimitsError::Rate(RateConfigError::WindowNotRepresentable)
        );
        assert_eq!(
            refused(|c| c.offer_window = Duration::from_micros(10)),
            LimitsError::Rate(RateConfigError::EmissionIntervalZero)
        );
    }
}
