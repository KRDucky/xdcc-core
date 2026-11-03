//! Safety decisions that sit between untrusted protocol values and later layers.
//!
//! Nothing in this module performs I/O, reads a clock, or needs a runtime. Each
//! piece is a pure decision, and each says plainly what it does not promise.
//!
//! - [`NetPolicy`] decides whether a peer address may be connected to. An
//!   [`ApprovedAddr`] does not authenticate the peer, and translation detection
//!   is not universal.
//! - [`SafeName`] turns a remote filename into one path component, or refuses
//!   it. A `SafeName` does not establish containment, and sanitisation causes
//!   collisions.
//! - [`OfferRateLimiter`] bounds offers per nick in fixed memory.
//! - [`Limits`] validates the resource limits that later layers enforce.
//!
//! `proto` never depends on this module. A value from `proto` stays untrusted
//! until one of these types has accepted it.
//!
//! # Network policy
//!
//! [`NetPolicy::check`] turns an address and port into an [`ApprovedAddr`] or a
//! named refusal. It is a pure function of its arguments and the configuration.
//!
//! ## Limits
//!
//! - An [`ApprovedAddr`] is a decision about one endpoint at one moment. It does
//!   not authenticate the peer, and the address may change hands afterwards. The
//!   future `net` layer must call `check` again immediately before connecting
//!   (`SECURITY.md` SEC-2).
//! - Translation detection is not universal. Built-in prefixes such as
//!   `64:ff9b::/96`, `2002::/16`, `::/96`, `::ffff:0:0:0/96` and Teredo are
//!   denied whole, and their embedded IPv4 address is checked too. A
//!   deployment-specific NAT64 prefix (RFC 6052 §2.2) inside global space cannot
//!   be recognised from the address, so an address under one is judged as the
//!   IPv6 address it is.
//! - The metadata list is best-effort and not exhaustive. Each entry comes from
//!   that vendor's documentation, listed in `docs/SECURITY.md` §4.
//! - Parsing an offer never produces an [`ApprovedAddr`]. Nothing here accepts a
//!   `DccOffer` or `OfferEndpoint`, and a passive offer has no peer to approve.
//!
//! ## Decision order
//!
//! 1. The address is canonicalised, so `::ffff:a.b.c.d` is judged as IPv4.
//! 2. Port 0 and, unless allowed, ports below 1024 are refused.
//! 3. If the most specific built-in range holding the address is a transition
//!    range that embeds an IPv4 address, that address (two for Teredo) is
//!    decoded. `::` and `::1` decode nothing, because `::/128` and `::1/128`
//!    are more specific than `::/96`.
//! 4. Unspecified, multicast, reserved and broadcast ranges are always refused,
//!    for the address and for every decoded one.
//! 5. An explicit deny rule that matches the address or a decoded one refuses.
//!    Deny always beats allow.
//! 6. The most specific built-in range holding the address is found.
//! 7. That range is cleared only by an allow rule that contains the address and
//!    is at least as long as the range, or by `allow_private_destinations` for
//!    a private range. So `0.0.0.0/0` clears nothing, and a metadata host needs
//!    an allow rule for that exact host.
//! 8. Each decoded address goes through steps 4 to 7 as IPv4.
//!
//! Decoding never approves anything. It only adds refusals.
//!
//! ## Built-in ranges
//!
//! `allow_private_destinations` relaxes only the private class. Loopback,
//! link-local, metadata, special-use and transition ranges need an allow rule.
//! Some entries inside `2001::/23` and `192.0.0.0/24` are globally reachable in
//! the IANA registries; the parents are denied on purpose because no DCC peer
//! belongs there. `64:ff9b::/96` is also globally reachable and is denied anyway.
//!
//! IPv6 outside `2000::/3` with no narrower entry is refused as special-use,
//! because IANA assigns no global unicast there. An allow rule of `/3` or longer
//! clears it. Everything else, in both families, is treated as public.
//!
//! # Filenames
//!
//! [`SafeName`] is a string the sanitiser produced and re-checked. It is either
//! returned whole or refused, and sanitising it again changes nothing.
//!
//! ## Limits
//!
//! - A `SafeName` does not establish containment. It is one component with no
//!   separators, but joining it to a directory, symlinks in that directory, races
//!   between check and create, exclusive creation, and case collisions on the
//!   target filesystem all belong to the storage layer (`SECURITY.md` SEC-4 and
//!   SEC-5).
//! - Sanitisation causes collisions. `a?b` and `a*b` both become `a_b`, and
//!   `CON` and `_CON` both become `_CON`. A `SafeName` does not authorise
//!   overwriting anything.
//! - Percent sequences are literal. `%2F` stays text and is never decoded.
//! - The reserved names follow Microsoft's naming documentation, plus `COM0`,
//!   `LPT0`, `CONIN$` and `CONOUT$` as portable caution. `COM⁴` (U+2074) is not
//!   reserved.
//!
//! ## Steps
//!
//! The input is decoded lossily and then run through a pass until it stops
//! changing, at most [`MAX_PASSES`] times. Each step can invalidate another:
//! removing a character can join a composable pair, NFC can produce ASCII
//! (U+212A becomes `K`, U+037E becomes `;`), and truncation can expose a trailing
//! dot. A pass:
//!
//! 1. normalises to NFC;
//! 2. keeps the text after the last `/` or `\`;
//! 3. removes control, invisible and bidirectional-control characters;
//! 4. replaces `< > : " | ? *` and look-alike separators with `_`;
//! 5. strips leading `.`, space and `-`, and trailing `.` and space;
//! 6. prefixes `_` to a Windows reserved stem;
//! 7. refuses the reserved suffixes `.xdccpart`, `.xdccmeta` and `.xdccmeta.tmp`;
//! 8. truncates to [`MAX_OUTPUT`] bytes, keeping an extension of up to
//!    [`MAX_EXTENSION`] bytes.
//!
//! A result is accepted only if one more pass leaves it unchanged and a separate
//! predicate, which shares no transformation code, agrees that it is valid.
//!
//! # Offer rate limiting
//!
//! The limiter uses GCRA (a virtual-scheduling leaky bucket) over integer
//! milliseconds. The caller passes the time as a [`Duration`](std::time::Duration) since an origin of
//! its choosing, so nothing here reads a clock.
//!
//! ## What the rate means
//!
//! "5 per minute" is a sustained rate with a burst of 5, not a hard cap. The
//! emission interval is `ceil(window / burst)`, so the default admits 5 offers
//! at once and then one every 12 s. In any half-open window of one `window`
//! length a key can be allowed at most `2 * burst - 1` offers (9 by default):
//! 5 at the start, then 4 more as the budget refills. A hard cap would need a
//! timestamp log per key.
//!
//! ## Memory
//!
//! All memory is allocated by [`OfferRateLimiter::new`]. The table never grows,
//! and each call costs at most [`MAX_PROBE`] slot visits plus one pass over the
//! nick. A key is stored as a 64-bit fingerprint of its folded bytes, never as
//! the nick. Two nicks whose fingerprints collide share one bucket, which can
//! only limit them more.
//!
//! A slot is reclaimed only when its bucket has fully refilled, so forgetting it
//! gives that key exactly the budget it already had. A flood of new nicks
//! therefore cannot reset an attacker's budget. A key with no free slot in its
//! probe window shares one overflow bucket with the same parameters.
//!
//! A key that claims a new slot starts from the shared bucket's state. So a key
//! that spent the shared budget cannot take a fresh slot and exceed the window
//! maximum. A refusal for that reason reports [`RateDecision::LimitedShared`].
//!
//! ## Floods
//!
//! About `tracked_keys` distinct nicks within one emission interval fill the
//! table, and enough further new nicks drain the shared bucket. A new nick is
//! then refused ([`RateDecision::LimitedShared`]) for up to one window. A bot a
//! user requested is usually a new nick, so a flood can delay a real transfer
//! by that long. Tracked keys are unaffected.
//!
//! The limiter retains a 64-bit fingerprint of every nick it is asked about,
//! matched or not, so `SECURITY.md` §10 no longer says that nothing is
//! retained for unmatched offers. The engine should consult the limiter only
//! after it has matched an offer to a request, so unrequested offers never
//! occupy a slot.
//!
//! ## Time
//!
//! Time that runs backwards is clamped to the highest time seen, so it neither
//! refills nor panics. A forward jump refills normally. Times above about
//! 2.9e8 years are clamped, which keeps every sum free of saturation.
//!
//! ## Casemapping changes
//!
//! A key's fingerprint depends on the active [`CaseMapping`](crate::proto::CaseMapping). After
//! [`OfferRateLimiter::set_casemapping`] the old fingerprints cannot be
//! recomputed, but a nick without a byte that folds differently keeps its
//! fingerprint. Nicks with such a byte, tracked or new, have no spare budget
//! until every bucket that existed at the change has refilled. This applies to
//! tracked nicks too, so switching a mapping back cannot recover a spent budget.
//!
//! # Resource limits
//!
//! [`Limits`] only validates and carries numbers. Policy enforces none of the
//! transfer limits; each belongs to the layer that owns the resource.
//!
//! | Limit | Default | Enforced by |
//! |---|---|---|
//! | Filename input | 512 bytes (fixed) | [`SafeName`], in this milestone |
//! | Inbound line | `MAX_LINE_LEN` (fixed) | `proto::LineFramer`, in this milestone |
//! | Offers per window, offer window, tracked keys | 5, 60 s, 1024 | [`OfferRateLimiter`], in this milestone |
//! | Concurrent transfers, per-bot transfers | 4, 1 | `engine` |
//! | Max file size | 64 GiB | `engine` and `store` |
//! | Read buffer | 256 KiB | `net` |
//! | Event ring, transfer mailbox | 256, 64 | `engine` |
//! | Storage job queue | 8 | `store` |
//! | IRC inbound and outbound channels | 256, 64 | `link` |
//! | Finished outcomes retained | 1024 | `engine` |
//! | Reconciliation attempts | 8 | `engine` |
//! | Bot notice retained | 512 bytes | `engine` |
//!
//! The layers after `policy` do not exist yet, so those rows are the intended
//! owners, not enforcement.

mod limits;
mod name;
mod net;
mod rate;

pub use limits::{
    FILENAME_INPUT_LEN, INBOUND_LINE_LEN, Limits, LimitsConfig, LimitsError, MAX_BOT_NOTICE_BYTES,
    MAX_CAPACITY, MAX_CONCURRENT_TRANSFERS, MAX_READ_BUFFER, MAX_TOTAL_BYTES,
};
pub use name::{MAX_EXTENSION, MAX_INPUT, MAX_OUTPUT, MAX_PASSES, NameRefusal, SafeName};
pub use net::{
    ApprovedAddr, IpPrefix, MAX_RULES, NetClass, NetPolicy, NetPolicyConfig, NetPolicyError,
    NetRefusal, PrefixError,
};
pub use rate::{
    MAX_BURST, MAX_NICK_LEN, MAX_PROBE, MAX_TRACKED_KEYS, MAX_WINDOW, OfferRateLimiter, RateConfig,
    RateConfigError, RateDecision,
};
