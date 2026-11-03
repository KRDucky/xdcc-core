//! Destination policy for DCC peers.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU16;

/// The most rules in either list.
pub const MAX_RULES: usize = 256;

/// Ports below this need `allow_low_ports`.
const FIRST_UNPRIVILEGED_PORT: u16 = 1024;

/// The family-independent form of an address: `(is_ipv6, bits)`.
type Bits = (bool, u128);

const fn width(wide: bool) -> u32 {
    if wide { 128 } else { 32 }
}

/// The low bits that a prefix of `len` leaves free.
fn host_mask(wide: bool, len: u8) -> u128 {
    let shift = 128 - width(wide) + u32::from(len);
    u128::MAX.checked_shr(shift).unwrap_or(0)
}

fn in_prefix(base: u128, len: u8, wide: bool, value: u128) -> bool {
    (base ^ value) & !host_mask(wide, len) == 0
}

fn split(addr: IpAddr) -> Bits {
    match addr {
        IpAddr::V4(v4) => (false, u128::from(u32::from(v4))),
        IpAddr::V6(v6) => (true, u128::from(v6)),
    }
}

/// The kind of destination a range describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NetClass {
    /// `0.0.0.0/8` and `::/128`.
    Unspecified,
    /// `224.0.0.0/4` and `ff00::/8`.
    Multicast,
    /// `240.0.0.0/4`, which includes the broadcast address.
    Reserved,
    /// `127.0.0.0/8` and `::1/128`.
    Loopback,
    /// Private, unique-local and carrier-grade NAT ranges.
    Private,
    /// IPv4 and IPv6 link-local ranges, and deprecated site-local.
    LinkLocal,
    /// Cloud metadata hosts. Best-effort, not exhaustive.
    Metadata,
    /// Special-use, benchmarking and documentation ranges.
    SpecialUse,
    /// Ranges that translate or tunnel IPv4.
    Transition,
}

impl NetClass {
    /// A short fixed name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Multicast => "multicast",
            Self::Reserved => "reserved",
            Self::Loopback => "loopback",
            Self::Private => "private",
            Self::LinkLocal => "link-local",
            Self::Metadata => "metadata",
            Self::SpecialUse => "special-use",
            Self::Transition => "transition",
        }
    }
}

/// How a transition range embeds an IPv4 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decode {
    None,
    /// Bits 96 to 127.
    Low32,
    /// Bits 16 to 47 (RFC 3056).
    SixToFour,
    /// Server in bits 32 to 63, client in bits 96 to 127 inverted (RFC 4380).
    Teredo,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    base: u128,
    len: u8,
    class: NetClass,
    /// Refused whatever the configuration says.
    always: bool,
    decode: Decode,
}

const fn v4(a: u8, b: u8, c: u8, d: u8, len: u8, class: NetClass) -> Entry {
    Entry {
        base: u32::from_be_bytes([a, b, c, d]) as u128,
        len,
        class,
        always: false,
        decode: Decode::None,
    }
}

const fn v4_always(a: u8, len: u8, class: NetClass) -> Entry {
    Entry {
        base: u32::from_be_bytes([a, 0, 0, 0]) as u128,
        len,
        class,
        always: true,
        decode: Decode::None,
    }
}

const fn v6(segments: [u16; 8], len: u8, class: NetClass) -> Entry {
    v6_with(segments, len, class, false, Decode::None)
}

const fn v6_with(
    segments: [u16; 8],
    len: u8,
    class: NetClass,
    always: bool,
    decode: Decode,
) -> Entry {
    let mut base = 0u128;
    let mut index = 0;
    while index < 8 {
        base = (base << 16) | segments[index] as u128;
        index += 1;
    }
    Entry {
        base,
        len,
        class,
        always,
        decode,
    }
}

const fn v6_transition(segments: [u16; 8], len: u8, decode: Decode) -> Entry {
    v6_with(segments, len, NetClass::Transition, false, decode)
}

use NetClass::{LinkLocal, Loopback, Metadata, Private, SpecialUse};

static BUILTIN_V4: [Entry; 17] = [
    v4_always(0, 8, NetClass::Unspecified),
    v4_always(224, 4, NetClass::Multicast),
    v4_always(240, 4, NetClass::Reserved),
    v4(127, 0, 0, 0, 8, Loopback),
    v4(10, 0, 0, 0, 8, Private),
    v4(172, 16, 0, 0, 12, Private),
    v4(192, 168, 0, 0, 16, Private),
    v4(100, 64, 0, 0, 10, Private),
    v4(169, 254, 0, 0, 16, LinkLocal),
    v4(169, 254, 169, 254, 32, Metadata),
    v4(100, 100, 100, 200, 32, Metadata),
    v4(192, 0, 0, 0, 24, SpecialUse),
    v4(192, 0, 2, 0, 24, SpecialUse),
    v4(198, 18, 0, 0, 15, SpecialUse),
    v4(198, 51, 100, 0, 24, SpecialUse),
    v4(203, 0, 113, 0, 24, SpecialUse),
    v4(192, 88, 99, 0, 24, SpecialUse),
];

static BUILTIN_V6: [Entry; 20] = [
    v6_with([0; 8], 128, NetClass::Unspecified, true, Decode::None),
    v6_with(
        [0xff00, 0, 0, 0, 0, 0, 0, 0],
        8,
        NetClass::Multicast,
        true,
        Decode::None,
    ),
    v6([0, 0, 0, 0, 0, 0, 0, 1], 128, Loopback),
    v6([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7, Private),
    v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10, LinkLocal),
    v6([0xfec0, 0, 0, 0, 0, 0, 0, 0], 10, LinkLocal),
    v6([0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254], 128, Metadata),
    v6([0xfd20, 0x00ce, 0, 0, 0, 0, 0, 0x0254], 128, Metadata),
    v6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 0], 32, SpecialUse),
    v6([0x0100, 0, 0, 0, 0, 0, 0, 0], 64, SpecialUse),
    v6([0x0100, 0, 0, 1, 0, 0, 0, 0], 64, SpecialUse),
    v6([0x2001, 0, 0, 0, 0, 0, 0, 0], 23, SpecialUse),
    v6([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20, SpecialUse),
    v6([0x5f00, 0, 0, 0, 0, 0, 0, 0], 16, SpecialUse),
    v6_transition([0x0064, 0xff9b, 0, 0, 0, 0, 0, 0], 96, Decode::Low32),
    v6_transition([0x0064, 0xff9b, 1, 0, 0, 0, 0, 0], 48, Decode::None),
    v6_transition([0x2002, 0, 0, 0, 0, 0, 0, 0], 16, Decode::SixToFour),
    v6_transition([0; 8], 96, Decode::Low32),
    // IPv4-translated (SIIT), `::ffff:0:a.b.c.d`. This is not the mapped range.
    v6_transition([0, 0, 0, 0, 0xffff, 0, 0, 0], 96, Decode::Low32),
    v6_transition([0x2001, 0, 0, 0, 0, 0, 0, 0], 32, Decode::Teredo),
];

/// Covers IPv6 outside `2000::/3` that has no narrower entry. IANA assigns no
/// global unicast there, so such an address is never treated as public. This
/// also catches the neighbours of the NAT64 prefixes. Its length is the /3 of
/// the space it complements, so an allow rule must be at least that specific.
static OUTSIDE_GLOBAL_UNICAST: Entry = v6([0; 8], 3, SpecialUse);

/// The most specific built-in entry holding `value`.
fn lookup(wide: bool, value: u128) -> Option<&'static Entry> {
    let table: &'static [Entry] = if wide { &BUILTIN_V6 } else { &BUILTIN_V4 };
    table
        .iter()
        .filter(|entry| in_prefix(entry.base, entry.len, wide, value))
        .max_by_key(|entry| entry.len)
        .or((wide && value >> 125 != 0b001).then_some(&OUTSIDE_GLOBAL_UNICAST))
}

/// Decodes the IPv4 addresses a transition entry embeds in `value`.
fn embedded(entry: &Entry, value: u128) -> [Option<u32>; 2] {
    let low = |shift: u32| u32::try_from((value >> shift) & u128::from(u32::MAX)).ok();
    match entry.decode {
        Decode::None => [None, None],
        Decode::Low32 => [low(0), None],
        Decode::SixToFour => [low(80), None],
        Decode::Teredo => [low(64), low(0).map(|client| !client)],
    }
}

/// Why an [`IpPrefix`] was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrefixError {
    /// The length exceeds the family maximum.
    TooLong,
    /// The address has bits set beyond the prefix length.
    HostBits,
    /// A short IPv6 prefix would contain `::ffff:0:0/96`.
    ///
    /// Addresses are canonicalised first, so such a rule could never match the
    /// mapped addresses it appears to cover.
    StraddlesMapped,
}

impl fmt::Display for PrefixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLong => "prefix length exceeds the address size",
            Self::HostBits => "address has bits set beyond the prefix",
            Self::StraddlesMapped => "IPv6 prefix contains the IPv4-mapped range",
        })
    }
}

impl std::error::Error for PrefixError {}

/// An address prefix such as `10.0.0.0/8`.
///
/// An IPv6 prefix of at least 96 bits inside `::ffff:0:0/96` becomes the IPv4
/// prefix it stands for, so `::ffff:10.0.0.0/104` equals `10.0.0.0/8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpPrefix {
    wide: bool,
    bits: u128,
    len: u8,
}

/// `::ffff:0:0` as a number.
const MAPPED: u128 = 0xffff << 32;

impl IpPrefix {
    /// Builds a prefix, refusing a length over the family maximum and any host
    /// bits.
    pub fn new(addr: IpAddr, len: u8) -> Result<Self, PrefixError> {
        let (wide, bits) = split(addr);
        if u32::from(len) > width(wide) {
            return Err(PrefixError::TooLong);
        }
        if bits & host_mask(wide, len) != 0 {
            return Err(PrefixError::HostBits);
        }
        if wide {
            if len >= 96 && bits >> 32 == 0xffff {
                return Ok(Self {
                    wide: false,
                    bits: bits & u128::from(u32::MAX),
                    len: len - 96,
                });
            }
            if len < 96 && in_prefix(bits, len, true, MAPPED) {
                return Err(PrefixError::StraddlesMapped);
            }
        }
        Ok(Self { wide, bits, len })
    }

    /// The network address, in canonical form.
    pub fn addr(&self) -> IpAddr {
        if self.wide {
            IpAddr::V6(Ipv6Addr::from(self.bits))
        } else {
            IpAddr::V4(Ipv4Addr::from(u32::try_from(self.bits).unwrap_or(0)))
        }
    }

    /// The prefix length, in the canonical family.
    pub const fn len(&self) -> u8 {
        self.len
    }

    /// True for a zero-length prefix, which holds every address of its family.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn contains(&self, (wide, value): Bits) -> bool {
        self.wide == wide && in_prefix(self.bits, self.len, wide, value)
    }
}

/// The configuration of a [`NetPolicy`].
///
/// The type is `non_exhaustive`: start from [`Default`] and assign fields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct NetPolicyConfig {
    /// Clears the private class, and nothing else.
    pub allow_private_destinations: bool,
    /// Permits ports 1 to 1023.
    pub allow_low_ports: bool,
    /// Always refused, and always beats `allow`.
    pub deny: Vec<IpPrefix>,
    /// Clears a built-in range if the rule is at least as long as the range.
    pub allow: Vec<IpPrefix>,
}

/// Why a [`NetPolicyConfig`] was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetPolicyError {
    /// More than [`MAX_RULES`] deny rules.
    TooManyDenyRules,
    /// More than [`MAX_RULES`] allow rules.
    TooManyAllowRules,
}

impl fmt::Display for NetPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooManyDenyRules => "too many deny rules",
            Self::TooManyAllowRules => "too many allow rules",
        })
    }
}

impl std::error::Error for NetPolicyError {}

/// Why a destination was refused. It holds no data from the offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetRefusal {
    /// The port is 0.
    PortZero,
    /// The port is below 1024 and low ports are not allowed.
    LowPort,
    /// A range no setting can open.
    Always {
        /// The range's class.
        class: NetClass,
        /// True if the address was decoded from a transition address.
        embedded: bool,
    },
    /// An explicit deny rule matched.
    Denied {
        /// True if the address was decoded from a transition address.
        embedded: bool,
    },
    /// A built-in range matched and nothing cleared it.
    Range {
        /// The range's class.
        class: NetClass,
        /// True if the address was decoded from a transition address.
        embedded: bool,
    },
}

impl fmt::Display for NetRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (what, class, embedded) = match *self {
            Self::PortZero => return f.write_str("port 0"),
            Self::LowPort => return f.write_str("port below 1024"),
            Self::Always { class, embedded } => ("never-allowed", Some(class), embedded),
            Self::Denied { embedded } => ("denied by rule", None, embedded),
            Self::Range { class, embedded } => ("blocked", Some(class), embedded),
        };
        let place = if embedded {
            "embedded address"
        } else {
            "address"
        };
        match class {
            Some(class) => write!(f, "{place} {what} ({})", class.as_str()),
            None => write!(f, "{place} {what}"),
        }
    }
}

impl std::error::Error for NetRefusal {}

/// A destination that passed [`NetPolicy::check`].
///
/// This is a decision about one endpoint at one moment. It does not
/// authenticate the peer, and the future `net` layer must call `check` again
/// immediately before connecting. Only `check` builds one: it has private
/// fields and no `Clone`, `Copy`, `Default`, `From`, `FromStr` or `Deserialize`.
/// Parsing an offer never produces one.
///
/// ```
/// use std::net::{IpAddr, Ipv4Addr};
/// use xdcc_core::policy::{NetPolicy, NetPolicyConfig};
///
/// let policy = NetPolicy::new(NetPolicyConfig::default())?;
/// let ok = policy.check(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 6000)?;
/// assert_eq!(ok.port(), 6000);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// It cannot be built by hand:
///
/// ```compile_fail,E0451
/// use std::net::{IpAddr, Ipv4Addr};
/// use std::num::NonZeroU16;
/// use xdcc_core::policy::ApprovedAddr;
///
/// let _ = ApprovedAddr {
///     ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
///     port: NonZeroU16::MIN,
/// };
/// ```
///
/// It cannot be cloned:
///
/// ```compile_fail,E0599
/// use std::net::{IpAddr, Ipv4Addr};
/// use xdcc_core::policy::{NetPolicy, NetPolicyConfig};
///
/// let policy = NetPolicy::new(NetPolicyConfig::default())?;
/// let ok = policy.check(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 6000)?;
/// let _copy = ok.clone();
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// It has no default:
///
/// ```compile_fail,E0599
/// let _ = xdcc_core::policy::ApprovedAddr::default();
/// ```
///
/// It cannot be converted from a socket address:
///
/// ```compile_fail,E0277
/// use std::net::SocketAddr;
/// use xdcc_core::policy::ApprovedAddr;
///
/// let addr: SocketAddr = "8.8.8.8:6000".parse().unwrap();
/// let _: ApprovedAddr = addr.into();
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct ApprovedAddr {
    ip: IpAddr,
    port: NonZeroU16,
}

impl ApprovedAddr {
    /// The canonical address.
    pub const fn ip(&self) -> IpAddr {
        self.ip
    }

    /// The port, which is never 0.
    pub const fn port(&self) -> u16 {
        self.port.get()
    }

    /// The address and port together.
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port.get())
    }
}

/// A validated destination policy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetPolicy {
    config: NetPolicyConfig,
}

impl NetPolicy {
    /// Validates a configuration.
    pub fn new(config: NetPolicyConfig) -> Result<Self, NetPolicyError> {
        if config.deny.len() > MAX_RULES {
            return Err(NetPolicyError::TooManyDenyRules);
        }
        if config.allow.len() > MAX_RULES {
            return Err(NetPolicyError::TooManyAllowRules);
        }
        Ok(Self { config })
    }

    /// Decides whether `addr:port` may be connected to.
    ///
    /// The order of the checks is described in the [`policy` documentation](crate::policy).
    /// This allocates nothing.
    pub fn check(&self, addr: IpAddr, port: u16) -> Result<ApprovedAddr, NetRefusal> {
        let addr = addr.to_canonical();
        let port = NonZeroU16::new(port).ok_or(NetRefusal::PortZero)?;
        if port.get() < FIRST_UNPRIVILEGED_PORT && !self.config.allow_low_ports {
            return Err(NetRefusal::LowPort);
        }

        let main = split(addr);
        let main_entry = lookup(main.0, main.1);
        let decoded = main_entry
            .filter(|entry| !entry.always)
            .map_or([None, None], |entry| embedded(entry, main.1));
        // Candidates: the address, then each decoded address as IPv4.
        let mut candidates: [Option<(Bits, bool)>; 3] = [Some((main, false)), None, None];
        for (slot, value) in candidates[1..].iter_mut().zip(decoded) {
            *slot = value.map(|ip| ((false, u128::from(ip)), true));
        }

        for (bits, via) in candidates.iter().flatten().copied() {
            if let Some(entry) = lookup(bits.0, bits.1).filter(|entry| entry.always) {
                return Err(NetRefusal::Always {
                    class: entry.class,
                    embedded: via,
                });
            }
        }
        for (bits, via) in candidates.iter().flatten().copied() {
            if self.config.deny.iter().any(|rule| rule.contains(bits)) {
                return Err(NetRefusal::Denied { embedded: via });
            }
        }
        for (bits, via) in candidates.iter().flatten().copied() {
            if let Some(entry) = lookup(bits.0, bits.1) {
                if !self.cleared(entry, bits) {
                    return Err(NetRefusal::Range {
                        class: entry.class,
                        embedded: via,
                    });
                }
            }
        }
        Ok(ApprovedAddr { ip: addr, port })
    }

    fn cleared(&self, entry: &Entry, bits: Bits) -> bool {
        if entry.class == Private && self.config.allow_private_destinations {
            return true;
        }
        self.config
            .allow
            .iter()
            .any(|rule| rule.len >= entry.len && rule.contains(bits))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn prefix(text: &str) -> IpPrefix {
        let (addr, len) = text.split_once('/').unwrap();
        IpPrefix::new(ip(addr), len.parse().unwrap()).unwrap()
    }

    fn policy(change: impl FnOnce(&mut NetPolicyConfig)) -> NetPolicy {
        let mut config = NetPolicyConfig::default();
        change(&mut config);
        NetPolicy::new(config).unwrap()
    }

    fn with_allow(rules: &[&str]) -> NetPolicy {
        policy(|c| c.allow = rules.iter().map(|r| prefix(r)).collect())
    }

    fn range(class: NetClass) -> NetRefusal {
        NetRefusal::Range {
            class,
            embedded: false,
        }
    }

    fn via(class: NetClass) -> NetRefusal {
        NetRefusal::Range {
            class,
            embedded: true,
        }
    }

    fn always(class: NetClass) -> NetRefusal {
        NetRefusal::Always {
            class,
            embedded: false,
        }
    }

    fn verdict(policy: &NetPolicy, text: &str) -> Result<IpAddr, NetRefusal> {
        policy.check(ip(text), 6000).map(|ok| ok.ip())
    }

    /// Independent description of every range, as `(cidr, class, always)`.
    const ROWS: &[(&str, NetClass, bool)] = &[
        ("0.0.0.0/8", NetClass::Unspecified, true),
        ("224.0.0.0/4", NetClass::Multicast, true),
        ("240.0.0.0/4", NetClass::Reserved, true),
        ("127.0.0.0/8", Loopback, false),
        ("10.0.0.0/8", Private, false),
        ("172.16.0.0/12", Private, false),
        ("192.168.0.0/16", Private, false),
        ("100.64.0.0/10", Private, false),
        ("169.254.0.0/16", LinkLocal, false),
        ("169.254.169.254/32", Metadata, false),
        ("100.100.100.200/32", Metadata, false),
        ("192.0.0.0/24", SpecialUse, false),
        ("192.0.2.0/24", SpecialUse, false),
        ("198.18.0.0/15", SpecialUse, false),
        ("198.51.100.0/24", SpecialUse, false),
        ("203.0.113.0/24", SpecialUse, false),
        ("192.88.99.0/24", SpecialUse, false),
        ("::/128", NetClass::Unspecified, true),
        ("ff00::/8", NetClass::Multicast, true),
        ("::1/128", Loopback, false),
        ("fc00::/7", Private, false),
        ("fe80::/10", LinkLocal, false),
        ("fec0::/10", LinkLocal, false),
        ("fd00:ec2::254/128", Metadata, false),
        ("fd20:ce::254/128", Metadata, false),
        ("2001:db8::/32", SpecialUse, false),
        ("100::/64", SpecialUse, false),
        ("100:0:0:1::/64", SpecialUse, false),
        ("2001::/23", SpecialUse, false),
        ("3fff::/20", SpecialUse, false),
        ("5f00::/16", SpecialUse, false),
        ("64:ff9b::/96", NetClass::Transition, false),
        ("64:ff9b:1::/48", NetClass::Transition, false),
        ("2002::/16", NetClass::Transition, false),
        ("::/96", NetClass::Transition, false),
        ("::ffff:0:0:0/96", NetClass::Transition, false),
        ("2001::/32", NetClass::Transition, false),
    ];

    fn bounds(cidr: &str) -> (bool, u128, u128, u8) {
        let (addr, len) = cidr.split_once('/').unwrap();
        let (wide, base) = split(ip(addr));
        let len: u8 = len.parse().unwrap();
        let top = base | host_mask(wide, len);
        (wide, base, top, len)
    }

    fn make(wide: bool, value: u128) -> IpAddr {
        if wide {
            IpAddr::V6(Ipv6Addr::from(value))
        } else {
            IpAddr::V4(Ipv4Addr::from(u32::try_from(value).unwrap()))
        }
    }

    /// The row an address belongs to, found by plain range arithmetic.
    fn oracle(wide: bool, value: u128) -> Option<(&'static str, NetClass, bool)> {
        ROWS.iter()
            .copied()
            .filter(|(cidr, _, _)| {
                let (w, base, top, _) = bounds(cidr);
                w == wide && (base..=top).contains(&value)
            })
            .max_by_key(|(cidr, _, _)| bounds(cidr).3)
    }

    /// Allows the outer prefix, denies one IPv4 host, and returns the verdict.
    fn embedded_denied(outer: &str, inner: &str, addr: &str) -> Result<IpAddr, NetRefusal> {
        let policy = policy(|c| {
            c.allow = vec![prefix(outer)];
            c.deny = vec![prefix(&format!("{inner}/32"))];
        });
        verdict(&policy, addr)
    }

    #[test]
    fn only_a_zero_length_prefix_is_empty() {
        assert!(prefix("0.0.0.0/0").is_empty());
        assert!(!prefix("10.0.0.0/8").is_empty());
    }

    /// Worked examples published by the RFCs, not derived from this code.
    #[test]
    fn rfc_examples_decode_to_the_published_ipv4_address() {
        const DENIED: Result<IpAddr, NetRefusal> = Err(NetRefusal::Denied { embedded: true });
        // RFC 6052 §2.4, Table 2.
        let nat64 = ("64:ff9b::/96", "192.0.2.33", "64:ff9b::192.0.2.33");
        // 192.0.2.33 is special-use, so the host needs clearing to reach the rule.
        assert_eq!(embedded_denied(nat64.0, nat64.1, nat64.2), DENIED);
        // RFC 3056 §5.1, the two sites of its example.
        for (inner, addr) in [
            ("192.1.2.3", "2002:c001:0203::1"),
            ("9.254.253.252", "2002:09fe:fdfc::1"),
        ] {
            assert_eq!(embedded_denied("2002::/16", inner, addr), DENIED);
            assert!(embedded_denied("2002::/16", "8.8.8.8", addr).is_ok());
        }
    }

    /// RFC 4380 has no worked address, so this vector comes from CPython's
    /// `ipaddress.IPv6Address.teredo`, a separate implementation.
    #[test]
    fn teredo_matches_an_independent_decoder() {
        const ADDR: &str = "2001:0:4136:e378:8000:63bf:3fff:fdd2";
        const DENIED: Result<IpAddr, NetRefusal> = Err(NetRefusal::Denied { embedded: true });
        assert_eq!(embedded_denied("2001::/32", "65.54.227.120", ADDR), DENIED);
        // The client's documentation address is special-use, so it refuses
        // through the range even without the deny rule.
        assert_eq!(embedded_denied("2001::/32", "192.0.2.45", ADDR), DENIED);
        assert_eq!(
            verdict(&with_allow(&["2001::/32"]), ADDR),
            Err(NetRefusal::Range {
                class: NetClass::SpecialUse,
                embedded: true
            })
        );
        // Without the inversion the client would read 63.255.253.210.
        assert_eq!(
            verdict(&with_allow(&["2001::/32", "192.0.2.45/32"]), ADDR).map(|_| ()),
            Ok(())
        );
        assert_eq!(
            embedded_denied("2001::/32", "63.255.253.210", ADDR),
            Err(NetRefusal::Range {
                class: NetClass::SpecialUse,
                embedded: true
            })
        );
    }

    /// Loopback opens only through a rule at least as narrow as its range, for
    /// exactly the family and range that rule names.
    #[test]
    fn loopback_exceptions_are_exact() {
        let default = NetPolicy::default();
        let private = policy(|c| c.allow_private_destinations = true);
        for text in ["127.0.0.1", "127.255.255.255", "::1", "::ffff:127.0.0.1"] {
            assert_eq!(verdict(&default, text), Err(range(Loopback)), "{text}");
            assert_eq!(verdict(&private, text), Err(range(Loopback)), "{text}");
        }

        let host = with_allow(&["127.0.0.1/32"]);
        assert_eq!(verdict(&host, "127.0.0.1"), Ok(ip("127.0.0.1")));
        assert_eq!(verdict(&host, "::ffff:127.0.0.1"), Ok(ip("127.0.0.1")));
        assert_eq!(verdict(&host, "127.0.0.2"), Err(range(Loopback)));
        assert_eq!(verdict(&host, "::1"), Err(range(Loopback)));

        let mapped_rule = with_allow(&["::ffff:127.0.0.1/128"]);
        assert_eq!(verdict(&mapped_rule, "127.0.0.1"), Ok(ip("127.0.0.1")));

        let six = with_allow(&["::1/128"]);
        assert_eq!(verdict(&six, "::1"), Ok(ip("::1")));
        assert_eq!(verdict(&six, "127.0.0.1"), Err(range(Loopback)));

        for broad in ["0.0.0.0/0", "126.0.0.0/7"] {
            assert_eq!(
                verdict(&with_allow(&[broad]), "127.0.0.1"),
                Err(range(Loopback)),
                "{broad}"
            );
        }
    }

    #[test]
    fn ipv6_outside_global_unicast_is_never_public() {
        let policy = NetPolicy::default();
        for addr in [
            "64:ff9b::1:0:0:1",
            "64:ff9b:0:0:1::",
            "64:ff9c::1",
            "400::1",
            "1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "4000::1",
            "e000::1",
        ] {
            assert_eq!(
                verdict(&policy, addr),
                Err(NetRefusal::Range {
                    class: NetClass::SpecialUse,
                    embedded: false
                }),
                "{addr}"
            );
        }
        for addr in ["2000::1", "3ffe:ffff::1"] {
            assert!(verdict(&policy, addr).is_ok(), "{addr}");
        }
        assert!(verdict(&with_allow(&["4000::/3"]), "4000::1").is_ok());
        assert!(verdict(&with_allow(&["4000::/2"]), "4000::1").is_err());
    }

    #[test]
    fn every_range_refuses_first_and_last_and_spares_its_neighbours() {
        let open = NetPolicy::default();
        for &(cidr, _, _) in ROWS {
            let (wide, base, top, _) = bounds(cidr);
            let max = if wide {
                u128::MAX
            } else {
                u128::from(u32::MAX)
            };
            let mut probes = vec![base, top];
            if base > 0 {
                probes.push(base - 1);
            }
            if top < max {
                probes.push(top + 1);
            }
            for value in probes {
                let got = open.check(make(wide, value), 6000);
                match oracle(wide, value) {
                    None if wide && value >> 125 != 0b001 => assert_eq!(
                        got.unwrap_err(),
                        range(NetClass::SpecialUse),
                        "{cidr}: {} is outside 2000::/3",
                        make(wide, value)
                    ),
                    None => assert!(got.is_ok(), "{cidr}: {} should pass", make(wide, value)),
                    Some((_, class, true)) => assert_eq!(
                        got.unwrap_err(),
                        NetRefusal::Always {
                            class,
                            embedded: false
                        },
                        "{cidr}: {}",
                        make(wide, value)
                    ),
                    Some((_, NetClass::Transition, false)) => {
                        // Decoding may name the embedded address first.
                        assert!(
                            matches!(
                                got,
                                Err(NetRefusal::Range { .. } | NetRefusal::Always { .. })
                            ),
                            "{cidr}: {}",
                            make(wide, value)
                        );
                    }
                    Some((_, class, false)) => assert_eq!(
                        got.unwrap_err(),
                        range(class),
                        "{cidr}: {}",
                        make(wide, value)
                    ),
                }
            }
        }
    }

    #[test]
    fn mapped_forms_agree_with_plain_ipv4_for_every_row() {
        for policy in [NetPolicy::default(), with_allow(&["10.0.0.0/8"])] {
            for &(cidr, _, _) in ROWS {
                let (wide, base, top, _) = bounds(cidr);
                if wide {
                    continue;
                }
                for value in [
                    base,
                    top,
                    base.saturating_sub(1),
                    (top + 1).min(u128::from(u32::MAX)),
                ] {
                    let plain = Ipv4Addr::from(u32::try_from(value).unwrap());
                    let mapped = plain.to_ipv6_mapped();
                    assert_eq!(
                        policy.check(IpAddr::V4(plain), 6000),
                        policy.check(IpAddr::V6(mapped), 6000),
                        "{plain}"
                    );
                }
            }
        }
        assert_eq!(
            verdict(&NetPolicy::default(), "::ffff:127.0.0.1"),
            Err(range(Loopback))
        );
    }

    #[test]
    fn ports_around_the_boundaries() {
        let strict = NetPolicy::default();
        let ip4 = ip("8.8.8.8");
        assert_eq!(strict.check(ip4, 0), Err(NetRefusal::PortZero));
        assert_eq!(strict.check(ip4, 1), Err(NetRefusal::LowPort));
        assert_eq!(strict.check(ip4, 1023), Err(NetRefusal::LowPort));
        assert_eq!(strict.check(ip4, 1024).unwrap().port(), 1024);
        assert_eq!(strict.check(ip4, 65535).unwrap().port(), 65535);
        let low = policy(|c| c.allow_low_ports = true);
        assert_eq!(low.check(ip4, 0), Err(NetRefusal::PortZero));
        assert_eq!(low.check(ip4, 1).unwrap().port(), 1);
        assert_eq!(low.check(ip4, 1023).unwrap().port(), 1023);
    }

    #[test]
    fn the_port_is_checked_before_the_address() {
        assert_eq!(
            NetPolicy::default().check(ip("127.0.0.1"), 0),
            Err(NetRefusal::PortZero)
        );
        assert_eq!(
            NetPolicy::default().check(ip("127.0.0.1"), 80),
            Err(NetRefusal::LowPort)
        );
    }

    #[test]
    fn approved_addresses_are_canonical_and_expose_a_socket_address() {
        let ok = NetPolicy::default()
            .check(ip("::ffff:8.8.8.8"), 6000)
            .unwrap();
        assert_eq!(ok.ip(), ip("8.8.8.8"));
        assert_eq!(ok.socket_addr(), "8.8.8.8:6000".parse().unwrap());
        let v6 = NetPolicy::default()
            .check(ip("2606:4700::1111"), 6000)
            .unwrap();
        assert_eq!(v6.socket_addr(), "[2606:4700::1111]:6000".parse().unwrap());
    }

    #[test]
    fn deny_beats_allow_and_matches_the_canonical_form() {
        let policy = policy(|c| {
            c.allow = vec![prefix("10.0.0.0/8"), prefix("8.8.8.0/24")];
            c.deny = vec![prefix("10.0.0.5/32"), prefix("8.8.8.8/32")];
        });
        assert_eq!(
            verdict(&policy, "10.0.0.5"),
            Err(NetRefusal::Denied { embedded: false })
        );
        assert!(verdict(&policy, "10.0.0.6").is_ok());
        assert_eq!(
            verdict(&policy, "::ffff:8.8.8.8"),
            Err(NetRefusal::Denied { embedded: false })
        );
        assert!(verdict(&policy, "8.8.8.9").is_ok());
    }

    #[test]
    fn broad_allow_clears_nothing_and_exact_allow_clears_its_range() {
        let broad = with_allow(&["0.0.0.0/0", "2000::/3"]);
        assert_eq!(verdict(&broad, "10.0.0.5"), Err(range(Private)));
        assert_eq!(verdict(&broad, "127.0.0.1"), Err(range(Loopback)));
        assert_eq!(verdict(&broad, "169.254.169.254"), Err(range(Metadata)));
        assert_eq!(verdict(&broad, "2001:db8::1"), Err(range(SpecialUse)));
        assert!(verdict(&broad, "8.8.8.8").is_ok());

        let short = with_allow(&["8.0.0.0/5"]);
        assert_eq!(verdict(&short, "10.0.0.5"), Err(range(Private)));

        let exact = with_allow(&["10.0.0.0/8"]);
        assert!(verdict(&exact, "10.255.255.255").is_ok());
        assert_eq!(verdict(&exact, "11.0.0.0"), Ok(ip("11.0.0.0")));
        assert_eq!(verdict(&exact, "172.16.0.1"), Err(range(Private)));

        let host = with_allow(&["127.0.0.1/32"]);
        assert!(verdict(&host, "127.0.0.1").is_ok());
        assert_eq!(verdict(&host, "127.0.0.2"), Err(range(Loopback)));
        // Any rule at least as long as the range works.
        assert!(verdict(&with_allow(&["127.0.0.0/8"]), "127.9.9.9").is_ok());
        assert!(verdict(&with_allow(&["127.1.0.0/16"]), "127.1.9.9").is_ok());
    }

    #[test]
    fn metadata_needs_its_exact_host() {
        let private = policy(|c| c.allow_private_destinations = true);
        assert_eq!(verdict(&private, "169.254.169.254"), Err(range(Metadata)));
        assert_eq!(verdict(&private, "100.100.100.200"), Err(range(Metadata)));
        assert_eq!(verdict(&private, "fd00:ec2::254"), Err(range(Metadata)));
        assert_eq!(verdict(&private, "fd20:ce::254"), Err(range(Metadata)));
        assert!(verdict(&private, "100.100.100.201").is_ok());
        assert!(verdict(&private, "fd00:ec2::255").is_ok());

        for (rule, host) in [
            ("169.254.0.0/16", "169.254.169.254"),
            ("100.64.0.0/10", "100.100.100.200"),
            ("fc00::/7", "fd00:ec2::254"),
        ] {
            assert_eq!(
                verdict(&with_allow(&[rule]), host),
                Err(range(Metadata)),
                "{rule}"
            );
        }
        for host in [
            "169.254.169.254",
            "100.100.100.200",
            "fd00:ec2::254",
            "fd20:ce::254",
        ] {
            let exact = with_allow(&[&format!(
                "{host}/{}",
                if host.contains(':') { 128 } else { 32 }
            )]);
            assert_eq!(verdict(&exact, host), Ok(ip(host)), "{host}");
        }
    }

    #[test]
    fn allow_private_destinations_relaxes_only_the_private_class() {
        let relaxed = policy(|c| c.allow_private_destinations = true);
        for open in [
            "10.1.1.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "100.64.0.1",
            "fc00::1",
            "fdff::1",
        ] {
            assert!(verdict(&relaxed, open).is_ok(), "{open}");
        }
        let cases = [
            ("127.0.0.1", range(Loopback)),
            ("::1", range(Loopback)),
            ("169.254.1.1", range(LinkLocal)),
            ("fe80::1", range(LinkLocal)),
            ("fec0::1", range(LinkLocal)),
            ("192.0.2.1", range(SpecialUse)),
            ("198.18.0.1", range(SpecialUse)),
            ("224.0.0.1", always(NetClass::Multicast)),
            ("239.255.255.255", always(NetClass::Multicast)),
            ("ff02::1", always(NetClass::Multicast)),
            ("0.0.0.0", always(NetClass::Unspecified)),
            ("0.1.2.3", always(NetClass::Unspecified)),
            ("::", always(NetClass::Unspecified)),
            ("240.0.0.1", always(NetClass::Reserved)),
            ("255.255.255.255", always(NetClass::Reserved)),
            ("64:ff9b::808:808", range(NetClass::Transition)),
            ("2002:808:808::", range(NetClass::Transition)),
        ];
        for (host, expected) in cases {
            assert_eq!(verdict(&relaxed, host), Err(expected), "{host}");
        }
    }

    #[test]
    fn the_never_tier_ignores_every_setting() {
        let everything = policy(|c| {
            c.allow_private_destinations = true;
            c.allow_low_ports = true;
            c.allow = [
                "0.0.0.0/8",
                "224.0.0.0/4",
                "240.0.0.0/4",
                "ff00::/8",
                "::/128",
                "255.255.255.255/32",
            ]
            .iter()
            .map(|r| prefix(r))
            .collect();
        });
        for host in [
            "0.0.0.0",
            "0.255.255.255",
            "224.0.0.1",
            "255.255.255.255",
            "ff02::1",
            "::",
        ] {
            assert!(
                matches!(verdict(&everything, host), Err(NetRefusal::Always { .. })),
                "{host}"
            );
        }
    }

    #[test]
    fn loopback_is_reachable_only_through_an_explicit_allow_rule() {
        assert_eq!(verdict(&NetPolicy::default(), "::1"), Err(range(Loopback)));
        let allowed = with_allow(&["::1/128"]);
        assert_eq!(
            allowed.check(ip("::1"), 1024).unwrap().socket_addr(),
            "[::1]:1024".parse().unwrap()
        );
        assert_eq!(
            NetPolicy::default().check(ip("::1"), 1024),
            Err(range(Loopback))
        );
        assert!(verdict(&allowed, "127.0.0.1").is_err());
    }

    #[test]
    fn explicit_deny_beats_the_never_free_ranges_too() {
        let policy = policy(|c| {
            c.allow = vec![prefix("127.0.0.1/32")];
            c.deny = vec![prefix("127.0.0.0/8")];
        });
        assert_eq!(
            verdict(&policy, "127.0.0.1"),
            Err(NetRefusal::Denied { embedded: false })
        );
    }

    #[test]
    fn rule_canonicalisation_makes_mapped_rules_equal_ipv4_rules() {
        let mapped = IpPrefix::new(ip("::ffff:10.0.0.0"), 104).unwrap();
        assert_eq!(mapped, prefix("10.0.0.0/8"));
        assert_eq!(mapped.addr(), ip("10.0.0.0"));
        assert_eq!(mapped.len(), 8);
        assert_eq!(
            IpPrefix::new(ip("::ffff:0:0"), 96).unwrap(),
            prefix("0.0.0.0/0")
        );
        let allow = with_allow(&["::ffff:10.0.0.0/104"]);
        assert!(verdict(&allow, "10.9.9.9").is_ok());
        assert!(verdict(&allow, "::ffff:10.9.9.9").is_ok());
        let deny = policy_deny(&["::ffff:8.8.8.0/120"]);
        assert!(verdict(&deny, "8.8.8.8").is_err());
        assert!(verdict(&deny, "::ffff:8.8.8.200").is_err());
        assert!(verdict(&deny, "8.8.9.1").is_ok());
    }

    fn policy_deny(rules: &[&str]) -> NetPolicy {
        policy(|c| c.deny = rules.iter().map(|r| prefix(r)).collect())
    }

    #[test]
    fn prefix_errors() {
        assert_eq!(IpPrefix::new(ip("10.0.0.0"), 33), Err(PrefixError::TooLong));
        assert_eq!(IpPrefix::new(ip("::"), 129), Err(PrefixError::TooLong));
        assert_eq!(IpPrefix::new(ip("10.0.0.1"), 8), Err(PrefixError::HostBits));
        assert_eq!(IpPrefix::new(ip("fc00::1"), 7), Err(PrefixError::HostBits));
        assert!(IpPrefix::new(ip("10.0.0.1"), 32).is_ok());
        assert!(IpPrefix::new(ip("0.0.0.0"), 0).is_ok());
        assert!(IpPrefix::new(ip("::"), 128).is_ok());
        for text in ["::/0", "::/80", "::fffe:0:0/95", "::/1", "8000::/1"] {
            let (addr, len) = text.split_once('/').unwrap();
            let got = IpPrefix::new(ip(addr), len.parse().unwrap());
            if text == "8000::/1" {
                assert!(got.is_ok(), "{text}");
            } else {
                assert_eq!(got, Err(PrefixError::StraddlesMapped), "{text}");
            }
        }
        // Prefixes that stop just short of the mapped range are ordinary.
        assert!(IpPrefix::new(ip("::"), 81).is_ok());
        assert!(IpPrefix::new(ip("::ffff:0:0"), 96).is_ok());
        assert!(IpPrefix::new(ip("::ffff:0:0"), 128).is_ok());
    }

    #[test]
    fn rule_lists_are_bounded() {
        let rule = prefix("8.8.8.8/32");
        let at_limit = |c: &mut NetPolicyConfig| {
            c.deny = vec![rule; MAX_RULES];
            c.allow = vec![rule; MAX_RULES];
        };
        let mut config = NetPolicyConfig::default();
        at_limit(&mut config);
        assert!(NetPolicy::new(config.clone()).is_ok());
        config.deny.push(rule);
        assert_eq!(
            NetPolicy::new(config.clone()),
            Err(NetPolicyError::TooManyDenyRules)
        );
        config.deny.pop();
        config.allow.push(rule);
        assert_eq!(
            NetPolicy::new(config),
            Err(NetPolicyError::TooManyAllowRules)
        );
    }

    #[test]
    fn nat64_is_denied_whole_and_its_embedded_address_adds_refusals() {
        let open = NetPolicy::default();
        assert_eq!(
            verdict(&open, "64:ff9b::808:808"),
            Err(range(NetClass::Transition))
        );
        assert_eq!(
            verdict(&open, "64:ff9b::7f00:1"),
            Err(range(NetClass::Transition))
        );

        let outer = with_allow(&["64:ff9b::/96"]);
        assert!(verdict(&outer, "64:ff9b::808:808").is_ok());
        assert_eq!(verdict(&outer, "64:ff9b::7f00:1"), Err(via(Loopback)));
        assert_eq!(verdict(&outer, "64:ff9b::a9fe:a9fe"), Err(via(Metadata)));
        assert_eq!(verdict(&outer, "64:ff9b::a00:1"), Err(via(Private)));
        assert_eq!(
            verdict(&outer, "64:ff9b::e000:1"),
            Err(NetRefusal::Always {
                class: NetClass::Multicast,
                embedded: true
            })
        );
        assert_eq!(
            verdict(&outer, "64:ff9b::"),
            Err(NetRefusal::Always {
                class: NetClass::Unspecified,
                embedded: true
            })
        );

        let both = with_allow(&["64:ff9b::/96", "127.0.0.1/32"]);
        assert!(verdict(&both, "64:ff9b::7f00:1").is_ok());

        let relaxed = policy(|c| {
            c.allow = vec![prefix("64:ff9b::/96")];
            c.allow_private_destinations = true;
        });
        assert!(verdict(&relaxed, "64:ff9b::a00:1").is_ok());

        let denied = policy(|c| {
            c.allow = vec![prefix("64:ff9b::/96")];
            c.deny = vec![prefix("8.8.8.8/32")];
        });
        assert_eq!(
            verdict(&denied, "64:ff9b::808:808"),
            Err(NetRefusal::Denied { embedded: true })
        );
    }

    #[test]
    fn local_use_nat64_prefix_is_not_decoded() {
        let open = NetPolicy::default();
        for host in [
            "64:ff9b:1::1",
            "64:ff9b:1::7f00:1",
            "64:ff9b:1:ffff:ffff:ffff:ffff:ffff",
        ] {
            assert_eq!(
                verdict(&open, host),
                Err(range(NetClass::Transition)),
                "{host}"
            );
        }
        let outer = with_allow(&["64:ff9b:1::/48"]);
        assert!(verdict(&outer, "64:ff9b:1::7f00:1").is_ok());
        // The /96 rule is too short to clear a /48 range's longer neighbours.
        assert_eq!(
            verdict(&with_allow(&["64:ff9b::/96"]), "64:ff9b:1::1"),
            Err(range(NetClass::Transition))
        );
    }

    #[test]
    fn six_to_four_decodes_bits_16_to_47() {
        let open = NetPolicy::default();
        assert_eq!(
            verdict(&open, "2002:808:808::"),
            Err(range(NetClass::Transition))
        );
        let outer = with_allow(&["2002::/16"]);
        assert!(verdict(&outer, "2002:808:808::1").is_ok());
        assert_eq!(verdict(&outer, "2002:7f00:1::"), Err(via(Loopback)));
        assert_eq!(verdict(&outer, "2002:7f00:1:ffff::1"), Err(via(Loopback)));
        assert_eq!(verdict(&outer, "2002:a9fe:a9fe::"), Err(via(Metadata)));
        assert_eq!(verdict(&outer, "2002:c0a8:101::"), Err(via(Private)));
        // Bits outside 16 to 47 are not part of the embedded address.
        assert!(verdict(&outer, "2002:808:808:7f00:1::").is_ok());
        let both = with_allow(&["2002::/16", "127.0.0.0/8"]);
        assert!(verdict(&both, "2002:7f00:1::").is_ok());
    }

    #[test]
    fn ipv4_compatible_addresses_decode_their_low_bits() {
        let open = NetPolicy::default();
        assert_eq!(verdict(&open, "::7f00:1"), Err(range(NetClass::Transition)));
        assert_eq!(
            verdict(&open, "::808:808"),
            Err(range(NetClass::Transition))
        );
        // `::` and `::1` are more specific than `::/96`, and decode nothing.
        assert_eq!(verdict(&open, "::"), Err(always(NetClass::Unspecified)));
        assert_eq!(verdict(&open, "::1"), Err(range(Loopback)));
        let outer = with_allow(&["::/96"]);
        assert!(verdict(&outer, "::808:808").is_ok());
        assert_eq!(verdict(&outer, "::7f00:1"), Err(via(Loopback)));
        assert_eq!(verdict(&outer, "::a9fe:a9fe"), Err(via(Metadata)));
        assert_eq!(verdict(&outer, "::"), Err(always(NetClass::Unspecified)));
        assert_eq!(verdict(&outer, "::1"), Err(range(Loopback)));
        // 0.0.0.5 is in the never tier.
        assert_eq!(
            verdict(&outer, "::5"),
            Err(NetRefusal::Always {
                class: NetClass::Unspecified,
                embedded: true
            })
        );
    }

    #[test]
    fn siit_is_distinct_from_the_mapped_range() {
        assert_eq!(
            ip("::ffff:0:808:808"),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0xffff, 0, 0x0808, 0x0808))
        );
        let open = NetPolicy::default();
        assert_eq!(
            verdict(&open, "::ffff:0:808:808"),
            Err(range(NetClass::Transition))
        );
        let prefix_siit =
            IpPrefix::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0xffff, 0, 0, 0)), 96).unwrap();
        let allowed = policy(|c| c.allow = vec![prefix_siit]);
        assert!(verdict(&allowed, "::ffff:0:808:808").is_ok());
        assert_eq!(verdict(&allowed, "::ffff:0:7f00:1"), Err(via(Loopback)));
        // The mapped form of the same dotted address is plain IPv4.
        assert_eq!(verdict(&open, "::ffff:8.8.8.8"), Ok(ip("8.8.8.8")));
        assert_eq!(
            verdict(&open, "::ffff:0.0.0.1"),
            Err(always(NetClass::Unspecified))
        );
    }

    #[test]
    fn teredo_decodes_server_and_inverted_client() {
        let open = NetPolicy::default();
        // Server 8.8.4.4, client 8.8.8.8 (stored as its complement).
        let public = "2001:0:808:404:0:0:f7f7:f7f7";
        assert_eq!(verdict(&open, public), Err(range(NetClass::Transition)));
        let outer = with_allow(&["2001::/32"]);
        assert!(verdict(&outer, public).is_ok());
        // Loopback server.
        assert_eq!(
            verdict(&outer, "2001:0:7f00:1:0:0:f7f7:f7f7"),
            Err(via(Loopback))
        );
        // Loopback client: !0x7f000001 = 0x80fffffe.
        assert_eq!(
            verdict(&outer, "2001:0:808:404:0:0:80ff:fffe"),
            Err(via(Loopback))
        );
        // Metadata client: !0xa9fea9fe = 0x56015601.
        assert_eq!(
            verdict(&outer, "2001:0:808:404:0:0:5601:5601"),
            Err(via(Metadata))
        );
        // 808:808 is the client 247.247.247.247 once inverted, so it is reserved.
        assert_eq!(
            verdict(&outer, "2001:0:808:404:0:0:808:808"),
            Err(NetRefusal::Always {
                class: NetClass::Reserved,
                embedded: true
            })
        );
        // The parent range is too short to clear the Teredo entry.
        assert_eq!(
            verdict(&with_allow(&["2001::/23"]), public),
            Err(range(NetClass::Transition))
        );
        let both = with_allow(&["2001::/32", "127.0.0.1/32"]);
        assert!(verdict(&both, "2001:0:7f00:1:0:0:f7f7:f7f7").is_ok());
        // Outside Teredo, 2001::/23 is plain special-use.
        assert_eq!(verdict(&open, "2001:1::1"), Err(range(SpecialUse)));
        assert!(verdict(&with_allow(&["2001::/23"]), "2001:1::1").is_ok());
    }

    #[test]
    fn refusals_describe_themselves_without_data() {
        let text = NetPolicy::default()
            .check(ip("127.0.0.1"), 6000)
            .unwrap_err()
            .to_string();
        assert!(text.contains("loopback"));
        assert!(!text.contains("127"));
        assert_eq!(NetRefusal::PortZero.to_string(), "port 0");
    }
}
