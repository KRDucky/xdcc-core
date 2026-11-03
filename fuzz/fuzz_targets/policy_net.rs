//! Destination policy: agreement between forms, and refusals that must hold.
//!
//! Layout: flags, port (2 bytes), address (16 bytes), then 18-byte rules of a
//! kind-and-length byte, a length byte, and 16 address bytes.

#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libfuzzer_sys::fuzz_target;
use xdcc_core::policy::{IpPrefix, NetPolicy, NetPolicyConfig, NetRefusal};
use xdcc_core_fuzz::{check_bound, measured};

const HEADER: usize = 19;
const RULE: usize = 18;
const MAX_FUZZ_RULES: usize = 8;

fn rule(bytes: &[u8]) -> Option<(bool, IpPrefix)> {
    let (&kind, rest) = bytes.split_first()?;
    let (&len, address) = rest.split_first()?;
    let wide = kind & 1 != 0;
    let bits = u128::from_be_bytes(address.get(..16)?.try_into().ok()?);
    if wide {
        let len = len % 129;
        let masked = if len == 0 {
            0
        } else {
            bits & (u128::MAX << (128 - len))
        };
        let prefix = IpPrefix::new(IpAddr::V6(Ipv6Addr::from(masked)), len).ok()?;
        Some((kind & 2 != 0, prefix))
    } else {
        let len = len % 33;
        let top = (bits >> 96) as u32;
        let masked = if len == 0 {
            0
        } else {
            top & (u32::MAX << (32 - len))
        };
        let prefix = IpPrefix::new(IpAddr::V4(Ipv4Addr::from(masked)), len).ok()?;
        Some((kind & 2 != 0, prefix))
    }
}

/// The IPv4 addresses a transition address embeds, found without the library.
fn embedded(bits: u128) -> Vec<u32> {
    let low = bits as u32;
    if bits >> 32 == 0x0064_ff9b_0000_0000_0000_0000 {
        // 64:ff9b::/96
        vec![low]
    } else if bits >> 112 == 0x2002 {
        // 2002::/16, bits 16 to 47
        vec![(bits >> 80) as u32]
    } else if bits >> 32 == 0 && low > 1 {
        // ::/96, other than `::` and `::1`
        vec![low]
    } else if bits >> 32 == 0xffff_0000 {
        // ::ffff:0:0:0/96
        vec![low]
    } else if bits >> 96 == 0x2001_0000 {
        // Teredo: server in bits 32 to 63, client inverted in bits 96 to 127
        vec![(bits >> 64) as u32, !low]
    } else {
        Vec::new()
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < HEADER {
        return;
    }
    let (head, rules) = data.split_at(HEADER);
    let flags = head[0];
    let port = u16::from_be_bytes([head[1], head[2]]);
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&head[3..HEADER]);
    let addr = if flags & 1 != 0 {
        IpAddr::V6(Ipv6Addr::from(octets))
    } else {
        IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
    };

    let mut config = NetPolicyConfig::default();
    config.allow_private_destinations = flags & 2 != 0;
    config.allow_low_ports = flags & 4 != 0;
    let mut denied = Vec::new();
    for chunk in rules.chunks_exact(RULE).take(MAX_FUZZ_RULES) {
        if let Some((deny, prefix)) = rule(chunk) {
            if deny {
                denied.push(prefix);
                config.deny.push(prefix);
            } else {
                config.allow.push(prefix);
            }
        }
    }
    let Ok(policy) = NetPolicy::new(config) else {
        return;
    };

    let (result, bytes) = measured(|| policy.check(addr, port));
    check_bound(bytes);
    assert_eq!(bytes, 0, "check allocated");
    let canonical = addr.to_canonical();

    if let Ok(approved) = &result {
        assert_eq!(approved.ip(), canonical);
        assert_eq!(approved.port(), port);
        assert!(port != 0);
        assert_eq!(approved.socket_addr().port(), port);
    }
    if port == 0 {
        assert_eq!(result, Err(NetRefusal::PortZero));
    }

    // An IPv4 address and its mapped form get the same answer.
    if let IpAddr::V4(plain) = canonical {
        let mapped = policy.check(IpAddr::V6(plain.to_ipv6_mapped()), port);
        assert_eq!(result, mapped);
        let first = plain.octets()[0];
        if first == 0 || first >= 224 {
            assert!(matches!(
                result,
                Err(NetRefusal::PortZero | NetRefusal::LowPort | NetRefusal::Always { .. })
            ));
        }
    }

    // A deny rule always wins, whatever else the address is.
    if denied.iter().any(|prefix| prefix_holds(prefix, canonical)) {
        assert!(result.is_err());
    }

    // Decoding only adds refusals: an approved transition address has an
    // approved embedded address under the same policy.
    if let (Ok(_), IpAddr::V6(v6)) = (&result, canonical) {
        for ip in embedded(u128::from(v6)) {
            let inner = policy.check(IpAddr::V4(Ipv4Addr::from(ip)), port);
            assert!(
                inner.is_ok(),
                "{v6} approved but {} is refused",
                Ipv4Addr::from(ip)
            );
        }
    }
});

/// Whether `prefix` holds `addr`, using only the prefix's public parts.
fn prefix_holds(prefix: &IpPrefix, addr: IpAddr) -> bool {
    let len = u32::from(prefix.len());
    match (prefix.addr(), addr) {
        (IpAddr::V4(base), IpAddr::V4(ip)) => {
            let mask = u32::MAX.checked_shl(32 - len).unwrap_or(0);
            u32::from(base) & mask == u32::from(ip) & mask
        }
        (IpAddr::V6(base), IpAddr::V6(ip)) => {
            let mask = u128::MAX.checked_shl(128 - len).unwrap_or(0);
            u128::from(base) & mask == u128::from(ip) & mask
        }
        _ => false,
    }
}
