//! Reserved-address rejection for the connect-time gate (SEC-004).
//!
//! Scope is expressed as hostnames, so the operative rebinding/SSRF defence is:
//! a resolved IP must be a public, routable address. The single most dangerous
//! bypass is an **IPv4-mapped IPv6** literal (`::ffff:127.0.0.1`) — `std`'s
//! `is_loopback`/`is_private` do not see through the mapping, so we canonicalize
//! first and re-run the IPv4 checks on the embedded address. Fail closed:
//! anything not proven public is rejected.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Whether an IP is a public, routable address safe to connect to. Everything
/// reserved/internal is rejected (SEC-004).
pub fn ip_allowed(ip: IpAddr) -> bool {
    // Canonicalize: an IPv4-mapped IPv6 address becomes its IPv4 form, so the
    // IPv4 reserved-range checks apply and the mapping cannot smuggle loopback
    // or the metadata endpoint past us.
    let canon = match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => v6.to_canonical(),
    };
    match canon {
        IpAddr::V4(v4) => ipv4_allowed(v4),
        IpAddr::V6(v6) => ipv6_allowed(v6),
    }
}

fn ipv4_allowed(a: Ipv4Addr) -> bool {
    let o = a.octets();
    // std helpers cover: loopback 127/8, private 10/8+172.16/12+192.168/16,
    // link-local 169.254/16, broadcast, documentation, unspecified, multicast.
    if a.is_loopback()
        || a.is_private()
        || a.is_link_local()
        || a.is_broadcast()
        || a.is_documentation()
        || a.is_unspecified()
        || a.is_multicast()
    {
        return false;
    }
    // "This network" 0.0.0.0/8.
    if o[0] == 0 {
        return false;
    }
    // Carrier-grade NAT 100.64.0.0/10.
    if o[0] == 100 && (o[1] & 0xc0) == 64 {
        return false;
    }
    // IETF protocol assignments 192.0.0.0/24 (includes 192.0.0.0/29, etc.).
    if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        return false;
    }
    // Benchmarking 198.18.0.0/15.
    if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
        return false;
    }
    // Reserved (future use) 240.0.0.0/4.
    if o[0] >= 240 {
        return false;
    }
    true
}

fn ipv6_allowed(a: Ipv6Addr) -> bool {
    if a.is_loopback() || a.is_unspecified() || a.is_multicast() {
        return false;
    }
    let seg = a.segments();
    // Any address embedded in ::/96 (IPv4-compatible, deprecated) carries a v4
    // in its low 32 bits — validate that, not the v6 wrapper.
    if seg[..6].iter().all(|&s| s == 0) {
        let v4 = Ipv4Addr::new(
            (seg[6] >> 8) as u8,
            (seg[6] & 0xff) as u8,
            (seg[7] >> 8) as u8,
            (seg[7] & 0xff) as u8,
        );
        return ipv4_allowed(v4);
    }
    // Link-local fe80::/10.
    if (seg[0] & 0xffc0) == 0xfe80 {
        return false;
    }
    // Unique-local fc00::/7 (includes the AWS metadata fd00:ec2::/… range).
    if (seg[0] & 0xfe00) == 0xfc00 {
        return false;
    }
    // Documentation 2001:db8::/32.
    if seg[0] == 0x2001 && seg[1] == 0x0db8 {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn allowed(s: &str) -> bool {
        ip_allowed(IpAddr::from_str(s).unwrap())
    }

    #[test]
    fn public_addresses_allowed() {
        assert!(allowed("93.184.216.34")); // example.com
        assert!(allowed("8.8.8.8"));
        assert!(allowed("2606:2800:220:1:248:1893:25c8:1946"));
    }

    #[test]
    fn reserved_ipv4_rejected() {
        for a in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.5.4",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "100.64.0.1",      // CGNAT
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",  // multicast
            "198.18.0.1", // benchmarking
            "240.0.0.1",  // reserved
            "192.0.2.1",  // documentation
        ] {
            assert!(!allowed(a), "{a} should be rejected");
        }
    }

    #[test]
    fn reserved_ipv6_rejected() {
        for a in [
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd00::1",
            "ff02::1",
            "2001:db8::1",
        ] {
            assert!(!allowed(a), "{a} should be rejected");
        }
    }

    /// The critical bypass: IPv4-mapped IPv6 must be seen through to the v4.
    #[test]
    fn ipv4_mapped_ipv6_rejected() {
        assert!(
            !allowed("::ffff:127.0.0.1"),
            "mapped loopback must be rejected"
        );
        assert!(
            !allowed("::ffff:169.254.169.254"),
            "mapped metadata endpoint must be rejected"
        );
        assert!(
            !allowed("::ffff:10.0.0.1"),
            "mapped private must be rejected"
        );
        // A mapped public address is still allowed.
        assert!(allowed("::ffff:93.184.216.34"));
    }

    /// IPv4-compatible (deprecated ::a.b.c.d) also embeds a v4.
    #[test]
    fn ipv4_compatible_rejected() {
        assert!(!allowed("::7f00:1")); // ::127.0.0.1 form
    }
}
