use std::net::{
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
};

/// Returns whether `address` may be connected to: not loopback, private, shared, link-local,
/// multicast, broadcast, unspecified, reserved, documentation or benchmarking space, and not an
/// IPv6 address that embeds or translates to such an IPv4 address (mapped, translated,
/// compatible, NAT64, 6to4). Teredo and the local-use NAT64 prefix are refused outright, since
/// where they lead cannot be told from the address.
#[must_use]
pub fn is_public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_v4(address),
        IpAddr::V6(address) => is_public_v6(address),
    }
}

fn is_public_v4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    let reserved = a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..128).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..32).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && (c == 0 || c == 2))
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113);
    !reserved
}

fn is_public_v6(address: Ipv6Addr) -> bool {
    if let Some(inner) = embedded_v4(address) {
        return is_public_v4(inner);
    }
    let [first, second, third, fourth, ..] = address.segments();
    let reserved = address.is_unspecified()
        || address.is_loopback()
        || first & 0xfe00 == 0xfc00
        || first & 0xffc0 == 0xfe80
        || first & 0xffc0 == 0xfec0
        || first & 0xff00 == 0xff00
        || (first == 0x3fff && second & 0xf000 == 0)
        || (first == 0x2001 && (second == 0 || second == 0x0db8))
        || (first == 0x2001 && second == 2 && third == 0)
        || (first == 0x0064 && second == 0xff9b && third == 1)
        || (first == 0x0100 && second == 0 && third == 0 && fourth == 0);
    !reserved
}

fn embedded_v4(address: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return Some(mapped);
    }
    let segments = address.segments();
    let [first, second, third, ..] = segments;
    if first == 0x2002 {
        return Some(v4_from(second, third));
    }
    let [.., high, low] = segments;
    let nat64 = segments[..6] == [0x0064, 0xff9b, 0, 0, 0, 0];
    let translated = segments[..6] == [0, 0, 0, 0, 0xffff, 0];
    let compatible =
        segments[..6] == [0, 0, 0, 0, 0, 0] && !address.is_loopback() && !address.is_unspecified();
    (nat64 || translated || compatible).then(|| v4_from(high, low))
}

fn v4_from(high: u16, low: u16) -> Ipv4Addr {
    let [a, b] = high.to_be_bytes();
    let [c, d] = low.to_be_bytes();
    Ipv4Addr::new(a, b, c, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public(text: &str) -> bool {
        is_public(text.parse().unwrap())
    }

    #[test]
    fn internet_addresses_are_public() {
        for text in [
            "1.1.1.1",
            "8.8.8.8",
            "160.79.104.10",
            "2607:6bc0::10",
            "2a00:1450:4007:80e::200e",
        ] {
            assert!(public(text), "{text}");
        }
    }

    #[test]
    fn local_private_and_special_addresses_are_not() {
        for text in [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.1",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "2001:db8::1",
            "100::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "::127.0.0.1",
            "::ffff:0:127.0.0.1",
            "::ffff:0:10.0.0.1",
            "64:ff9b:1::a9fe:a9fe",
            "64:ff9b:1::808:808",
            "2002:7f00:1::",
            "2002:c0a8:101::",
            "2001:0:4136:e378::1",
            "3fff::1",
            "3fff:fff::1",
            "2001:2::1",
        ] {
            assert!(!public(text), "{text}");
        }
        assert!(public("::ffff:8.8.8.8"));
        assert!(public("64:ff9b::808:808"));
        assert!(public("2002:808:808::1"));
        assert!(public("::ffff:0:8.8.8.8"));
        assert!(public("3ff0::1"));
    }
}
