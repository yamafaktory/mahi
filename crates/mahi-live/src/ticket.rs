use std::{
    fmt,
    net::{
        IpAddr,
        Ipv4Addr,
        Ipv6Addr,
        SocketAddr,
        SocketAddrV4,
        SocketAddrV6,
    },
    str::FromStr,
};

use bech32::{
    Bech32m,
    Hrp,
    primitives::decode::CheckedHrpstring,
};
use iroh::RelayUrl;
use mahi_core::ThreadId;
use mahi_thread::{
    KeyError,
    NodeId,
    NodeIdError,
    ParticipantKey,
};
use serde::{
    Deserialize,
    Serialize,
};
use thiserror::Error;

const HRP: &str = "mahi";
const VERSION: u16 = 1;
const MAX_TICKET_CHARS: usize = 1023;
const MAX_RELAY_URL_BYTES: usize = 256;
const MAX_OWNER_KEY_BYTES: usize = 256;
/// The most direct addresses a host address holds.
pub const MAX_DIRECT_ADDRESSES: usize = 8;

/// Where a host's node can be reached: its node id, the relay it is connected to, and the
/// addresses it can be reached at directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAddress {
    node: NodeId,
    relay: Option<RelayUrl>,
    direct: Vec<SocketAddr>,
}

/// An invitation to a thread, given to one participant: where its host is, whom to trust as its
/// owner, and which `meta` generation to accept at least.
///
/// It holds no secret, and is written as `mahi1…`, bech32m over `postcard`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    thread: ThreadId,
    host: HostAddress,
    owner: ParticipantKey,
    min_generation: u64,
    invitee: NodeId,
}

/// A host address that cannot go into a ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AddressError {
    /// The relay URL is longer than 256 bytes, not https, not on a domain name, names
    /// `localhost`, or carries user information, a query, a fragment or port 0.
    #[error("the relay URL must be a plain https URL on a domain name")]
    Relay,
    /// A direct address is unspecified, multicast, broadcast, IPv6 link-local, or has port 0,
    /// none of which reaches a peer.
    #[error("a direct address cannot reach a peer")]
    Direct,
    /// There are more than [`MAX_DIRECT_ADDRESSES`] direct addresses.
    #[error("more than {MAX_DIRECT_ADDRESSES} direct addresses")]
    TooManyAddresses,
}

/// A string that is not a usable ticket.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TicketError {
    /// The text is longer than 1023 characters, not bech32m, or not a mahi ticket.
    #[error("not a mahi ticket")]
    Malformed,
    /// The ticket was made by a mahi with another ticket format.
    #[error("ticket version {0} is not supported")]
    UnsupportedVersion(u16),
    /// A node id in the ticket is not usable.
    #[error("the ticket holds an invalid node id")]
    Node(#[from] NodeIdError),
    /// The owner key is not a usable SSH ed25519 key.
    #[error("the ticket holds an invalid owner key")]
    Owner(#[from] KeyError),
    /// The host address is not usable.
    #[error("the ticket holds an invalid host address")]
    Address(#[from] AddressError),
    /// Encoding the ticket failed.
    #[error("cannot encode the ticket")]
    Encode,
}

#[derive(Serialize, Deserialize)]
struct WireTicket<'a> {
    version: u16,
    thread: [u8; 16],
    host: [u8; 32],
    relay: Option<&'a str>,
    direct: Vec<WireAddress>,
    owner: &'a str,
    min_generation: u64,
    invitee: [u8; 32],
}

#[derive(Serialize, Deserialize)]
enum WireAddress {
    V4([u8; 4], u16),
    V6([u8; 16], u16),
}

impl HostAddress {
    /// Makes the address of `node`, reached through `relay` or directly at `direct`.
    ///
    /// # Errors
    ///
    /// Returns [`AddressError::Relay`] if the relay URL is not a plain https URL on a domain
    /// name of at most 256 bytes, [`AddressError::Direct`] if a direct address cannot reach a
    /// peer (see [`is_reachable`]), or [`AddressError::TooManyAddresses`] if there are more than
    /// [`MAX_DIRECT_ADDRESSES`].
    pub fn new(
        node: NodeId,
        relay: Option<RelayUrl>,
        direct: Vec<SocketAddr>,
    ) -> Result<Self, AddressError> {
        if relay.as_ref().is_some_and(|relay| !is_plain_relay(relay)) {
            return Err(AddressError::Relay);
        }
        if direct.len() > MAX_DIRECT_ADDRESSES {
            return Err(AddressError::TooManyAddresses);
        }
        if !direct.iter().all(is_reachable) {
            return Err(AddressError::Direct);
        }
        Ok(Self {
            node,
            relay,
            direct,
        })
    }

    /// Returns the host's node id.
    #[must_use]
    pub fn node(&self) -> &NodeId {
        &self.node
    }

    /// Returns the relay the host is connected to, if any.
    #[must_use]
    pub fn relay(&self) -> Option<&RelayUrl> {
        self.relay.as_ref()
    }

    /// Returns the addresses the host can be reached at directly.
    #[must_use]
    pub fn direct(&self) -> &[SocketAddr] {
        &self.direct
    }
}

impl Ticket {
    /// Makes a ticket for `invitee` to join `thread`, hosted at `host` and owned by `owner`,
    /// accepting `meta` from `min_generation` on.
    #[must_use]
    pub fn new(
        thread: ThreadId,
        host: HostAddress,
        owner: ParticipantKey,
        min_generation: u64,
        invitee: NodeId,
    ) -> Self {
        Self {
            thread,
            host,
            owner,
            min_generation,
            invitee,
        }
    }

    /// Returns the thread the ticket invites to.
    #[must_use]
    pub fn thread(&self) -> ThreadId {
        self.thread
    }

    /// Returns where the thread's host is.
    #[must_use]
    pub fn host(&self) -> &HostAddress {
        &self.host
    }

    /// Returns the owner's key, which the thread's `meta` must be signed with.
    #[must_use]
    pub fn owner(&self) -> &ParticipantKey {
        &self.owner
    }

    /// Returns the lowest `meta` generation the joiner may accept.
    #[must_use]
    pub fn min_generation(&self) -> u64 {
        self.min_generation
    }

    /// Returns the node id of the participant the ticket was made for.
    #[must_use]
    pub fn invitee(&self) -> &NodeId {
        &self.invitee
    }

    /// Writes the ticket as `mahi1…`.
    ///
    /// # Errors
    ///
    /// Returns [`TicketError::Encode`] if the ticket does not fit 1023 characters, which a
    /// ticket with a host address [`HostAddress::new`] accepted always does.
    pub fn encode(&self) -> Result<String, TicketError> {
        let owner = self.owner.to_openssh();
        let wire = WireTicket {
            version: VERSION,
            thread: *self.thread.as_bytes(),
            host: *self.host.node.as_bytes(),
            relay: self.host.relay.as_ref().map(|relay| relay.as_str()),
            direct: self.host.direct.iter().map(WireAddress::from).collect(),
            owner,
            min_generation: self.min_generation,
            invitee: *self.invitee.as_bytes(),
        };
        let bytes = postcard::to_allocvec(&wire).map_err(|_| TicketError::Encode)?;
        let hrp = Hrp::parse(HRP).map_err(|_| TicketError::Encode)?;
        bech32::encode::<Bech32m>(hrp, &bytes).map_err(|_| TicketError::Encode)
    }
}

impl fmt::Display for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = self.encode().map_err(|_| fmt::Error)?;
        f.write_str(&encoded)
    }
}

impl FromStr for Ticket {
    type Err = TicketError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.trim();
        if text.len() > MAX_TICKET_CHARS {
            return Err(TicketError::Malformed);
        }
        let checked = CheckedHrpstring::new::<Bech32m>(text).map_err(|_| TicketError::Malformed)?;
        if !checked.hrp().as_str().eq_ignore_ascii_case(HRP) {
            return Err(TicketError::Malformed);
        }
        let bytes: Vec<u8> = checked.byte_iter().collect();
        let (wire, rest): (WireTicket<'_>, _) =
            postcard::take_from_bytes(&bytes).map_err(|_| TicketError::Malformed)?;
        if !rest.is_empty() {
            return Err(TicketError::Malformed);
        }
        if wire.version != VERSION {
            return Err(TicketError::UnsupportedVersion(wire.version));
        }
        if wire.owner.len() > MAX_OWNER_KEY_BYTES {
            return Err(TicketError::Malformed);
        }
        let relay = match wire.relay {
            Some(url) if url.len() <= MAX_RELAY_URL_BYTES => {
                Some(url.parse::<RelayUrl>().map_err(|_| AddressError::Relay)?)
            }
            Some(_) => return Err(AddressError::Relay.into()),
            None => None,
        };
        let host = HostAddress::new(
            NodeId::from_bytes(wire.host)?,
            relay,
            wire.direct.into_iter().map(SocketAddr::from).collect(),
        )?;
        Ok(Self {
            thread: ThreadId::from_bytes(wire.thread),
            host,
            owner: ParticipantKey::from_openssh(wire.owner)?,
            min_generation: wire.min_generation,
            invitee: NodeId::from_bytes(wire.invitee)?,
        })
    }
}

/// Says whether `address` can reach a peer: it is not unspecified, multicast, broadcast or IPv6
/// link-local (whose scope a ticket cannot carry), and its port is not 0.
#[must_use]
pub fn is_reachable(address: &SocketAddr) -> bool {
    let ip_usable = match address.ip() {
        IpAddr::V4(ip) => !(ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast()),
        IpAddr::V6(ip) => !(ip.is_unspecified() || ip.is_multicast() || ip.is_unicast_link_local()),
    };
    ip_usable && address.port() != 0
}

fn is_plain_relay(relay: &RelayUrl) -> bool {
    let Some(domain) = relay.domain() else {
        return false;
    };
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    relay.as_str().len() <= MAX_RELAY_URL_BYTES
        && relay.scheme() == "https"
        && domain != "localhost"
        && !domain.ends_with(".localhost")
        && relay.username().is_empty()
        && relay.password().is_none()
        && relay.query().is_none()
        && relay.fragment().is_none()
        && relay.port() != Some(0)
}

impl From<&SocketAddr> for WireAddress {
    fn from(address: &SocketAddr) -> Self {
        match address {
            SocketAddr::V4(v4) => Self::V4(v4.ip().octets(), v4.port()),
            SocketAddr::V6(v6) => Self::V6(v6.ip().octets(), v6.port()),
        }
    }
}

impl From<WireAddress> for SocketAddr {
    fn from(address: WireAddress) -> Self {
        match address {
            WireAddress::V4(ip, port) => Self::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)),
            WireAddress::V6(ip, port) => {
                Self::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ssh_key::{
        Algorithm,
        PrivateKey,
        rand_core::OsRng,
    };

    use super::*;
    use crate::testing::random_node;

    fn owner() -> ParticipantKey {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        ParticipantKey::from_public_key(key.public_key()).unwrap()
    }

    fn ticket(direct: usize) -> Ticket {
        let addresses = (0..direct)
            .map(|index| {
                if index % 2 == 0 {
                    SocketAddr::from(([192, 0, 2, 1], 40_000 + u16::try_from(index).unwrap()))
                } else {
                    SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 41_000))
                }
            })
            .collect();
        Ticket::new(
            ThreadId::random().unwrap(),
            HostAddress::new(
                random_node(),
                Some("https://euc1-1.relay.n0.iroh.link./".parse().unwrap()),
                addresses,
            )
            .unwrap(),
            owner(),
            7,
            random_node(),
        )
    }

    #[test]
    fn a_full_ticket_round_trips_as_mahi1_text() {
        let ticket = ticket(MAX_DIRECT_ADDRESSES);
        let text = ticket.to_string();
        assert!(text.starts_with("mahi1"));
        assert!(text.len() <= MAX_TICKET_CHARS);
        assert_eq!(text.parse::<Ticket>().unwrap(), ticket);
        assert_eq!(format!(" {text}\n").parse::<Ticket>().unwrap(), ticket);
        assert_eq!(text.to_uppercase().parse::<Ticket>().unwrap(), ticket);
        assert_eq!(ticket.min_generation(), 7);
    }

    #[test]
    fn a_changed_or_foreign_string_is_not_a_ticket() {
        let text = ticket(2).to_string();
        let mut changed = text.clone().into_bytes();
        let last = changed.len() - 1;
        changed[last] = if changed[last] == b'q' { b'p' } else { b'q' };
        let changed = String::from_utf8(changed).unwrap();
        let hrp = Hrp::parse("other").unwrap();
        let foreign = bech32::encode::<Bech32m>(hrp, b"x").unwrap();
        let bech32_not_m =
            bech32::encode::<bech32::Bech32>(Hrp::parse(HRP).unwrap(), b"x").unwrap();
        for bad in [
            changed.as_str(),
            foreign.as_str(),
            bech32_not_m.as_str(),
            "mahi1",
            "",
            &"q".repeat(MAX_TICKET_CHARS + 1),
        ] {
            assert_eq!(bad.parse::<Ticket>(), Err(TicketError::Malformed), "{bad}");
        }
    }

    fn encode(wire: &WireTicket<'_>) -> String {
        let bytes = postcard::to_allocvec(wire).unwrap();
        bech32::encode::<Bech32m>(Hrp::parse(HRP).unwrap(), &bytes).unwrap()
    }

    #[test]
    fn each_bad_field_is_refused_for_its_reason() {
        let owner = owner();
        let owner_line = owner.to_openssh().to_owned();
        let good = || WireTicket {
            version: VERSION,
            thread: [1; 16],
            host: *random_node().as_bytes(),
            relay: Some("https://relay.example/"),
            direct: vec![WireAddress::V4([192, 0, 2, 1], 1)],
            owner: &owner_line,
            min_generation: 0,
            invitee: *random_node().as_bytes(),
        };
        assert!(encode(&good()).parse::<Ticket>().is_ok());
        let parse = |wire: WireTicket<'_>| encode(&wire).parse::<Ticket>();

        assert_eq!(
            parse(WireTicket {
                version: 2,
                ..good()
            }),
            Err(TicketError::UnsupportedVersion(2))
        );
        assert!(matches!(
            parse(WireTicket {
                host: [0; 32],
                ..good()
            }),
            Err(TicketError::Node(_))
        ));
        assert!(matches!(
            parse(WireTicket {
                invitee: [0; 32],
                ..good()
            }),
            Err(TicketError::Node(_))
        ));
        for relay in ["ftp://relay.example/", "not a url"] {
            assert_eq!(
                parse(WireTicket {
                    relay: Some(relay),
                    ..good()
                }),
                Err(TicketError::Address(AddressError::Relay))
            );
        }
        let long_relay = format!("https://{}.example/", "a".repeat(MAX_RELAY_URL_BYTES));
        assert_eq!(
            parse(WireTicket {
                relay: Some(&long_relay),
                ..good()
            }),
            Err(TicketError::Address(AddressError::Relay))
        );
        assert_eq!(
            parse(WireTicket {
                direct: (0..=MAX_DIRECT_ADDRESSES)
                    .map(|_| WireAddress::V4([192, 0, 2, 1], 1))
                    .collect(),
                ..good()
            }),
            Err(TicketError::Address(AddressError::TooManyAddresses))
        );
        assert!(matches!(
            parse(WireTicket {
                owner: "ssh-ed25519 AAAA",
                ..good()
            }),
            Err(TicketError::Owner(_))
        ));
        let mut trailing = postcard::to_allocvec(&good()).unwrap();
        trailing.push(0);
        let trailing = bech32::encode::<Bech32m>(Hrp::parse(HRP).unwrap(), &trailing).unwrap();
        assert_eq!(trailing.parse::<Ticket>(), Err(TicketError::Malformed));
    }

    #[test]
    fn only_plain_https_relays_on_domain_names_are_taken() {
        let address =
            |relay: &str| HostAddress::new(random_node(), Some(relay.parse().unwrap()), Vec::new());
        for bad in [
            "http://relay.example/",
            "https://user:pass@relay.example/",
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://localhost/",
            "https://a.localhost./",
            "https://relay.example/?q=1",
            "https://relay.example/#f",
            "https://relay.example:0/",
        ] {
            assert_eq!(address(bad), Err(AddressError::Relay), "{bad}");
        }
        assert!(address("https://relay.example:4443/").is_ok());
    }

    #[test]
    fn direct_addresses_that_reach_no_peer_are_refused() {
        let address =
            |direct: &str| HostAddress::new(random_node(), None, vec![direct.parse().unwrap()]);
        for bad in [
            "0.0.0.0:1",
            "224.0.0.1:1",
            "255.255.255.255:1",
            "192.0.2.1:0",
            "[::]:1",
            "[ff02::1]:1",
            "[fe80::1]:1",
        ] {
            assert_eq!(address(bad), Err(AddressError::Direct), "{bad}");
        }
        for good in ["127.0.0.1:1", "10.0.0.1:1", "[2001:db8::1]:1", "[::1]:1"] {
            assert!(address(good).is_ok(), "{good}");
        }
    }

    #[test]
    fn the_largest_ticket_still_encodes_and_mixed_case_is_refused() {
        let prefix = "https://";
        let suffix = ".example/";
        let label = "a".repeat(MAX_RELAY_URL_BYTES - prefix.len() - suffix.len());
        let relay = format!("{prefix}{label}{suffix}");
        assert_eq!(relay.len(), MAX_RELAY_URL_BYTES);
        let direct = (0..MAX_DIRECT_ADDRESSES)
            .map(|index| {
                let segment = u16::try_from(index).unwrap() + 1;
                SocketAddr::from((
                    [
                        0x2001, 0xdb8, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, segment,
                    ],
                    65_535,
                ))
            })
            .collect();
        let ticket = Ticket::new(
            ThreadId::random().unwrap(),
            HostAddress::new(random_node(), Some(relay.parse().unwrap()), direct).unwrap(),
            owner(),
            u64::MAX,
            random_node(),
        );
        let text = ticket.encode().unwrap();
        assert!(text.len() <= MAX_TICKET_CHARS);
        assert_eq!(text.parse::<Ticket>().unwrap(), ticket);

        let mixed: String = text
            .chars()
            .enumerate()
            .map(|(index, character)| {
                if index % 2 == 0 {
                    character.to_ascii_uppercase()
                } else {
                    character
                }
            })
            .collect();
        assert_eq!(mixed.parse::<Ticket>(), Err(TicketError::Malformed));
    }
}
