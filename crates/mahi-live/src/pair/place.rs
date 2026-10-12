use crate::{
    HostAddress,
    Relays,
    TicketError,
};

const PLACE_MAGIC: &[u8] = b"mahi-pair-v1\n";
/// The most a pairing place takes, as the store bounds the blob that holds it.
pub const MAX_PLACE_BYTES: usize = 1024;

/// Encodes where the owner waits for a pairing, for the `where` blob of its pairing ref: with
/// `relays`, its node id and relay URL only, so a public remote never shows its IP addresses;
/// without, on a local network, its node id and direct addresses.
///
/// # Errors
///
/// Returns [`TicketError::Malformed`] if `host` does not have that shape, or
/// [`TicketError::Encode`] if encoding fails or the result is larger than [`MAX_PLACE_BYTES`].
pub fn place_bytes(host: &HostAddress, relays: Relays) -> Result<Vec<u8>, TicketError> {
    if !has_shape(host, relays) {
        return Err(TicketError::Malformed);
    }
    let mut bytes = PLACE_MAGIC.to_vec();
    bytes.extend_from_slice(&host.to_bytes()?);
    if bytes.len() > MAX_PLACE_BYTES {
        return Err(TicketError::Encode);
    }
    Ok(bytes)
}

/// Reads where the owner waits from a pairing ref's `where` blob, which anyone who can push to
/// the remote may have written, with the checks of a ticket's host address and the shape
/// [`place_bytes`] writes for `relays`, so a forged ref cannot point the joiner at addresses
/// on its network when a relay is expected.
///
/// # Errors
///
/// Returns [`TicketError::Malformed`] if the bytes are not a pairing place of that shape, or
/// another [`TicketError`] if the address breaks a ticket's rules.
pub fn parse_place(bytes: &[u8], relays: Relays) -> Result<HostAddress, TicketError> {
    if bytes.len() > MAX_PLACE_BYTES {
        return Err(TicketError::Malformed);
    }
    let address = bytes
        .strip_prefix(PLACE_MAGIC)
        .ok_or(TicketError::Malformed)?;
    let host = HostAddress::from_bytes(address)?;
    if has_shape(&host, relays) {
        Ok(host)
    } else {
        Err(TicketError::Malformed)
    }
}

fn has_shape(host: &HostAddress, relays: Relays) -> bool {
    match relays {
        Relays::Public => host.relay().is_some() && host.direct().is_empty(),
        Relays::Disabled => host.relay().is_none() && !host.direct().is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use mahi_thread::NodeId;

    use super::*;

    fn node() -> NodeId {
        NodeId::from_bytes(
            *ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                .verifying_key()
                .as_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn a_place_reads_back_with_its_node_and_relay() {
        let relay = "https://relay.example.org".parse().unwrap();
        let host = HostAddress::new(node(), Some(relay), Vec::new()).unwrap();
        let bytes = place_bytes(&host, Relays::Public).unwrap();
        assert!(bytes.starts_with(b"mahi-pair-v1\n"));
        assert_eq!(parse_place(&bytes, Relays::Public).unwrap(), host);
        assert!(parse_place(&bytes, Relays::Disabled).is_err());
        let local =
            HostAddress::new(node(), None, vec!["192.168.1.2:4000".parse().unwrap()]).unwrap();
        let bytes = place_bytes(&local, Relays::Disabled).unwrap();
        assert_eq!(parse_place(&bytes, Relays::Disabled).unwrap(), local);
        assert!(parse_place(&bytes, Relays::Public).is_err());
    }

    #[test]
    fn a_place_with_addresses_beside_its_relay_or_neither_is_refused() {
        let relay = "https://relay.example.org".parse().unwrap();
        let both =
            HostAddress::new(node(), Some(relay), vec!["10.0.0.1:22".parse().unwrap()]).unwrap();
        let neither = HostAddress::new(node(), None, Vec::new()).unwrap();
        for host in [&both, &neither] {
            for relays in [Relays::Public, Relays::Disabled] {
                assert!(place_bytes(host, relays).is_err());
                let mut forged = PLACE_MAGIC.to_vec();
                forged.extend_from_slice(&host.to_bytes().unwrap());
                assert!(parse_place(&forged, relays).is_err());
            }
        }
    }

    #[test]
    fn other_bytes_or_hostile_addresses_are_refused() {
        let relay = "https://relay.example.org".parse().unwrap();
        let host = HostAddress::new(node(), Some(relay), Vec::new()).unwrap();
        let bytes = place_bytes(&host, Relays::Public).unwrap();
        assert!(parse_place(&bytes[1..], Relays::Public).is_err());
        assert!(parse_place(b"", Relays::Public).is_err());
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(parse_place(&longer, Relays::Public).is_err());
        assert!(parse_place(&vec![b'm'; MAX_PLACE_BYTES + 1], Relays::Public).is_err());
        let mut local = b"mahi-pair-v1\n".to_vec();
        local.extend_from_slice(&[7; 32]);
        local.extend_from_slice(&[1, 22]);
        local.extend_from_slice(b"https://localhost/x123");
        assert!(parse_place(&local, Relays::Public).is_err());
    }
}
