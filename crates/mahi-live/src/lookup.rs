use iroh::{
    Endpoint,
    EndpointId,
    address_lookup::{
        AddressLookup,
        AddressLookupBuilder,
        AddressLookupBuilderError,
        EndpointInfo,
        Error,
        Item,
        pkarr::{
            PkarrPublisher,
            PkarrResolver,
        },
    },
    endpoint::Builder,
};
use n0_future::{
    StreamExt as _,
    boxed::BoxStream,
};

use crate::{
    Relays,
    ticket::is_plain_relay,
};

/// How an endpoint finds the machines of the peers it reaches, beyond the addresses it is
/// given: not at all, through the relay-only records hosts publish, or also by publishing its
/// own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lookup {
    None,
    Resolve,
    Publish,
}

/// Adds to `builder` the pkarr lookups `lookup` asks for, through n0's server, only when the
/// endpoint uses the public relays: a record names a relay, so without one there is nothing to
/// publish or to meet at.
pub(crate) fn with_lookups(builder: Builder, relays: Relays, lookup: Lookup) -> Builder {
    let (resolves, publishes) = lookups(relays, lookup);
    let builder = if resolves {
        builder.address_lookup(CheckedBuilder(PkarrResolver::n0_dns()))
    } else {
        builder
    };
    if publishes {
        builder.address_lookup(PkarrPublisher::n0_dns())
    } else {
        builder
    }
}

/// Returns whether an endpoint with `relays` that `lookup` describes resolves records and
/// whether it publishes its own.
fn lookups(relays: Relays, lookup: Lookup) -> (bool, bool) {
    match (relays, lookup) {
        (Relays::Disabled, _) | (Relays::Public, Lookup::None) => (false, false),
        (Relays::Public, Lookup::Resolve) => (true, false),
        (Relays::Public, Lookup::Publish) => (true, true),
    }
}

/// Builds the lookup `T` builds, as a [`Checked`] one.
#[derive(Debug)]
struct CheckedBuilder<T>(T);

/// A lookup whose results keep only the relays a ticket's relay could be, and no direct
/// address, since a peer's record is untrusted input.
#[derive(Debug)]
struct Checked<T>(T);

impl<T: AddressLookupBuilder> AddressLookupBuilder for CheckedBuilder<T> {
    fn into_address_lookup(
        self,
        endpoint: &Endpoint,
    ) -> Result<impl AddressLookup, AddressLookupBuilderError> {
        Ok(Checked(self.0.into_address_lookup(endpoint)?))
    }
}

impl<T: AddressLookup> AddressLookup for Checked<T> {
    fn resolve(&self, endpoint_id: EndpointId) -> Option<BoxStream<Result<Item, Error>>> {
        let found = self.0.resolve(endpoint_id)?;
        Some(Box::pin(found.filter_map(|item| match item {
            Ok(item) => checked(&item).map(Ok),
            Err(error) => Some(Err(error)),
        })))
    }
}

/// Returns `item` with only its first relay a ticket could hold and none of its direct
/// addresses, or `None` when it names no such relay.
fn checked(item: &Item) -> Option<Item> {
    let info = item.endpoint_info();
    let relay = info.data.relay_urls().find(|relay| is_plain_relay(relay))?;
    Some(Item::new(
        EndpointInfo::new(info.endpoint_id).with_relay_url(relay.clone()),
        item.provenance(),
        item.last_updated(),
    ))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use iroh::{
        RelayUrl,
        SecretKey,
    };

    use super::*;

    fn item(relays: &[&str], direct: &[&str]) -> Item {
        let id = SecretKey::from_bytes(&[7; 32]).public();
        let mut info = EndpointInfo::new(id).with_ip_addrs(
            direct
                .iter()
                .map(|address| address.parse::<SocketAddr>().unwrap())
                .collect(),
        );
        for relay in relays {
            info = info.with_relay_url(relay.parse::<RelayUrl>().unwrap());
        }
        Item::new(info, "test", Some(1))
    }

    #[derive(Debug)]
    struct Fake(Vec<Result<Item, Error>>);

    impl AddressLookup for Fake {
        fn resolve(&self, _endpoint_id: EndpointId) -> Option<BoxStream<Result<Item, Error>>> {
            Some(Box::pin(n0_future::stream::iter(self.0.clone())))
        }
    }

    #[test]
    fn only_a_host_with_the_public_relays_publishes_and_no_endpoint_without_them_looks_up() {
        assert_eq!(lookups(Relays::Public, Lookup::Publish), (true, true));
        assert_eq!(lookups(Relays::Public, Lookup::Resolve), (true, false));
        assert_eq!(lookups(Relays::Public, Lookup::None), (false, false));
        for lookup in [Lookup::None, Lookup::Resolve, Lookup::Publish] {
            assert_eq!(lookups(Relays::Disabled, lookup), (false, false));
        }
    }

    #[test]
    fn a_checked_lookup_drops_direct_addresses_and_relayless_records_and_passes_errors_on() {
        let failed = Error::from_err("fake", std::io::Error::other("down"));
        let fake = Checked(Fake(vec![
            Ok(item(&["https://relay.example/"], &["192.0.2.1:4000"])),
            Err(failed),
            Ok(item(&[], &["192.0.2.2:4000"])),
        ]));
        let id = SecretKey::from_bytes(&[7; 32]).public();
        let found: Vec<Result<Item, Error>> = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(fake.resolve(id).unwrap().collect());
        assert_eq!(found.len(), 2);
        let first = found[0].as_ref().unwrap();
        assert_eq!(first.endpoint_info().data.ip_addrs().count(), 0);
        assert_eq!(first.endpoint_info().data.relay_urls().count(), 1);
        assert!(found[1].is_err());
    }

    #[test]
    fn a_record_keeps_only_a_relay_a_ticket_could_hold_and_no_direct_address() {
        let kept = checked(&item(
            &["http://relay.example/", "https://relay.example/"],
            &["192.0.2.1:4000"],
        ))
        .unwrap();
        let relays: Vec<String> = kept
            .endpoint_info()
            .data
            .relay_urls()
            .map(ToString::to_string)
            .collect();
        assert_eq!(relays, ["https://relay.example/"]);
        assert_eq!(kept.endpoint_info().data.ip_addrs().count(), 0);
        assert_eq!(kept.provenance(), "test");
        assert_eq!(kept.last_updated(), Some(1));
        assert!(checked(&item(&["https://localhost/"], &["192.0.2.1:4000"])).is_none());
        assert!(checked(&item(&["https://127.0.0.1/"], &[])).is_none());
        assert!(checked(&item(&[], &["192.0.2.1:4000"])).is_none());
    }
}
