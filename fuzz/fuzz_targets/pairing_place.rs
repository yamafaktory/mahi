#![no_main]

use mahi_live::{
    MAX_PLACE_BYTES,
    Relays,
    parse_place,
    place_bytes,
};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    for relays in [Relays::Public, Relays::Disabled] {
        let Ok(host) = parse_place(data, relays) else {
            continue;
        };
        assert!(data.len() <= MAX_PLACE_BYTES);
        let written = place_bytes(&host, relays).unwrap();
        assert_eq!(parse_place(&written, relays).unwrap(), host);
        match relays {
            Relays::Public => {
                assert!(host.direct().is_empty());
                assert_eq!(host.relay().map(|relay| relay.scheme()), Some("https"));
            }
            Relays::Disabled => assert!(host.relay().is_none() && !host.direct().is_empty()),
        }
    }
});
