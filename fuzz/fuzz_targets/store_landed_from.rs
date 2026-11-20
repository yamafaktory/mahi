#![no_main]

use mahi_store::{
    landed_from,
    landing_trailers,
};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let landed = landed_from(data);
    assert!(landed.len() <= 64);
    for named in &landed {
        assert!(named.agents.len() <= 64);
        let written = landing_trailers(named.thread, &named.agents);
        assert_eq!(landed_from(written.as_bytes()), [named.clone()]);
    }
});
