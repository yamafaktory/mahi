#![no_main]

use std::str::FromStr;

use mahi_core::{
    AgentName,
    AgentSlot,
    ParticipantName,
    ThreadId,
    ThreadRef,
};

fn round_trips<T: FromStr + ToString>(text: &str) {
    if let Ok(value) = T::from_str(text) {
        assert_eq!(value.to_string(), text);
    }
}

libfuzzer_sys::fuzz_target!(|text: &str| {
    round_trips::<ThreadId>(text);
    round_trips::<ThreadRef>(text);
    round_trips::<AgentSlot>(text);
    round_trips::<ParticipantName>(text);
    round_trips::<AgentName>(text);
    let _ = mahi_identity::CredentialName::from_str(text);
    let _ = mahi_proxy::HostName::from_str(text);
});
