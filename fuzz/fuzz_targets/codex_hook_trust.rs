#![no_main]

use mahi_agent::codex::HookTrust;

const HOOKS: &str = "/state/t/alice.codex/hooks.json";

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let recorded = HookTrust::recorded(text, HOOKS);
    let saved = HookTrust::from_saved(text);
    assert_eq!(HookTrust::from_saved(&saved.to_saved()), saved);
    for trust in [&recorded, &saved] {
        if let Some(added) = trust.added_to(text, HOOKS) {
            assert!(added.starts_with(text));
            assert_eq!(trust.added_to(&added, HOOKS), None);
            let after = HookTrust::recorded(&added, HOOKS);
            for ((after, before), given) in after
                .hashes()
                .iter()
                .zip(recorded.hashes())
                .zip(trust.hashes())
            {
                if before.is_some() {
                    assert_eq!(after, before);
                } else {
                    assert!(after.is_none() || after == given);
                }
            }
        }
    }
});
