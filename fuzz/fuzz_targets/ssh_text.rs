#![no_main]

libfuzzer_sys::fuzz_target!(|text: &str| {
    let _ = mahi_ssh::KnownHosts::parse(text);
    let _ = mahi_ssh::SshRemote::parse(text);
});
