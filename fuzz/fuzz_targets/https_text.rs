#![no_main]

libfuzzer_sys::fuzz_target!(|text: &str| {
    let _ = mahi_http::HttpsRemote::parse(text);
    let (proxy, no_proxy) = text.split_once('\n').unwrap_or((text, ""));
    if let Ok(Some(setting)) = mahi_http::ProxySetting::from_values(Some(proxy), Some(no_proxy)) {
        for host in no_proxy.split(',') {
            let _ = setting.for_host(host);
        }
    }
});
