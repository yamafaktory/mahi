use std::fmt;

use thiserror::Error;

/// The proxy that HTTPS requests go through, from `HTTPS_PROXY`, and the hosts `NO_PROXY`
/// lets reach directly.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxySetting {
    url: String,
    bypass: Vec<String>,
    everything_bypassed: bool,
}

/// Why `HTTPS_PROXY` cannot be used. The value itself is never included, since it may hold a
/// password.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProxyError {
    /// The proxy is not `http://host:port`, or a bare `host:port`.
    #[error("HTTPS_PROXY must be an http:// proxy, such as http://proxy.example.com:3128")]
    Unsupported,
}

impl ProxySetting {
    /// Reads the values of `HTTPS_PROXY` and `NO_PROXY`, or `None` when there is no proxy.
    /// `NO_PROXY` is a comma-separated list of host names, each also matching its subdomains
    /// (with or without a leading dot), and `*` for every host.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::Unsupported`] if the proxy is not an HTTP one.
    pub fn from_values(
        https_proxy: Option<&str>,
        no_proxy: Option<&str>,
    ) -> Result<Option<Self>, ProxyError> {
        let Some(proxy) = https_proxy.map(str::trim).filter(|proxy| !proxy.is_empty()) else {
            return Ok(None);
        };
        let url = match proxy.split_once("://") {
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("http") && !rest.is_empty() => {
                format!("http://{rest}")
            }
            Some(_) => return Err(ProxyError::Unsupported),
            None => format!("http://{proxy}"),
        };
        let mut bypass = Vec::new();
        let mut everything_bypassed = false;
        for entry in no_proxy.unwrap_or_default().split(',') {
            let entry = entry.trim();
            if entry == "*" {
                everything_bypassed = true;
                continue;
            }
            if let Some(host) = no_proxy_host(entry) {
                bypass.push(host);
            }
        }
        Ok(Some(Self {
            url,
            bypass,
            everything_bypassed,
        }))
    }

    /// Returns the proxy URL to reach `host` through, or `None` when `NO_PROXY` lets it be
    /// reached directly.
    #[must_use]
    pub fn for_host(&self, host: &str) -> Option<&str> {
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let bypassed = self.everything_bypassed
            || self.bypass.iter().any(|entry| {
                host == *entry
                    || host
                        .strip_suffix(entry.as_str())
                        .is_some_and(|rest| rest.ends_with('.'))
            });
        (!bypassed).then_some(self.url.as_str())
    }
}

/// Returns the host a `NO_PROXY` entry names, without a leading or trailing dot, a port, or
/// the brackets of an IPv6 address; a bare IPv6 address is kept whole.
fn no_proxy_host(entry: &str) -> Option<String> {
    let entry = entry.trim_start_matches('.');
    let host = if let Some(bracketed) = entry.strip_prefix('[') {
        bracketed
            .split_once(']')
            .map_or(bracketed, |(host, _)| host)
    } else if entry.matches(':').count() == 1 {
        entry
            .split_once(':')
            .filter(|(_, port)| port.bytes().all(|byte| byte.is_ascii_digit()))
            .map_or(entry, |(host, _)| host)
    } else {
        entry
    };
    let host = host.trim_end_matches('.');
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

impl fmt::Debug for ProxySetting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxySetting")
            .field("bypass", &self.bypass)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_go_through_the_proxy_unless_no_proxy_names_them() {
        let proxy = ProxySetting::from_values(
            Some("proxy.corp:3128"),
            Some(" .internal.corp, git.example.com:443 ,*.bad, ,localhost"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(proxy.for_host("github.com"), Some("http://proxy.corp:3128"));
        for direct in [
            "internal.corp",
            "git.internal.corp",
            "GIT.example.com",
            "localhost",
        ] {
            assert_eq!(proxy.for_host(direct), None, "{direct}");
        }
        assert_eq!(
            proxy.for_host("notinternal.corp"),
            Some("http://proxy.corp:3128")
        );
        let ipv6 = ProxySetting::from_values(
            Some("HTTP://proxy:3128"),
            Some("::1,[2001:db8::1]:443,example.org."),
        )
        .unwrap()
        .unwrap();
        for direct in ["::1", "[2001:db8::1]", "git.example.org", "example.org."] {
            assert_eq!(ipv6.for_host(direct), None, "{direct}");
        }
        assert_eq!(ipv6.for_host("2001:db8::2"), Some("http://proxy:3128"));
        let all = ProxySetting::from_values(Some("http://u:p@proxy:8080"), Some("*"))
            .unwrap()
            .unwrap();
        assert_eq!(all.for_host("github.com"), None);
        assert!(!format!("{all:?}").contains("u:p"));
        assert_eq!(ProxySetting::from_values(None, Some("x")), Ok(None));
        assert_eq!(ProxySetting::from_values(Some("  "), None), Ok(None));
        for bad in ["socks5://proxy:1080", "https://proxy:443", "http://"] {
            assert_eq!(
                ProxySetting::from_values(Some(bad), None),
                Err(ProxyError::Unsupported),
                "{bad}"
            );
        }
    }
}
