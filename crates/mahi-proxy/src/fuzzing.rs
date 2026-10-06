//! Entry points for the fuzz targets in `fuzz/`, built only with `--cfg fuzzing` or, to lint them,
//! the `fuzzing` feature: each takes untrusted bytes as the agent could send them, and must neither
//! panic nor use more than its bounds allow.

use crate::proxy;

/// Parses `data` as the head of a request the agent sends the proxy.
pub fn request(data: &[u8]) {
    let _ = proxy::parse(data);
}
