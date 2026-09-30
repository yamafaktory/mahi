//! Entry points for the fuzz targets in `fuzz/`, built only with `--cfg fuzzing`: each takes
//! untrusted bytes as ssh-agent could answer them, and must neither panic nor use more than its
//! bounds allow.

use crate::ssh_agent;

/// Reads `data` as ssh-agent's answer to a sign request and to a key listing.
pub fn agent_answer(data: &[u8]) {
    let _ = ssh_agent::parse_signature(data);
    let _ = ssh_agent::parse_identities(data);
}
