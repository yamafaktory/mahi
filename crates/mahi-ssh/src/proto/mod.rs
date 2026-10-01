#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the protocol is wired into the session in a later piece"
    )
)]

pub(crate) mod auth;
pub(crate) mod cipher;
pub(crate) mod kex;
pub(crate) mod message;
pub(crate) mod packet;
#[cfg(test)]
pub(crate) mod test_server;
pub(crate) mod transport;
pub(crate) mod wire;
