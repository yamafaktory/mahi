#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the protocol is wired into the session in a later piece"
    )
)]

pub(crate) mod message;
pub(crate) mod wire;
