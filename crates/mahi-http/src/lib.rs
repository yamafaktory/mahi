//! mahi's HTTPS transport: git remotes over HTTPS, through the proxy the environment names.

mod client;
mod proxy;
mod remote;

pub use client::{
    Client,
    ConnectError,
    HttpsAccess,
    HttpsTransport,
    Roots,
    Token,
    client,
    connect,
    connect_within,
};
pub use proxy::{
    ProxyError,
    ProxySetting,
};
pub use remote::{
    HttpsRemote,
    RemoteError,
};
