use ed25519_dalek::SigningKey;
use mahi_thread::NodeId;

pub(crate) fn random_node() -> NodeId {
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed).unwrap();
    NodeId::from_bytes(SigningKey::from_bytes(&seed).verifying_key().to_bytes()).unwrap()
}
