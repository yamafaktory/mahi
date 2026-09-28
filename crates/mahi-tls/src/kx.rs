use rustls::{
    Error,
    NamedGroup,
    PeerMisbehaved,
    crypto::{
        ActiveKeyExchange,
        GetRandomFailed,
        SharedSecret,
        SupportedKxGroup,
    },
};
use x25519_dalek::{
    PublicKey,
    StaticSecret,
};
use zeroize::Zeroizing;

pub(crate) static X25519: &dyn SupportedKxGroup = &X25519Group;

#[derive(Debug)]
struct X25519Group;

impl SupportedKxGroup for X25519Group {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut secret = Zeroizing::new([0_u8; 32]);
        getrandom::fill(secret.as_mut_slice()).map_err(|_| GetRandomFailed)?;
        Ok(Box::new(X25519Exchange::new(StaticSecret::from(*secret))))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct X25519Exchange {
    secret: StaticSecret,
    public: PublicKey,
}

impl X25519Exchange {
    fn new(secret: StaticSecret) -> Self {
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }
}

impl ActiveKeyExchange for X25519Exchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let peer =
            <[u8; 32]>::try_from(peer_pub_key).map_err(|_| PeerMisbehaved::InvalidKeyShare)?;
        let shared = self.secret.diffie_hellman(&PublicKey::from(peer));
        if !shared.was_contributory() {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        Ok(SharedSecret::from(shared.as_bytes().as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        self.public.as_bytes()
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::hex;

    fn exchange(secret: &str) -> X25519Exchange {
        let secret = <[u8; 32]>::try_from(hex(secret)).unwrap();
        X25519Exchange::new(StaticSecret::from(secret))
    }

    #[test]
    fn the_shared_secret_matches_rfc_7748_section_6_1() {
        let alice = exchange("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        assert_eq!(
            alice.pub_key(),
            hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        let bob = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        assert_eq!(
            Box::new(alice).complete(&bob).unwrap().secret_bytes(),
            hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        );
    }

    #[test]
    fn fresh_exchanges_agree_and_bad_peer_keys_are_refused() {
        let first = X25519.start().unwrap();
        let second = X25519.start().unwrap();
        assert_eq!(first.group(), NamedGroup::X25519);
        let first_public = first.pub_key().to_vec();
        let second_public = second.pub_key().to_vec();
        assert_ne!(first_public, second_public);
        assert_eq!(
            first.complete(&second_public).unwrap().secret_bytes(),
            second.complete(&first_public).unwrap().secret_bytes()
        );
        for bad in [vec![0_u8; 32], vec![1_u8; 31], vec![9_u8; 33]] {
            assert!(X25519.start().unwrap().complete(&bad).is_err());
        }
    }
}
