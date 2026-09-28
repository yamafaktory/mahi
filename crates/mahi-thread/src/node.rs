use std::{
    fmt,
    str::FromStr,
};

use ed25519_dalek::VerifyingKey;
use thiserror::Error;

const BYTES: usize = 32;
const HEX_DIGITS: usize = BYTES * 2;

/// The public key of a participant's iroh node, which names their machine on the live layer.
///
/// It is written as 64 lowercase hex digits, as iroh writes node ids. Points that are not on
/// the curve, points of small order, for which anyone can forge signatures, and non-canonical
/// encodings, which would give one key two ids, are refused.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId([u8; BYTES]);

/// Bytes or text that are not a usable node id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum NodeIdError {
    /// The text is not 64 lowercase hex digits.
    #[error("a node id is {HEX_DIGITS} lowercase hex digits")]
    Malformed,
    /// The key is not a valid ed25519 point, or is a point of small order.
    #[error("the node id is not a usable ed25519 key")]
    Weak,
}

impl NodeId {
    /// Accepts `bytes` if they are a usable ed25519 public key.
    ///
    /// # Errors
    ///
    /// Returns [`NodeIdError::Weak`] if they are not a point on the curve, or are a point of
    /// small order.
    pub fn from_bytes(bytes: [u8; BYTES]) -> Result<Self, NodeIdError> {
        let point = VerifyingKey::from_bytes(&bytes).map_err(|_| NodeIdError::Weak)?;
        if point.is_weak() || point.to_edwards().compress().to_bytes() != bytes {
            return Err(NodeIdError::Weak);
        }
        Ok(Self(bytes))
    }

    /// Returns the public key's bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; BYTES] {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({self})")
    }
}

impl FromStr for NodeId {
    type Err = NodeIdError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (pairs, []) = text.as_bytes().as_chunks::<2>() else {
            return Err(NodeIdError::Malformed);
        };
        if pairs.len() != BYTES {
            return Err(NodeIdError::Malformed);
        }
        let mut bytes = [0; BYTES];
        for (byte, [high, low]) in bytes.iter_mut().zip(pairs) {
            *byte = (hex_value(*high)? << 4) | hex_value(*low)?;
        }
        Self::from_bytes(bytes)
    }
}

fn hex_value(digit: u8) -> Result<u8, NodeIdError> {
    match digit {
        b'0'..=b'9' => Ok(digit - b'0'),
        b'a'..=b'f' => Ok(digit - b'a' + 10),
        _ => Err(NodeIdError::Malformed),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    fn node(seed: u8) -> NodeId {
        NodeId::from_bytes(
            SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap()
    }

    pub(crate) fn random_node() -> NodeId {
        let mut seed = [0_u8; 32];
        getrandom::fill(&mut seed).unwrap();
        NodeId::from_bytes(SigningKey::from_bytes(&seed).verifying_key().to_bytes()).unwrap()
    }

    #[test]
    fn a_node_id_round_trips_through_lowercase_hex() {
        let id = node(1);
        let text = id.to_string();
        assert_eq!(text.len(), HEX_DIGITS);
        assert!(
            text.bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        );
        assert_eq!(text.parse::<NodeId>().unwrap(), id);
        assert_eq!(format!("{id:?}"), format!("NodeId({text})"));
    }

    #[test]
    fn malformed_text_and_weak_points_are_refused() {
        let text = node(2).to_string();
        for bad in [
            String::new(),
            text[..62].to_owned(),
            format!("{text}00"),
            text.to_uppercase(),
            format!("g{}", &text[1..]),
        ] {
            assert_eq!(bad.parse::<NodeId>(), Err(NodeIdError::Malformed), "{bad}");
        }
        let mut identity = [0_u8; 32];
        identity[0] = 1;
        assert_eq!(NodeId::from_bytes(identity), Err(NodeIdError::Weak));
        assert_eq!(NodeId::from_bytes([0; 32]), Err(NodeIdError::Weak));
        let mut non_canonical = [0xff_u8; 32];
        non_canonical[0] = 0xf0;
        non_canonical[31] = 0x7f;
        assert!(VerifyingKey::from_bytes(&non_canonical).is_ok());
        assert_eq!(NodeId::from_bytes(non_canonical), Err(NodeIdError::Weak));
    }
}
