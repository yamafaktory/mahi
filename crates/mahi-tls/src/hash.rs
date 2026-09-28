use std::marker::PhantomData;

use rustls::crypto::hash::{
    Context,
    Hash,
    HashAlgorithm,
    Output,
};
use sha2::{
    Digest,
    Sha256,
    Sha384,
};

pub(crate) static SHA256: Sha<Sha256> = Sha::new(HashAlgorithm::SHA256);
pub(crate) static SHA384: Sha<Sha384> = Sha::new(HashAlgorithm::SHA384);

/// A SHA-2 hash for rustls.
pub(crate) struct Sha<D> {
    algorithm: HashAlgorithm,
    digest: PhantomData<fn() -> D>,
}

impl<D> Sha<D> {
    const fn new(algorithm: HashAlgorithm) -> Self {
        Self {
            algorithm,
            digest: PhantomData,
        }
    }
}

impl<D: Digest + Clone + Send + Sync + 'static> Hash for Sha<D> {
    fn start(&self) -> Box<dyn Context> {
        Box::new(Running(D::new()))
    }

    fn hash(&self, data: &[u8]) -> Output {
        Output::new(&D::digest(data))
    }

    fn output_len(&self) -> usize {
        <D as Digest>::output_size()
    }

    fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }
}

struct Running<D>(D);

impl<D: Digest + Clone + Send + Sync + 'static> Context for Running<D> {
    fn fork_finish(&self) -> Output {
        Output::new(&self.0.clone().finalize())
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(Self(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> Output {
        Output::new(&self.0.finalize())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::hex;

    #[test]
    fn digests_match_the_fips_180_vectors_whole_and_in_parts() {
        let cases: [(&dyn Hash, &str); 2] = [
            (
                &SHA256,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                &SHA384,
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163
                 1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
            ),
        ];
        for (hash, expected) in cases {
            let expected = hex(expected);
            assert_eq!(hash.hash(b"abc").as_ref(), expected);
            assert_eq!(hash.output_len(), expected.len());
            let mut context = hash.start();
            context.update(b"a");
            let fork = context.fork();
            context.update(b"bc");
            assert_eq!(context.fork_finish().as_ref(), expected);
            assert_eq!(context.finish().as_ref(), expected);
            assert_eq!(fork.finish().as_ref(), hash.hash(b"a").as_ref());
        }
    }
}
