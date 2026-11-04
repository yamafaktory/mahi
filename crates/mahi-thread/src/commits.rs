use std::error::Error;

use mahi_core::{
    ThreadId,
    ThreadRef,
};
use mahi_store::{
    CommitSigner,
    ObjectId,
    Store,
    StoreError,
    appended_trailers,
};
use ssh_key::{
    HashAlg,
    LineEnding,
    SshSig,
};
use thiserror::Error;

use crate::{
    ParticipantKey,
    SshSigner,
};

/// The SSHSIG namespace git signs commits in.
pub const COMMIT_NAMESPACE: &str = "git";

const THREAD_TRAILER: &str = "Mahi-Thread: ";

/// Returns `message`, a snapshot's, with the trailer that names its thread `thread`: joined to
/// its trailer block, or starting one.
#[must_use]
pub fn snapshot_message(message: &str, thread: ThreadId) -> String {
    let trailer = format!("{THREAD_TRAILER}{thread}\n");
    appended_trailers(message.into(), &trailer).to_string()
}

/// Writes a snapshot of `tree` on `parent` in `snapshots`, signed by `signer`, its message
/// `message` with the trailer that names the ref's thread, and returns it.
///
/// # Errors
///
/// Returns the errors of [`Store::append_signed`].
pub fn append_snapshot(
    store: &Store,
    snapshots: &ThreadRef,
    (parent, tree): (Option<ObjectId>, ObjectId),
    message: &str,
    signer: &dyn CommitSigner,
) -> Result<ObjectId, StoreError> {
    let message = snapshot_message(message, snapshots.thread());
    store.append_signed(snapshots, parent, tree, &message, signer)
}

/// Says whether a snapshot's `message` names its thread `thread`, and no other.
#[must_use]
pub fn names_thread(message: &[u8], thread: ThreadId) -> bool {
    named_thread(message, thread) == NamedThread::This
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NamedThread {
    None,
    This,
    Other,
}

pub(crate) fn named_thread(message: &[u8], thread: ThreadId) -> NamedThread {
    let mut named = NamedThread::None;
    let lines = message.split(|byte| *byte == b'\n');
    for line in lines {
        let Some(value) = line.strip_prefix(THREAD_TRAILER.as_bytes()) else {
            continue;
        };
        let parsed = std::str::from_utf8(value)
            .ok()
            .and_then(|value| value.parse::<ThreadId>().ok());
        if parsed != Some(thread) {
            return NamedThread::Other;
        }
        named = NamedThread::This;
    }
    named
}

#[derive(Debug, Error)]
#[error("the signature is not by the signing key over the commit")]
struct NotOwnSignature;

/// Signs commits as git does with an SSH key, through an [`SshSigner`]. A signature that does
/// not check against the signer's own key, over the commit in the `git` namespace, is refused.
#[derive(Debug)]
pub struct GitSigner<S>(pub S);

impl<S: SshSigner> CommitSigner for GitSigner<S> {
    fn sign_commit(&self, payload: &[u8]) -> Result<String, Box<dyn Error + Send + Sync>> {
        let signature = self
            .0
            .sign_sshsig(COMMIT_NAMESPACE, HashAlg::Sha512, payload)?;
        self.0
            .public_key()
            .verify(COMMIT_NAMESPACE, payload, &signature)
            .map_err(|_| NotOwnSignature)?;
        Ok(signature.to_pem(LineEnding::LF)?)
    }
}

/// Returns whether `commit` carries a git SSH signature made by `key`; an unsigned commit, or
/// one whose signature is malformed, in another namespace or by another key, is not.
///
/// # Errors
///
/// Returns [`StoreError`] if the commit cannot be read, is larger than 64 KiB or is malformed
/// before its signature; a caller checking fetched commits must refuse them then too.
pub fn signed_by(
    store: &Store,
    commit: ObjectId,
    key: &ParticipantKey,
) -> Result<bool, StoreError> {
    let Some(signature) = store.commit_signature(commit)? else {
        return Ok(false);
    };
    let Ok(parsed) = SshSig::from_pem(signature.armored.trim_end()) else {
        return Ok(false);
    };
    Ok(key.verifies(COMMIT_NAMESPACE, &signature.payload, &parsed))
}

#[cfg(test)]
mod tests {
    use mahi_core::{
        RefKind,
        ThreadId,
        ThreadRef,
    };
    use mahi_store::EntryKind;
    use ssh_key::{
        Algorithm,
        PrivateKey,
        rand_core::OsRng,
    };

    use super::*;

    struct Fixed(String);

    impl CommitSigner for Fixed {
        fn sign_commit(&self, _: &[u8]) -> Result<String, Box<dyn Error + Send + Sync>> {
            Ok(self.0.clone())
        }
    }

    pub(crate) fn ed25519() -> PrivateKey {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()
    }

    #[test]
    fn a_snapshot_names_its_thread_in_its_trailer_block_and_only_an_exact_name_counts() {
        let thread: ThreadId = "0123456789abcdef0123456789abcdef".parse().unwrap();
        let other: ThreadId = "fedcba9876543210fedcba9876543210".parse().unwrap();
        let named = format!("Mahi-Thread: {thread}");
        assert_eq!(
            snapshot_message("snapshot", thread),
            format!("snapshot\n\n{named}\n")
        );
        assert_eq!(
            snapshot_message("snapshot\n", thread),
            format!("snapshot\n\n{named}\n")
        );
        assert_eq!(
            snapshot_message("snapshot\n\nMahi-Turn-End: alice.claude\n", thread),
            format!("snapshot\n\nMahi-Turn-End: alice.claude\n{named}\n")
        );
        let cases: [(String, NamedThread); 8] = [
            ("snapshot".to_owned(), NamedThread::None),
            (snapshot_message("snapshot", thread), NamedThread::This),
            (snapshot_message("snapshot", other), NamedThread::Other),
            (
                format!("snapshot\n\n{named}\nMahi-Thread: {other}\n"),
                NamedThread::Other,
            ),
            (format!("snapshot\r\n\r\n{named}\r\n"), NamedThread::Other),
            (format!("snapshot\n\n{named} \n"), NamedThread::Other),
            (
                format!(
                    "snapshot\n\nMahi-Thread: {}\n",
                    thread.to_string().to_uppercase()
                ),
                NamedThread::Other,
            ),
            (
                "snapshot\n\nMahi-Thread: 0123\n".to_owned(),
                NamedThread::Other,
            ),
        ];
        for (message, expected) in cases {
            assert_eq!(
                named_thread(message.as_bytes(), thread),
                expected,
                "{message:?}"
            );
        }
        assert!(names_thread(
            snapshot_message("snapshot", thread).as_bytes(),
            thread
        ));
        assert!(!names_thread(b"snapshot", thread));
    }

    #[test]
    fn a_commit_is_signed_by_the_key_that_signed_it_and_no_other() {
        let dir = tempfile::tempdir().unwrap();
        gix::init(dir.path()).unwrap();
        let store = Store::open(dir.path()).unwrap();
        let thread_ref = ThreadRef::new(ThreadId::random().unwrap(), RefKind::Meta);
        let content = store.write_blob(b"x").unwrap();
        let tree = store
            .write_tree(&[("x", EntryKind::Blob, content)])
            .unwrap();
        let (alice, bob) = (ed25519(), ed25519());
        let alice_key = ParticipantKey::from_public_key(alice.public_key()).unwrap();
        let bob_key = ParticipantKey::from_public_key(bob.public_key()).unwrap();
        let signed = store
            .append_signed(&thread_ref, None, tree, "m", &GitSigner(alice))
            .unwrap();
        assert!(signed_by(&store, signed, &alice_key).unwrap());
        assert!(!signed_by(&store, signed, &bob_key).unwrap());
        let plain = store.append(&thread_ref, Some(signed), tree, "n").unwrap();
        assert!(!signed_by(&store, plain, &alice_key).unwrap());
        let elsewhere = bob
            .sign("file", HashAlg::Sha512, b"anything")
            .unwrap()
            .to_pem(LineEnding::LF)
            .unwrap();
        let wrong_namespace = store
            .append_signed(&thread_ref, Some(plain), tree, "o", &Fixed(elsewhere))
            .unwrap();
        assert!(!signed_by(&store, wrong_namespace, &bob_key).unwrap());
        let garbage = store
            .append_signed(
                &thread_ref,
                Some(wrong_namespace),
                tree,
                "p",
                &Fixed("not a signature".to_owned()),
            )
            .unwrap();
        assert!(!signed_by(&store, garbage, &alice_key).unwrap());
    }

    #[test]
    fn a_signed_commit_changed_after_signing_is_not_signed_by_anyone() {
        let dir = tempfile::tempdir().unwrap();
        let repo = gix::init(dir.path()).unwrap();
        let store = Store::open(dir.path()).unwrap();
        let thread_ref = ThreadRef::new(ThreadId::random().unwrap(), RefKind::Meta);
        let tree = store.write_tree(&[]).unwrap();
        let alice = ed25519();
        let alice_key = ParticipantKey::from_public_key(alice.public_key()).unwrap();
        let signed = store
            .append_signed(&thread_ref, None, tree, "original", &GitSigner(alice))
            .unwrap();
        let bytes = repo.find_object(signed).unwrap().data.clone();
        let text = String::from_utf8(bytes).unwrap();
        let tampered = text.replace("original", "tampered");
        assert_ne!(tampered, text);
        let forged = gix::objs::Write::write_buf(
            &repo.objects,
            gix::object::Kind::Commit,
            tampered.as_bytes(),
        )
        .unwrap();
        assert!(signed_by(&store, signed, &alice_key).unwrap());
        assert!(!signed_by(&store, forged, &alice_key).unwrap());
    }

    struct Impostor(PrivateKey, PrivateKey);

    impl SshSigner for Impostor {
        fn public_key(&self) -> &ssh_key::PublicKey {
            self.0.public_key()
        }

        fn sign_sshsig(
            &self,
            namespace: &str,
            hash: HashAlg,
            message: &[u8],
        ) -> Result<SshSig, crate::SignError> {
            Ok(self.1.sign(namespace, hash, message)?)
        }
    }

    #[test]
    fn a_signer_whose_signature_is_by_another_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        gix::init(dir.path()).unwrap();
        let store = Store::open(dir.path()).unwrap();
        let thread_ref = ThreadRef::new(ThreadId::random().unwrap(), RefKind::Meta);
        let tree = store.write_tree(&[]).unwrap();
        let signer = GitSigner(Impostor(ed25519(), ed25519()));
        assert!(matches!(
            store.append_signed(&thread_ref, None, tree, "m", &signer),
            Err(StoreError::Sign(_))
        ));
        assert_eq!(store.head(&thread_ref).unwrap(), None);
    }
}

#[cfg(test)]
mod git_tests {
    use std::process::Command;

    use mahi_core::{
        RefKind,
        ThreadId,
        ThreadRef,
    };
    use mahi_store::EntryKind;

    use super::{
        tests::ed25519,
        *,
    };

    #[test]
    fn git_verifies_the_commits_mahi_signs() {
        let dir = tempfile::tempdir().unwrap();
        gix::init(dir.path()).unwrap();
        let store = Store::open(dir.path()).unwrap();
        let thread_ref = ThreadRef::new(ThreadId::random().unwrap(), RefKind::Meta);
        let blob = store.write_blob(b"x").unwrap();
        let tree = store.write_tree(&[("x", EntryKind::Blob, blob)]).unwrap();
        let key = ed25519();
        let allowed = dir.path().join("allowed_signers");
        std::fs::write(
            &allowed,
            format!(
                "mahi@mahi.invalid {}\n",
                key.public_key().to_openssh().unwrap()
            ),
        )
        .unwrap();
        let commit = store
            .append_signed(&thread_ref, None, tree, "signed", &GitSigner(key))
            .unwrap();
        let output = Command::new("git")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .arg("-C")
            .arg(dir.path())
            .args(["-c", "gpg.format=ssh", "-c"])
            .arg(format!("gpg.ssh.allowedSignersFile={}", allowed.display()))
            .args(["verify-commit", &commit.to_string()])
            .output()
            .expect("git is installed");
        assert!(output.status.success(), "{output:?}");
    }
}
