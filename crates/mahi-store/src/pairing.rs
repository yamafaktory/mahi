use std::sync::atomic::AtomicBool;

use gix::{
    bstr::ByteSlice,
    objs::{
        Commit,
        Kind,
    },
    protocol::transport::client::blocking_io::Transport,
    remote::{
        Direction,
        fetch::Tags,
        ref_map,
    },
};

use crate::{
    EntryKind,
    ObjectId,
    Pushed,
    Store,
    StoreError,
    push::{
        Command,
        advertisement,
        finish_without_commands,
        settle,
    },
    store::generic_signature,
};

/// Where pairing refs live: `refs/mahi/pair/<slot>`.
pub const PAIR_PREFIX: &str = "refs/mahi/pair/";
/// The name of the one blob a pairing commit's tree holds.
pub const PLACE_ENTRY: &str = "where";
/// The most a pairing commit's `where` blob may hold.
pub const MAX_PLACE_BYTES: u64 = 1024;
const MAX_PAIRING_COMMIT_BYTES: u64 = 2048;
const MAX_PAIRING_TREE_BYTES: u64 = 128;
const MAX_PAIR_SLOT: u16 = 999;

fn pair_ref(slot: u16) -> String {
    format!("{PAIR_PREFIX}{slot}")
}

fn slot_of(name: &str) -> Option<u16> {
    let digits = name.strip_prefix(PAIR_PREFIX)?;
    let plain = !digits.is_empty()
        && digits.len() <= 3
        && !digits.starts_with('0')
        && digits.bytes().all(|byte| byte.is_ascii_digit());
    plain
        .then(|| digits.parse().ok())
        .flatten()
        .filter(|slot| (1..=MAX_PAIR_SLOT).contains(slot))
}

impl Store {
    /// Writes a pairing commit: no parent, the fixed committer and a timestamp of zero, and a
    /// tree that holds only `place` as its `where` blob. No ref points at it.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::TooLarge`] if `place` is larger than [`MAX_PLACE_BYTES`], or
    /// [`StoreError::Git`] if writing fails.
    pub fn write_pairing(&self, place: &[u8]) -> Result<ObjectId, StoreError> {
        if place.len() as u64 > MAX_PLACE_BYTES {
            return Err(StoreError::TooLarge {
                id: ObjectId::null(gix::hash::Kind::Sha1),
                limit: MAX_PLACE_BYTES,
            });
        }
        let blob = self.write_blob(place)?;
        let tree = self.write_tree(&[(PLACE_ENTRY, EntryKind::Blob, blob)])?;
        let commit = Commit {
            tree,
            parents: Vec::new().into(),
            author: generic_signature(),
            committer: generic_signature(),
            encoding: None,
            message: "pairing".into(),
            extra_headers: Vec::new(),
        };
        Ok(self.repo.write_object(&commit)?.detach())
    }

    /// Lists the pairing refs the remote `transport` reaches advertises for a push, as slots
    /// with the commit each points to; refs under the prefix that do not name a slot from 1 to
    /// 999 are left out.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::PushFailed`] if the remote does not speak the protocol mahi needs
    /// or lists more refs than mahi reads, or [`StoreError::Git`] if the transport fails.
    pub fn remote_pairings<T: Transport>(
        &self,
        mut transport: T,
    ) -> Result<Vec<(u16, ObjectId)>, StoreError> {
        let advertised =
            advertisement(&mut transport, &|name| slot_of(name).is_some(), &|_| false)?;
        finish_without_commands(&mut transport)?;
        let mut pairings: Vec<(u16, ObjectId)> = advertised
            .wanted
            .iter()
            .filter_map(|(name, id)| slot_of(name).map(|slot| (slot, *id)))
            .collect();
        pairings.sort_unstable();
        Ok(pairings)
    }

    /// Creates the pairing ref for `slot` on the remote at `commit`, only if the remote has no
    /// ref there: a taken slot is [`Pushed::Behind`] and nothing is sent, and one taken while
    /// this push ran is [`Pushed::Refused`] by the remote, which the caller treats as taken
    /// too.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::PushFailed`] if the remote does not speak the protocol mahi needs
    /// or cannot unpack what was sent, [`StoreError::Interrupted`] if `interrupt` is set, or
    /// [`StoreError::Git`] if the transport or building the pack fails.
    pub fn push_pairing<T: Transport>(
        &self,
        mut transport: T,
        slot: u16,
        commit: ObjectId,
        interrupt: &AtomicBool,
    ) -> Result<Pushed, StoreError> {
        let name = pair_ref(slot);
        let advertised = advertisement(&mut transport, &|other| other == name, &|_| false)?;
        if advertised.wanted.contains_key(&name) {
            finish_without_commands(&mut transport)?;
            return Ok(Pushed::Behind);
        }
        let tree = self.commit_tree(commit)?;
        let Some(blob) = self
            .commit_blobs(commit)?
            .into_iter()
            .find(|(entry, _)| entry == PLACE_ENTRY)
            .map(|(_, id)| id)
        else {
            finish_without_commands(&mut transport)?;
            return Err(StoreError::WrongObject {
                id: commit,
                expected: Kind::Blob,
            });
        };
        let commands: Vec<Command> = vec![(name.clone(), None, commit)];
        let report = self.send(
            &mut transport,
            &commands,
            (advertised.atomic, &[commit, tree, blob]),
            interrupt,
        )?;
        let mut outcome = Pushed::Updated;
        settle(&mut outcome, &report, &name);
        Ok(outcome)
    }

    /// Deletes the pairing ref for `slot` on the remote, only while it still points at
    /// `expected`: a ref already gone is [`Pushed::UpToDate`], and one that points elsewhere is
    /// [`Pushed::Behind`] and left alone.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::PushFailed`] if the remote does not speak the protocol mahi needs
    /// or does not offer `delete-refs`, [`StoreError::Interrupted`] if `interrupt` is set, or
    /// [`StoreError::Git`] if the transport fails.
    pub fn delete_pairing<T: Transport>(
        &self,
        mut transport: T,
        slot: u16,
        expected: ObjectId,
        interrupt: &AtomicBool,
    ) -> Result<Pushed, StoreError> {
        let name = pair_ref(slot);
        let advertised = advertisement(&mut transport, &|other| other == name, &|_| false)?;
        let current = advertised.wanted.get(&name).copied();
        let outcome = match current {
            None => Some(Pushed::UpToDate),
            Some(id) if id != expected => Some(Pushed::Behind),
            Some(_) if !advertised.delete_refs => {
                finish_without_commands(&mut transport)?;
                return Err(StoreError::PushFailed(
                    "the remote does not offer delete-refs".to_owned(),
                ));
            }
            Some(_) => None,
        };
        if let Some(outcome) = outcome {
            finish_without_commands(&mut transport)?;
            return Ok(outcome);
        }
        let null = ObjectId::null(gix::hash::Kind::Sha1);
        let commands: Vec<Command> = vec![(name.clone(), Some(expected), null)];
        let report = self.send(
            &mut transport,
            &commands,
            (advertised.atomic, &[]),
            interrupt,
        )?;
        let mut outcome = Pushed::Updated;
        settle(&mut outcome, &report, &name);
        Ok(outcome)
    }

    /// Fetches the pairing ref for `slot` from the remote `transport` reaches without writing
    /// any ref, and returns its `where` blob, or `None` when the remote has no such ref.
    ///
    /// What the remote sent is untrusted: the commit must have no parent and be at most
    /// 2 KiB, its tree must hold exactly one entry, the `where` blob, in at most 128 bytes, and
    /// the blob must be at most [`MAX_PLACE_BYTES`], each checked from its header before it is
    /// loaded. The fetch itself takes whatever the remote sends for the ref, so `transport`
    /// must carry a small read budget, a few KiB, to keep a forged ref from pulling a whole
    /// history into the repository.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::WrongObject`] or [`StoreError::TooLarge`] if the pairing commit
    /// is not of that shape, or [`StoreError::Git`] if the fetch fails or is interrupted.
    pub fn fetch_pairing<T: Transport>(
        &self,
        transport: T,
        slot: u16,
        interrupt: &AtomicBool,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let url = transport.to_url().into_owned();
        let name = pair_ref(slot);
        let remote = self
            .repo
            .remote_at(url.as_bstr())
            .map_err(gix::Error::from_error)?
            .with_fetch_tags(Tags::None)
            .with_refspecs([name.as_str()], Direction::Fetch)
            .map_err(gix::Error::from_error)?;
        let prepared = remote
            .to_connection_with_transport(transport)
            .with_credentials(|_| Ok(None))
            .prepare_fetch(gix::progress::Discard, ref_map::Options::default())
            .map_err(gix::Error::from_error)?;
        let Some(commit) = prepared
            .ref_map()
            .mappings
            .iter()
            .find_map(|mapping| mapping.remote.as_id().map(ToOwned::to_owned))
        else {
            return Ok(None);
        };
        prepared
            .receive(gix::progress::Discard, interrupt)
            .map_err(gix::Error::from_error)?;
        self.read_pairing(commit).map(Some)
    }

    fn read_pairing(&self, commit: ObjectId) -> Result<Vec<u8>, StoreError> {
        self.require_bounded(commit, Kind::Commit, MAX_PAIRING_COMMIT_BYTES)?;
        let wrong = |expected| StoreError::WrongObject {
            id: commit,
            expected,
        };
        if self.parent(commit)?.is_some() {
            return Err(wrong(Kind::Commit));
        }
        let tree = self.commit_tree(commit)?;
        self.require_bounded(tree, Kind::Tree, MAX_PAIRING_TREE_BYTES)?;
        let entries = self.repo.find_tree(tree)?.iter().count();
        let blobs = self.commit_blobs(commit)?;
        let [(entry, blob)] = blobs.as_slice() else {
            return Err(wrong(Kind::Tree));
        };
        if entries != 1 || entry != PLACE_ENTRY {
            return Err(wrong(Kind::Tree));
        }
        self.read_blob(*blob, MAX_PLACE_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_slots_from_1_to_999_written_plainly_are_pairing_refs() {
        assert_eq!(slot_of("refs/mahi/pair/1"), Some(1));
        assert_eq!(slot_of("refs/mahi/pair/999"), Some(999));
        for name in [
            "refs/mahi/pair/0",
            "refs/mahi/pair/1000",
            "refs/mahi/pair/012",
            "refs/mahi/pair/",
            "refs/mahi/pair/1a",
            "refs/mahi/pair/1/x",
            "refs/heads/1",
        ] {
            assert_eq!(slot_of(name), None, "{name}");
        }
    }

    #[test]
    fn a_pairing_commit_reads_back_and_other_shapes_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        gix::init(dir.path()).unwrap();
        let store = Store::open(dir.path()).unwrap();
        let commit = store.write_pairing(b"place").unwrap();
        assert_eq!(store.read_pairing(commit).unwrap(), b"place");
        assert!(store.parent(commit).unwrap().is_none());
        assert!(matches!(
            store.write_pairing(&[0; 1025]),
            Err(StoreError::TooLarge { .. })
        ));

        let blob = store.write_blob(b"place").unwrap();
        let other = store.write_blob(b"x").unwrap();
        let extra = store
            .write_tree(&[
                (PLACE_ENTRY, EntryKind::Blob, blob),
                ("more", EntryKind::Blob, other),
            ])
            .unwrap();
        let renamed = store
            .write_tree(&[("there", EntryKind::Blob, blob)])
            .unwrap();
        let inner = store.write_tree(&[("x", EntryKind::Blob, other)]).unwrap();
        let nested = store
            .write_tree(&[
                (PLACE_ENTRY, EntryKind::Blob, blob),
                ("dir", EntryKind::Tree, inner),
            ])
            .unwrap();
        for tree in [extra, renamed, nested] {
            let commit = store
                .repo
                .write_object(&Commit {
                    tree,
                    parents: Vec::new().into(),
                    author: generic_signature(),
                    committer: generic_signature(),
                    encoding: None,
                    message: "pairing".into(),
                    extra_headers: Vec::new(),
                })
                .unwrap()
                .detach();
            assert!(matches!(
                store.read_pairing(commit),
                Err(StoreError::WrongObject { .. })
            ));
        }
        let child = store
            .repo
            .write_object(&Commit {
                tree: store.commit_tree(commit).unwrap(),
                parents: vec![commit].into(),
                author: generic_signature(),
                committer: generic_signature(),
                encoding: None,
                message: "pairing".into(),
                extra_headers: Vec::new(),
            })
            .unwrap()
            .detach();
        assert!(matches!(
            store.read_pairing(child),
            Err(StoreError::WrongObject { .. })
        ));
        let large = store.write_blob(&[1; 2048]).unwrap();
        let tree = store
            .write_tree(&[(PLACE_ENTRY, EntryKind::Blob, large)])
            .unwrap();
        let commit = store
            .repo
            .write_object(&Commit {
                tree,
                parents: Vec::new().into(),
                author: generic_signature(),
                committer: generic_signature(),
                encoding: None,
                message: "pairing".into(),
                extra_headers: Vec::new(),
            })
            .unwrap()
            .detach();
        assert!(matches!(
            store.read_pairing(commit),
            Err(StoreError::TooLarge { .. })
        ));
    }
}
