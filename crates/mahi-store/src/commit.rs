use gix::{
    ObjectId,
    actor::Signature,
    bstr::BStr,
    date::Time,
    object::{
        Kind,
        tree::EntryKind,
    },
    objs::Commit,
};

use crate::{
    store::{
        CommitSigner,
        MAX_COMMIT_BYTES,
        Store,
        StoreError,
    },
    trailers::appended_trailers,
};

/// Who made a commit and when, as its author and committer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The person's name, as git's `user.name` holds it.
    pub name: String,
    /// The person's email, as git's `user.email` holds it.
    pub email: String,
    /// When, in seconds since the Unix epoch.
    pub seconds: i64,
    /// The time zone's offset from UTC, in seconds.
    pub offset: i32,
}

impl Identity {
    /// Returns `name` and `email` at the current time, in the local time zone when it is known.
    #[must_use]
    pub fn now(name: String, email: String) -> Self {
        let now = Time::now_local_or_utc();
        Self {
            name,
            email,
            seconds: now.seconds,
            offset: now.offset,
        }
    }
}

impl Store {
    /// Returns a tree holding `base`'s entries, with each of the file paths `paths` as `source`
    /// holds it: a file there is taken, and a file of `base` is removed where `source` holds
    /// none, a directory included, whose files come through their own paths.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::WrongObject`] if `base` or `source` is not a tree, or
    /// [`StoreError::Git`] if a tree cannot be read or written.
    pub fn tree_with_paths(
        &self,
        base: ObjectId,
        source: ObjectId,
        paths: &[&str],
    ) -> Result<ObjectId, StoreError> {
        self.require_kind(base, Kind::Tree)?;
        self.require_kind(source, Kind::Tree)?;
        let (source, old) = (self.repo.find_tree(source)?, self.repo.find_tree(base)?);
        let mut editor = self.repo.edit_tree(base)?;
        for &path in paths {
            let file = |tree: &gix::Tree<'_>| {
                tree.lookup_entry(path.split('/')).map(|entry| {
                    entry
                        .filter(|entry| !entry.mode().is_tree())
                        .map(|entry| (EntryKind::from(entry.mode()), entry.object_id()))
                })
            };
            match file(&source)? {
                Some((kind, id)) => {
                    editor.upsert(path, kind, id)?;
                }
                None if file(&old)?.is_some() => {
                    editor.remove(path)?;
                }
                None => {}
            }
        }
        Ok(editor.write()?.detach())
    }

    /// Writes a commit of `tree` on `parent` by `identity`, its message `message` with
    /// `trailers` added as [`Store::add_trailers`] adds them, signed by `signer`; it moves no
    /// ref.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::WrongObject`] if `tree` is not a tree or `parent` not a commit,
    /// [`StoreError::InvalidIdentity`] if the name or the email holds `<`, `>` or a line break,
    /// [`StoreError::CommitTooLarge`] if the commit would be larger than mahi reads,
    /// [`StoreError::Sign`] if `signer` cannot sign, or [`StoreError::Git`] if writing fails.
    pub fn write_commit(
        &self,
        (tree, parent): (ObjectId, ObjectId),
        (message, trailers): (&str, &str),
        identity: &Identity,
        signer: &dyn CommitSigner,
    ) -> Result<ObjectId, StoreError> {
        self.require_kind(tree, Kind::Tree)?;
        self.require_kind(parent, Kind::Commit)?;
        for part in [&identity.name, &identity.email] {
            if part.contains(['<', '>', '\n', '\r']) {
                return Err(StoreError::InvalidIdentity(part.clone()));
            }
        }
        let person = Signature {
            name: identity.name.as_str().into(),
            email: identity.email.as_str().into(),
            time: Time {
                seconds: identity.seconds,
                offset: identity.offset,
            },
        };
        let commit = Commit {
            tree,
            parents: vec![parent].into(),
            author: person.clone(),
            committer: person,
            encoding: None,
            message: appended_trailers(BStr::new(message), trailers),
            extra_headers: Vec::new(),
        };
        self.write_signed(commit, Some(signer), MAX_COMMIT_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::store::tests::{
        Recording,
        store,
        tree_of as tree,
    };

    fn alice() -> Identity {
        Identity {
            name: "Alice Example".to_owned(),
            email: "alice@example.com".to_owned(),
            seconds: 1_793_000_000,
            offset: 3600,
        }
    }

    #[test]
    fn a_tree_takes_only_the_paths_named_from_the_source() {
        let (_dir, store) = store();
        let base = tree(
            &store,
            &[
                ("kept.txt", EntryKind::Blob, b"kept"),
                ("src/a.rs", EntryKind::Blob, b"old a"),
                ("src/gone.rs", EntryKind::Blob, b"gone"),
                ("src/later.rs", EntryKind::Blob, b"old later"),
            ],
        );
        let source = tree(
            &store,
            &[
                ("kept.txt", EntryKind::Blob, b"changed but not named"),
                ("src/a.rs", EntryKind::Blob, b"new a"),
                ("src/later.rs", EntryKind::Blob, b"new later"),
                ("bin/run", EntryKind::BlobExecutable, b"#!/bin/sh"),
            ],
        );
        let built = store
            .tree_with_paths(base, source, &["src/a.rs", "src/gone.rs", "bin/run"])
            .unwrap();
        let expected = tree(
            &store,
            &[
                ("kept.txt", EntryKind::Blob, b"kept"),
                ("src/a.rs", EntryKind::Blob, b"new a"),
                ("src/later.rs", EntryKind::Blob, b"old later"),
                ("bin/run", EntryKind::BlobExecutable, b"#!/bin/sh"),
            ],
        );
        assert_eq!(built, expected);
        assert_eq!(
            store
                .tree_with_paths(built, source, &["src/later.rs", "kept.txt"])
                .unwrap(),
            source
        );
        let blob = store.write_blob(b"x").unwrap();
        assert!(matches!(
            store.tree_with_paths(blob, source, &[]),
            Err(StoreError::WrongObject { .. })
        ));
    }

    #[test]
    fn a_file_that_becomes_a_directory_or_the_other_way_lands_path_by_path() {
        let (_dir, store) = store();
        let file = tree(&store, &[("docs", EntryKind::Blob, b"notes")]);
        let directory = tree(
            &store,
            &[
                ("docs/x", EntryKind::Blob, b"x"),
                ("docs/y", EntryKind::Blob, b"y"),
            ],
        );
        let removed = store.tree_with_paths(file, directory, &["docs"]).unwrap();
        assert_eq!(removed, tree(&store, &[]));
        let first = store
            .tree_with_paths(removed, directory, &["docs/x"])
            .unwrap();
        assert_eq!(first, tree(&store, &[("docs/x", EntryKind::Blob, b"x")]));

        let nested = tree(&store, &[("a/c", EntryKind::Blob, b"c")]);
        let flat = tree(&store, &[("a", EntryKind::Blob, b"a")]);
        let gone = store.tree_with_paths(nested, flat, &["a/c"]).unwrap();
        assert_eq!(gone, tree(&store, &[]));
        assert_eq!(store.tree_with_paths(gone, flat, &["a"]).unwrap(), flat);
    }

    #[test]
    fn a_written_commit_carries_the_identity_the_trailers_and_a_signature() {
        let (_dir, store) = store();
        let first = tree(&store, &[("a", EntryKind::Blob, b"a")]);
        let parent = store
            .append(
                &mahi_core::ThreadRef::new(
                    mahi_core::ThreadId::random().unwrap(),
                    mahi_core::RefKind::Meta,
                ),
                None,
                first,
                "base",
            )
            .unwrap();
        let second = tree(&store, &[("a", EntryKind::Blob, b"b")]);
        let signer = Recording(Mutex::new(Vec::new()));
        let trailers = "Thread: 7f3a\nAgent: alice.claude\n";
        let commit = store
            .write_commit(
                (second, parent),
                ("Change a\n\nBecause.", trailers),
                &alice(),
                &signer,
            )
            .unwrap();
        assert_eq!(store.commit_tree(commit).unwrap(), second);
        assert_eq!(store.parent(commit).unwrap(), Some(parent));
        assert_eq!(
            store.commit_message(commit).unwrap(),
            "Change a\n\nBecause.\n\nThread: 7f3a\nAgent: alice.claude\n"
        );
        let found = store.repo.find_commit(commit).unwrap();
        let author = found.author().unwrap();
        assert_eq!(
            (author.name, author.email),
            ("Alice Example".into(), "alice@example.com".into())
        );
        let signature = store.commit_signature(commit).unwrap().unwrap();
        assert_eq!(signature.payload, signer.0.lock().unwrap()[0]);

        let forged = store
            .write_commit(
                (second, parent),
                ("Change a\n\nThread: 7f3a\nAgent: bob.claude", trailers),
                &alice(),
                &signer,
            )
            .unwrap();
        assert_eq!(
            store.commit_message(forged).unwrap(),
            "Change a\n\nThread: 7f3a\nAgent: bob.claude\nThread: 7f3a\nAgent: alice.claude\n"
        );
        let signed_before = signer.0.lock().unwrap().len();
        assert!(matches!(
            store.write_commit(
                (second, parent),
                (&"x".repeat(64 * 1024), trailers),
                &alice(),
                &signer,
            ),
            Err(StoreError::CommitTooLarge(_))
        ));
        assert_eq!(signer.0.lock().unwrap().len(), signed_before);
        for (name, email) in [("Alice <a>", "alice@example.com"), ("Alice", "a@x\nb")] {
            let odd = Identity {
                name: name.to_owned(),
                email: email.to_owned(),
                ..alice()
            };
            assert!(matches!(
                store.write_commit((second, parent), ("m", trailers), &odd, &signer),
                Err(StoreError::InvalidIdentity(_))
            ));
        }
    }
}
