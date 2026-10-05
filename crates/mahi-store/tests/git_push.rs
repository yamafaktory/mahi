//! Pushes thread refs with `Store::push_refs` through gix's local transport, which runs the
//! real `git receive-pack`, so it needs `git` and runs with `just test-git`.

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::PermissionsExt,
        path::Path,
        process::Command,
        sync::atomic::AtomicBool,
    };

    use gix::protocol::transport::{
        Protocol,
        client::blocking_io::file,
    };
    use mahi_core::{
        AgentName,
        AgentSlot,
        ParticipantName,
        RefKind,
        ThreadId,
        ThreadRef,
    };
    use mahi_store::{
        EntryKind,
        ObjectId,
        Pushed,
        Store,
    };

    fn git(repository: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(["-c", "user.name=test", "-c", "user.email=test@example.org"])
            .args(args)
            .output()
            .expect("git is installed");
        assert!(output.status.success(), "git {args:?}: {output:?}");
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn commit(
        store: &Store,
        thread_ref: &ThreadRef,
        parent: Option<ObjectId>,
        text: &str,
    ) -> ObjectId {
        let blob = store.write_blob(text.as_bytes()).unwrap();
        let shared = store.write_blob(b"shared by every commit\n").unwrap();
        let inner = store
            .write_tree(&[("shared", EntryKind::Blob, shared)])
            .unwrap();
        let tree = store
            .write_tree(&[
                ("dir", EntryKind::Tree, inner),
                ("entry", EntryKind::Blob, blob),
            ])
            .unwrap();
        store.append(thread_ref, parent, tree, "m").unwrap()
    }

    fn push(store: &Store, remote: &Path, refs: &[ThreadRef]) -> Vec<(ThreadRef, Pushed)> {
        store
            .push_refs(
                file::connect(remote.as_os_str().as_encoded_bytes(), Protocol::V1, false).unwrap(),
                refs,
                &AtomicBool::new(false),
            )
            .unwrap()
    }

    struct Setup {
        _dir: tempfile::TempDir,
        store: Store,
        local: std::path::PathBuf,
        remote: std::path::PathBuf,
        meta: ThreadRef,
        snapshots: ThreadRef,
    }

    fn setup() -> Setup {
        let dir = tempfile::tempdir().unwrap();
        let (local, remote) = (dir.path().join("local"), dir.path().join("remote.git"));
        gix::init(&local).unwrap();
        std::fs::create_dir(&remote).unwrap();
        git(&remote, &["init", "-q", "--bare"]);
        let thread = ThreadId::random().unwrap();
        let slot = AgentSlot::new(
            ParticipantName::new("bob").unwrap(),
            AgentName::new("claude").unwrap(),
        );
        Setup {
            store: Store::open(&local).unwrap(),
            local,
            _dir: dir,
            remote,
            meta: ThreadRef::new(thread, RefKind::Meta),
            snapshots: ThreadRef::new(thread, RefKind::Snapshots(slot)),
        }
    }

    #[test]
    fn new_and_moved_refs_are_pushed_with_everything_the_remote_lacks() {
        let setup = setup();
        let refs = [setup.meta.clone(), setup.snapshots.clone()];
        let meta = commit(&setup.store, &setup.meta, None, "meta");
        let first = commit(&setup.store, &setup.snapshots, None, "first");
        let pushed = push(&setup.store, &setup.remote, &refs);
        assert_eq!(
            pushed,
            [
                (setup.meta.clone(), Pushed::Updated),
                (setup.snapshots.clone(), Pushed::Updated)
            ]
        );
        let second = commit(&setup.store, &setup.snapshots, Some(first), "second");
        git(&setup.local, &["repack", "-adq"]);
        let pushed = push(
            &setup.store,
            &setup.remote,
            &[refs[0].clone(), refs[1].clone(), refs[1].clone()],
        );
        assert_eq!(
            pushed,
            [
                (setup.meta.clone(), Pushed::UpToDate),
                (setup.snapshots.clone(), Pushed::Updated)
            ]
        );
        git(&setup.remote, &["fsck", "--strict", "--no-dangling"]);
        assert_eq!(
            git(&setup.remote, &["rev-parse", &setup.meta.to_string()]),
            meta.to_string()
        );
        assert_eq!(
            git(&setup.remote, &["rev-parse", &setup.snapshots.to_string()]),
            second.to_string()
        );
        let pushed = push(&setup.store, &setup.remote, &refs);
        git(
            &setup.remote,
            &[
                "update-ref",
                &setup.snapshots.to_string(),
                &second.to_string(),
            ],
        );
        gix::open(&setup.local)
            .unwrap()
            .reference(
                setup.snapshots.to_string(),
                first,
                gix::refs::transaction::PreviousValue::Any,
                "test",
            )
            .unwrap();
        assert_eq!(
            push(
                &setup.store,
                &setup.remote,
                std::slice::from_ref(&setup.snapshots)
            ),
            [(setup.snapshots.clone(), Pushed::Behind)]
        );
        assert!(
            pushed
                .iter()
                .all(|(_, outcome)| *outcome == Pushed::UpToDate)
        );
    }

    #[test]
    fn an_interrupted_push_moves_nothing() {
        let setup = setup();
        commit(&setup.store, &setup.meta, None, "meta");
        let interrupted = setup.store.push_refs(
            file::connect(
                setup.remote.as_os_str().as_encoded_bytes(),
                Protocol::V1,
                false,
            )
            .unwrap(),
            std::slice::from_ref(&setup.meta),
            &AtomicBool::new(true),
        );
        assert!(
            matches!(interrupted, Err(mahi_store::StoreError::Interrupted)),
            "{interrupted:?}"
        );
        assert!(git(&setup.remote, &["for-each-ref"]).is_empty());
    }

    #[test]
    fn a_ref_the_remote_moved_elsewhere_is_left_alone() {
        let setup = setup();
        commit(&setup.store, &setup.meta, None, "meta");
        let empty = git(&setup.remote, &["mktree"]);
        let theirs = git(&setup.remote, &["commit-tree", &empty, "-m", "theirs"]);
        git(
            &setup.remote,
            &["update-ref", &setup.meta.to_string(), &theirs],
        );
        let pushed = push(
            &setup.store,
            &setup.remote,
            std::slice::from_ref(&setup.meta),
        );
        assert_eq!(pushed, [(setup.meta.clone(), Pushed::Behind)]);
        assert_eq!(
            git(&setup.remote, &["rev-parse", &setup.meta.to_string()]),
            theirs
        );
    }

    #[test]
    fn a_refusal_by_the_remote_is_reported_and_nothing_moves() {
        let setup = setup();
        let hook = setup.remote.join("hooks").join("update");
        std::fs::write(
            &hook,
            "#!/bin/sh\ncase \"$1\" in *snapshots) exit 1;; esac\n",
        )
        .unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        commit(&setup.store, &setup.meta, None, "meta");
        commit(&setup.store, &setup.snapshots, None, "first");
        let both = [setup.meta.clone(), setup.snapshots.clone()];
        let pushed = push(&setup.store, &setup.remote, &both);
        assert!(
            pushed
                .iter()
                .all(|(_, outcome)| matches!(outcome, Pushed::Refused(_))),
            "{pushed:?}"
        );
        let listed = git(&setup.remote, &["for-each-ref"]);
        assert!(listed.is_empty(), "{listed}");
        git(
            &setup.remote,
            &["config", "receive.advertiseAtomic", "false"],
        );
        let pushed = push(&setup.store, &setup.remote, &both);
        assert!(
            matches!(
                pushed.as_slice(),
                [(_, Pushed::Updated), (_, Pushed::Refused(reason))] if reason.contains("hook declined")
            ),
            "{pushed:?}"
        );
        git(&setup.remote, &["rev-parse", &setup.meta.to_string()]);
    }

    fn push_branch(store: &Store, remote: &Path, branch: &str) -> Pushed {
        store
            .push_branch(
                file::connect(remote.as_os_str().as_encoded_bytes(), Protocol::V1, false).unwrap(),
                branch,
                &AtomicBool::new(false),
            )
            .unwrap()
    }

    #[test]
    fn a_branch_with_merges_is_pushed_with_only_what_the_remote_lacks() {
        let setup = setup();
        let local = &setup.local;
        std::fs::write(local.join("a"), "a\n").unwrap();
        git(local, &["add", "a"]);
        git(local, &["commit", "-qm", "base", "--no-gpg-sign"]);
        let main = git(local, &["symbolic-ref", "--short", "HEAD"]);
        assert_eq!(
            push_branch(&setup.store, &setup.remote, &main),
            Pushed::Updated
        );
        git(local, &["checkout", "-qb", "land"]);
        std::fs::write(local.join("b"), "b\n").unwrap();
        git(local, &["add", "b"]);
        git(local, &["commit", "-qm", "one", "--no-gpg-sign"]);
        git(local, &["checkout", "-qb", "side", &main]);
        std::fs::create_dir(local.join("dir")).unwrap();
        std::fs::write(local.join("dir/c"), "c\n").unwrap();
        git(local, &["add", "dir"]);
        git(local, &["commit", "-qm", "side", "--no-gpg-sign"]);
        git(local, &["checkout", "-q", "land"]);
        git(
            local,
            &["merge", "-q", "--no-edit", "--no-gpg-sign", "side"],
        );
        git(local, &["repack", "-adq"]);
        assert_eq!(
            push_branch(&setup.store, &setup.remote, "land"),
            Pushed::Updated
        );
        git(&setup.remote, &["fsck", "--strict", "--no-dangling"]);
        assert_eq!(
            git(&setup.remote, &["rev-parse", "refs/heads/land"]),
            git(local, &["rev-parse", "HEAD"])
        );
        assert_eq!(
            push_branch(&setup.store, &setup.remote, "land"),
            Pushed::UpToDate
        );
        git(local, &["checkout", "-q", "side"]);
        std::fs::write(local.join("dir/e"), "e\n").unwrap();
        git(local, &["add", "dir"]);
        git(local, &["commit", "-qm", "side again", "--no-gpg-sign"]);
        git(local, &["checkout", "-q", "land"]);
        git(
            local,
            &["merge", "-q", "--no-edit", "--no-gpg-sign", "side"],
        );
        assert_eq!(
            push_branch(&setup.store, &setup.remote, "land"),
            Pushed::Updated
        );
        git(&setup.remote, &["fsck", "--strict", "--no-dangling"]);
        assert_eq!(
            git(&setup.remote, &["rev-parse", "refs/heads/land"]),
            git(local, &["rev-parse", "HEAD"])
        );
        git(local, &["reset", "-q", "--hard", "HEAD~1"]);
        std::fs::write(local.join("d"), "d\n").unwrap();
        git(local, &["add", "d"]);
        git(local, &["commit", "-qm", "rewritten", "--no-gpg-sign"]);
        assert_eq!(
            push_branch(&setup.store, &setup.remote, "land"),
            Pushed::Behind
        );
        assert!(matches!(
            setup.store.push_branch(
                file::connect(
                    setup.remote.as_os_str().as_encoded_bytes(),
                    Protocol::V1,
                    false
                )
                .unwrap(),
                "missing",
                &AtomicBool::new(false),
            ),
            Err(mahi_store::StoreError::NoBranch(_))
        ));
    }

    fn push_within(
        store: &Store,
        remote: &Path,
        refs: &[ThreadRef],
        max_bytes: u64,
    ) -> Vec<(ThreadRef, Pushed)> {
        store
            .push_refs_within(
                file::connect(remote.as_os_str().as_encoded_bytes(), Protocol::V1, false).unwrap(),
                refs,
                max_bytes,
                &AtomicBool::new(false),
            )
            .unwrap()
    }

    #[test]
    fn a_push_sends_the_refs_that_fit_and_leaves_the_rest_for_later() {
        let setup = setup();
        let alice = ThreadRef::new(
            setup.meta.thread(),
            RefKind::Snapshots(AgentSlot::new(
                ParticipantName::new("alice").unwrap(),
                AgentName::new("codex").unwrap(),
            )),
        );
        commit(&setup.store, &setup.meta, None, "meta");
        let bob = commit(&setup.store, &setup.snapshots, None, &"b".repeat(15 << 10));
        let alice_tip = commit(&setup.store, &alice, None, &"a".repeat(15 << 10));
        let refs = [setup.meta.clone(), setup.snapshots.clone(), alice.clone()];
        assert_eq!(
            push_within(&setup.store, &setup.remote, &refs, 4 << 10),
            [
                (setup.meta.clone(), Pushed::Updated),
                (setup.snapshots.clone(), Pushed::TooLarge(4 << 10)),
                (alice.clone(), Pushed::TooLarge(4 << 10)),
            ]
        );
        git(&setup.remote, &["rev-parse", &setup.meta.to_string()]);
        assert_eq!(
            push_within(&setup.store, &setup.remote, &refs, 20 << 10),
            [
                (setup.meta.clone(), Pushed::UpToDate),
                (setup.snapshots.clone(), Pushed::Updated),
                (alice.clone(), Pushed::Deferred),
            ]
        );
        assert_eq!(
            git(&setup.remote, &["rev-parse", &setup.snapshots.to_string()]),
            bob.to_string()
        );
        assert_eq!(
            push_within(&setup.store, &setup.remote, &refs, 20 << 10),
            [
                (setup.meta.clone(), Pushed::UpToDate),
                (setup.snapshots.clone(), Pushed::UpToDate),
                (alice.clone(), Pushed::Updated),
            ]
        );
        assert_eq!(
            git(&setup.remote, &["rev-parse", &alice.to_string()]),
            alice_tip.to_string()
        );
        git(&setup.remote, &["fsck", "--strict", "--no-dangling"]);
    }

    #[test]
    fn a_branch_larger_than_the_limit_is_not_pushed() {
        let setup = setup();
        let local = &setup.local;
        std::fs::write(local.join("big"), "x".repeat(32 << 10)).unwrap();
        git(local, &["add", "big"]);
        git(local, &["commit", "-qm", "big", "--no-gpg-sign"]);
        let branch = git(local, &["symbolic-ref", "--short", "HEAD"]);
        let pushed = setup
            .store
            .push_branch_within(
                file::connect(
                    setup.remote.as_os_str().as_encoded_bytes(),
                    Protocol::V1,
                    false,
                )
                .unwrap(),
                &branch,
                16 << 10,
                &AtomicBool::new(false),
            )
            .unwrap();
        assert_eq!(pushed, Pushed::TooLarge(16 << 10));
        assert!(git(&setup.remote, &["for-each-ref"]).is_empty());
        assert_eq!(
            push_branch(&setup.store, &setup.remote, &branch),
            Pushed::Updated
        );
    }

    fn snapshots_of(thread: ThreadId, participant: &str) -> ThreadRef {
        ThreadRef::new(
            thread,
            RefKind::Snapshots(AgentSlot::new(
                ParticipantName::new(participant).unwrap(),
                AgentName::new("sh").unwrap(),
            )),
        )
    }

    #[test]
    fn refs_after_a_deferred_one_wait_and_a_too_large_ref_holds_none_back() {
        let setup = setup();
        let thread = setup.meta.thread();
        let (carol, dave, erin) = (
            snapshots_of(thread, "carol"),
            snapshots_of(thread, "dave"),
            snapshots_of(thread, "erin"),
        );
        let bob = commit(&setup.store, &setup.snapshots, None, &"b".repeat(15 << 10));
        commit(&setup.store, &carol, None, &"c".repeat(15 << 10));
        commit(&setup.store, &dave, None, "small");
        let refs = [setup.snapshots.clone(), carol.clone(), dave.clone()];
        assert_eq!(
            push_within(&setup.store, &setup.remote, &refs, 20 << 10),
            [
                (setup.snapshots.clone(), Pushed::Updated),
                (carol.clone(), Pushed::Deferred),
                (dave.clone(), Pushed::Deferred),
            ]
        );
        assert_eq!(
            git(&setup.remote, &["rev-parse", &setup.snapshots.to_string()]),
            bob.to_string()
        );
        let shared = setup.store.write_blob(&[b's'; 10 << 10]).unwrap();
        let other = setup.store.write_blob(&[b'o'; 10 << 10]).unwrap();
        let big_tree = setup
            .store
            .write_tree(&[
                ("other", EntryKind::Blob, other),
                ("shared", EntryKind::Blob, shared),
            ])
            .unwrap();
        let small_tree = setup
            .store
            .write_tree(&[("shared", EntryKind::Blob, shared)])
            .unwrap();
        let big = ThreadRef::new(thread, RefKind::Meta);
        setup.store.append(&big, None, big_tree, "big").unwrap();
        let erin_tip = setup.store.append(&erin, None, small_tree, "erin").unwrap();
        assert_eq!(
            push_within(
                &setup.store,
                &setup.remote,
                &[big.clone(), erin.clone()],
                15 << 10
            ),
            [
                (big, Pushed::TooLarge(15 << 10)),
                (erin.clone(), Pushed::Updated)
            ]
        );
        assert_eq!(
            git(&setup.remote, &["rev-parse", &erin.to_string()]),
            erin_tip.to_string()
        );
        git(&setup.remote, &["fsck", "--strict", "--no-dangling"]);
    }
}
