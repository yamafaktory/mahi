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
}
