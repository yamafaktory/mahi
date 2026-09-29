//! Fetches thread refs with `Store::fetch_thread` through gix's local transport, which runs the
//! real `git upload-pack`, so it needs `git` and runs with `just test-git`.

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

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
        Store,
    };

    fn commit(
        store: &Store,
        thread_ref: &ThreadRef,
        parent: Option<ObjectId>,
        text: &str,
    ) -> ObjectId {
        let blob = store.write_blob(text.as_bytes()).unwrap();
        let tree = store
            .write_tree(&[("entry", EntryKind::Blob, blob)])
            .unwrap();
        store.append(thread_ref, parent, tree, "m").unwrap()
    }

    #[test]
    fn a_threads_refs_are_fetched_into_the_waiting_area_and_mirror_the_remote() {
        let dir = tempfile::tempdir().unwrap();
        let (source_dir, target_dir) = (dir.path().join("source"), dir.path().join("target"));
        gix::init(&source_dir).unwrap();
        gix::init(&target_dir).unwrap();
        let source = Store::open(&source_dir).unwrap();
        let target = Store::open(&target_dir).unwrap();
        let thread = ThreadId::random().unwrap();
        let other = ThreadId::random().unwrap();
        let meta = ThreadRef::new(thread, RefKind::Meta);
        let slot = AgentSlot::new(
            ParticipantName::new("bob").unwrap(),
            AgentName::new("claude").unwrap(),
        );
        let snapshots = ThreadRef::new(thread, RefKind::Snapshots(slot));
        let meta_commit = commit(&source, &meta, None, "meta");
        let snapshot = commit(&source, &snapshots, None, "snapshot");
        commit(
            &source,
            &ThreadRef::new(other, RefKind::Meta),
            None,
            "other",
        );
        let fetch = |store: &Store| {
            store
                .fetch_thread(
                    file::connect(
                        source_dir.as_os_str().as_encoded_bytes(),
                        Protocol::V2,
                        false,
                    )
                    .unwrap(),
                    thread,
                    &AtomicBool::new(false),
                )
                .unwrap();
        };
        fetch(&target);
        assert_eq!(
            target.fetched_refs(thread).unwrap(),
            [(meta.clone(), meta_commit), (snapshots.clone(), snapshot)]
        );
        assert!(target.thread_refs().unwrap().is_empty());
        assert!(target.fetched_refs(other).unwrap().is_empty());
        assert_eq!(
            target.commit_tree(snapshot).unwrap(),
            source.commit_tree(snapshot).unwrap()
        );
        source.remove(&snapshots, snapshot).unwrap();
        let next = commit(&source, &meta, Some(meta_commit), "meta 2");
        fetch(&target);
        assert_eq!(target.fetched_refs(thread).unwrap(), [(meta, next)]);
    }
}
