use std::{
    fs,
    path::PathBuf,
    sync::LazyLock,
};

use gix::{
    ObjectId,
    ThreadSafeRepository,
    refs::transaction::PreviousValue,
};

use crate::{
    Store,
    store,
};

struct Scratch {
    git_dir: PathBuf,
    repo: ThreadSafeRepository,
}

static SCRATCH: LazyLock<Scratch> = LazyLock::new(|| {
    let root = std::env::temp_dir().join(format!("mahi-fuzz-scratch-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    gix::init(&root).expect("a repository is created");
    let repo = gix::open_opts(&root, store::open_options())
        .expect("the repository opens")
        .into_sync();
    Scratch {
        git_dir: root.join(".git"),
        repo,
    }
});

/// Returns a store over a repository of the fuzz process's own, with no thread refs, fetched
/// refs or pins left from an earlier call, whose objects stay in memory.
///
/// # Panics
///
/// Panics if the repository cannot be set up.
#[must_use]
pub fn scratch_store() -> Store {
    let scratch = &*SCRATCH;
    for leftover in ["refs/threads", "refs/mahi", "mahi", "packed-refs"] {
        let path = scratch.git_dir.join(leftover);
        let _ = fs::remove_dir_all(&path);
        let _ = fs::remove_file(&path);
    }
    Store {
        repo: scratch.repo.to_thread_local().with_object_memory(),
    }
}

/// Points the ref `name` at `id` in `store`, whatever it pointed at before.
///
/// # Panics
///
/// Panics if the ref cannot be written.
pub fn set_ref(store: &Store, name: &str, id: ObjectId) {
    store
        .repo
        .reference(name, id, PreviousValue::Any, "fuzz")
        .expect("a ref is written");
}
