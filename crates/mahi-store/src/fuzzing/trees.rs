use std::{
    collections::BTreeMap,
    fs,
    os::unix::{
        ffi::{
            OsStrExt,
            OsStringExt,
        },
        fs::PermissionsExt,
    },
    path::{
        Path,
        PathBuf,
    },
    sync::{
        LazyLock,
        atomic::AtomicBool,
    },
};

use gix::{
    ObjectId,
    ThreadSafeRepository,
    actor::Signature,
    date::Time,
    object::Kind,
    objs::{
        Commit,
        Write as _,
    },
};

use crate::{
    Store,
    store,
};

const MAX_ENTRIES: usize = 64;
const MAX_TREES: usize = 8;
const MAX_LISTED: usize = 256;
const MAX_CHECKED_OUT: usize = 4096;
const MAX_CHECKED_OUT_BYTES: u64 = 64 * 1024 * 1024;
const NESTING: usize = 17;
const CANARY: &[u8] = b"untouched\n";
const RESTORED: &str = "r";
const MERGED: &str = "m";
const REGISTRATION: [&str; 4] = ["HEAD", "commondir", "gitdir", "index"];

struct Place {
    root: PathBuf,
    nested: PathBuf,
    sandbox: PathBuf,
    outside: PathBuf,
    worktrees: PathBuf,
    repo: ThreadSafeRepository,
    baseline: BTreeMap<PathBuf, Vec<u8>>,
}

static PLACE: LazyLock<Place> = LazyLock::new(|| {
    let root = super::temp::fresh_dir("mahi-fuzz-trees");
    let nested: PathBuf = std::iter::repeat_n("n", NESTING).collect();
    fs::create_dir_all(root.join(&nested).join("sandbox")).expect("the sandbox is created");
    fs::create_dir_all(root.join("outside")).expect("the outside directory is created");
    fs::write(root.join("outside/canary"), CANARY).expect("the canary is written");
    gix::init(root.join("repo")).expect("a repository is created");
    let repo = gix::open_opts(root.join("repo"), store::open_options())
        .expect("the repository opens")
        .into_sync();
    let root = fs::canonicalize(&root).expect("the root resolves");
    let mut place = Place {
        nested: root.join(&nested),
        sandbox: root.join(&nested).join("sandbox"),
        outside: root.join("outside"),
        worktrees: root.join("repo/.git/worktrees"),
        root,
        repo,
        baseline: BTreeMap::new(),
    };
    place.baseline = place.listing();
    place
});

impl Place {
    fn listing(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut listed = BTreeMap::new();
        let mut pending = vec![self.root.clone()];
        while let Some(dir) = pending.pop() {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path == self.sandbox || path == self.worktrees {
                    continue;
                }
                let Ok(metadata) = fs::symlink_metadata(&path) else {
                    continue;
                };
                let mut seen = metadata.permissions().mode().to_be_bytes().to_vec();
                if metadata.is_symlink() {
                    let target = fs::read_link(&path).unwrap_or_default();
                    seen.extend_from_slice(target.as_os_str().as_bytes());
                } else if metadata.is_dir() {
                    pending.push(path.clone());
                } else {
                    seen.extend(fs::read(&path).unwrap_or_default());
                }
                listed.insert(path, seen);
            }
        }
        listed
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort_unstable();
        names
    }

    fn assert_only(&self, worktree: &str, commit: ObjectId, made: bool) {
        let expected: Vec<String> = if made {
            vec![worktree.to_owned()]
        } else {
            Vec::new()
        };
        assert_eq!(
            Self::names(&self.sandbox),
            expected,
            "something was written beside the worktree"
        );
        assert_eq!(
            Self::names(&self.worktrees),
            expected,
            "a registration appeared that was not made"
        );
        if made {
            let admin = self.worktrees.join(worktree);
            let mut registration: Vec<String> =
                REGISTRATION.iter().map(|name| (*name).to_owned()).collect();
            registration.sort_unstable();
            assert_eq!(
                Self::names(&admin),
                registration,
                "the registration changed"
            );
            let path = self.sandbox.join(worktree);
            assert_eq!(
                fs::read(admin.join("HEAD")).ok(),
                Some(format!("{commit}\n").into_bytes())
            );
            assert_eq!(
                fs::read(admin.join("commondir")).ok(),
                Some(b"../..\n".to_vec())
            );
            let mut gitdir = path.join(".git").into_os_string().into_vec();
            gitdir.push(b'\n');
            assert_eq!(fs::read(admin.join("gitdir")).ok(), Some(gitdir));
        }
        let now = self.listing();
        assert!(
            now == self.baseline,
            "something outside the worktree changed: {:?}",
            now.iter()
                .filter(|(path, seen)| self.baseline.get(*path) != Some(*seen))
                .map(|(path, _)| path)
                .chain(self.baseline.keys().filter(|path| !now.contains_key(*path)))
                .collect::<Vec<_>>()
        );
    }

    fn clean(&self) {
        let _ = fs::remove_dir_all(self.sandbox.join(RESTORED));
        let _ = fs::remove_dir_all(self.sandbox.join(MERGED));
        let _ = fs::remove_dir_all(&self.worktrees);
        assert!(
            Self::names(&self.sandbox).is_empty(),
            "the sandbox is emptied"
        );
        assert!(!self.worktrees.exists(), "the registrations are removed");
    }

    fn contained(&self, target: &[u8]) -> Vec<u8> {
        match target.strip_prefix(b"/") {
            Some(rest) => {
                let mut inside = self.nested.as_os_str().as_bytes().to_vec();
                inside.push(b'/');
                inside.extend_from_slice(rest);
                inside
            }
            None => target.to_vec(),
        }
    }
}

struct Input<'a>(&'a [u8]);

impl<'a> Input<'a> {
    fn byte(&mut self) -> Option<u8> {
        let (&first, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(first)
    }

    fn bytes(&mut self, max: usize) -> &'a [u8] {
        let wanted = self
            .byte()
            .map_or(0, |length| usize::from(length) % (max + 1));
        let (taken, rest) = self.0.split_at(wanted.min(self.0.len()));
        self.0 = rest;
        taken
    }
}

fn write_raw(store: &Store, kind: Kind, bytes: &[u8]) -> ObjectId {
    store
        .repo
        .write_buf(kind, bytes)
        .expect("an object is written to memory")
}

fn entry(tree: &mut Vec<u8>, mode: &[u8], name: &[u8], id: ObjectId) {
    tree.extend_from_slice(mode);
    tree.push(b' ');
    tree.extend_from_slice(name);
    tree.push(0);
    tree.extend_from_slice(id.as_bytes());
}

fn base(store: &Store, outside: &Path) -> ObjectId {
    let one = write_raw(store, Kind::Blob, b"one\ntwo\n");
    let x = write_raw(store, Kind::Blob, b"x\n");
    let target = write_raw(store, Kind::Blob, outside.as_os_str().as_bytes());
    let mut inner = Vec::new();
    entry(&mut inner, b"100644", b"x", x);
    let inner = write_raw(store, Kind::Tree, &inner);
    let mut top = Vec::new();
    entry(&mut top, b"100644", b"a", one);
    entry(&mut top, b"40000", b"d", inner);
    entry(&mut top, b"120000", b"l", target);
    write_raw(store, Kind::Tree, &top)
}

fn escape(place: &Place, choice: u8) -> Vec<u8> {
    match choice % 4 {
        0 => place.outside.as_os_str().as_bytes().to_vec(),
        1 => place.outside.join("escaped").into_os_string().into_vec(),
        _ => {
            let mut target = b"../".repeat(usize::from(choice / 4) % (NESTING + MAX_TREES + 4) + 1);
            target.extend_from_slice(b"outside");
            target
        }
    }
}

fn theirs(store: &Store, data: &[u8], place: &Place) -> (ObjectId, Vec<u8>) {
    let empty = write_raw(store, Kind::Tree, b"");
    let mut input = Input(data);
    let mut trees: Vec<ObjectId> = Vec::new();
    let mut current = Vec::new();
    let mut first_name = None;
    let mut entries = 0;
    while let Some(op) = input.byte() {
        if entries >= MAX_ENTRIES {
            break;
        }
        if op % 8 == 6 {
            trees.push(write_raw(store, Kind::Tree, &current));
            current.clear();
            if trees.len() >= MAX_TREES {
                break;
            }
            continue;
        }
        let name = input.bytes(24);
        first_name.get_or_insert_with(|| name.to_vec());
        let raw_mode;
        let (mode, id): (&[u8], ObjectId) = match op % 8 {
            0 => (b"100644", write_raw(store, Kind::Blob, input.bytes(64))),
            1 => (b"100755", write_raw(store, Kind::Blob, input.bytes(64))),
            2 => {
                let target = place.contained(input.bytes(48));
                (b"120000", write_raw(store, Kind::Blob, &target))
            }
            3 => {
                let at = input.byte().map_or(0, usize::from);
                let tree = if trees.is_empty() {
                    empty
                } else {
                    trees[at % trees.len()]
                };
                (b"40000", tree)
            }
            4 => {
                let raw = input.bytes(20);
                let mut id = [0_u8; 20];
                id[..raw.len()].copy_from_slice(raw);
                (b"160000", ObjectId::from_bytes_or_panic(&id))
            }
            5 => {
                let high = input.byte().unwrap_or(0);
                let low = input.byte().unwrap_or(0);
                raw_mode = format!("{:o}", u16::from_be_bytes([high, low]));
                let content = place.contained(input.bytes(16));
                (raw_mode.as_bytes(), write_raw(store, Kind::Blob, &content))
            }
            _ => {
                let target = escape(place, input.byte().unwrap_or(0));
                (b"120000", write_raw(store, Kind::Blob, &target))
            }
        };
        entry(&mut current, mode, name, id);
        entries += 1;
    }
    let top = if current.is_empty() {
        trees.last().copied().unwrap_or(empty)
    } else {
        write_raw(store, Kind::Tree, &current)
    };
    (top, first_name.unwrap_or_else(|| b"a".to_vec()))
}

fn commit(store: &Store, tree: ObjectId) -> ObjectId {
    let signature = Signature {
        name: "fuzz".into(),
        email: "fuzz@example.invalid".into(),
        time: Time {
            seconds: 0,
            offset: 0,
        },
    };
    let commit = Commit {
        tree,
        parents: std::iter::empty().collect(),
        author: signature.clone(),
        committer: signature,
        encoding: None,
        message: "fuzz\n".into(),
        extra_headers: Vec::new(),
    };
    store
        .repo
        .write_object(&commit)
        .expect("a commit is written to memory")
        .detach()
}

/// Builds a teammate's tree from `data`, in memory, with any names, modes and links, some
/// pointing out of the worktree by absolute and relative paths, and reads it every way mahi
/// reads a teammate's work: the paths it changes from a base and the diff of each, one entry
/// by name, a worktree restored from it, and a merge of it applied to a worktree of the base
/// whose own link points out. Each worktree is checked on its own: nothing else under the fuzz
/// directory may change, and its registration must hold exactly what the store wrote.
///
/// # Panics
///
/// Panics if something outside the worktree changed, or if the fuzz directory cannot be
/// set up.
pub fn trees(data: &[u8]) {
    let place = &*PLACE;
    let store = Store {
        repo: place.repo.to_thread_local().with_object_memory(),
    };
    let base = base(&store, &place.outside);
    let (theirs, name) = theirs(&store, data, place);
    let empty = write_raw(&store, Kind::Tree, b"");

    if let Ok(changes) = store.changed_paths(base, theirs, MAX_LISTED) {
        assert!(changes.paths.len() <= MAX_LISTED);
        for (path, _) in changes.paths.iter().take(4) {
            let _ = store.file_diff(base, theirs, path);
        }
    }
    let _ = store.changed_paths(theirs, base, MAX_LISTED);
    let theirs_commit = commit(&store, theirs);
    let base_commit = commit(&store, base);
    if let Ok(name) = std::str::from_utf8(&name) {
        let _ = store.read_entry(theirs_commit, name, 4096);
    }

    let stop = AtomicBool::new(false);
    let restored = store.restore_worktree_within(
        (RESTORED, &place.sandbox.join(RESTORED)),
        (base_commit, theirs),
        (MAX_CHECKED_OUT, MAX_CHECKED_OUT_BYTES),
        &stop,
    );
    place.assert_only(RESTORED, base_commit, restored.is_ok());
    place.clean();

    let added = store.add_worktree(MERGED, &place.sandbox.join(MERGED), base_commit, &stop);
    assert!(added.is_ok(), "a worktree of the base is added: {added:?}");
    if let Ok(merged) = store.merge_trees(empty, base, theirs, ("ours", "theirs")) {
        let _ = store.apply_merge(MERGED, base, merged.tree, &stop);
    }
    place.assert_only(MERGED, base_commit, true);
    place.clean();
}
