use std::collections::VecDeque;

use mahi_store::{
    ObjectId,
    PathEntry,
    Store,
};

const MAX_HOPS: usize = 40;
const MAX_FOLLOWED: usize = 4096;

/// Returns the `/`-separated paths that the links `picks` picks in the tree `tree` read
/// through: each link on the way, through linked directories and chains of links, and the
/// path each one ends at, a directory standing for everything below it, with the links below
/// it read through in turn, and the empty path for the whole tree. A target that goes missing
/// is held where it first does. A link to an absolute path is not followed, so it adds only
/// the links before it. Returns `None` when they cannot all be told: a tree too large to walk,
/// more than 40 links on one way or 4,096 links to follow, or a tree that cannot be read.
pub(crate) fn read_through(
    store: &Store,
    tree: ObjectId,
    picks: &dyn Fn(&[u8]) -> bool,
) -> Option<Vec<Vec<u8>>> {
    let links = store.links(tree).ok()??;
    let mut followed = vec![false; links.len()];
    let mut queue: VecDeque<usize> = (0..links.len())
        .filter(|index| links.get(*index).is_some_and(|link| picks(link)))
        .collect();
    let mut paths = Vec::new();
    let mut count = 0;
    while let Some(index) = queue.pop_front() {
        let (Some(link), Some(seen)) = (links.get(index), followed.get_mut(index)) else {
            return None;
        };
        if std::mem::replace(seen, true) {
            continue;
        }
        count += 1;
        if count > MAX_FOLLOWED {
            return None;
        }
        let start = paths.len();
        follow(store, tree, link, &mut paths)?;
        let added = paths.get(start..)?;
        if added.iter().any(Vec::is_empty) {
            return Some(vec![Vec::new()]);
        }
        let below = (0..links.len()).filter(|other| {
            !followed.get(*other).is_some_and(|seen| *seen)
                && links
                    .get(*other)
                    .is_some_and(|other| added.iter().any(|read| lies_below(read, other)))
        });
        queue.extend(below);
    }
    Some(paths)
}

fn follow(store: &Store, tree: ObjectId, link: &[u8], paths: &mut Vec<Vec<u8>>) -> Option<()> {
    let mut rest: VecDeque<Vec<u8>> = parts(link).map(<[u8]>::to_vec).collect();
    let mut done: Vec<Vec<u8>> = Vec::new();
    let mut hops = 0;
    while let Some(part) = rest.pop_front() {
        let named = !matches!(part.as_slice(), b"." | b"..");
        if !step(&mut done, part) {
            return Some(());
        }
        if !named {
            continue;
        }
        let at: Vec<&[u8]> = done.iter().map(Vec::as_slice).collect();
        match store.entry_at(tree, &at).ok()? {
            PathEntry::Link(target) => {
                hops += 1;
                if hops > MAX_HOPS {
                    return None;
                }
                paths.push(joined(&done));
                done.pop();
                if target.starts_with(b"/") {
                    return Some(());
                }
                let mut next: VecDeque<Vec<u8>> = parts(&target).map(<[u8]>::to_vec).collect();
                next.extend(rest.drain(..));
                rest = next;
            }
            PathEntry::Directory if !rest.is_empty() => {}
            PathEntry::Missing | PathEntry::Directory | PathEntry::File | PathEntry::Gitlink => {
                paths.push(joined(&done));
                return Some(());
            }
        }
    }
    paths.push(joined(&done));
    Some(())
}

/// Moves `done` by the path part `part`, and says whether it stays inside the tree.
fn step(done: &mut Vec<Vec<u8>>, part: Vec<u8>) -> bool {
    match part.as_slice() {
        b"." => true,
        b".." => done.pop().is_some(),
        _ => {
            done.push(part);
            true
        }
    }
}

fn parts(path: &[u8]) -> impl Iterator<Item = &[u8]> {
    path.split(|byte| *byte == b'/')
        .filter(|part| !part.is_empty())
}

fn joined(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.join(&b'/')
}

/// Says whether a change to the `/`-separated path `path` changes what `read` holds: `path`
/// is `read`, lies below it, or holds it, ASCII case aside.
pub(crate) fn covers(read: &[u8], path: &[u8]) -> bool {
    covers_below(read, path) || covers_below(path, read)
}

fn lies_below(read: &[u8], path: &[u8]) -> bool {
    path.len() > read.len() && covers_below(read, path)
}

fn covers_below(read: &[u8], path: &[u8]) -> bool {
    read.is_empty()
        || path.get(..read.len()).is_some_and(|start| {
            start.eq_ignore_ascii_case(read)
                && path
                    .get(read.len()..)
                    .is_some_and(|rest| rest.is_empty() || rest.first() == Some(&b'/'))
        })
}

#[cfg(test)]
mod tests {
    use mahi_store::EntryKind;

    use super::*;

    struct Tree {
        _dir: tempfile::TempDir,
        store: Store,
    }

    fn tree() -> Tree {
        let dir = tempfile::tempdir().unwrap();
        gix::init(dir.path().join("repo")).unwrap();
        let store = Store::open(&dir.path().join("repo")).unwrap();
        Tree { _dir: dir, store }
    }

    impl Tree {
        fn write(&self, entries: &[(&str, EntryKind, &str)]) -> ObjectId {
            let mut root: Vec<(String, EntryKind, ObjectId)> = Vec::new();
            let mut dirs: std::collections::BTreeMap<String, Vec<(&str, EntryKind, &str)>> =
                std::collections::BTreeMap::new();
            for (path, kind, text) in entries {
                match path.split_once('/') {
                    Some((dir, below)) => dirs
                        .entry(dir.to_owned())
                        .or_default()
                        .push((below, *kind, text)),
                    None => root.push((
                        (*path).to_owned(),
                        *kind,
                        self.store.write_blob(text.as_bytes()).unwrap(),
                    )),
                }
            }
            for (dir, below) in dirs {
                let id = self.write(&below);
                root.push((dir, EntryKind::Tree, id));
            }
            let entries: Vec<_> = root
                .iter()
                .map(|(name, kind, id)| (name.as_str(), *kind, *id))
                .collect();
            self.store.write_tree(&entries).unwrap()
        }

        fn read(&self, tree: ObjectId) -> Option<Vec<String>> {
            let picks = |path: &[u8]| path.ends_with(b"CLAUDE.md") || path == b".claude";
            read_through(&self.store, tree, &picks).map(|paths| {
                paths
                    .iter()
                    .map(|path| String::from_utf8(path.clone()).unwrap())
                    .collect()
            })
        }
    }

    #[test]
    fn a_settings_link_is_read_through_to_its_target_and_every_link_on_the_way() {
        let tree = tree();
        let root = tree.write(&[
            ("CLAUDE.md", EntryKind::Link, "docs/guide.md"),
            ("docs", EntryKind::Link, "real/docs"),
            ("real/docs/guide.md", EntryKind::Link, "../shared/./text.md"),
            ("real/shared/text.md", EntryKind::Blob, "obey"),
            ("README", EntryKind::Blob, "hello"),
        ]);
        assert_eq!(
            tree.read(root).unwrap(),
            [
                "CLAUDE.md",
                "docs",
                "real/docs/guide.md",
                "real/shared/text.md"
            ]
        );
    }

    #[test]
    fn a_linked_settings_directory_or_a_missing_target_is_read_through_as_a_whole() {
        let tree = tree();
        let root = tree.write(&[
            (".claude", EntryKind::Link, "config/agent"),
            ("config/agent/settings.json", EntryKind::Blob, "{}"),
            ("sub/CLAUDE.md", EntryKind::Link, "../notes/later.md"),
            ("plain/CLAUDE.md", EntryKind::Blob, "plain"),
        ]);
        assert_eq!(
            tree.read(root).unwrap(),
            [".claude", "config/agent", "sub/CLAUDE.md", "notes"]
        );
    }

    #[test]
    fn a_link_out_of_the_tree_adds_nothing_past_it_and_a_loop_cannot_be_told() {
        let tree = tree();
        let outside = tree.write(&[
            ("CLAUDE.md", EntryKind::Link, "/etc/agent.md"),
            ("a/CLAUDE.md", EntryKind::Link, "../../above.md"),
            ("b/CLAUDE.md", EntryKind::Link, "../.."),
        ]);
        assert_eq!(
            tree.read(outside).unwrap(),
            ["CLAUDE.md", "a/CLAUDE.md", "b/CLAUDE.md"]
        );
        let root = tree.write(&[
            ("CLAUDE.md", EntryKind::Link, "."),
            ("other", EntryKind::Link, "elsewhere"),
        ]);
        assert_eq!(tree.read(root).unwrap(), [""]);
        let looped = tree.write(&[
            ("CLAUDE.md", EntryKind::Link, "x"),
            ("x", EntryKind::Link, "y"),
            ("y", EntryKind::Link, "x"),
        ]);
        assert_eq!(tree.read(looped), None);
    }

    #[test]
    fn a_missing_target_is_held_where_it_first_goes_missing() {
        let tree = tree();
        let root = tree.write(&[
            ("CLAUDE.md", EntryKind::Link, "docs/later.md"),
            ("docs/a.txt", EntryKind::Blob, "a"),
            ("sub/CLAUDE.md", EntryKind::Link, "../gone/../x.md"),
        ]);
        assert_eq!(
            tree.read(root).unwrap(),
            ["CLAUDE.md", "docs/later.md", "sub/CLAUDE.md", "gone"]
        );
    }

    #[test]
    fn links_below_a_linked_settings_directory_are_read_through_too() {
        let tree = tree();
        let root = tree.write(&[
            (".claude", EntryKind::Link, "config/agent"),
            ("config/agent/commands", EntryKind::Link, "../../other"),
            ("other/deploy.md", EntryKind::Blob, "deploy"),
            ("other/back", EntryKind::Link, "../config"),
        ]);
        let mut read = tree.read(root).unwrap();
        read.sort();
        assert_eq!(
            read,
            [
                ".claude",
                "config",
                "config/agent",
                "config/agent/commands",
                "other",
                "other/back"
            ]
        );
    }

    #[test]
    fn a_path_is_covered_by_itself_what_holds_it_what_it_holds_and_the_empty_path() {
        assert!(covers(b"docs", b"docs"));
        assert!(covers(b"docs", b"docs/guide.md"));
        assert!(covers(b"docs/later.md", b"docs"));
        assert!(covers(b"", b"anything"));
        assert!(covers(b"Docs/Guide.md", b"docs/guide.md"));
        assert!(covers(b"Docs/Guide.md", b"DOCS"));
        assert!(!covers(b"docs", b"docs2/guide.md"));
        assert!(!covers(b"docs/guide.md", b"doc"));
        assert!(!covers(b"docs/guide.md", b"docs/guide"));
    }
}
