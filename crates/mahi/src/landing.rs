use std::{
    collections::{
        BTreeMap,
        BTreeSet,
    },
    fmt::{
        Display,
        Write as _,
    },
};

use mahi_agent::mcp;
use mahi_core::{
    AgentSlot,
    ParticipantName,
    ThreadId,
};
use mahi_store::{
    Change,
    Changes,
    CommitSigner,
    Identity,
    ObjectId,
    Store,
    StoreError,
};
use serde_json::{
    Map,
    Value,
};

use crate::mcp::{
    ToolError,
    push_clean,
};

const MAX_COMMITS: usize = 100;
pub(crate) const MAX_LANDED_PATHS: usize = 10_000;
const MAX_PATH_CHARS: usize = 4096;
const MAX_MESSAGE_CHARS: usize = 64 * 1024;
const MAX_TITLE_CHARS: usize = 1024;
const MAX_DESCRIPTION_CHARS: usize = 256 * 1024;
const LISTED: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Call {
    pub(crate) commits: Vec<Planned>,
    pub(crate) title: String,
    pub(crate) description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Planned {
    pub(crate) message: String,
    pub(crate) paths: Vec<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Misplaced {
    in_none: Vec<String>,
    twice: Vec<String>,
    unchanged: Vec<String>,
}

pub(crate) fn parse(arguments: &Map<String, Value>) -> Result<Call, ToolError> {
    let text = |name, most| {
        mcp::text_argument(arguments, name, most)?
            .map(str::to_owned)
            .ok_or(ToolError::Arguments)
    };
    let title = text("title", MAX_TITLE_CHARS)?;
    let description = text("description", MAX_DESCRIPTION_CHARS)?;
    let Some(Value::Array(listed)) = arguments.get("commits") else {
        return Err(ToolError::Arguments);
    };
    if listed.is_empty() || listed.len() > MAX_COMMITS {
        return Err(ToolError::Arguments);
    }
    let mut commits = Vec::with_capacity(listed.len());
    for commit in listed {
        let Value::Object(commit) = commit else {
            return Err(ToolError::Arguments);
        };
        let message = mcp::text_argument(commit, "message", MAX_MESSAGE_CHARS)?
            .filter(|message| !message.trim().is_empty())
            .ok_or(ToolError::Arguments)?
            .to_owned();
        let Some(Value::Array(paths)) = commit.get("paths") else {
            return Err(ToolError::Arguments);
        };
        if paths.len() > MAX_LANDED_PATHS {
            return Err(ToolError::Arguments);
        }
        let paths = paths
            .iter()
            .map(|path| match path {
                Value::String(path) if path.chars().count() <= MAX_PATH_CHARS => Ok(path.clone()),
                _ => Err(ToolError::Arguments),
            })
            .collect::<Result<_, _>>()?;
        commits.push(Planned { message, paths });
    }
    Ok(Call {
        commits,
        title,
        description,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Landable {
    pub(crate) paths: Vec<String>,
    pub(crate) gone: Vec<Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    NothingChanged,
    TooMany,
    NotUtf8(Vec<String>),
}

impl Landable {
    fn bytes(&self) -> impl Iterator<Item = &[u8]> {
        let named = self.paths.iter().map(String::as_bytes);
        named.chain(self.gone.iter().map(Vec::as_slice))
    }
}

impl Refused {
    pub(crate) fn text(&self) -> String {
        match self {
            Self::NothingChanged => NOTHING_CHANGED.to_owned(),
            Self::TooMany => TOO_MANY.to_owned(),
            Self::NotUtf8(paths) => {
                let mut text =
                    "not landed: rename these files, whose names are not UTF-8: ".to_owned();
                push_paths(&mut text, paths);
                text
            }
        }
    }
}

pub(crate) fn landable(changes: Changes) -> Result<Landable, Refused> {
    if changes.truncated {
        return Err(Refused::TooMany);
    }
    let mut marked = changes.not_utf8.into_iter().peekable();
    let mut landable = Landable {
        paths: Vec::with_capacity(changes.paths.len()),
        gone: Vec::new(),
    };
    let mut refused = Vec::new();
    let listed = changes.paths.into_iter().enumerate();
    for (index, (shown, change)) in listed {
        match marked.next_if(|(at, _)| *at == index) {
            None => landable.paths.push(shown),
            Some((_, bytes)) if change == Change::Deleted => landable.gone.push(bytes),
            Some(_) => refused.push(shown),
        }
    }
    if !refused.is_empty() {
        Err(Refused::NotUtf8(refused))
    } else if landable.paths.is_empty() {
        Err(Refused::NothingChanged)
    } else {
        Ok(landable)
    }
}

pub(crate) fn check(call: &Call, changed: &[String]) -> Result<(), Misplaced> {
    let changed: BTreeSet<&str> = changed.iter().map(String::as_str).collect();
    let mut placed: BTreeMap<&str, usize> = BTreeMap::new();
    let named = call.commits.iter().flat_map(|commit| &commit.paths);
    for path in named {
        *placed.entry(path.as_str()).or_default() += 1;
    }
    let misplaced = Misplaced {
        in_none: changed
            .iter()
            .filter(|path| !placed.contains_key(*path))
            .map(|path| (*path).to_owned())
            .collect(),
        twice: placed
            .iter()
            .filter(|&(path, &count)| count > 1 && changed.contains(path))
            .map(|(path, _)| (*path).to_owned())
            .collect(),
        unchanged: placed
            .keys()
            .filter(|path| !changed.contains(*path))
            .map(|path| (*path).to_owned())
            .collect(),
    };
    if misplaced == Misplaced::default() {
        return Ok(());
    }
    Err(misplaced)
}

impl Misplaced {
    pub(crate) fn text(&self) -> String {
        let mut text = "not landed: each changed path goes in exactly one commit\n".to_owned();
        for (label, paths) in [
            ("in no commit", &self.in_none),
            ("in more than one commit", &self.twice),
            ("did not change", &self.unchanged),
        ] {
            if paths.is_empty() {
                continue;
            }
            let _ = write!(text, "  {label}: ");
            push_paths(&mut text, paths);
            text.push('\n');
        }
        text
    }
}

pub(crate) fn owner_only(owner: &ParticipantName) -> String {
    format!("only {owner}, the thread's owner, lands this thread; ask them to")
}

pub(crate) fn conflicts_first(paths: &[String]) -> String {
    let mut text = "not landed: resolve the conflict markers first, in ".to_owned();
    push_paths(&mut text, paths);
    text
}

pub(crate) const NOTHING_CHANGED: &str = "nothing changed since the last landing";
const TOO_MANY: &str = "not landed: more than 10000 paths changed since the last landing";

pub(crate) fn identity_unset(key: &str, owner: &ParticipantName) -> String {
    format!(
        "not landed: git's {key} is not set in this repository; ask {owner} to set it with git config {key}"
    )
}

pub(crate) fn control_characters(commit: usize) -> String {
    format!(
        "not landed: the message of commit {commit} holds control characters; write it without them"
    )
}

pub(crate) fn no_landing_branch(landing: &str, remote: &impl Display) -> String {
    format!("the landing branch {landing} does not exist on {remote}")
}

pub(crate) fn changed_upstream(landing: &str, remote: &impl Display, paths: &[String]) -> String {
    let mut text = format!(
        "not landed: {landing} on {remote} changed these paths since the last landing too: "
    );
    push_paths(&mut text, paths);
    text
}

pub(crate) fn cannot_confirm(owner: &ParticipantName, thread: ThreadId) -> String {
    format!(
        "not landed: this run of {owner}'s agent cannot show the landing to push or cancel; resume the thread in a terminal with mahi resume {thread}"
    )
}

pub(crate) fn no_remote(owner: &ParticipantName) -> String {
    format!(
        "not landed: no remote is chosen for this clone; ask {owner} to choose one with mahi remote <name> --private or --public"
    )
}

pub(crate) fn waiting(owner: &ParticipantName) -> String {
    format!("mahi shows the landing to {owner} to push or cancel; your next note says which")
}

fn push_paths(text: &mut String, paths: &[String]) {
    let shown = paths.iter().take(LISTED);
    for (index, path) in shown.enumerate() {
        if index > 0 {
            text.push_str(", ");
        }
        push_clean(text, path);
    }
    let more = paths.len().saturating_sub(LISTED);
    if more > 0 {
        let _ = write!(text, " and {more} more");
    }
}

pub(crate) fn printable(text: &str) -> String {
    text.chars()
        .filter(|character| !is_control(*character) && !mahi_core::is_invisible(*character))
        .collect()
}

pub(crate) fn controlled_commit(call: &Call) -> Option<usize> {
    call.commits
        .iter()
        .position(|commit| commit.message.chars().any(is_control))
        .map(|index| index + 1)
}

fn is_control(character: char) -> bool {
    character.is_control() && !matches!(character, '\n' | '\t')
}

pub(crate) fn trailers(thread: ThreadId, agents: &[AgentSlot]) -> String {
    let mut trailers = format!("Thread: {thread}\n");
    for slot in agents {
        let _ = writeln!(trailers, "Agent: {slot}");
    }
    trailers
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Onto {
    Merged(ObjectId),
    Conflicts(Vec<String>),
}

pub(crate) fn onto(
    store: &Store,
    (measured, parent, worktree): (ObjectId, ObjectId, ObjectId),
    changed: &Landable,
) -> Result<Onto, StoreError> {
    if parent == measured {
        return Ok(Onto::Merged(worktree));
    }
    let every: Vec<&[u8]> = changed.bytes().collect();
    let ours = store.tree_with_paths(measured, parent, &every)?;
    let paths: Vec<&str> = changed.paths.iter().map(String::as_str).collect();
    let merged = store.merge_trees(measured, ours, worktree, ("landing", "worktree"))?;
    let mut clashes = Vec::new();
    for (path, at) in store.kind_clashes(parent, merged.tree, &paths)? {
        if store.object_at(parent, at)? != store.object_at(measured, at)? {
            clashes.push(path);
        }
    }
    if merged.conflicts.is_empty() && clashes.is_empty() {
        return Ok(Onto::Merged(merged.tree));
    }
    let conflicting: BTreeSet<String> = merged
        .conflicts
        .iter()
        .map(|(path, _)| path.to_string())
        .chain(clashes.iter().map(|path| (*path).to_owned()))
        .collect();
    Ok(Onto::Conflicts(conflicting.into_iter().collect()))
}

pub(crate) fn build(
    store: &Store,
    (landed, worktree): (ObjectId, ObjectId),
    gone: &[Vec<u8>],
    call: &mut Call,
    (thread, agents): (ThreadId, &[AgentSlot]),
    (identity, signer): (&Identity, &dyn CommitSigner),
) -> Result<Vec<ObjectId>, StoreError> {
    let trailers = trailers(thread, agents);
    let mut tree = store.commit_tree(landed)?;
    let mut parent = landed;
    let mut built = Vec::with_capacity(call.commits.len());
    let mut kept = Vec::with_capacity(call.commits.len());
    let last = call.commits.len().saturating_sub(1);
    let planned_commits = call.commits.drain(..).enumerate();
    for (index, planned) in planned_commits {
        let mut paths: Vec<&[u8]> = planned.paths.iter().map(String::as_bytes).collect();
        if index == last {
            paths.extend(gone.iter().map(Vec::as_slice));
        }
        let next = store.tree_with_paths(tree, worktree, &paths)?;
        if next == tree {
            continue;
        }
        tree = next;
        parent = store.write_commit(
            (tree, parent),
            (&planned.message, &trailers),
            identity,
            signer,
        )?;
        built.push(parent);
        kept.push(planned);
    }
    call.commits = kept;
    Ok(built)
}

#[cfg(test)]
mod tests {
    use mahi_store::EntryKind;
    use serde_json::json;

    use super::*;
    use crate::session::tests::repository_on_main;

    fn raw(store: &Store, files: &[(&[u8], &[u8])]) -> ObjectId {
        let repo = gix::open(store.common_dir()).unwrap();
        let mut tree = gix::objs::Tree {
            entries: files
                .iter()
                .map(|&(name, content)| gix::objs::tree::Entry {
                    mode: EntryKind::Blob.into(),
                    filename: name.into(),
                    oid: store.write_blob(content).unwrap(),
                })
                .collect(),
        };
        tree.entries.sort();
        repo.write_object(&tree).unwrap().detach()
    }

    #[test]
    fn a_deleted_name_that_is_not_utf8_conflicts_with_an_upstream_change_to_it() {
        let (_dir, store) = repository_on_main();
        let measured = raw(&store, &[(b"a.txt", b"a"), (b"old\xff", b"old")]);
        let upstream = raw(
            &store,
            &[(b"a.txt", b"a"), (b"old\xff", b"edited upstream")],
        );
        let worktree = raw(&store, &[(b"a.txt", b"a2")]);
        let changed = changed(&store, (measured, worktree)).unwrap();
        assert_eq!(changed.gone, [b"old\xff".to_vec()]);
        assert_eq!(
            onto(&store, (measured, upstream, worktree), &changed).unwrap(),
            Onto::Conflicts(vec!["old\u{fffd}".to_owned()])
        );
        let untouched = raw(
            &store,
            &[(b"a.txt", b"a"), (b"old\xff", b"old"), (b"up", b"u")],
        );
        let Onto::Merged(merged) = onto(&store, (measured, untouched, worktree), &changed).unwrap()
        else {
            panic!("an upstream change elsewhere merges");
        };
        assert_eq!(merged, worktree);
    }

    fn named(paths: &[String]) -> Landable {
        Landable {
            paths: paths.to_vec(),
            gone: Vec::new(),
        }
    }

    fn changed(
        store: &Store,
        (landed, worktree): (ObjectId, ObjectId),
    ) -> Result<Landable, Refused> {
        landable(
            store
                .changed_paths(landed, worktree, MAX_LANDED_PATHS)
                .unwrap(),
        )
    }

    struct Signing;

    impl CommitSigner for Signing {
        fn sign_commit(
            &self,
            _: &[u8],
        ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
            Ok("-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n-----END SSH SIGNATURE-----".to_owned())
        }
    }

    fn arguments(value: Value) -> Map<String, Value> {
        let Value::Object(map) = value else {
            panic!("the arguments are an object");
        };
        map
    }

    fn call(commits: &[(&str, &[&str])]) -> Call {
        Call {
            commits: commits
                .iter()
                .map(|(message, paths)| Planned {
                    message: (*message).to_owned(),
                    paths: paths.iter().map(|path| (*path).to_owned()).collect(),
                })
                .collect(),
            title: "Retry failed requests".to_owned(),
            description: "Why.".to_owned(),
        }
    }

    fn alice() -> Identity {
        Identity {
            name: "Alice".to_owned(),
            email: "alice@example.com".to_owned(),
            seconds: 1_793_000_000,
            offset: 0,
        }
    }

    fn base_on_head(store: &Store, base: ObjectId) -> ObjectId {
        store
            .write_commit(
                (base, store.head_commit().unwrap()),
                ("Base", ""),
                &alice(),
                &Signing,
            )
            .unwrap()
    }

    fn owned(paths: &[&str]) -> Vec<String> {
        paths.iter().map(|path| (*path).to_owned()).collect()
    }

    #[test]
    fn a_landing_refuses_names_that_are_not_utf8_it_would_write_and_deletes_the_others() {
        let paths = |listed: &[(&str, Change)]| -> Vec<(String, Change)> {
            listed
                .iter()
                .map(|(name, change)| ((*name).to_owned(), *change))
                .collect()
        };
        let both = Changes {
            paths: paths(&[
                ("caf\u{fffd}.txt", Change::Added),
                ("caf\u{fffd}.txt", Change::Modified),
                ("old\u{fffd}", Change::Deleted),
            ]),
            truncated: false,
            not_utf8: vec![(0, b"caf\xe9.txt".to_vec()), (2, b"old\xff".to_vec())],
        };
        let refused = landable(both).unwrap_err();
        assert_eq!(
            refused.text(),
            "not landed: rename these files, whose names are not UTF-8: caf\u{fffd}.txt"
        );
        let renamed = Changes {
            paths: paths(&[("old\u{fffd}", Change::Deleted), ("old.txt", Change::Added)]),
            truncated: false,
            not_utf8: vec![(0, b"old\xff".to_vec())],
        };
        assert_eq!(
            landable(renamed),
            Ok(Landable {
                paths: vec!["old.txt".to_owned()],
                gone: vec![b"old\xff".to_vec()],
            })
        );
        let cut = Changes {
            paths: paths(&[("a\u{fffd}", Change::Added)]),
            truncated: true,
            not_utf8: vec![(0, b"a\xff".to_vec())],
        };
        assert_eq!(landable(cut), Err(Refused::TooMany));
    }

    #[test]
    fn the_first_commit_whose_message_holds_a_control_character_is_named() {
        assert_eq!(
            controlled_commit(&call(&[("Add\n\n\tWhy.", &[]), ("Fix", &[])])),
            None
        );
        assert_eq!(
            controlled_commit(&call(&[
                ("Add", &[]),
                ("Fix\u{1b}[2J", &[]),
                ("Bell\u{7}", &[])
            ])),
            Some(2)
        );
        assert_eq!(controlled_commit(&call(&[("C1\u{9b}", &[])])), Some(1));
        assert_eq!(controlled_commit(&call(&[("Line\r", &[])])), Some(1));
    }

    #[test]
    fn a_call_is_read_from_its_commits_title_and_description_within_bounds() {
        let read = parse(&arguments(json!({
            "commits": [{ "message": "Retry", "paths": ["src/a.rs"] }],
            "title": "Retry failed requests",
            "description": "Why."
        })))
        .unwrap();
        assert_eq!(read, call(&[("Retry", &["src/a.rs"])]));
        let refused = [
            json!({ "title": "t", "description": "d" }),
            json!({ "commits": [], "title": "t", "description": "d" }),
            json!({ "commits": [{ "message": " ", "paths": [] }], "title": "t", "description": "d" }),
            json!({ "commits": [{ "message": "m", "paths": [1] }], "title": "t", "description": "d" }),
            json!({ "commits": [{ "message": "m", "paths": [] }], "description": "d" }),
            json!({ "commits": [{ "message": "m", "paths": [] }], "title": "t".repeat(1025), "description": "d" }),
            json!({ "commits": vec![json!({ "message": "m", "paths": [] }); 101], "title": "t", "description": "d" }),
        ];
        for refused in refused {
            assert!(
                matches!(
                    parse(&arguments(refused.clone())),
                    Err(ToolError::Arguments)
                ),
                "{refused}"
            );
        }
    }

    #[test]
    fn each_changed_path_goes_in_exactly_one_commit() {
        let changed = owned(&["README.md", "src/a.rs", "src/b.rs", "src/c.rs"]);
        let placed = call(&[
            ("One", &["src/a.rs", "src/c.rs"]),
            ("Two", &["src/b.rs", "README.md"]),
        ]);
        assert_eq!(check(&placed, &changed), Ok(()));
        let misplaced = call(&[
            ("One", &["src/a.rs", "src/c.rs", "docs/old.md"]),
            ("Two", &["src/c.rs"]),
        ]);
        let refused = check(&misplaced, &changed).unwrap_err();
        assert_eq!(
            refused.text(),
            "not landed: each changed path goes in exactly one commit\n  in no commit: \
             README.md, src/b.rs\n  in more than one commit: src/c.rs\n  did not change: \
             docs/old.md\n"
        );
    }

    #[test]
    fn the_answers_read_as_the_user_chose_and_list_at_most_twenty_paths() {
        let alice = ParticipantName::new("alice").unwrap();
        assert_eq!(
            owner_only(&alice),
            "only alice, the thread's owner, lands this thread; ask them to"
        );
        assert_eq!(
            waiting(&alice),
            "mahi shows the landing to alice to push or cancel; your next note says which"
        );
        assert_eq!(
            conflicts_first(&owned(&["src/a.rs"])),
            "not landed: resolve the conflict markers first, in src/a.rs"
        );
        let many: Vec<String> = (0..23).map(|index| format!("f{index}\u{7}")).collect();
        let text = conflicts_first(&many);
        assert!(text.ends_with("f19 and 3 more"), "{text}");
        assert!(!text.contains('\u{7}'), "{text}");
    }

    #[test]
    fn a_deleted_name_that_is_not_utf8_goes_out_in_the_last_commit() {
        let (_dir, store) = repository_on_main();
        let base = raw(&store, &[(b"a.txt", b"a"), (b"old\xff", b"old")]);
        let worktree = raw(&store, &[(b"a.txt", b"a2"), (b"old.txt", b"old")]);
        let changed = changed(&store, (base, worktree)).unwrap();
        assert_eq!(changed.paths, owned(&["a.txt", "old.txt"]));
        assert_eq!(changed.gone, [b"old\xff".to_vec()]);
        let (identity, landed) = (alice(), base_on_head(&store, base));
        let mut planned = call(&[("Edit a", &["a.txt"]), ("Rename old", &["old.txt"])]);
        let built = build(
            &store,
            (landed, worktree),
            &changed.gone,
            &mut planned,
            (ThreadId::random().unwrap(), &[]),
            (&identity, &Signing),
        )
        .unwrap();
        assert_eq!(built.len(), 2);
        let first = store.commit_tree(built[0]).unwrap();
        assert_eq!(store.changed_paths(base, first, 10).unwrap().paths.len(), 1);
        assert_eq!(store.commit_tree(built[1]).unwrap(), worktree);
    }

    #[test]
    fn a_directory_that_became_a_gitlink_lands_without_the_file_it_held() {
        let (_dir, store) = repository_on_main();
        let foreign = ObjectId::from_hex(b"1111111111111111111111111111111111111111").unwrap();
        let x = store.write_blob(b"x").unwrap();
        let sub = store.write_tree(&[("x", EntryKind::Blob, x)]).unwrap();
        let base = store.write_tree(&[("sub", EntryKind::Tree, sub)]).unwrap();
        let worktree = store
            .write_tree(&[("sub", EntryKind::Commit, foreign)])
            .unwrap();
        let (identity, landed) = (alice(), base_on_head(&store, base));
        let landable = changed(&store, (base, worktree)).unwrap();
        let named: Vec<&str> = landable.paths.iter().map(String::as_str).collect();
        let mut planned = call(&[("Make sub a submodule", &named)]);
        let built = build(
            &store,
            (landed, worktree),
            &[],
            &mut planned,
            (ThreadId::random().unwrap(), &[]),
            (&identity, &Signing),
        )
        .unwrap();
        assert_eq!(built.len(), 1);
        assert_eq!(store.commit_tree(built[0]).unwrap(), worktree);

        let other = store.write_blob(b"upstream").unwrap();
        let parent = store
            .write_tree(&[
                ("other.txt", EntryKind::Blob, other),
                ("sub", EntryKind::Tree, sub),
            ])
            .unwrap();
        let expected = store
            .write_tree(&[
                ("other.txt", EntryKind::Blob, other),
                ("sub", EntryKind::Commit, foreign),
            ])
            .unwrap();
        assert_eq!(
            onto(&store, (base, parent, worktree), &landable).unwrap(),
            Onto::Merged(worktree)
        );
        assert_eq!(
            store.tree_with_paths(parent, worktree, &named).unwrap(),
            expected
        );

        let edited = store.write_blob(b"x upstream").unwrap();
        let edited = store.write_tree(&[("x", EntryKind::Blob, edited)]).unwrap();
        let parent = store
            .write_tree(&[("sub", EntryKind::Tree, edited)])
            .unwrap();
        assert_eq!(
            onto(&store, (base, parent, worktree), &landable).unwrap(),
            Onto::Conflicts(owned(&["sub", "sub/x"]))
        );
    }

    #[test]
    fn the_commits_take_their_paths_from_the_worktree_one_after_the_other() {
        let (_dir, store) = repository_on_main();
        let blob = |content: &[u8]| store.write_blob(content).unwrap();
        let tree = |files: &[(&str, &[u8])]| {
            let entries: Vec<_> = files
                .iter()
                .map(|(name, content)| (*name, EntryKind::Blob, blob(content)))
                .collect();
            store.write_tree(&entries).unwrap()
        };
        let landed = store.head_commit().unwrap();
        let base = store.commit_tree(landed).unwrap();
        let added = tree(&[("a.txt", b"a"), ("b.txt", b"b")]);
        let worktree = store
            .tree_with_paths(base, added, &["a.txt", "b.txt"])
            .unwrap();
        let paths = changed(&store, (base, worktree)).unwrap().paths;
        let planned = call(&[("Add a", &["a.txt"]), ("Add b", &["b.txt"])]);
        assert_eq!(check(&planned, &paths), Ok(()));
        let thread = ThreadId::random().unwrap();
        let agents = [
            "alice.claude".parse().unwrap(),
            "bob.codex".parse().unwrap(),
        ];
        let identity = alice();
        let mut planned = planned;
        let built = build(
            &store,
            (landed, worktree),
            &[],
            &mut planned,
            (thread, &agents),
            (&identity, &Signing),
        )
        .unwrap();
        assert_eq!(built.len(), 2);
        assert_eq!(store.parent(built[0]).unwrap(), Some(landed));
        assert_eq!(store.parent(built[1]).unwrap(), Some(built[0]));
        assert_eq!(store.commit_tree(built[1]).unwrap(), worktree);
        let first = store.commit_tree(built[0]).unwrap();
        assert_eq!(store.changed_paths(base, first, 10).unwrap().paths.len(), 1);
        assert_eq!(
            store.commit_message(built[0]).unwrap(),
            format!("Add a\n\nThread: {thread}\nAgent: alice.claude\nAgent: bob.codex\n")
        );
        assert!(store.commit_signature(built[1]).unwrap().is_some());
        let mut again = call(&[("Add a again", &["a.txt"]), ("Add b", &["b.txt"])]);
        let on_a = build(
            &store,
            (built[0], worktree),
            &[],
            &mut again,
            (thread, &agents),
            (&identity, &Signing),
        )
        .unwrap();
        assert_eq!(on_a.len(), 1);
        assert_eq!(store.parent(on_a[0]).unwrap(), Some(built[0]));
        assert_eq!(store.commit_tree(on_a[0]).unwrap(), worktree);
        assert_eq!(again, call(&[("Add b", &["b.txt"])]));
        assert_eq!(
            changed(&store, (worktree, worktree)),
            Err(Refused::NothingChanged)
        );
    }

    #[test]
    fn a_landing_onto_its_parent_keeps_both_sides_changes_and_lists_the_paths_that_conflict() {
        let (_dir, store) = repository_on_main();
        let tree = |files: &[(&str, &str)]| {
            let entries: Vec<_> = files
                .iter()
                .map(|(name, content)| {
                    (
                        *name,
                        EntryKind::Blob,
                        store.write_blob(content.as_bytes()).unwrap(),
                    )
                })
                .collect();
            store.write_tree(&entries).unwrap()
        };
        let landed = tree(&[("m.txt", "1\n2\n3\n4\n5\n")]);
        let upstream = tree(&[("m.txt", "one\n2\n3\n4\n5\n"), ("u.txt", "u\n")]);
        let worktree = tree(&[("m.txt", "1\n2\n3\n4\nfive\n"), ("w.txt", "w\n")]);
        let paths = changed(&store, (landed, worktree)).unwrap().paths;
        assert_eq!(paths, owned(&["m.txt", "w.txt"]));
        let Onto::Merged(merged) =
            onto(&store, (landed, upstream, worktree), &named(&paths)).unwrap()
        else {
            panic!("the changes do not overlap");
        };
        let path_refs: Vec<&str> = paths.iter().map(String::as_str).collect();
        let landing = store.tree_with_paths(upstream, merged, &path_refs).unwrap();
        assert_eq!(
            landing,
            tree(&[
                ("m.txt", "one\n2\n3\n4\nfive\n"),
                ("u.txt", "u\n"),
                ("w.txt", "w\n")
            ])
        );
        let clashing = tree(&[("m.txt", "1\n2\n3\n4\nFIVE\n"), ("w.txt", "other\n")]);
        assert_eq!(
            onto(&store, (landed, clashing, worktree), &named(&paths)).unwrap(),
            Onto::Conflicts(owned(&["m.txt", "w.txt"]))
        );
        let next = tree(&[("m.txt", "1\n2\nthree\n4\nfive\n"), ("w.txt", "w\n")]);
        let paths = changed(&store, (worktree, next)).unwrap().paths;
        assert_eq!(paths, owned(&["m.txt"]));
        let Onto::Merged(merged) = onto(&store, (worktree, landing, next), &named(&paths)).unwrap()
        else {
            panic!("the landing branch's lines stay apart from the new change");
        };
        assert_eq!(
            store.tree_with_paths(landing, merged, &["m.txt"]).unwrap(),
            tree(&[
                ("m.txt", "one\n2\nthree\n4\nfive\n"),
                ("u.txt", "u\n"),
                ("w.txt", "w\n")
            ])
        );
        let inner = tree(&[("inner", "x\n")]);
        let directory = store
            .write_tree(&[
                (
                    "m.txt",
                    EntryKind::Blob,
                    store.write_blob(b"1\n2\n3\n4\n5\n").unwrap(),
                ),
                ("w.txt", EntryKind::Tree, inner),
            ])
            .unwrap();
        assert_eq!(
            onto(
                &store,
                (landed, directory, worktree),
                &named(&owned(&["w.txt"]))
            )
            .unwrap(),
            Onto::Conflicts(owned(&["w.txt"]))
        );
        assert_eq!(
            changed_upstream("main", &"up", &owned(&["src/a.rs", "src/b.rs"])),
            "not landed: main on up changed these paths since the last landing too: src/a.rs, src/b.rs"
        );
    }

    #[test]
    fn a_worktree_that_swaps_a_directory_for_a_file_lands_where_the_parent_did_not_change_it() {
        let (_dir, store) = repository_on_main();
        let blob = |content: &[u8]| store.write_blob(content).unwrap();
        let guide = store
            .write_tree(&[("guide.md", EntryKind::Blob, blob(b"guide\n"))])
            .unwrap();
        let landed = store
            .write_tree(&[
                ("d", EntryKind::Blob, blob(b"file\n")),
                ("docs", EntryKind::Tree, guide),
            ])
            .unwrap();
        let inner = store
            .write_tree(&[("f", EntryKind::Blob, blob(b"under\n"))])
            .unwrap();
        let worktree = store
            .write_tree(&[
                ("d", EntryKind::Tree, inner),
                ("docs", EntryKind::Blob, blob(b"now a file\n")),
            ])
            .unwrap();
        let paths = changed(&store, (landed, worktree)).unwrap().paths;
        assert_eq!(paths, owned(&["d/f", "d", "docs/guide.md", "docs"]));
        assert_eq!(
            onto(&store, (landed, landed, worktree), &named(&paths)).unwrap(),
            Onto::Merged(worktree)
        );
        let upstream = store
            .write_tree(&[
                ("d", EntryKind::Blob, blob(b"file\n")),
                ("docs", EntryKind::Tree, guide),
                ("u.txt", EntryKind::Blob, blob(b"u\n")),
            ])
            .unwrap();
        let Onto::Merged(merged) =
            onto(&store, (landed, upstream, worktree), &named(&paths)).unwrap()
        else {
            panic!("the landing branch kept d and docs as they were");
        };
        let path_refs: Vec<&str> = paths.iter().map(String::as_str).collect();
        let landing = store.tree_with_paths(upstream, merged, &path_refs).unwrap();
        assert_eq!(
            store.changed_paths(worktree, landing, 10).unwrap().paths,
            [("u.txt".to_owned(), mahi_store::Change::Added)]
        );
        let grown = store
            .write_tree(&[
                ("guide.md", EntryKind::Blob, blob(b"guide\n")),
                ("new.md", EntryKind::Blob, blob(b"new\n")),
            ])
            .unwrap();
        let added_under = store
            .write_tree(&[
                ("d", EntryKind::Blob, blob(b"file\n")),
                ("docs", EntryKind::Tree, grown),
            ])
            .unwrap();
        assert_eq!(
            onto(&store, (landed, added_under, worktree), &named(&paths)).unwrap(),
            Onto::Conflicts(owned(&["docs"]))
        );
    }
}
