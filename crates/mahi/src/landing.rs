use std::{
    collections::{
        BTreeMap,
        BTreeSet,
    },
    fmt::Write as _,
};

use mahi_agent::mcp;
use mahi_core::{
    AgentSlot,
    ParticipantName,
    ThreadId,
};
use mahi_store::{
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
const MAX_LANDED_PATHS: usize = 10_000;
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

pub(crate) fn changed(
    store: &Store,
    (landed, worktree): (ObjectId, ObjectId),
) -> Result<Option<Vec<String>>, StoreError> {
    let changes = store.changed_paths(landed, worktree, MAX_LANDED_PATHS)?;
    if changes.truncated {
        return Ok(None);
    }
    Ok(Some(
        changes.paths.into_iter().map(|(path, _)| path).collect(),
    ))
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
pub(crate) const TOO_MANY: &str =
    "not landed: more than 10000 paths changed since the last landing";

pub(crate) fn identity_unset(key: &str, owner: &ParticipantName) -> String {
    format!(
        "not landed: git's {key} is not set in this repository; ask {owner} to set it with git config {key}"
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

pub(crate) fn trailers(thread: ThreadId, agents: &[AgentSlot]) -> String {
    let mut trailers = format!("Thread: {thread}\n");
    for slot in agents {
        let _ = writeln!(trailers, "Agent: {slot}");
    }
    trailers
}

pub(crate) fn build(
    store: &Store,
    (landed, worktree): (ObjectId, ObjectId),
    call: &Call,
    (thread, agents): (ThreadId, &[AgentSlot]),
    (identity, signer): (&Identity, &dyn CommitSigner),
) -> Result<Vec<ObjectId>, StoreError> {
    let trailers = trailers(thread, agents);
    let mut tree = store.commit_tree(landed)?;
    let mut parent = landed;
    let mut built = Vec::with_capacity(call.commits.len());
    for planned in &call.commits {
        let paths: Vec<&str> = planned.paths.iter().map(String::as_str).collect();
        tree = store.tree_with_paths(tree, worktree, &paths)?;
        parent = store.write_commit(
            (tree, parent),
            (&planned.message, &trailers),
            identity,
            signer,
        )?;
        built.push(parent);
    }
    Ok(built)
}

#[cfg(test)]
mod tests {
    use mahi_store::EntryKind;
    use serde_json::json;

    use super::*;
    use crate::session::tests::repository_on_main;

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

    fn owned(paths: &[&str]) -> Vec<String> {
        paths.iter().map(|path| (*path).to_owned()).collect()
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
        let paths = changed(&store, (base, worktree)).unwrap().unwrap();
        let planned = call(&[("Add a", &["a.txt"]), ("Add b", &["b.txt"])]);
        assert_eq!(check(&planned, &paths), Ok(()));
        let thread = ThreadId::random().unwrap();
        let agents = [
            "alice.claude".parse().unwrap(),
            "bob.codex".parse().unwrap(),
        ];
        let identity = Identity {
            name: "Alice".to_owned(),
            email: "alice@example.com".to_owned(),
            seconds: 1_793_000_000,
            offset: 0,
        };
        let built = build(
            &store,
            (landed, worktree),
            &planned,
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
        assert_eq!(
            changed(&store, (worktree, worktree)).unwrap(),
            Some(Vec::new())
        );
    }
}
