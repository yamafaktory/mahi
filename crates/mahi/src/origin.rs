use mahi_core::{
    AgentSlot,
    RefKind,
    ThreadId,
    ThreadRef,
};
use mahi_store::{
    Blamed,
    BlamedLine,
    Change,
    MAX_DIFFED_BYTES,
    ObjectId,
    Store,
    StoreError,
    landed_from,
};
use mahi_thread::names_thread;

use crate::{
    merged,
    turn_end::turn_of,
};

/// The most units of work one trace spends, over every thread and agent it searches: each
/// snapshot walked, compared, or looked into for a move.
pub(crate) const MAX_TRACE_WORK: usize = 4096;
const MAX_MOVES_FOLLOWED: usize = 16;
const MAX_MOVED_PATHS: usize = 500;

/// Where the commit that last changed a line leads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Origin {
    /// The commit names no mahi thread.
    Outside,
    /// The commit is too large to read its message.
    TooLarge,
    /// The commit landed the threads it names.
    Landed(Vec<Searched>),
    /// The commit is a snapshot of the thread the agent works in.
    Unlanded(Searched),
}

/// A thread searched for the snapshot that first holds a line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Searched {
    /// The thread.
    pub(crate) thread: ThreadId,
    /// The agents the landing names, or, for a line not landed, the agents searched. A landing
    /// that names none has every agent with snapshots in its thread searched.
    pub(crate) agents: Vec<AgentSlot>,
    /// What the search found.
    pub(crate) found: Found,
}

/// What a search of a thread's snapshots found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Found {
    /// The repository holds no snapshots of the agents searched.
    NoSnapshots,
    /// The snapshots that first hold the line, one per agent at most, and whether the trace
    /// spent its [`MAX_TRACE_WORK`] before it searched them all.
    Snapshots(Vec<FirstHeld>, Walked),
}

/// Whether a search walked every snapshot it meant to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Walked {
    All,
    Cut,
}

/// The snapshot of an agent that first holds a line, with the transcript turn it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FirstHeld {
    pub(crate) slot: AgentSlot,
    pub(crate) snapshot: ObjectId,
    pub(crate) turn: Option<u64>,
}

/// Blames line `line` of the file at `path` in `at`, a snapshot of an agent in `thread` or the
/// thread's `base`. An agent's first snapshot has no parent, so a line blamed on it is blamed
/// again in `base`, when `base` holds the same file at the same path. A commit too large to read
/// is no snapshot.
///
/// # Errors
///
/// Returns [`StoreError`] when a commit, a tree or the history cannot be read.
pub(crate) fn blame(
    store: &Store,
    (thread, base): (ThreadId, ObjectId),
    at: ObjectId,
    (path, line): (&str, u32),
) -> Result<Blamed, StoreError> {
    let blamed = store.line_commit(at, path, line)?;
    let Blamed::Commit(found) = &blamed else {
        return Ok(blamed);
    };
    let snapshot = match store.commit_message(found.commit) {
        Ok(message) => names_thread(&message, thread),
        Err(StoreError::TooLarge { .. }) => false,
        Err(error) => return Err(error),
    };
    if !snapshot || store.parent(found.commit)?.is_some() {
        return Ok(blamed);
    }
    let path = found.path.as_str();
    let object_at = |commit| match store.object_at(store.commit_tree(commit)?, path) {
        Err(error) if unreadable(&error) => Ok(None),
        read => read,
    };
    let started = object_at(found.commit)?;
    if started.is_none() || started != object_at(base)? {
        return Ok(blamed);
    }
    store.line_commit(base, path, found.line)
}

/// Follows `line` from the commit that last changed it to the snapshots that first hold it:
/// of the threads and agents the commit's landing trailers name, or, when the commit is a
/// snapshot of `current`, of every agent with snapshots in `current`. A commit too large to
/// read leads nowhere. The whole trace spends at most [`MAX_TRACE_WORK`] units of work.
///
/// # Errors
///
/// Returns [`StoreError`] when a commit, a tree or a ref cannot be read.
pub(crate) fn trace(
    store: &Store,
    current: ThreadId,
    line: &BlamedLine,
) -> Result<Origin, StoreError> {
    let message = match store.commit_message(line.commit) {
        Ok(message) => message,
        Err(StoreError::TooLarge { .. }) => return Ok(Origin::TooLarge),
        Err(error) => return Err(error),
    };
    let mut budget = MAX_TRACE_WORK;
    let landed = landed_from(&message);
    if !landed.is_empty() {
        let refs = if landed.iter().any(|landed| landed.agents.is_empty()) {
            store.thread_refs()?
        } else {
            Vec::new()
        };
        let searched = landed
            .into_iter()
            .map(|landed| {
                let heads = if landed.agents.is_empty() {
                    snapshot_heads(&refs, landed.thread)
                } else {
                    named_heads(store, landed.thread, &landed.agents)?
                };
                Ok(Searched {
                    thread: landed.thread,
                    found: search(store, (landed.thread, heads), line, &mut budget)?,
                    agents: landed.agents,
                })
            })
            .collect::<Result<_, StoreError>>()?;
        return Ok(Origin::Landed(searched));
    }
    if !names_thread(&message, current) {
        return Ok(Origin::Outside);
    }
    let heads = snapshot_heads(&store.thread_refs()?, current);
    let agents = heads.iter().map(|(slot, _)| slot.clone()).collect();
    Ok(Origin::Unlanded(Searched {
        thread: current,
        agents,
        found: search(store, (current, heads), line, &mut budget)?,
    }))
}

/// Returns each agent with snapshots in `thread`, among `refs`, with the newest of them.
fn snapshot_heads(
    refs: &[(ThreadRef, ObjectId)],
    thread: ThreadId,
) -> Vec<(AgentSlot, Option<ObjectId>)> {
    refs.iter()
        .filter(|(thread_ref, _)| thread_ref.thread() == thread)
        .filter_map(|(thread_ref, head)| match thread_ref.kind() {
            RefKind::Snapshots(slot) => Some((slot.clone(), Some(*head))),
            RefKind::Meta | RefKind::State | RefKind::Transcript(_) | RefKind::Session(_) => None,
        })
        .collect()
}

/// Returns each of `agents` with its newest snapshot in `thread`, when it has any here.
fn named_heads(
    store: &Store,
    thread: ThreadId,
    agents: &[AgentSlot],
) -> Result<Vec<(AgentSlot, Option<ObjectId>)>, StoreError> {
    agents
        .iter()
        .map(|slot| {
            let head = store.head(&ThreadRef::new(thread, RefKind::Snapshots(slot.clone())))?;
            Ok((slot.clone(), head))
        })
        .collect()
}

fn search(
    store: &Store,
    (thread, heads): (ThreadId, Vec<(AgentSlot, Option<ObjectId>)>),
    line: &BlamedLine,
    budget: &mut usize,
) -> Result<Found, StoreError> {
    let mut held_any = false;
    let mut first_held = Vec::new();
    let mut walked = Walked::All;
    for (slot, head) in heads {
        let Some(head) = head else {
            continue;
        };
        held_any = true;
        match first_holding(store, (thread, head), line, budget)? {
            Holding::First(snapshot, turn) => first_held.push(FirstHeld {
                slot,
                snapshot,
                turn,
            }),
            Holding::None => {}
            Holding::Cut => walked = Walked::Cut,
        }
    }
    Ok(if held_any {
        Found::Snapshots(first_held, walked)
    } else {
        Found::NoSnapshots
    })
}

/// Takes one unit of work from `budget`, or says it is spent.
fn spend(budget: &mut usize) -> bool {
    let Some(left) = budget.checked_sub(1) else {
        return false;
    };
    *budget = left;
    true
}

enum Holding {
    First(ObjectId, Option<u64>),
    None,
    Cut,
}

struct Step {
    commit: ObjectId,
    merges: bool,
    turn: Option<u64>,
}

/// Returns the oldest snapshot of the history ending at `head` in `thread` that holds more
/// copies of `line` than the snapshot before it. The oldest snapshot is where the agent's
/// worktree started, so it is never the one. A merge snapshot is never the one either: when the
/// copies first grow in one, the line came from a teammate. When the copies first grow where
/// the file appears at its path, and that snapshot deleted a file that held the line, the file
/// moved there, so the search goes on at its old path in the snapshots before, for at most
/// [`MAX_MOVES_FOLLOWED`] moves. Each snapshot walked, compared or looked into for a move spends
/// a unit of `budget`. A snapshot mahi refuses to read ends the walk there.
fn first_holding(
    store: &Store,
    (thread, head): (ThreadId, ObjectId),
    line: &BlamedLine,
    budget: &mut usize,
) -> Result<Holding, StoreError> {
    let mut steps = Vec::new();
    let mut next = Some(head);
    while let Some(commit) = next {
        let message = match store.commit_message(commit) {
            Ok(message) => message,
            Err(error) if unreadable(&error) => break,
            Err(error) => return Err(error),
        };
        if !names_thread(&message, thread) {
            break;
        }
        if !spend(budget) {
            return Ok(Holding::Cut);
        }
        steps.push(Step {
            commit,
            merges: merged::merges(&message),
            turn: turn_of(&message),
        });
        next = match store.parent(commit) {
            Ok(parent) => parent,
            Err(error) if unreadable(&error) => None,
            Err(error) => return Err(error),
        };
    }
    steps.reverse();
    let mut path = line.path.clone();
    let mut end = steps.len();
    for _ in 0..=MAX_MOVES_FOLLOWED {
        let run = steps.get(..end).unwrap_or_default();
        let (at, before, after) = match first_growth(store, run, (&path, &line.text), budget)? {
            Growth::Grew { at, before, after } => (at, before, after),
            Growth::Never => return Ok(Holding::None),
            Growth::Cut => return Ok(Holding::Cut),
        };
        if after.step.merges {
            return Ok(Holding::None);
        }
        if before.copies.object.is_some() {
            return Ok(Holding::First(after.step.commit, after.step.turn));
        }
        match moved_from(store, (before.step.commit, &after), &line.text, budget)? {
            Moved::From(moved) => {
                path = moved;
                end = at;
            }
            Moved::Nowhere => return Ok(Holding::First(after.step.commit, after.step.turn)),
            Moved::Cut => return Ok(Holding::Cut),
        }
    }
    Ok(Holding::Cut)
}

/// Says whether `error` comes from an object mahi refuses to read, as a teammate's malformed
/// snapshot can hold: too large, of the wrong kind, with several parents or a name twice.
fn unreadable(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::TooLarge { .. }
            | StoreError::WrongObject { .. }
            | StoreError::NotLinear(_)
            | StoreError::DuplicateEntryName(_)
    )
}

/// A snapshot with what it holds of a line.
struct Held<'run> {
    step: &'run Step,
    copies: Copies,
}

/// Where the copies of a line first grew in a run of snapshots, oldest first.
enum Growth<'run> {
    /// They grew in the snapshot `after`, at index `at` of the run, from `before`.
    Grew {
        at: usize,
        before: Held<'run>,
        after: Held<'run>,
    },
    Never,
    Cut,
}

fn first_growth<'run>(
    store: &Store,
    run: &'run [Step],
    (path, text): (&str, &[u8]),
    budget: &mut usize,
) -> Result<Growth<'run>, StoreError> {
    let mut before: Option<Held<'run>> = None;
    let pairs = run.iter().zip(run.iter().skip(1)).enumerate();
    for (at, (earlier, step)) in pairs {
        if !spend(budget) {
            return Ok(Growth::Cut);
        }
        let earlier = match before.take() {
            Some(held) => held,
            None => Held {
                step: earlier,
                copies: Copies::of(store, earlier.commit, (path, text), None)?,
            },
        };
        let after = Held {
            step,
            copies: Copies::of(store, step.commit, (path, text), Some(&earlier.copies))?,
        };
        if after.copies.count > earlier.copies.count {
            return Ok(Growth::Grew {
                at: at + 1,
                before: earlier,
                after,
            });
        }
        before = Some(after);
    }
    Ok(Growth::Never)
}

enum Moved {
    From(String),
    Nowhere,
    Cut,
}

/// Returns a file that `after` deleted from the snapshot `before` and that held `text` there:
/// one with the same content as `after`'s file when there is one, or else the first. It looks
/// at most at [`MAX_MOVED_PATHS`] changed paths, each deleted one a unit of `budget`.
fn moved_from(
    store: &Store,
    (before, after): (ObjectId, &Held<'_>),
    text: &[u8],
    budget: &mut usize,
) -> Result<Moved, StoreError> {
    let changes = match store.changed_paths(
        store.commit_tree(before)?,
        after.copies.tree,
        MAX_MOVED_PATHS,
    ) {
        Ok(changes) => changes,
        Err(error) if unreadable(&error) => return Ok(Moved::Nowhere),
        Err(error) => return Err(error),
    };
    let deleted = changes
        .paths
        .into_iter()
        .filter_map(|(path, change)| (change == Change::Deleted).then_some(path));
    let mut holding = None;
    for path in deleted {
        if !spend(budget) {
            return Ok(Moved::Cut);
        }
        let copies = Copies::of(store, before, (&path, text), None)?;
        if copies.count == 0 {
            continue;
        }
        if copies.object == after.copies.object {
            return Ok(Moved::From(path));
        }
        holding.get_or_insert(path);
    }
    Ok(holding.map_or(Moved::Nowhere, Moved::From))
}

/// How many lines of a file read a given text, with the tree read and the object at the
/// file's path in it.
struct Copies {
    tree: ObjectId,
    object: Option<ObjectId>,
    count: usize,
}

impl Copies {
    /// Counts the lines of the file at `path` in `commit` that read `text`, looking the path up
    /// only when the tree differs from `before`'s, and reading the file only when its object
    /// does. A file larger than [`MAX_DIFFED_BYTES`], a path that holds no file, or one under a
    /// tree too large to read, has none.
    fn of(
        store: &Store,
        commit: ObjectId,
        (path, text): (&str, &[u8]),
        before: Option<&Self>,
    ) -> Result<Self, StoreError> {
        let tree = store.commit_tree(commit)?;
        if let Some(before) = before
            && before.tree == tree
        {
            return Ok(Self { tree, ..*before });
        }
        let object = match store.object_at(tree, path) {
            Ok(object) => object,
            Err(error) if unreadable(&error) => None,
            Err(error) => return Err(error),
        };
        if let Some(before) = before
            && before.object == object
        {
            return Ok(Self {
                tree,
                object,
                count: before.count,
            });
        }
        let count = match object.map(|id| store.read_blob(id, MAX_DIFFED_BYTES)) {
            None => 0,
            Some(Err(error)) if unreadable(&error) => 0,
            Some(Err(error)) => return Err(error),
            Some(Ok(data)) => data
                .split_inclusive(|byte| *byte == b'\n')
                .filter(|read| read.strip_suffix(b"\n").unwrap_or(read) == text)
                .count(),
        };
        Ok(Self {
            tree,
            object,
            count,
        })
    }
}

#[cfg(test)]
mod tests {
    use gix::objs::tree::EntryKind;
    use mahi_store::{
        Blamed,
        landing_trailers,
    };
    use mahi_thread::snapshot_message;

    use super::*;

    const FILE: &str = "lib.rs";

    struct Repo {
        _dir: tempfile::TempDir,
        store: Store,
        main: ThreadRef,
    }

    fn repo() -> Repo {
        let dir = tempfile::tempdir().unwrap();
        gix::init(dir.path()).unwrap();
        let store = Store::open(dir.path()).unwrap();
        let main = ThreadRef::new(ThreadId::random().unwrap(), RefKind::Meta);
        Repo {
            _dir: dir,
            store,
            main,
        }
    }

    fn slot(name: &str) -> AgentSlot {
        name.parse().unwrap()
    }

    impl Repo {
        fn tree(&self, text: &str) -> ObjectId {
            let blob = self.store.write_blob(text.as_bytes()).unwrap();
            self.store
                .write_tree(&[(FILE, EntryKind::Blob, blob)])
                .unwrap()
        }

        fn on_main(&self, text: &str, message: &str) -> ObjectId {
            let head = self.store.head(&self.main).unwrap();
            self.store
                .append(&self.main, head, self.tree(text), message)
                .unwrap()
        }

        fn landing(&self, text: &str, thread: ThreadId, agents: &[AgentSlot]) -> ObjectId {
            let message = format!("Land the work\n\n{}", landing_trailers(thread, agents));
            self.on_main(text, &message)
        }

        fn snapshot(
            &self,
            (thread, agent): (ThreadId, &str),
            text: &str,
            trailers: &str,
        ) -> ObjectId {
            let snapshots = ThreadRef::new(thread, RefKind::Snapshots(slot(agent)));
            let head = self.store.head(&snapshots).unwrap();
            let message = snapshot_message(&format!("snapshot\n\n{trailers}"), thread);
            self.store
                .append(&snapshots, head, self.tree(text), &message)
                .unwrap()
        }

        fn blamed(&self, at: ObjectId, line: u32) -> BlamedLine {
            match self.store.line_commit(at, FILE, line).unwrap() {
                Blamed::Commit(blamed) => blamed,
                other => panic!("line {line} is not blamed: {other:?}"),
            }
        }
    }

    #[test]
    fn a_line_the_first_snapshot_started_with_is_blamed_in_the_threads_base() {
        let repo = repo();
        let thread = ThreadId::random().unwrap();
        let base = repo.on_main("a\nb\n", "base");
        let started = repo.snapshot((thread, "alice.claude"), "x\na\nb\n", "");
        let latest = repo.snapshot((thread, "alice.claude"), "x\na\nb\nc\n", "");
        let blamed = |line| match blame(&repo.store, (thread, base), latest, (FILE, line)).unwrap()
        {
            Blamed::Commit(blamed) => blamed.commit,
            other => panic!("line {line} is not blamed: {other:?}"),
        };
        assert_eq!(blamed(2), started);
        assert_eq!(blamed(4), latest);
        let thread = ThreadId::random().unwrap();
        repo.snapshot((thread, "bob.codex"), "a\nb\n", "");
        let latest = repo.snapshot((thread, "bob.codex"), "z\na\nb\n", "");
        let blamed = |line| match blame(&repo.store, (thread, base), latest, (FILE, line)).unwrap()
        {
            Blamed::Commit(blamed) => blamed,
            other => panic!("line {line} is not blamed: {other:?}"),
        };
        assert_eq!(blamed(3).commit, base);
        assert_eq!(blamed(3).line, 2);
        assert_eq!(blamed(1).commit, latest);
    }

    fn found(first_held: Vec<FirstHeld>) -> Found {
        Found::Snapshots(first_held, Walked::All)
    }

    #[test]
    fn a_landed_line_leads_to_the_snapshot_that_first_added_it_and_its_turn() {
        let repo = repo();
        let thread = ThreadId::random().unwrap();
        repo.on_main("a\n", "base");
        repo.snapshot((thread, "alice.claude"), "a\n", "");
        let added = repo.snapshot((thread, "alice.claude"), "a\nb\n", "Mahi-Turn: 1\n");
        repo.snapshot((thread, "alice.claude"), "a\nb\nc\n", "Mahi-Turn: 2\n");
        let agents = vec![slot("alice.claude")];
        let landed = repo.landing("a\nb\nc\n", thread, &agents);
        let current = ThreadId::random().unwrap();
        assert_eq!(
            trace(&repo.store, current, &repo.blamed(landed, 2)).unwrap(),
            Origin::Landed(vec![Searched {
                thread,
                agents,
                found: found(vec![FirstHeld {
                    slot: slot("alice.claude"),
                    snapshot: added,
                    turn: Some(1),
                }]),
            }])
        );
    }

    #[test]
    fn a_line_a_teammate_merged_in_is_credited_to_the_teammate_only() {
        let repo = repo();
        let thread = ThreadId::random().unwrap();
        repo.on_main("a\n", "base");
        repo.snapshot((thread, "alice.claude"), "a\n", "");
        let wrote = repo.snapshot((thread, "alice.claude"), "a\nb\n", "Mahi-Turn: 4\n");
        repo.snapshot((thread, "bob.codex"), "a\n", "");
        let merged = format!("Mahi-Merged: alice.claude {wrote}\n");
        repo.snapshot((thread, "bob.codex"), "a\nb\n", &merged);
        repo.snapshot((thread, "bob.codex"), "a\nb\nb\n", "Mahi-Turn: 1\n");
        let agents = vec![slot("alice.claude"), slot("bob.codex")];
        let landed = repo.landing("a\nb\n", thread, &agents);
        let Origin::Landed(searched) = trace(
            &repo.store,
            ThreadId::random().unwrap(),
            &repo.blamed(landed, 2),
        )
        .unwrap() else {
            panic!("the commit landed a thread");
        };
        assert_eq!(
            searched[0].found,
            found(vec![FirstHeld {
                slot: slot("alice.claude"),
                snapshot: wrote,
                turn: Some(4),
            }])
        );
    }

    #[test]
    fn a_line_the_worktree_started_with_counts_only_once_another_copy_is_added() {
        let repo = repo();
        let thread = ThreadId::random().unwrap();
        repo.on_main("}\n", "base");
        repo.snapshot((thread, "alice.claude"), "}\n", "");
        repo.snapshot((thread, "alice.claude"), "}\nx\n", "Mahi-Turn: 1\n");
        let copied = repo.snapshot((thread, "alice.claude"), "}\nx\n}\n", "");
        let agents = vec![slot("alice.claude")];
        let landed = repo.landing("}\nx\n}\n", thread, &agents);
        let Origin::Landed(searched) = trace(
            &repo.store,
            ThreadId::random().unwrap(),
            &repo.blamed(landed, 3),
        )
        .unwrap() else {
            panic!("the commit landed a thread");
        };
        assert_eq!(
            searched[0].found,
            found(vec![FirstHeld {
                slot: slot("alice.claude"),
                snapshot: copied,
                turn: None,
            }])
        );
    }

    #[test]
    fn a_commit_without_trailers_is_outside_and_a_thread_without_snapshots_here_is_told() {
        let repo = repo();
        let base = repo.on_main("a\n", "base");
        let current = ThreadId::random().unwrap();
        assert_eq!(
            trace(&repo.store, current, &repo.blamed(base, 1)).unwrap(),
            Origin::Outside
        );
        let gone = ThreadId::random().unwrap();
        let agents = vec![slot("alice.claude")];
        let landed = repo.landing("a\nb\n", gone, &agents);
        assert_eq!(
            trace(&repo.store, current, &repo.blamed(landed, 2)).unwrap(),
            Origin::Landed(vec![Searched {
                thread: gone,
                agents,
                found: Found::NoSnapshots,
            }])
        );
    }

    #[test]
    fn a_line_not_landed_yet_is_searched_in_every_agent_of_the_current_thread() {
        let repo = repo();
        let current = ThreadId::random().unwrap();
        repo.on_main("a\n", "base");
        repo.snapshot((current, "alice.claude"), "a\n", "");
        let latest = repo.snapshot((current, "alice.claude"), "a\nb\n", "Mahi-Turn: 3\n");
        repo.snapshot((current, "bob.codex"), "a\n", "");
        assert_eq!(
            trace(&repo.store, current, &repo.blamed(latest, 2)).unwrap(),
            Origin::Unlanded(Searched {
                thread: current,
                agents: vec![slot("alice.claude"), slot("bob.codex")],
                found: found(vec![FirstHeld {
                    slot: slot("alice.claude"),
                    snapshot: latest,
                    turn: Some(3),
                }]),
            })
        );
    }

    #[test]
    fn a_landing_that_names_no_agent_searches_every_agent_of_its_thread() {
        let repo = repo();
        let thread = ThreadId::random().unwrap();
        repo.on_main("a\n", "base");
        repo.snapshot((thread, "alice.claude"), "a\n", "");
        let added = repo.snapshot((thread, "alice.claude"), "a\nb\n", "Mahi-Turn: 2\n");
        let landed = repo.landing("a\nb\n", thread, &[]);
        assert_eq!(
            trace(
                &repo.store,
                ThreadId::random().unwrap(),
                &repo.blamed(landed, 2)
            )
            .unwrap(),
            Origin::Landed(vec![Searched {
                thread,
                agents: Vec::new(),
                found: found(vec![FirstHeld {
                    slot: slot("alice.claude"),
                    snapshot: added,
                    turn: Some(2),
                }]),
            }])
        );
    }

    #[test]
    fn a_line_not_landed_that_a_merge_brought_leads_to_the_teammate_who_added_it() {
        let repo = repo();
        let current = ThreadId::random().unwrap();
        repo.on_main("a\n", "base");
        repo.snapshot((current, "alice.claude"), "a\n", "");
        let wrote = repo.snapshot((current, "alice.claude"), "a\nb\n", "Mahi-Turn: 2\n");
        repo.snapshot((current, "bob.codex"), "a\n", "");
        let merged = format!("Mahi-Merged: alice.claude {wrote}\n");
        let latest = repo.snapshot((current, "bob.codex"), "a\nb\n", &merged);
        assert_eq!(
            trace(&repo.store, current, &repo.blamed(latest, 2)).unwrap(),
            Origin::Unlanded(Searched {
                thread: current,
                agents: vec![slot("alice.claude"), slot("bob.codex")],
                found: found(vec![FirstHeld {
                    slot: slot("alice.claude"),
                    snapshot: wrote,
                    turn: Some(2),
                }]),
            })
        );
    }

    #[test]
    fn a_line_blamed_on_a_merge_or_a_large_commit_on_main_still_gets_an_answer() {
        let repo = repo();
        let thread = ThreadId::random().unwrap();
        let first = repo.on_main("a\n", "first");
        let side = repo.on_main("a\nb\n", "side");
        let git = gix::open(repo.store.common_dir()).unwrap();
        let merge = gix::objs::Commit {
            tree: repo.tree("a\nb\nc\n"),
            parents: [side, first].into_iter().collect(),
            author: gix::actor::Signature::default(),
            committer: gix::actor::Signature::default(),
            encoding: None,
            message: "merge".into(),
            extra_headers: Vec::new(),
        };
        let merge = git.write_object(&merge).unwrap().detach();
        let Blamed::Commit(blamed) = blame(&repo.store, (thread, merge), merge, (FILE, 3)).unwrap()
        else {
            panic!("line 3 is blamed");
        };
        assert_eq!(blamed.commit, merge);
        let long = format!("large\n\n{}\n", "x".repeat(70 * 1024));
        let large = repo.on_main("a\nb\nd\n", &long);
        let Blamed::Commit(blamed) = blame(&repo.store, (thread, large), large, (FILE, 3)).unwrap()
        else {
            panic!("line 3 is blamed");
        };
        assert_eq!(
            trace(&repo.store, thread, &blamed).unwrap(),
            Origin::TooLarge
        );
    }

    #[test]
    fn a_file_renamed_in_the_thread_leads_to_the_snapshot_that_added_the_line_before() {
        let repo = repo();
        let thread = ThreadId::random().unwrap();
        repo.on_main("a\n", "base");
        repo.snapshot((thread, "alice.claude"), "a\n", "");
        let added = repo.snapshot((thread, "alice.claude"), "a\nb\n", "Mahi-Turn: 2\n");
        let snapshots = ThreadRef::new(thread, RefKind::Snapshots(slot("alice.claude")));
        let head = repo.store.head(&snapshots).unwrap();
        let blob = repo.store.write_blob(b"a\nb\n").unwrap();
        let moved = repo
            .store
            .write_tree(&[("moved.rs", EntryKind::Blob, blob)])
            .unwrap();
        let message = snapshot_message("snapshot\n\nMahi-Turn: 5\n", thread);
        repo.store
            .append(&snapshots, head, moved, &message)
            .unwrap();
        let agents = vec![slot("alice.claude")];
        let message = format!("Land\n\n{}", landing_trailers(thread, &agents));
        let main_head = repo.store.head(&repo.main).unwrap();
        let landed = repo
            .store
            .append(&repo.main, main_head, moved, &message)
            .unwrap();
        let Blamed::Commit(blamed) = repo.store.line_commit(landed, "moved.rs", 2).unwrap() else {
            panic!("line 2 is blamed");
        };
        let Origin::Landed(searched) =
            trace(&repo.store, ThreadId::random().unwrap(), &blamed).unwrap()
        else {
            panic!("the commit landed a thread");
        };
        assert_eq!(
            searched[0].found,
            found(vec![FirstHeld {
                slot: slot("alice.claude"),
                snapshot: added,
                turn: Some(2),
            }])
        );
    }

    #[test]
    fn a_blank_line_is_credited_to_the_snapshot_that_added_it() {
        let repo = repo();
        let thread = ThreadId::random().unwrap();
        repo.on_main("", "base");
        let snapshots = ThreadRef::new(thread, RefKind::Snapshots(slot("alice.claude")));
        let other = repo.store.write_blob(b"other\n").unwrap();
        let empty = repo
            .store
            .write_tree(&[("other.rs", EntryKind::Blob, other)])
            .unwrap();
        let message = snapshot_message("snapshot\n", thread);
        repo.store
            .append(&snapshots, None, empty, &message)
            .unwrap();
        repo.snapshot((thread, "alice.claude"), "a\n", "Mahi-Turn: 1\n");
        let added = repo.snapshot((thread, "alice.claude"), "a\n\nb\n", "Mahi-Turn: 2\n");
        let agents = vec![slot("alice.claude")];
        let landed = repo.landing("a\n\nb\n", thread, &agents);
        let Origin::Landed(searched) = trace(
            &repo.store,
            ThreadId::random().unwrap(),
            &repo.blamed(landed, 2),
        )
        .unwrap() else {
            panic!("the commit landed a thread");
        };
        assert_eq!(
            searched[0].found,
            found(vec![FirstHeld {
                slot: slot("alice.claude"),
                snapshot: added,
                turn: Some(2),
            }])
        );
    }

    #[test]
    fn following_a_file_that_moved_in_every_snapshot_counts_against_the_walk() {
        let repo = repo();
        let thread = ThreadId::random().unwrap();
        repo.on_main("a\n", "base");
        let snapshots = ThreadRef::new(thread, RefKind::Snapshots(slot("alice.claude")));
        let message = snapshot_message("snapshot\n\nMahi-Turn: 1\n", thread);
        let blob = repo.store.write_blob(b"a\nb\n").unwrap();
        let mut head = Some(repo.snapshot((thread, "alice.claude"), "a\n", ""));
        let mut tree = repo.tree("a\nb\n");
        for moved in 0..100 {
            let name = format!("moved{moved}.rs");
            tree = repo
                .store
                .write_tree(&[(name.as_str(), EntryKind::Blob, blob)])
                .unwrap();
            head = Some(repo.store.append(&snapshots, head, tree, &message).unwrap());
        }
        let agents = vec![slot("alice.claude")];
        let message = format!("Land\n\n{}", landing_trailers(thread, &agents));
        let main_head = repo.store.head(&repo.main).unwrap();
        let landed = repo
            .store
            .append(&repo.main, main_head, tree, &message)
            .unwrap();
        let Blamed::Commit(blamed) = repo.store.line_commit(landed, "moved99.rs", 2).unwrap()
        else {
            panic!("line 2 is blamed");
        };
        let Origin::Landed(searched) =
            trace(&repo.store, ThreadId::random().unwrap(), &blamed).unwrap()
        else {
            panic!("the commit landed a thread");
        };
        assert_eq!(searched[0].found, Found::Snapshots(Vec::new(), Walked::Cut));
    }

    #[test]
    fn a_teammates_snapshot_too_large_to_read_ends_its_walk_without_failing_the_trace() {
        let repo = repo();
        let thread = ThreadId::random().unwrap();
        repo.on_main("a\n", "base");
        repo.snapshot((thread, "alice.claude"), "a\n", "");
        let added = repo.snapshot((thread, "alice.claude"), "a\nb\n", "Mahi-Turn: 1\n");
        repo.snapshot((thread, "bob.codex"), "a\n", "");
        let large = format!("X-Pad: {}\n", "x".repeat(70 * 1024));
        repo.snapshot((thread, "bob.codex"), "a\nb\n", &large);
        let agents = vec![slot("alice.claude"), slot("bob.codex")];
        let landed = repo.landing("a\nb\n", thread, &agents);
        let Origin::Landed(searched) = trace(
            &repo.store,
            ThreadId::random().unwrap(),
            &repo.blamed(landed, 2),
        )
        .unwrap() else {
            panic!("the commit landed a thread");
        };
        assert_eq!(
            searched[0].found,
            found(vec![FirstHeld {
                slot: slot("alice.claude"),
                snapshot: added,
                turn: Some(1),
            }])
        );
    }

    #[test]
    fn the_search_stops_once_it_walked_the_most_snapshots_it_may() {
        let repo = repo();
        let thread = ThreadId::random().unwrap();
        repo.on_main("a\n", "base");
        for _ in 0..MAX_TRACE_WORK {
            repo.snapshot((thread, "alice.claude"), "a\n", "");
        }
        repo.snapshot((thread, "alice.claude"), "a\nb\n", "Mahi-Turn: 1\n");
        let agents = vec![slot("alice.claude")];
        let landed = repo.landing("a\nb\n", thread, &agents);
        let Origin::Landed(searched) = trace(
            &repo.store,
            ThreadId::random().unwrap(),
            &repo.blamed(landed, 2),
        )
        .unwrap() else {
            panic!("the commit landed a thread");
        };
        assert_eq!(searched[0].found, Found::Snapshots(Vec::new(), Walked::Cut));
    }
}
